using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Certael.Installer;

public sealed record Auth0ConsoleBootstrapRequest(
    string RootPath, string Authority, string TokenEndpoint, string ClientId,
    string Audience, string CoreBaseUrl);

public sealed record Auth0ConsoleBootstrapResult(
    InstallationPlan Plan, string ConfigurationPath, string CertificatePath,
    DateTimeOffset CertificateExpiresAt);

public static class CertaelConsoleBootstrap
{
    public static Auth0ConsoleBootstrapResult CreateDevelopmentPlan(
        Auth0ConsoleBootstrapRequest request, DateTimeOffset now)
    {
        string root = Path.GetFullPath(request.RootPath);
        ValidateRoot(root);
        Uri authority = ValidateHttps(request.Authority, nameof(request.Authority), allowPath: false);
        Uri tokenEndpoint = ValidateHttps(request.TokenEndpoint, nameof(request.TokenEndpoint), allowPath: true);
        Uri core = ValidateHttps(request.CoreBaseUrl, nameof(request.CoreBaseUrl), allowPath: true);
        ValidateIdentifier(request.ClientId, 256, nameof(request.ClientId));
        ValidateIdentifier(request.Audience, 512, nameof(request.Audience));

        DateTimeOffset expiresAt = now.AddDays(30);
        byte[] certificate = CreateDevelopmentCertificate(now, expiresAt);
        string certificatePath = Path.Combine(root, "console", "workload-development.pfx");
        string configurationPath = Path.Combine(root, "console", "appsettings.Certael.json");
        var configuration = new
        {
            Authentication = new
            {
                Authority = authority.AbsoluteUri.TrimEnd('/'),
                request.ClientId,
                ClientSecret = string.Empty,
                Scopes = new[] { "openid", "profile" }
            },
            TokenExchange = new
            {
                Endpoint = tokenEndpoint.AbsoluteUri,
                request.ClientId,
                ClientSecret = string.Empty,
                request.Audience,
                Scopes = "evidence:read cases:read cases:write cases:act privacy:export"
            },
            Core = new { BaseUrl = core.AbsoluteUri.TrimEnd('/'), request.Audience },
            WorkloadIdentity = new
            {
                CertificatePath = certificatePath,
                CertificatePassword = string.Empty
            }
        };
        byte[] configurationBytes = JsonSerializer.SerializeToUtf8Bytes(configuration,
            new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });
        string instructions = $"""
            Certael console Auth0 bootstrap

            1. Register {authority.AbsoluteUri.TrimEnd('/')} as the OIDC authority.
            2. Configure Auth0 OBO token exchange for audience {request.Audience}.
            3. Register the SHA-256 certificate thumbprint printed by certaelctl with Auth0
               mTLS sender constraining and with Core's trusted client certificate roots.
            4. Inject Authentication__ClientSecret and TokenExchange__ClientSecret from a
               secret store. Never add either value to this directory.
            5. Set CERTAEL_CONSOLE_CONFIG={configurationPath}
            6. Start the published Certael.Console.Bff; it serves the React console itself.

            This generated certificate is development-only and expires at {expiresAt:O}.
            Replace it with a CA-issued or managed workload certificate for production.
            """;
        var plan = new InstallationPlan(Guid.NewGuid(), root,
        [
            new CreateDirectoryOperation("console-directory", "Create console configuration directory", "console"),
            new WriteFileOperation("console-certificate", "Write development workload certificate",
                "console/workload-development.pfx", certificate, Private: true),
            new WriteFileOperation("console-configuration", "Write Auth0 console configuration",
                "console/appsettings.Certael.json", configurationBytes),
            new WriteFileOperation("console-instructions", "Write Auth0 configuration instructions",
                "console/README.txt", Encoding.UTF8.GetBytes(instructions))
        ], now);
        return new Auth0ConsoleBootstrapResult(plan, configurationPath, certificatePath, expiresAt);
    }

    public static string CertificateThumbprintSha256(string path)
    {
        using X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12FromFile(
            Path.GetFullPath(path), null, X509KeyStorageFlags.EphemeralKeySet);
        return Convert.ToBase64String(SHA256.HashData(certificate.RawData))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static byte[] CreateDevelopmentCertificate(DateTimeOffset now, DateTimeOffset expiresAt)
    {
        using RSA key = RSA.Create(3072);
        var request = new CertificateRequest("CN=Certael Console Development", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication") }, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using X509Certificate2 certificate = request.CreateSelfSigned(now.AddMinutes(-5), expiresAt);
        return certificate.Export(X509ContentType.Pkcs12);
    }

    private static Uri ValidateHttps(string value, string name, bool allowPath)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)
            || uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)
            || (!allowPath && uri.AbsolutePath is not "/" and not ""))
            throw new ConfigurationException($"{name} must be an HTTPS URI without credentials, query, or fragment.");
        return uri;
    }

    private static void ValidateRoot(string root)
    {
        string? filesystemRoot = Path.GetPathRoot(root);
        if (filesystemRoot is not null && string.Equals(root.TrimEnd(Path.DirectorySeparatorChar),
            filesystemRoot.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new ConfigurationException("The console root cannot be a filesystem root.");
    }

    private static void ValidateIdentifier(string value, int maximum, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum || value.Any(char.IsControl))
            throw new ConfigurationException($"{name} is invalid.");
    }
}
