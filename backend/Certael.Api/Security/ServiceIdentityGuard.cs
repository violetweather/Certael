using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Certael.Api.Security;

public enum ServiceIdentityDecision { Allowed, Unauthenticated, Forbidden }

public static class ServiceIdentityGuard
{
    public static ServiceIdentityDecision Authorize(
        ClaimsPrincipal principal,
        X509Certificate2? clientCertificate,
        string requiredScope,
        string requestedTenant,
        string requestedEnvironment,
        Func<X509Certificate2, bool>? trustValidator = null)
    {
        if (principal.Identity?.IsAuthenticated != true || clientCertificate is null)
            return ServiceIdentityDecision.Unauthenticated;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now < clientCertificate.NotBefore.ToUniversalTime()
            || now > clientCertificate.NotAfter.ToUniversalTime())
            return ServiceIdentityDecision.Unauthenticated;
        if (!(trustValidator ?? CertificateChainsToTrustedClientRoot)(clientCertificate))
            return ServiceIdentityDecision.Unauthenticated;
        if (!CertificateIsBoundToToken(principal, clientCertificate))
            return ServiceIdentityDecision.Forbidden;
        if (!Scopes(principal).Contains(requiredScope, StringComparer.Ordinal))
            return ServiceIdentityDecision.Forbidden;
        if (!string.Equals(principal.FindFirstValue("tenant_id"), requestedTenant, StringComparison.Ordinal)
            || !string.Equals(principal.FindFirstValue("environment_id"), requestedEnvironment, StringComparison.Ordinal))
            return ServiceIdentityDecision.Forbidden;
        return ServiceIdentityDecision.Allowed;
    }

    private static bool CertificateChainsToTrustedClientRoot(X509Certificate2 certificate)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
        chain.ChainPolicy.ApplicationPolicy.Add(
            new Oid("1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication"));
        try { return chain.Build(certificate); }
        catch (CryptographicException) { return false; }
    }

    private static IEnumerable<string> Scopes(ClaimsPrincipal principal) =>
        principal.FindAll("scope").SelectMany(claim =>
            claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    private static bool CertificateIsBoundToToken(ClaimsPrincipal principal, X509Certificate2 certificate)
    {
        string expected = Base64UrlEncode(SHA256.HashData(certificate.RawData));
        string? direct = principal.FindFirstValue("x5t#S256");
        if (direct is not null)
            return FixedTimeTextEquals(direct, expected);

        string? confirmation = principal.FindFirstValue("cnf");
        if (confirmation is null) return false;
        try
        {
            using JsonDocument document = JsonDocument.Parse(confirmation);
            return document.RootElement.TryGetProperty("x5t#S256", out JsonElement thumbprint)
                && thumbprint.ValueKind == JsonValueKind.String
                && FixedTimeTextEquals(thumbprint.GetString()!, expected);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool FixedTimeTextEquals(string supplied, string expected)
    {
        byte[] left = System.Text.Encoding.ASCII.GetBytes(supplied);
        byte[] right = System.Text.Encoding.ASCII.GetBytes(expected);
        return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    }
}
