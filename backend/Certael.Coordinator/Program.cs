using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certael.Coordinator;
using Certael.Server.Sessions;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Npgsql;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 64 * 1024;
    if (!builder.Environment.IsDevelopment())
        options.ConfigureHttpsDefaults(https =>
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate);
});
string connection = builder.Configuration.GetConnectionString("ControlPostgres")
    ?? throw new InvalidOperationException(
        "ConnectionStrings:ControlPostgres is required.");
builder.Services.AddSingleton(NpgsqlDataSource.Create(connection));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<CoordinatorStore>();
string signingKeyId = builder.Configuration["Coordinator:SigningKeyId"]
    ?? (builder.Environment.IsDevelopment() ? "development-transfer-key"
        : throw new InvalidOperationException("Coordinator:SigningKeyId is required."));
string? signingKeyValue = builder.Configuration["Coordinator:SigningPrivateKeyPkcs8Base64"];
ECDsa signingKey;
if (builder.Environment.IsDevelopment() && string.IsNullOrWhiteSpace(signingKeyValue))
{
    signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
}
else
{
    if (string.IsNullOrWhiteSpace(signingKeyValue)) throw new InvalidOperationException(
        "Coordinator:SigningPrivateKeyPkcs8Base64 is required.");
    byte[] signingMaterial;
    try { signingMaterial = Convert.FromBase64String(signingKeyValue); }
    catch (FormatException exception)
    { throw new InvalidOperationException("Coordinator signing key is invalid.", exception); }
    if (signingMaterial.Length is < 64 or > 4096)
        throw new InvalidOperationException("Coordinator signing key size is invalid.");
    signingKey = ECDsa.Create();
    try
    {
        signingKey.ImportPkcs8PrivateKey(signingMaterial, out int consumed);
        if (consumed != signingMaterial.Length || signingKey.KeySize != 256)
            throw new InvalidOperationException("Coordinator signing key must be P-256.");
    }
    finally { CryptographicOperations.ZeroMemory(signingMaterial); }
}
builder.Services.AddSingleton(signingKey);
builder.Services.AddSingleton(new RegionTransferGrantSigner(signingKey, signingKeyId));

WebApplication app = builder.Build();
await ApplyMigrations(app.Services.GetRequiredService<NpgsqlDataSource>());
bool insecureDevelopment = app.Environment.IsDevelopment()
    && app.Configuration.GetValue("Coordinator:AllowInsecureDevelopment", false);
X509Certificate2? clientCa = LoadClientCa(app.Configuration, app.Environment,
    insecureDevelopment);
HashSet<string> failoverCertificates = app.Configuration
    .GetSection("Coordinator:FailoverCertificateThumbprints").Get<string[]>()?
    .Select(NormalizeThumbprint).ToHashSet(StringComparer.Ordinal) ?? [];

app.Use(async (context, next) =>
{
    if (context.Request.Path == "/healthz") { await next(); return; }
    X509Certificate2? certificate = await context.Connection.GetClientCertificateAsync(
        context.RequestAborted);
    if (certificate is not null && clientCa is not null
        && ValidClientCertificate(certificate, clientCa, DateTime.UtcNow))
    {
        string subject = certificate.GetNameInfo(X509NameType.SimpleName, false);
        if (!Identifier(subject)) { context.Response.StatusCode = 401; return; }
        context.Items["CertaelIdentity"] = new CoordinatorIdentity(subject,
            NormalizeThumbprint(certificate.Thumbprint), false);
        await next(); return;
    }
    if (insecureDevelopment
        && context.Request.Headers.TryGetValue("X-Certael-Development-Identity", out var values)
        && values.Count == 1 && Identifier(values[0]!))
    {
        context.Items["CertaelIdentity"] = new CoordinatorIdentity(values[0]!, "development", true);
        await next(); return;
    }
    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
});

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
app.MapPost("/v1/leases/acquire", async (AcquireRequest request, HttpContext context,
    CoordinatorStore store, CancellationToken cancellationToken) =>
{
    CoordinatorIdentity identity = Identity(context);
    if (request.Force)
    {
        if (!(identity.Development && identity.Subject.StartsWith("operator-",
                StringComparison.Ordinal))
            && !failoverCertificates.Contains(identity.Thumbprint)) return Results.Forbid();
    }
    else if (request.ServerId != identity.Subject) return Results.Forbid();
    RegionalLeaseV1? lease = await store.AcquireAsync(request.TenantId, request.GameId,
        request.EnvironmentId, request.MatchId, request.Region, request.ServerId,
        request.Force, identity.Subject, cancellationToken);
    return lease is null ? Results.Conflict(new { reason = "MATCH_OWNED" }) : Results.Ok(lease);
});
app.MapPost("/v1/leases/renew", async (RegionalLeaseV1 lease, HttpContext context,
    CoordinatorStore store, CancellationToken cancellationToken) =>
{
    if (lease.OwnerServer != Identity(context).Subject) return Results.Forbid();
    RegionalLeaseV1? renewed = await store.RenewAsync(lease, cancellationToken);
    return renewed is null
        ? Results.Conflict(new { reason = "STALE_FENCING_EPOCH" }) : Results.Ok(renewed);
});
app.MapPost("/v1/leases/release", async (ReleaseRequest request, HttpContext context,
    CoordinatorStore store, CancellationToken cancellationToken) =>
{
    CoordinatorIdentity identity = Identity(context);
    if (request.Lease.OwnerServer != identity.Subject) return Results.Forbid();
    return await store.ReleaseAsync(request.Lease, identity.Subject, cancellationToken)
        ? Results.NoContent() : Results.Conflict(new { reason = "STALE_FENCING_EPOCH" });
});
app.MapPost("/v1/leases/validate", async (RegionalLeaseV1 lease, HttpContext context,
    CoordinatorStore store, CancellationToken cancellationToken) =>
{
    if (lease.OwnerServer != Identity(context).Subject) return Results.Forbid();
    return await store.IsCurrentOwnerAsync(lease, cancellationToken)
        ? Results.NoContent() : Results.Conflict(new { reason = "STALE_FENCING_EPOCH" });
});
app.MapPost("/v1/transfers", async (TransferRequest request, HttpContext context,
    CoordinatorStore store, RegionTransferGrantSigner signer, TimeProvider clock,
    CancellationToken cancellationToken) =>
{
    CoordinatorIdentity identity = Identity(context);
    if (request.Lease.OwnerServer != identity.Subject || !Identifier(request.PlayerSubject)
        || !Identifier(request.DestinationRegion)
        || request.DestinationRegion == request.Lease.OwnerRegion) return Results.Forbid();
    DateTimeOffset now = clock.GetUtcNow();
    var grant = new RegionTransferGrantV1(Guid.NewGuid(), request.Lease.TenantId,
        request.Lease.GameId, request.Lease.EnvironmentId, request.Lease.MatchId,
        request.PlayerSubject, request.Lease.OwnerRegion, request.DestinationRegion,
        request.Lease.FencingEpoch, RandomNumberGenerator.GetBytes(32), now,
        now.AddSeconds(60));
    SignedRegionTransferGrant signed = signer.Sign(grant);
    return await store.RecordGrantIfOwnerAsync(request.Lease, grant, signed,
        identity.Subject, cancellationToken)
        ? Results.Ok(signed) : Results.Conflict(new { reason = "STALE_FENCING_EPOCH" });
});
app.MapPost("/v1/transfers/redeem", async (RedeemRequest request, HttpContext context,
    CoordinatorStore store, ECDsa key, TimeProvider clock, CancellationToken cancellationToken) =>
{
    CoordinatorIdentity identity = Identity(context); RegionTransferGrantV1 grant;
    try
    {
        if (request.Grant.KeyId != signingKeyId)
            throw new RegionTransferGrantException("Unknown signing key.");
        grant = RegionTransferGrantSigner.Verify(request.Grant,
            new Dictionary<string, ECDsa> { [signingKeyId] = key }, clock.GetUtcNow());
    }
    catch (RegionTransferGrantException)
    { return Results.BadRequest(new { reason = "INVALID_TRANSFER_GRANT" }); }
    RegionalLeaseV1? lease = await store.RedeemAsync(grant, request.Grant, identity.Subject,
        identity.Subject, cancellationToken);
    return lease is null ? Results.Conflict(new { reason = "TRANSFER_NOT_REDEEMABLE" })
        : Results.Ok(new TransferRedemption(lease, true, true));
});
await app.RunAsync();

static CoordinatorIdentity Identity(HttpContext context) =>
    context.Items["CertaelIdentity"] as CoordinatorIdentity
    ?? throw new InvalidOperationException("Coordinator identity middleware did not run.");
static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
    && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
        || character is '.' or '_' or '-' or ':');
static string NormalizeThumbprint(string value) =>
    new(value.Where(char.IsAsciiHexDigit).Select(char.ToUpperInvariant).ToArray());
static X509Certificate2? LoadClientCa(IConfiguration configuration,
    IHostEnvironment environment, bool insecureDevelopment)
{
    string? path = configuration["Coordinator:ClientCaCertificatePath"];
    if (string.IsNullOrWhiteSpace(path))
    {
        if (environment.IsDevelopment() && insecureDevelopment) return null;
        throw new InvalidOperationException(
            "Coordinator:ClientCaCertificatePath is required outside insecure development.");
    }
    X509Certificate2 certificate;
    try { certificate = X509Certificate2.CreateFromPemFile(path); }
    catch (Exception exception) when (exception is CryptographicException
        or IOException or UnauthorizedAccessException)
    {
        throw new InvalidOperationException("Coordinator client CA is invalid.", exception);
    }
    if (!certificate.Extensions.OfType<X509BasicConstraintsExtension>()
        .Any(extension => extension.CertificateAuthority))
    {
        certificate.Dispose();
        throw new InvalidOperationException("Coordinator client CA is not a CA certificate.");
    }
    return certificate;
}
static bool ValidClientCertificate(X509Certificate2 certificate,
    X509Certificate2 clientCa, DateTime utcNow)
{
    if (certificate.NotBefore.ToUniversalTime() > utcNow
        || certificate.NotAfter.ToUniversalTime() <= utcNow) return false;
    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(clientCa);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
    chain.ChainPolicy.ApplicationPolicy.Add(
        new Oid("1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication"));
    return chain.Build(certificate)
        && chain.ChainElements.Count > 1
        && CryptographicOperations.FixedTimeEquals(
            chain.ChainElements[^1].Certificate.GetCertHash(HashAlgorithmName.SHA256),
            clientCa.GetCertHash(HashAlgorithmName.SHA256));
}
static async Task ApplyMigrations(NpgsqlDataSource source)
{
    string[] resources = Assembly.GetExecutingAssembly().GetManifestResourceNames()
        .Where(name => name.Contains(".Migrations.", StringComparison.Ordinal)
            && name.EndsWith(".sql", StringComparison.Ordinal))
        .Order(StringComparer.Ordinal).ToArray();
    if (resources.Length == 0) throw new InvalidOperationException("No coordinator migrations found.");
    await using NpgsqlConnection connection = await source.OpenConnectionAsync();
    foreach (string resource in resources)
    {
        await using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException($"Missing migration {resource}.");
        using var reader = new StreamReader(stream);
        await using var command = new NpgsqlCommand(await reader.ReadToEndAsync(), connection);
        await command.ExecuteNonQueryAsync();
    }
}

public sealed record CoordinatorIdentity(string Subject, string Thumbprint, bool Development);
public sealed record AcquireRequest(string TenantId, string GameId, string EnvironmentId,
    string MatchId, string Region, string ServerId, bool Force);
public sealed record ReleaseRequest(RegionalLeaseV1 Lease);
public sealed record TransferRequest(RegionalLeaseV1 Lease, string PlayerSubject,
    string DestinationRegion);
public sealed record RedeemRequest(SignedRegionTransferGrant Grant);
public sealed record TransferRedemption(RegionalLeaseV1 Lease, bool FreshCoreSessionRequired,
    bool FreshAgentSessionRequired);

public partial class Program;
