using System.Security.Claims;
using System.Security.Cryptography;
using Certael.Api.Security;
using Certael.Persistence.Postgres;
using Certael.Server.Economy;

namespace Certael.Api;

public static class EconomyEndpoints
{
    public static IEndpointRouteBuilder MapEconomyEndpoints(this IEndpointRouteBuilder endpoints)
    {
        RouteGroupBuilder group = endpoints.MapGroup("/v1/economy")
            .RequireAuthorization().RequireRateLimiting("administration");

        group.MapGet("/profiles", async (string tenantId, string gameId,
            string environmentId, HttpContext http, PostgresEconomyStore store,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "economy:read", tenantId, environmentId);
            return denied ?? Results.Ok(await store.ListProfilesAsync(tenantId, gameId,
                environmentId, cancellationToken));
        });

        group.MapPost("/profiles", async (SignedEconomyProfileRequest request,
            HttpContext http, EconomyProfileTrust trust, PostgresEconomyStore store,
            CancellationToken cancellationToken) =>
        {
            EconomyProtectionProfile profile;
            SignedEconomyProtectionProfile signed = request.ToSigned();
            try { profile = trust.Verify(signed); }
            catch (EconomyEventException)
            { return Results.BadRequest(new { error = "INVALID_SIGNED_ECONOMY_PROFILE" }); }
            IResult? denied = Authorize(http, "economy:write", profile.TenantId,
                profile.EnvironmentId);
            if (denied is not null) return denied;
            try
            {
                return Results.Created($"/v1/economy/profiles?tenantId={Uri.EscapeDataString(profile.TenantId)}" +
                    $"&gameId={Uri.EscapeDataString(profile.GameId)}&environmentId={Uri.EscapeDataString(profile.EnvironmentId)}",
                    await store.AddProfileAsync(signed, profile, Subject(http), cancellationToken));
            }
            catch (EconomyEventException)
            { return Results.Conflict(new { error = "ECONOMY_PROFILE_VERSION_CONFLICT" }); }
        });

        group.MapPost("/profiles/{profileId}/{version}/deployment", async (
            string profileId, string version, EconomyProfileDeploymentRequest request,
            HttpContext http, PostgresEconomyStore store, CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "economy:write", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            if (!Enum.TryParse(request.ExpectedStage, true, out EconomyProfileStage expected)
                || !Enum.TryParse(request.TargetStage, true, out EconomyProfileStage target)
                || !Enum.IsDefined(expected) || !Enum.IsDefined(target))
                return Results.BadRequest(new { error = "INVALID_ECONOMY_PROFILE_STAGE" });
            try
            {
                EconomyProfileSummary? result = await store.DeployProfileAsync(request.TenantId,
                    request.GameId, request.EnvironmentId, profileId, version, expected, target,
                    request.CanaryPercentage, Subject(http), cancellationToken);
                return result is null
                    ? Results.Conflict(new { error = "ECONOMY_PROFILE_DEPLOYMENT_CONFLICT" })
                    : Results.Ok(result);
            }
            catch (EconomyEventException)
            { return Results.BadRequest(new { error = "INVALID_ECONOMY_PROFILE_DEPLOYMENT" }); }
        });

        return endpoints;
    }

    private static IResult? Authorize(HttpContext http, string scope,
        string tenantId, string environmentId) =>
        ServiceIdentityGuard.Authorize(http.User, http.Connection.ClientCertificate,
            scope, tenantId, environmentId) switch
        {
            ServiceIdentityDecision.Unauthenticated => Results.Unauthorized(),
            ServiceIdentityDecision.Forbidden => Results.Forbid(),
            _ => null
        };

    private static string Subject(HttpContext http) => http.User.FindFirstValue("sub")
        ?? throw new InvalidOperationException("Missing subject.");
}

public sealed record SignedEconomyProfileRequest(byte[] CanonicalProfile, byte[] Signature,
    string KeyId, byte[] Digest)
{
    public SignedEconomyProtectionProfile ToSigned() =>
        new(CanonicalProfile, Signature, KeyId, Digest);
}

public sealed record EconomyProfileDeploymentRequest(string TenantId, string GameId,
    string EnvironmentId, string ExpectedStage, string TargetStage, int CanaryPercentage);

public sealed class EconomyProfileTrust : IDisposable
{
    private readonly Dictionary<string, ECDsa> _keys = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    public EconomyProfileTrust(IConfiguration configuration, IHostEnvironment environment,
        TimeProvider clock)
    {
        _clock = clock;
        IConfigurationSection[] configured = configuration
            .GetSection("ConfigurationSigning:TrustedKeys").GetChildren().ToArray();
        if (configured.Length == 0 && !environment.IsDevelopment())
            throw new InvalidOperationException("Economy profiles require configuration trust keys.");
        try
        {
            foreach (IConfigurationSection item in configured)
            {
                string keyId = item["KeyId"]
                    ?? throw new InvalidOperationException("Configuration trust key requires KeyId.");
                string path = item["PublicKeyPemPath"]
                    ?? throw new InvalidOperationException($"Configuration trust key {keyId} requires PublicKeyPemPath.");
                if (!ValidIdentifier(keyId) || _keys.ContainsKey(keyId))
                    throw new InvalidOperationException("Configuration trust key ID is invalid or duplicated.");
                var key = ECDsa.Create();
                try
                {
                    var info = new FileInfo(path);
                    if (!info.Exists || info.LinkTarget is not null || info.Length is < 1 or > 64 * 1024)
                        throw new InvalidOperationException("Configuration public key file is invalid.");
                    key.ImportFromPem(File.ReadAllText(info.FullName));
                    if (key.KeySize != 256) throw new InvalidOperationException("Configuration key must be P-256.");
                    _keys.Add(keyId, key);
                }
                catch { key.Dispose(); throw; }
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public EconomyProtectionProfile Verify(SignedEconomyProtectionProfile signed) =>
        EconomyProtectionProfileSigner.Verify(signed, _keys, _clock.GetUtcNow());

    public RelationshipProtectionProfile Verify(SignedRelationshipProtectionProfile signed) =>
        RelationshipProtectionProfileSigner.Verify(signed, _keys, _clock.GetUtcNow());

    public void Dispose()
    {
        foreach (ECDsa key in _keys.Values) key.Dispose();
        _keys.Clear();
    }

    private static bool ValidIdentifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-');
}
