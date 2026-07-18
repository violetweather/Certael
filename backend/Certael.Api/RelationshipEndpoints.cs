using System.Security.Claims;
using Certael.Api.Security;
using Certael.Persistence.Postgres;
using Certael.Server.Economy;

namespace Certael.Api;

public static class RelationshipEndpoints
{
    public static IEndpointRouteBuilder MapRelationshipEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        RouteGroupBuilder group = endpoints.MapGroup("/v1/relationships")
            .RequireAuthorization().RequireRateLimiting("administration");

        group.MapGet("/profiles", async (string tenantId, string gameId,
            string environmentId, HttpContext http, PostgresRelationshipStore store,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "economy:read", tenantId, environmentId);
            return denied ?? Results.Ok(await store.ListProfilesAsync(tenantId, gameId,
                environmentId, cancellationToken));
        });

        group.MapPost("/profiles", async (SignedRelationshipProfileRequest request,
            HttpContext http, EconomyProfileTrust trust, PostgresRelationshipStore store,
            CancellationToken cancellationToken) =>
        {
            SignedRelationshipProtectionProfile signed = request.ToSigned();
            RelationshipProtectionProfile profile;
            try { profile = trust.Verify(signed); }
            catch (EconomyEventException)
            { return Results.BadRequest(new { error = "INVALID_SIGNED_RELATIONSHIP_PROFILE" }); }
            IResult? denied = Authorize(http, "economy:write", profile.TenantId,
                profile.EnvironmentId);
            if (denied is not null) return denied;
            try
            {
                return Results.Created(
                    $"/v1/relationships/profiles?tenantId={Uri.EscapeDataString(profile.TenantId)}" +
                    $"&gameId={Uri.EscapeDataString(profile.GameId)}&environmentId={Uri.EscapeDataString(profile.EnvironmentId)}",
                    await store.AddProfileAsync(signed, profile, Subject(http), cancellationToken));
            }
            catch (EconomyEventException)
            { return Results.Conflict(new { error = "RELATIONSHIP_PROFILE_VERSION_CONFLICT" }); }
        });

        group.MapPost("/profiles/{profileId}/{version}/deployment", async (
            string profileId, string version, RelationshipProfileDeploymentRequest request,
            HttpContext http, PostgresRelationshipStore store,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "economy:write", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            if (!Enum.TryParse(request.ExpectedStage, true, out EconomyProfileStage expected)
                || !Enum.TryParse(request.TargetStage, true, out EconomyProfileStage target)
                || !Enum.IsDefined(expected) || !Enum.IsDefined(target))
                return Results.BadRequest(new { error = "INVALID_RELATIONSHIP_PROFILE_STAGE" });
            try
            {
                RelationshipProfileSummary? result = await store.DeployProfileAsync(
                    request.TenantId, request.GameId, request.EnvironmentId, profileId,
                    version, expected, target, request.CanaryPercentage, Subject(http),
                    cancellationToken);
                return result is null
                    ? Results.Conflict(new { error = "RELATIONSHIP_PROFILE_DEPLOYMENT_CONFLICT" })
                    : Results.Ok(result);
            }
            catch (EconomyEventException)
            { return Results.BadRequest(new { error = "INVALID_RELATIONSHIP_PROFILE_DEPLOYMENT" }); }
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

public sealed record SignedRelationshipProfileRequest(byte[] CanonicalProfile,
    byte[] Signature, string KeyId, byte[] Digest)
{
    public SignedRelationshipProtectionProfile ToSigned() =>
        new(CanonicalProfile, Signature, KeyId, Digest);
}

public sealed record RelationshipProfileDeploymentRequest(string TenantId, string GameId,
    string EnvironmentId, string ExpectedStage, string TargetStage,
    int CanaryPercentage);
