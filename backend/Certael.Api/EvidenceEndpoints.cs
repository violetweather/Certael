using Certael.Api.Security;
using Certael.Server.Evidence;

namespace Certael.Api;

public static class EvidenceEndpoints
{
    public static IEndpointRouteBuilder MapEvidenceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        RouteGroupBuilder group = endpoints.MapGroup("/v1/evidence")
            .RequireAuthorization().RequireRateLimiting("administration");

        group.MapGet("/page", async (string tenantId, string environmentId,
            string? search, string? playerSubject, string? sessionId, string? ruleId,
            string? signalFamily, string? recommendation, string? sortBy,
            string? sortDirection, string? cursor, int? pageSize, HttpContext http,
            IEvidenceStore evidence, CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, tenantId, environmentId);
            if (denied is not null) return denied;
            if (!TryParseOptional(signalFamily, out SignalFamily? parsedSignal)
                || !TryParseOptional(recommendation, out VerdictRecommendation? parsedRecommendation)
                || !TryParseOptional(sortBy, out EvidenceSortField? parsedSort)
                || !TryParseOptional(sortDirection, out EvidenceSortDirection? parsedDirection))
                return Results.BadRequest(new { error = "INVALID_EVIDENCE_QUERY" });
            try
            {
                return Results.Ok(await evidence.SearchAsync(new EvidenceSearchQuery(
                    tenantId, environmentId, search, playerSubject, sessionId, ruleId,
                    parsedSignal, parsedRecommendation, parsedSort ?? EvidenceSortField.CreatedAt,
                    parsedDirection ?? EvidenceSortDirection.Descending, cursor,
                    Math.Clamp(pageSize ?? 50, 1, 250)), cancellationToken));
            }
            catch (ArgumentException)
            {
                return Results.BadRequest(new { error = "INVALID_EVIDENCE_CURSOR" });
            }
        });

        group.MapGet("/{verdictId:guid}", async (Guid verdictId, string tenantId,
            string environmentId, HttpContext http, IEvidenceStore evidence,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, tenantId, environmentId);
            if (denied is not null) return denied;
            EvidenceBundle? bundle = await evidence.FindAsync(tenantId, verdictId, cancellationToken);
            return bundle is null || bundle.Verdict.EnvironmentId != environmentId
                ? Results.NotFound() : Results.Ok(bundle);
        });
        return endpoints;
    }

    private static IResult? Authorize(HttpContext http, string tenantId, string environmentId) =>
        ServiceIdentityGuard.Authorize(http.User, http.Connection.ClientCertificate,
            "evidence:read", tenantId, environmentId) switch
        {
            ServiceIdentityDecision.Unauthenticated => Results.Unauthorized(),
            ServiceIdentityDecision.Forbidden => Results.Forbid(),
            _ => null
        };

    private static bool TryParseOptional<T>(string? value, out T? parsed) where T : struct, Enum
    {
        parsed = null;
        if (value is null) return true;
        if (!Enum.TryParse(value, true, out T candidate) || !Enum.IsDefined(candidate)) return false;
        parsed = candidate;
        return true;
    }
}
