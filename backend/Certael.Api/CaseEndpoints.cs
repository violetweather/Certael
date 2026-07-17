using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Certael.Api.Security;
using Certael.Server.Cases;

namespace Certael.Api;

public static class CaseEndpoints
{
    public static IEndpointRouteBuilder MapCaseEndpoints(this IEndpointRouteBuilder endpoints)
    {
        RouteGroupBuilder group = endpoints.MapGroup("/v1/cases")
            .RequireAuthorization().RequireRateLimiting("administration");

        group.MapGet("/", async (string tenantId, string environmentId, string? state,
            string? assignedTo, string? playerSubject, string? search, int? maximum,
            HttpContext http, ICaseStore cases, CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:read", tenantId, environmentId);
            if (denied is not null) return denied;
            CaseState? parsedState = null;
            if (state is not null)
            {
                if (!Enum.TryParse(state, true, out CaseState candidate))
                    return Results.BadRequest(new { error = "INVALID_CASE_STATE" });
                parsedState = candidate;
            }
            var query = new CaseQueueQuery(tenantId, environmentId, parsedState,
                assignedTo, playerSubject, search, Math.Clamp(maximum ?? 100, 1, 1000));
            return Results.Ok(await cases.SearchAsync(query, cancellationToken));
        });

        group.MapGet("/{caseId:guid}", async (Guid caseId, string tenantId,
            string environmentId, HttpContext http, ICaseStore cases,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:read", tenantId, environmentId);
            if (denied is not null) return denied;
            CaseDetail? detail = await cases.FindAsync(tenantId, caseId, cancellationToken);
            return detail is null || detail.Case.EnvironmentId != environmentId
                ? Results.NotFound() : Results.Ok(detail);
        });

        group.MapPost("/{caseId:guid}/assignment", async (Guid caseId,
            CaseAssignmentRequest request, HttpContext http, ICaseStore cases,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:write", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            CaseSummary? result = await cases.AssignAsync(request.TenantId, caseId,
                request.AssignedTo, Subject(http), request.Reason, request.ExpectedVersion,
                cancellationToken);
            return result is null ? Results.Conflict(new { error = "CASE_VERSION_CONFLICT" })
                : Results.Ok(result);
        });

        group.MapPost("/{caseId:guid}/notes", async (Guid caseId,
            CaseNoteRequest request, HttpContext http, ICaseStore cases,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:write", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            CaseNote? result = await cases.AddNoteAsync(request.TenantId, caseId,
                Subject(http), request.Body, request.ExpectedVersion, cancellationToken);
            return result is null ? Results.Conflict(new { error = "CASE_VERSION_CONFLICT" })
                : Results.Ok(result);
        });

        group.MapPost("/{caseId:guid}/transition", async (Guid caseId,
            CaseTransitionRequest request, HttpContext http, ICaseStore cases,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:write", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            if (!Enum.TryParse(request.TargetState, true, out CaseState state)
                || (request.Disposition is not null && !Enum.TryParse(
                    request.Disposition, true, out CaseDisposition _)))
                return Results.BadRequest(new { error = "INVALID_CASE_TRANSITION" });
            CaseDisposition? disposition = request.Disposition is null ? null
                : Enum.Parse<CaseDisposition>(request.Disposition, true);
            CaseSummary? result = await cases.TransitionAsync(request.TenantId, caseId,
                state, disposition, Subject(http), request.Reason, request.ExpectedVersion,
                cancellationToken);
            return result is null ? Results.Conflict(new { error = "CASE_TRANSITION_CONFLICT" })
                : Results.Ok(result);
        });

        group.MapPost("/{caseId:guid}/actions", async (Guid caseId,
            BoundedActionRequest request, HttpContext http, ICaseStore cases,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:act", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            if (!Enum.TryParse(request.Kind, true, out BoundedActionKind kind))
                return Results.BadRequest(new { error = "INVALID_BOUNDED_ACTION" });
            string subject = Subject(http);
            byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|',
                subject, request.TenantId, caseId, kind, request.TargetType,
                request.TargetId, request.ExpectedVersion, request.Reason)));
            BoundedAction? result = await cases.ApproveActionAsync(request.TenantId,
                caseId, kind, request.TargetType, request.TargetId, request.Reason,
                subject, subject, digest, request.ExpectedVersion, cancellationToken);
            return result is null ? Results.Conflict(new { error = "ACTION_APPROVAL_CONFLICT" })
                : Results.Ok(result);
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

    private static string Subject(HttpContext http) =>
        http.User.FindFirstValue("sub") ?? throw new InvalidOperationException("Missing subject.");
}

public sealed record CaseAssignmentRequest(string TenantId, string EnvironmentId,
    string? AssignedTo, string Reason, long ExpectedVersion);
public sealed record CaseNoteRequest(string TenantId, string EnvironmentId,
    string Body, long ExpectedVersion);
public sealed record CaseTransitionRequest(string TenantId, string EnvironmentId,
    string TargetState, string? Disposition, string Reason, long ExpectedVersion);
public sealed record BoundedActionRequest(string TenantId, string EnvironmentId,
    string Kind, string TargetType, string TargetId, string Reason, long ExpectedVersion);
