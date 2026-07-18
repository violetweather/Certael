using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Certael.Api.Security;
using Certael.Server.Cases;
using Certael.Server.Evidence;

namespace Certael.Api;

public static class CaseEndpoints
{
    public static IEndpointRouteBuilder MapCaseEndpoints(this IEndpointRouteBuilder endpoints)
    {
        RouteGroupBuilder group = endpoints.MapGroup("/v1/cases")
            .RequireAuthorization().RequireRateLimiting("administration");

        group.MapGet("/", async (string tenantId, string environmentId, string? state,
            string? assignedTo, string? playerSubject, string? search, int? maximum,
            string? category, string? ruleId, string? signalFamily,
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
            SignalFamily? parsedSignal = ParseSignal(signalFamily);
            if (signalFamily is not null && parsedSignal is null)
                return Results.BadRequest(new { error = "INVALID_SIGNAL_FAMILY" });
            var query = new CaseQueueQuery(tenantId, environmentId, parsedState,
                assignedTo, playerSubject, search, Math.Clamp(maximum ?? 100, 1, 1000),
                category, ruleId, parsedSignal);
            return Results.Ok(await cases.SearchAsync(query, cancellationToken));
        });

        group.MapGet("/page", async (string tenantId, string environmentId, string? state,
            string? assignedTo, string? playerSubject, string? search, string? category,
            string? ruleId, string? signalFamily, string? sortBy, string? sortDirection,
            string? cursor, int? pageSize, HttpContext http, ICaseStore cases,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:read", tenantId, environmentId);
            if (denied is not null) return denied;
            if (!TryParseOptional(state, out CaseState? parsedState)
                || !TryParseOptional(signalFamily, out SignalFamily? parsedSignal)
                || !TryParseOptional(sortBy, out CaseSortField? parsedSort)
                || !TryParseOptional(sortDirection, out CaseSortDirection? parsedDirection))
                return Results.BadRequest(new { error = "INVALID_CASE_QUERY" });
            try
            {
                var query = new CaseQueueQuery(tenantId, environmentId, parsedState,
                    assignedTo, playerSubject, search, 100, category, ruleId, parsedSignal,
                    parsedSort ?? CaseSortField.UpdatedAt,
                    parsedDirection ?? CaseSortDirection.Descending,
                    cursor, Math.Clamp(pageSize ?? 50, 1, 250));
                return Results.Ok(await cases.SearchPageAsync(query, cancellationToken));
            }
            catch (ArgumentException)
            {
                return Results.BadRequest(new { error = "INVALID_CASE_CURSOR" });
            }
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
            CaseDetail? current = await FindInEnvironmentAsync(cases, request.TenantId,
                request.EnvironmentId, caseId, cancellationToken);
            if (current is null) return Results.NotFound();
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
            CaseDetail? current = await FindInEnvironmentAsync(cases, request.TenantId,
                request.EnvironmentId, caseId, cancellationToken);
            if (current is null) return Results.NotFound();
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
            CaseDetail? current = await FindInEnvironmentAsync(cases, request.TenantId,
                request.EnvironmentId, caseId, cancellationToken);
            if (current is null) return Results.NotFound();
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
            CaseDetail? current = await FindInEnvironmentAsync(cases, request.TenantId,
                request.EnvironmentId, caseId, cancellationToken);
            if (current is null) return Results.NotFound();
            if (!Enum.TryParse(request.Kind, true, out BoundedActionKind kind))
                return Results.BadRequest(new { error = "INVALID_BOUNDED_ACTION" });
            string subject = Subject(http);
            string policyRequester = $"policy:{current.Case.SignedPolicyId}@{current.Case.SignedPolicyVersion}";
            byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|',
                policyRequester, subject, request.TenantId, caseId, kind, request.TargetType,
                request.TargetId, request.ExpectedVersion, request.Reason)));
            BoundedAction? result = await cases.ApproveActionAsync(request.TenantId,
                caseId, kind, request.TargetType, request.TargetId, request.Reason,
                policyRequester, subject, digest, request.ExpectedVersion, cancellationToken);
            return result is null ? Results.Conflict(new { error = "ACTION_APPROVAL_CONFLICT" })
                : Results.Ok(result);
        });

        group.MapPut("/{caseId:guid}/metadata", async (Guid caseId,
            CaseMetadataRequest request, HttpContext http, ICaseStore cases,
            ICaseSettingsStore settingsStore,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:write", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            CaseDetail? current = await FindInEnvironmentAsync(cases, request.TenantId,
                request.EnvironmentId, caseId, cancellationToken);
            if (current is null) return Results.NotFound();
            try
            {
                CaseSettingsSnapshot settings = await settingsStore.GetAsync(
                    new CaseSettingsScope(request.TenantId, current.Case.GameId,
                        request.EnvironmentId), cancellationToken);
                IReadOnlyList<CaseMetadataValue> normalized = NormalizeMetadata(
                    settings, request.Category, request.Metadata);
                CaseSummary? result = await cases.UpdateMetadataAsync(request.TenantId, caseId,
                    request.Category, normalized, Subject(http), request.Reason,
                    request.ExpectedVersion, cancellationToken);
                return result is null ? Results.Conflict(new { error = "CASE_VERSION_CONFLICT" })
                    : Results.Ok(result);
            }
            catch (ArgumentException)
            {
                return Results.BadRequest(new { error = "INVALID_CASE_METADATA" });
            }
        });

        RouteGroupBuilder settings = endpoints.MapGroup("/v1/case-settings")
            .RequireAuthorization().RequireRateLimiting("administration");

        settings.MapGet("/", async (string tenantId, string gameId, string environmentId,
            HttpContext http, ICaseSettingsStore store, CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:read", tenantId, environmentId);
            if (denied is not null) return denied;
            try
            {
                return Results.Ok(await store.GetAsync(
                    new CaseSettingsScope(tenantId, gameId, environmentId), cancellationToken));
            }
            catch (ArgumentException)
            {
                return Results.BadRequest(new { error = "INVALID_CASE_SETTINGS_SCOPE" });
            }
        });

        settings.MapPut("/categories/{key}", async (string key,
            CaseCategorySettingsRequest request, HttpContext http, ICaseSettingsStore store,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:write", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            if (!string.Equals(key, request.Key, StringComparison.Ordinal))
                return Results.BadRequest(new { error = "CASE_SETTING_KEY_MISMATCH" });
            try
            {
                CaseCategoryDefinition? result = await store.UpsertCategoryAsync(
                    new CaseSettingsScope(request.TenantId, request.GameId, request.EnvironmentId),
                    new CaseCategoryDefinition(request.Key, request.DisplayName,
                        request.Description, request.Enabled, request.SortOrder, 0, default),
                    request.ExpectedVersion, Subject(http), request.Reason, cancellationToken);
                return result is null
                    ? Results.Conflict(new { error = "CASE_SETTING_VERSION_CONFLICT" })
                    : Results.Ok(result);
            }
            catch (ArgumentException)
            {
                return Results.BadRequest(new { error = "INVALID_CASE_CATEGORY_SETTING" });
            }
        });

        settings.MapPut("/metadata/{key}", async (string key,
            CaseMetadataSettingsRequest request, HttpContext http, ICaseSettingsStore store,
            CancellationToken cancellationToken) =>
        {
            IResult? denied = Authorize(http, "cases:write", request.TenantId,
                request.EnvironmentId);
            if (denied is not null) return denied;
            if (!string.Equals(key, request.Key, StringComparison.Ordinal))
                return Results.BadRequest(new { error = "CASE_SETTING_KEY_MISMATCH" });
            if (!Enum.TryParse(request.Type, true, out CaseMetadataType type)
                || !Enum.IsDefined(type))
                return Results.BadRequest(new { error = "INVALID_CASE_METADATA_TYPE" });
            try
            {
                CaseMetadataDefinition? result = await store.UpsertMetadataDefinitionAsync(
                    new CaseSettingsScope(request.TenantId, request.GameId, request.EnvironmentId),
                    new CaseMetadataDefinition(request.Key, request.Label, type,
                        request.EnumerationValues ?? [], request.Sensitive, request.Searchable,
                        request.Required, request.Enabled, 0, default),
                    request.ExpectedVersion, Subject(http), request.Reason, cancellationToken);
                return result is null
                    ? Results.Conflict(new { error = "CASE_SETTING_VERSION_CONFLICT" })
                    : Results.Ok(result);
            }
            catch (ArgumentException)
            {
                return Results.BadRequest(new { error = "INVALID_CASE_METADATA_SETTING" });
            }
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

    private static async ValueTask<CaseDetail?> FindInEnvironmentAsync(
        ICaseStore cases, string tenantId, string environmentId, Guid caseId,
        CancellationToken cancellationToken)
    {
        CaseDetail? current = await cases.FindAsync(tenantId, caseId, cancellationToken);
        return current is not null && current.Case.EnvironmentId == environmentId
            ? current : null;
    }

    private static IReadOnlyList<CaseMetadataValue> NormalizeMetadata(
        CaseSettingsSnapshot settings, string category,
        IReadOnlyList<CaseMetadataValue> requested)
    {
        CaseCategoryDefinition[] enabledCategories = settings.Categories
            .Where(value => value.Enabled).ToArray();
        if (enabledCategories.Length == 0)
        {
            if (!string.Equals(category, "General", StringComparison.Ordinal))
                throw new ArgumentException("A category definition is required.");
        }
        else if (!enabledCategories.Any(value => value.Key == category))
            throw new ArgumentException("The category is not enabled.");

        Dictionary<string, CaseMetadataDefinition> definitions = settings.MetadataDefinitions
            .Where(value => value.Enabled).ToDictionary(value => value.Key, StringComparer.Ordinal);
        if (requested.Select(value => value.Key).Distinct(StringComparer.Ordinal).Count()
            != requested.Count)
            throw new ArgumentException("Metadata keys must be unique.");
        var normalized = new List<CaseMetadataValue>(requested.Count);
        foreach (CaseMetadataValue value in requested)
        {
            if (!definitions.TryGetValue(value.Key, out CaseMetadataDefinition? definition)
                || value.Type != definition.Type)
                throw new ArgumentException("Metadata does not match an enabled definition.");
            if (definition.Type == CaseMetadataType.Enumeration
                && !definition.EnumerationValues.Contains(value.Value, StringComparer.Ordinal))
                throw new ArgumentException("Metadata enumeration value is not allowed.");
            normalized.Add(value with
            {
                Sensitive = definition.Sensitive,
                Searchable = definition.Searchable
            });
        }
        if (definitions.Values.Any(definition => definition.Required
            && normalized.All(value => value.Key != definition.Key)))
            throw new ArgumentException("Required metadata is missing.");
        return normalized;
    }

    private static SignalFamily? ParseSignal(string? value) => value is null ? null
        : Enum.TryParse(value, true, out SignalFamily parsed) ? parsed : null;

    private static bool TryParseOptional<T>(string? value, out T? parsed) where T : struct, Enum
    {
        parsed = null;
        if (value is null) return true;
        if (!Enum.TryParse(value, true, out T candidate) || !Enum.IsDefined(candidate)) return false;
        parsed = candidate;
        return true;
    }
}

public sealed record CaseAssignmentRequest(string TenantId, string EnvironmentId,
    string? AssignedTo, string Reason, long ExpectedVersion);
public sealed record CaseNoteRequest(string TenantId, string EnvironmentId,
    string Body, long ExpectedVersion);
public sealed record CaseTransitionRequest(string TenantId, string EnvironmentId,
    string TargetState, string? Disposition, string Reason, long ExpectedVersion);
public sealed record BoundedActionRequest(string TenantId, string EnvironmentId,
    string Kind, string TargetType, string TargetId, string Reason, long ExpectedVersion);
public sealed record CaseMetadataRequest(string TenantId, string EnvironmentId,
    string Category, IReadOnlyList<CaseMetadataValue> Metadata,
    string Reason, long ExpectedVersion);
public sealed record CaseCategorySettingsRequest(
    string TenantId, string GameId, string EnvironmentId, string Key,
    string DisplayName, string Description, bool Enabled, int SortOrder,
    long ExpectedVersion, string Reason);
public sealed record CaseMetadataSettingsRequest(
    string TenantId, string GameId, string EnvironmentId, string Key,
    string Label, string Type, IReadOnlyList<string>? EnumerationValues,
    bool Sensitive, bool Searchable, bool Required, bool Enabled,
    long ExpectedVersion, string Reason);
