using System.Collections.Concurrent;

namespace Certael.Server.Evidence;

public interface IEvidenceStore
{
    ValueTask SaveAsync(EvidenceBundle bundle, CancellationToken cancellationToken);
    ValueTask<EvidenceSearchPage> SearchAsync(
        EvidenceSearchQuery query, CancellationToken cancellationToken);
    ValueTask<EvidenceBundle?> FindAsync(string tenantId, Guid verdictId, CancellationToken cancellationToken);
    ValueTask DeletePlayerAsync(string tenantId, string environmentId, string playerSubject,
        CancellationToken cancellationToken);
}

public sealed class InMemoryEvidenceStore : IEvidenceStore
{
    private readonly ConcurrentDictionary<(string Tenant, Guid Verdict), EvidenceBundle> _bundles = new();

    public ValueTask SaveAsync(EvidenceBundle bundle, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (bundle.Findings.Any(value => value.TenantId != bundle.Verdict.TenantId))
            throw new InvalidOperationException("Cross-tenant evidence is prohibited.");
        if (!_bundles.TryAdd((bundle.Verdict.TenantId, bundle.Verdict.VerdictId), bundle))
            throw new InvalidOperationException("Evidence bundles are immutable.");
        return ValueTask.CompletedTask;
    }

    public ValueTask<EvidenceBundle?> FindAsync(string tenantId, Guid verdictId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(_bundles.GetValueOrDefault((tenantId, verdictId)));
    }

    public ValueTask<EvidenceSearchPage> SearchAsync(
        EvidenceSearchQuery query, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (query.PageSize is < 1 or > 250) throw new ArgumentOutOfRangeException(nameof(query));
        EvidenceSearchCursor? cursor = query.Cursor is null
            ? null : EvidenceSearchCursorCodec.Decode(query.Cursor);
        IEnumerable<(EvidenceSummary Summary, string SortKey)> values = _bundles.Values
            .Where(bundle => bundle.Verdict.TenantId == query.TenantId
                && bundle.Verdict.EnvironmentId == query.EnvironmentId)
            .Where(bundle => query.PlayerSubject is null
                || bundle.Verdict.PlayerSubject == query.PlayerSubject)
            .Where(bundle => query.SessionId is null || bundle.Verdict.SessionId == query.SessionId)
            .Where(bundle => query.RuleId is null || bundle.Findings.Any(finding =>
                finding.RuleId.Contains(query.RuleId, StringComparison.OrdinalIgnoreCase)))
            .Where(bundle => query.SignalFamily is null || bundle.Findings.Any(finding =>
                finding.SignalFamily == query.SignalFamily))
            .Where(bundle => query.Recommendation is null
                || bundle.Verdict.Recommendation == query.Recommendation)
            .Where(bundle => MatchesSearch(bundle, query.Search))
            .Select(bundle => Summary(bundle))
            .Select(summary => (summary, SortKey(summary, query.SortBy)));
        values = query.SortDirection == EvidenceSortDirection.Descending
            ? values.OrderByDescending(value => value.SortKey, StringComparer.Ordinal)
                .ThenByDescending(value => value.Summary.VerdictId)
            : values.OrderBy(value => value.SortKey, StringComparer.Ordinal)
                .ThenBy(value => value.Summary.VerdictId);
        if (cursor is not null)
        {
            values = values.Where(value => AfterCursor(value.SortKey, value.Summary.VerdictId,
                cursor, query.SortDirection));
        }
        (EvidenceSummary Summary, string SortKey)[] page = values.Take(query.PageSize + 1).ToArray();
        bool hasMore = page.Length > query.PageSize;
        var returned = page.Take(query.PageSize).ToArray();
        string? next = hasMore && returned.Length > 0
            ? EvidenceSearchCursorCodec.Encode(new EvidenceSearchCursor(
                returned[^1].SortKey, returned[^1].Summary.VerdictId)) : null;
        return ValueTask.FromResult(new EvidenceSearchPage(
            returned.Select(value => value.Summary).ToArray(), next, hasMore));
    }

    public ValueTask DeletePlayerAsync(string tenantId, string environmentId,
        string playerSubject, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var entry in _bundles.Where(value => value.Key.Tenant == tenantId
            && value.Value.Verdict.EnvironmentId == environmentId
            && value.Value.Verdict.PlayerSubject == playerSubject))
            _bundles.TryRemove(entry.Key, out _);
        return ValueTask.CompletedTask;
    }

    private static EvidenceSummary Summary(EvidenceBundle bundle) => new(
        bundle.Verdict.VerdictId, bundle.Verdict.TenantId, bundle.Verdict.GameId,
        bundle.Verdict.EnvironmentId, bundle.Verdict.SessionId, bundle.Verdict.PlayerSubject,
        bundle.Verdict.RiskScore, bundle.Verdict.Confidence, bundle.Verdict.Recommendation,
        bundle.Findings.Select(finding => finding.RuleId).Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal).ToArray(),
        bundle.Findings.Select(finding => finding.SignalFamily).Distinct().Order().ToArray(),
        bundle.Findings.Length, bundle.Verdict.CreatedAt);

    private static bool MatchesSearch(EvidenceBundle bundle, string? search)
    {
        if (string.IsNullOrWhiteSpace(search)) return true;
        string value = search.Trim();
        return bundle.Verdict.PlayerSubject.Contains(value, StringComparison.OrdinalIgnoreCase)
            || bundle.Verdict.SessionId.Contains(value, StringComparison.OrdinalIgnoreCase)
            || bundle.Verdict.VerdictId.ToString().Contains(value, StringComparison.OrdinalIgnoreCase)
            || bundle.Verdict.Recommendation.ToString().Contains(value, StringComparison.OrdinalIgnoreCase)
            || bundle.Findings.Any(finding =>
                finding.RuleId.Contains(value, StringComparison.OrdinalIgnoreCase)
                || finding.RuleVersion.Contains(value, StringComparison.OrdinalIgnoreCase)
                || finding.SignalFamily.ToString().Contains(value, StringComparison.OrdinalIgnoreCase));
    }

    private static string SortKey(EvidenceSummary summary, EvidenceSortField field) => field switch
    {
        EvidenceSortField.Risk => summary.RiskScore.ToString("D10", System.Globalization.CultureInfo.InvariantCulture),
        EvidenceSortField.Confidence => summary.Confidence.ToString("F9", System.Globalization.CultureInfo.InvariantCulture),
        EvidenceSortField.Player => summary.PlayerSubject,
        EvidenceSortField.Rule => summary.RuleIds.FirstOrDefault() ?? string.Empty,
        EvidenceSortField.Signal => summary.SignalFamilies.FirstOrDefault().ToString(),
        _ => summary.CreatedAt.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
    };

    private static bool AfterCursor(string sortKey, Guid verdictId,
        EvidenceSearchCursor cursor, EvidenceSortDirection direction)
    {
        int comparison = string.CompareOrdinal(sortKey, cursor.SortValue);
        if (comparison == 0) comparison = verdictId.CompareTo(cursor.VerdictId);
        return direction == EvidenceSortDirection.Descending ? comparison < 0 : comparison > 0;
    }
}
