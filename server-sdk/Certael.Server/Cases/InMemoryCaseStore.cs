using System.Globalization;
using System.Text.Json;
using Certael.Server.Evidence;

namespace Certael.Server.Cases;

public sealed class InMemoryCaseStore(TimeProvider timeProvider) : ICaseStore
{
    private sealed class Entry(CaseSummary summary, byte[] key, DateTimeOffset deduplicateUntil)
    {
        public CaseSummary Summary = summary;
        public byte[] Key = key;
        public DateTimeOffset DeduplicateUntil = deduplicateUntil;
        public List<CaseEvidence> Evidence = [];
        public List<CaseNote> Notes = [];
        public List<CaseActivity> Activity = [];
        public List<BoundedAction> Actions = [];
    }

    private readonly object gate = new();
    private readonly Dictionary<Guid, Entry> entries = [];

    public async ValueTask<IReadOnlyList<CaseSummary>> SearchAsync(CaseQueueQuery query,
        CancellationToken cancellationToken)
    {
        if (query.Maximum is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(query));
        var results = new List<CaseSummary>(query.Maximum);
        string? cursor = null;
        do
        {
            int remaining = query.Maximum - results.Count;
            CaseQueuePage page = await SearchPageAsync(query with
            {
                Cursor = cursor,
                PageSize = Math.Min(remaining, 250)
            }, cancellationToken);
            results.AddRange(page.Items);
            cursor = page.HasMore ? page.NextCursor : null;
        } while (cursor is not null && results.Count < query.Maximum);
        return results;
    }

    public ValueTask<CaseQueuePage> SearchPageAsync(CaseQueueQuery query,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (query.PageSize is < 1 or > 250) throw new ArgumentOutOfRangeException(nameof(query));
        CaseQueueCursor? cursor = query.Cursor is null ? null : CaseQueueCursorCodec.Decode(query.Cursor);
        lock (gate)
        {
            IEnumerable<Entry> filtered = entries.Values.Where(entry => Matches(entry, query));
            IOrderedEnumerable<Entry> ordered = Order(filtered, query.SortBy, query.SortDirection);
            if (cursor is not null) ordered = Order(ordered.Where(entry => IsAfter(entry, cursor, query)),
                query.SortBy, query.SortDirection);
            Entry[] page = ordered.Take(query.PageSize + 1).ToArray();
            bool hasMore = page.Length > query.PageSize;
            Entry[] returned = page.Take(query.PageSize).ToArray();
            string? next = hasMore && returned.Length > 0
                ? CaseQueueCursorCodec.Encode(new CaseQueueCursor(
                    SortValue(returned[^1], query.SortBy), returned[^1].Summary.CaseId)) : null;
            return ValueTask.FromResult(new CaseQueuePage(
                returned.Select(QueueSummary).ToArray(), next, hasMore));
        }
    }

    public ValueTask<CaseDetail?> FindAsync(string tenantId, Guid caseId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!entries.TryGetValue(caseId, out Entry? entry) || entry.Summary.TenantId != tenantId)
                return ValueTask.FromResult<CaseDetail?>(null);
            return ValueTask.FromResult<CaseDetail?>(Detail(entry));
        }
    }

    public ValueTask<CaseSummary?> OpenOrUpdateAsync(EvidenceBundle bundle, string title,
        string summary, string actorSubject, TimeSpan deduplicationWindow,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (bundle.Verdict.Recommendation is VerdictRecommendation.Allow or VerdictRecommendation.Observe)
            return ValueTask.FromResult<CaseSummary?>(null);
        DateTimeOffset now = timeProvider.GetUtcNow();
        byte[] key = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            $"{bundle.Verdict.TenantId}\0{bundle.Verdict.EnvironmentId}\0{bundle.Verdict.PlayerSubject}\0{bundle.SignedPolicyId}"));
        lock (gate)
        {
            Entry? entry = entries.Values.FirstOrDefault(value =>
                value.Summary.TenantId == bundle.Verdict.TenantId && value.Key.SequenceEqual(key)
                && value.DeduplicateUntil > now && value.Summary.State is CaseState.Open or CaseState.InReview);
            if (entry is null)
            {
                Guid id = Guid.NewGuid();
                var created = new CaseSummary(id, bundle.Verdict.TenantId, bundle.Verdict.GameId,
                    bundle.Verdict.EnvironmentId, bundle.Verdict.PlayerSubject, title, summary,
                    CaseState.Open, bundle.SignedPolicyId, bundle.SignedPolicyVersion, null,
                    1, now, now, null);
                entry = new Entry(created, key, now + deduplicationWindow);
                entries[id] = entry;
            }
            else
                entry.Summary = entry.Summary with
                {
                    Summary = summary, Version = entry.Summary.Version + 1, UpdatedAt = now
                };
            foreach (Finding finding in bundle.Findings.Where(finding =>
                !entry.Evidence.Any(value => value.FindingId == finding.FindingId)))
                entry.Evidence.Add(new CaseEvidence(bundle.Verdict.VerdictId, finding.FindingId,
                    finding.RuleId, finding.RuleVersion, finding.SignalFamily, finding.Trust,
                    finding.RiskContribution, finding.Confidence, finding.ObservedAt,
                    bundle.ReplayDigest, JsonSerializer.Serialize(finding.Fields)));
            entry.Activity.Add(Activity(actorSubject, "EvidenceAttached", "signed policy threshold",
                new { bundle.Verdict.VerdictId }, now));
            return ValueTask.FromResult<CaseSummary?>(entry.Summary);
        }
    }

    public ValueTask<CaseSummary?> AssignAsync(string tenantId, Guid caseId, string? assignedTo,
        string actorSubject, string reason, long expectedVersion, CancellationToken cancellationToken) =>
        Mutate(tenantId, caseId, expectedVersion, cancellationToken, (entry, now) =>
        {
            entry.Summary = entry.Summary with
            {
                AssignedTo = assignedTo, Version = expectedVersion + 1, UpdatedAt = now
            };
            entry.Activity.Add(Activity(actorSubject, "AssignmentChanged", reason, new { assignedTo }, now));
            return entry.Summary;
        });

    public ValueTask<CaseNote?> AddNoteAsync(string tenantId, Guid caseId, string authorSubject,
        string body, long expectedVersion, CancellationToken cancellationToken)
    {
        CaseNote? note = null;
        Mutate(tenantId, caseId, expectedVersion, cancellationToken, (entry, now) =>
        {
            note = new CaseNote(Guid.NewGuid(), authorSubject, body, now);
            entry.Notes.Add(note);
            entry.Summary = entry.Summary with { Version = expectedVersion + 1, UpdatedAt = now };
            entry.Activity.Add(Activity(authorSubject, "NoteAdded", "operator note", new { note.NoteId }, now));
            return entry.Summary;
        });
        return ValueTask.FromResult(note);
    }

    public ValueTask<CaseSummary?> TransitionAsync(string tenantId, Guid caseId,
        CaseState targetState, CaseDisposition? disposition, string actorSubject, string reason,
        long expectedVersion, CancellationToken cancellationToken) =>
        Mutate(tenantId, caseId, expectedVersion, cancellationToken, (entry, now) =>
        {
            bool valid = (entry.Summary.State, targetState) switch
            {
                (CaseState.Open, CaseState.InReview) => true,
                (CaseState.InReview, CaseState.Resolved or CaseState.Dismissed) => true,
                (CaseState.Resolved or CaseState.Dismissed, CaseState.Open) => true,
                _ => false
            };
            if (!valid || targetState is CaseState.Resolved or CaseState.Dismissed && disposition is null)
                return null;
            entry.Summary = entry.Summary with
            {
                State = targetState, Version = expectedVersion + 1, UpdatedAt = now,
                ResolvedAt = targetState is CaseState.Resolved or CaseState.Dismissed ? now : null
            };
            entry.Activity.Add(Activity(actorSubject, "StateChanged", reason,
                new { targetState, disposition }, now));
            return entry.Summary;
        });

    public ValueTask<BoundedAction?> ApproveActionAsync(string tenantId, Guid caseId,
        BoundedActionKind kind, string targetType, string targetId, string reason,
        string requestedBy, string approvedBy, byte[] authorizationDigest, long expectedVersion,
        CancellationToken cancellationToken)
    {
        BoundedAction? action = null;
        if (authorizationDigest.Length != 32 || requestedBy == approvedBy)
            return ValueTask.FromResult<BoundedAction?>(null);
        Mutate(tenantId, caseId, expectedVersion, cancellationToken, (entry, now) =>
        {
            action = new BoundedAction(Guid.NewGuid(), kind, targetType, targetId, reason,
                requestedBy, approvedBy, "Approved", null, now, null);
            entry.Actions.Add(action);
            entry.Summary = entry.Summary with { Version = expectedVersion + 1, UpdatedAt = now };
            entry.Activity.Add(Activity(approvedBy, "BoundedActionApproved", reason,
                new { action.BoundedActionId, kind, targetType, targetId }, now));
            return entry.Summary;
        });
        return ValueTask.FromResult(action);
    }

    public ValueTask<CaseSummary?> UpdateMetadataAsync(string tenantId, Guid caseId,
        string category, IReadOnlyList<CaseMetadataValue> metadata, string actorSubject,
        string reason, long expectedVersion, CancellationToken cancellationToken)
    {
        ValidateClassification(category, metadata);
        return Mutate(tenantId, caseId, expectedVersion, cancellationToken, (entry, now) =>
        {
            entry.Summary = entry.Summary with
            {
                Category = category, Metadata = metadata.ToArray(),
                Version = expectedVersion + 1, UpdatedAt = now
            };
            entry.Activity.Add(Activity(actorSubject, "MetadataChanged", reason,
                new { category, keys = metadata.Select(value => value.Key) }, now));
            return entry.Summary;
        });
    }

    private ValueTask<CaseSummary?> Mutate(string tenantId, Guid caseId, long expectedVersion,
        CancellationToken cancellationToken, Func<Entry, DateTimeOffset, CaseSummary?> mutation)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!entries.TryGetValue(caseId, out Entry? entry) || entry.Summary.TenantId != tenantId
                || entry.Summary.Version != expectedVersion)
                return ValueTask.FromResult<CaseSummary?>(null);
            return ValueTask.FromResult<CaseSummary?>(mutation(entry, timeProvider.GetUtcNow()));
        }
    }

    private static bool Matches(Entry entry, CaseQueueQuery query)
    {
        CaseSummary value = entry.Summary;
        bool defaultState = query.State is null && value.State is CaseState.Open or CaseState.InReview;
        return value.TenantId == query.TenantId && value.EnvironmentId == query.EnvironmentId
            && (defaultState || query.State is not null && value.State == query.State)
            && (query.AssignedTo is null || value.AssignedTo == query.AssignedTo)
            && (query.PlayerSubject is null || value.PlayerSubject == query.PlayerSubject)
            && (query.Category is null || value.Category == query.Category)
            && (query.RuleId is null || entry.Evidence.Any(evidence => evidence.RuleId.Contains(
                query.RuleId, StringComparison.OrdinalIgnoreCase)))
            && (query.SignalFamily is null || entry.Evidence.Any(evidence =>
                evidence.SignalFamily == query.SignalFamily))
            && (query.Search is null || Search(entry, query.Search));
    }

    private static bool Search(Entry entry, string search) =>
        entry.Summary.Title.Contains(search, StringComparison.OrdinalIgnoreCase)
        || entry.Summary.Summary.Contains(search, StringComparison.OrdinalIgnoreCase)
        || entry.Summary.PlayerSubject.Contains(search, StringComparison.OrdinalIgnoreCase)
        || entry.Summary.Category.Contains(search, StringComparison.OrdinalIgnoreCase)
        || (entry.Summary.Metadata?.Any(value => !value.Sensitive && value.Searchable &&
            (value.Key.Contains(search, StringComparison.OrdinalIgnoreCase)
             || value.Value.Contains(search, StringComparison.OrdinalIgnoreCase))) ?? false)
        || entry.Evidence.Any(value => value.RuleId.Contains(search, StringComparison.OrdinalIgnoreCase)
            || value.RuleVersion.Contains(search, StringComparison.OrdinalIgnoreCase)
            || value.SignalFamily?.ToString().Contains(search, StringComparison.OrdinalIgnoreCase) == true);

    private static IOrderedEnumerable<Entry> Order(IEnumerable<Entry> values, CaseSortField field,
        CaseSortDirection direction)
    {
        Func<Entry, string> key = value => SortValue(value, field);
        return direction == CaseSortDirection.Descending
            ? values.OrderByDescending(key, StringComparer.Ordinal).ThenByDescending(value => value.Summary.CaseId)
            : values.OrderBy(key, StringComparer.Ordinal).ThenBy(value => value.Summary.CaseId);
    }

    private static string SortValue(Entry entry, CaseSortField field) => field switch
    {
        CaseSortField.CreatedAt => entry.Summary.CreatedAt.UtcTicks.ToString("D20", CultureInfo.InvariantCulture),
        CaseSortField.Risk => entry.Evidence.Select(value => value.RiskContribution ?? 0).DefaultIfEmpty().Max()
            .ToString("D10", CultureInfo.InvariantCulture),
        CaseSortField.Confidence => entry.Evidence.Select(value => value.Confidence ?? 0).DefaultIfEmpty().Max()
            .ToString("F9", CultureInfo.InvariantCulture),
        CaseSortField.Rule => entry.Evidence.Select(value => value.RuleId).Where(value => value.Length > 0)
            .Order(StringComparer.Ordinal).FirstOrDefault() ?? string.Empty,
        CaseSortField.Signal => entry.Evidence.Select(value => value.SignalFamily?.ToString() ?? string.Empty)
            .Where(value => value.Length > 0).Order(StringComparer.Ordinal).FirstOrDefault() ?? string.Empty,
        _ => entry.Summary.UpdatedAt.UtcTicks.ToString("D20", CultureInfo.InvariantCulture)
    };

    private static CaseSummary QueueSummary(Entry entry) => entry.Summary with
    {
        HighestRisk = entry.Evidence.Select(value => value.RiskContribution ?? 0)
            .DefaultIfEmpty().Max(),
        HighestConfidence = entry.Evidence.Select(value => value.Confidence ?? 0)
            .DefaultIfEmpty().Max(),
        RuleIds = entry.Evidence.Select(value => value.RuleId).Where(value => value.Length > 0)
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
        SignalFamilies = entry.Evidence.Where(value => value.SignalFamily is not null)
            .Select(value => value.SignalFamily!.Value).Distinct().Order().ToArray()
    };

    private static bool IsAfter(Entry entry, CaseQueueCursor cursor, CaseQueueQuery query)
    {
        int comparison = string.CompareOrdinal(SortValue(entry, query.SortBy), cursor.SortValue);
        if (comparison == 0) comparison = entry.Summary.CaseId.CompareTo(cursor.CaseId);
        return query.SortDirection == CaseSortDirection.Descending ? comparison < 0 : comparison > 0;
    }

    private static void ValidateClassification(string category, IReadOnlyList<CaseMetadataValue> metadata)
    {
        if (string.IsNullOrWhiteSpace(category) || category.Length > 96 || metadata.Count > 64
            || metadata.Select(value => value.Key).Distinct(StringComparer.Ordinal).Count() != metadata.Count)
            throw new ArgumentException("Case classification is invalid.");
        foreach (CaseMetadataValue value in metadata)
            if (string.IsNullOrWhiteSpace(value.Key) || value.Key.Length > 96 || value.Value.Length > 4096
                || !Enum.IsDefined(value.Type))
                throw new ArgumentException("Case metadata is invalid.");
    }

    private static CaseActivity Activity(string actorSubject, string type, string reason,
        object details, DateTimeOffset now) => new(Guid.NewGuid(), actorSubject, type, reason,
            JsonSerializer.Serialize(details), now);

    private static CaseDetail Detail(Entry entry) => new(entry.Summary, entry.Evidence.ToArray(),
        entry.Notes.ToArray(), entry.Activity.ToArray(), entry.Actions.ToArray());
}
