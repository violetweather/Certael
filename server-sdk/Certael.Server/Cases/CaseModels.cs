using Certael.Server.Evidence;

namespace Certael.Server.Cases;

public enum CaseState { Open, InReview, Resolved, Dismissed }

public enum CaseDisposition
{
    ConfirmedAbuse,
    FalsePositive,
    ExpectedBehavior,
    InsufficientEvidence,
    Duplicate
}

public enum BoundedActionKind
{
    RevokeSession,
    RejectAction,
    IncreaseSampling,
    TemporaryRestriction,
    RecommendKick
}

public enum CaseMetadataType { Text, Number, Boolean, DateTime, Enumeration, Identifier }
public enum CaseSortField { UpdatedAt, CreatedAt, Risk, Confidence, Rule, Signal }
public enum CaseSortDirection { Ascending, Descending }

public sealed record CaseMetadataValue(
    string Key, CaseMetadataType Type, string Value, bool Sensitive = false,
    bool Searchable = false);

public sealed record CaseSummary(
    Guid CaseId, string TenantId, string GameId, string EnvironmentId,
    string PlayerSubject, string Title, string Summary, CaseState State,
    string SignedPolicyId, string SignedPolicyVersion, string? AssignedTo,
    long Version, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt,
    DateTimeOffset? ResolvedAt, string Category = "General",
    IReadOnlyList<CaseMetadataValue>? Metadata = null,
    int HighestRisk = 0, double HighestConfidence = 0,
    IReadOnlyList<string>? RuleIds = null,
    IReadOnlyList<SignalFamily>? SignalFamilies = null);

public sealed record CaseNote(
    Guid NoteId, string AuthorSubject, string Body, DateTimeOffset CreatedAt);

public sealed record CaseActivity(
    Guid ActivityId, string ActorSubject, string ActivityType, string Reason,
    string DetailsJson, DateTimeOffset OccurredAt);

public sealed record CaseEvidence(
    Guid VerdictId, Guid? FindingId, string RuleId, string RuleVersion,
    SignalFamily? SignalFamily, FindingTrust? Trust, int? RiskContribution,
    double? Confidence, DateTimeOffset ObservedAt, byte[] ReplayDigest,
    string FieldsJson);

public sealed record BoundedAction(
    Guid BoundedActionId, BoundedActionKind Kind, string TargetType,
    string TargetId, string Reason, string RequestedBy, string ApprovedBy,
    string Status, string? PublicResult, DateTimeOffset RequestedAt,
    DateTimeOffset? CompletedAt);

public sealed record CaseDetail(
    CaseSummary Case, IReadOnlyList<CaseEvidence> Evidence,
    IReadOnlyList<CaseNote> Notes, IReadOnlyList<CaseActivity> Activity,
    IReadOnlyList<BoundedAction> Actions);

public sealed record CaseQueueQuery(
    string TenantId, string EnvironmentId, CaseState? State = null,
    string? AssignedTo = null, string? PlayerSubject = null,
    string? Search = null, int Maximum = 100, string? Category = null,
    string? RuleId = null, SignalFamily? SignalFamily = null,
    CaseSortField SortBy = CaseSortField.UpdatedAt,
    CaseSortDirection SortDirection = CaseSortDirection.Descending,
    string? Cursor = null, int PageSize = 50);

public sealed record CaseQueuePage(
    IReadOnlyList<CaseSummary> Items, string? NextCursor, bool HasMore);

public interface ICaseStore
{
    ValueTask<IReadOnlyList<CaseSummary>> SearchAsync(
        CaseQueueQuery query, CancellationToken cancellationToken);
    ValueTask<CaseQueuePage> SearchPageAsync(
        CaseQueueQuery query, CancellationToken cancellationToken);
    ValueTask<CaseDetail?> FindAsync(
        string tenantId, Guid caseId, CancellationToken cancellationToken);
    ValueTask<CaseSummary?> OpenOrUpdateAsync(
        EvidenceBundle bundle, string title, string summary, string actorSubject,
        TimeSpan deduplicationWindow, CancellationToken cancellationToken);
    ValueTask<CaseSummary?> AssignAsync(
        string tenantId, Guid caseId, string? assignedTo, string actorSubject,
        string reason, long expectedVersion, CancellationToken cancellationToken);
    ValueTask<CaseNote?> AddNoteAsync(
        string tenantId, Guid caseId, string authorSubject, string body,
        long expectedVersion, CancellationToken cancellationToken);
    ValueTask<CaseSummary?> TransitionAsync(
        string tenantId, Guid caseId, CaseState targetState,
        CaseDisposition? disposition, string actorSubject, string reason,
        long expectedVersion, CancellationToken cancellationToken);
    ValueTask<BoundedAction?> ApproveActionAsync(
        string tenantId, Guid caseId, BoundedActionKind kind,
        string targetType, string targetId, string reason,
        string requestedBy, string approvedBy, byte[] authorizationDigest,
        long expectedVersion, CancellationToken cancellationToken);
    ValueTask<CaseSummary?> UpdateMetadataAsync(
        string tenantId, Guid caseId, string category,
        IReadOnlyList<CaseMetadataValue> metadata, string actorSubject,
        string reason, long expectedVersion, CancellationToken cancellationToken);
}
