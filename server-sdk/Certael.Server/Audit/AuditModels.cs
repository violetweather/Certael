using System.Collections.Concurrent;

namespace Certael.Server.Audit;

public sealed record AuditEvent(
    Guid AuditId, string TenantId, string EnvironmentId, string OperatorSubject,
    string Operation, string ResourceType, string ResourceId, string Reason,
    string? BeforeDigest, string? AfterDigest, string RequestId,
    DateTimeOffset OccurredAt, bool Succeeded,
    string? SourceNetwork = null, string? WorkloadIdentity = null);

public interface IAuditStore
{
    ValueTask AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken);
    ValueTask<IReadOnlyList<AuditEvent>> RecentAsync(string tenantId, string environmentId,
        int maximum, CancellationToken cancellationToken);
}

public static class AuditEventValidator
{
    public static void Validate(AuditEvent value)
    {
        if (value.AuditId == Guid.Empty || value.OccurredAt == default)
            throw new ArgumentException("Audit identity or timestamp is invalid.", nameof(value));
        Text(value.TenantId, 128); Text(value.EnvironmentId, 128);
        Text(value.OperatorSubject, 256); Text(value.Operation, 128);
        Text(value.ResourceType, 128); Text(value.ResourceId, 256);
        Text(value.Reason, 512); Text(value.RequestId, 128);
        Optional(value.BeforeDigest, 128); Optional(value.AfterDigest, 128);
        Optional(value.SourceNetwork, 128); Optional(value.WorkloadIdentity, 256);
    }

    private static void Optional(string? value, int maximum)
    {
        if (value is not null) Text(value, maximum);
    }

    private static void Text(string value, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum
            || value.Any(char.IsControl))
            throw new ArgumentException("Audit text is invalid.");
    }
}

public sealed class InMemoryAuditStore : IAuditStore
{
    private readonly ConcurrentQueue<AuditEvent> _events = new();
    public ValueTask AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); AuditEventValidator.Validate(auditEvent);
        _events.Enqueue(auditEvent); return ValueTask.CompletedTask;
    }
    public ValueTask<IReadOnlyList<AuditEvent>> RecentAsync(string tenantId, string environmentId,
        int maximum, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maximum is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximum));
        return ValueTask.FromResult<IReadOnlyList<AuditEvent>>(_events.Where(value => value.TenantId == tenantId
            && value.EnvironmentId == environmentId).OrderByDescending(value => value.OccurredAt).Take(maximum).ToArray());
    }
}
