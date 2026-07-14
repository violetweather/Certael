using System.Collections.Concurrent;

namespace Certael.Server.Evidence;

public interface IEvidenceStore
{
    ValueTask SaveAsync(EvidenceBundle bundle, CancellationToken cancellationToken);
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
}
