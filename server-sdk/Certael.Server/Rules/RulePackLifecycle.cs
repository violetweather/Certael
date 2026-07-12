using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Certael.Server.Rules;

public enum RuleDeploymentStage { Draft, Shadow, Canary, Enforced, Retired }

public sealed record RuleApproval(string ApproverSubject, DateTimeOffset ApprovedAt, byte[] PackDigest);

public sealed record RuleDeployment(
    SignedRulePack Pack,
    RuleDeploymentStage Stage,
    int CanaryPercentage,
    IReadOnlyList<RuleApproval> Approvals,
    DateTimeOffset UpdatedAt,
    string UpdatedBy);

public sealed class RulePackLifecycleStore(TimeProvider timeProvider, RulePackVerifier verifier)
{
    private readonly ConcurrentDictionary<string, RuleDeployment> _deployments = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _activeByEnvironment = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Stack<string>> _history = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public RuleDeployment AddDraft(SignedRulePack pack, string author)
    {
        if (!verifier.Verify(pack))
            throw new RuleLifecycleException("Rule-pack signature or canonical document is invalid.");
        string key = Key(pack.Document);
        var deployment = new RuleDeployment(pack, RuleDeploymentStage.Draft, 0, [],
            timeProvider.GetUtcNow(), RequireSubject(author));
        if (!_deployments.TryAdd(key, deployment))
            throw new RuleLifecycleException("Rule pack version is immutable and already exists.");
        return deployment;
    }

    public RuleDeployment Approve(string packId, string version, string approver)
    {
        string subject = RequireSubject(approver);
        return Update(packId, version, current =>
        {
            if (current.Approvals.Any(value => value.ApproverSubject == subject)) return current;
            RuleApproval approval = new(subject, timeProvider.GetUtcNow(), current.Pack.Digest.ToArray());
            return current with { Approvals = current.Approvals.Append(approval).ToArray(),
                UpdatedAt = timeProvider.GetUtcNow(), UpdatedBy = subject };
        });
    }

    public RuleDeployment Promote(string packId, string version, RuleDeploymentStage stage,
        int canaryPercentage, string operatorSubject)
    {
        if (stage is RuleDeploymentStage.Draft or RuleDeploymentStage.Retired)
            throw new RuleLifecycleException("Use add or retire for this stage.");
        if (stage == RuleDeploymentStage.Canary && canaryPercentage is < 1 or > 99)
            throw new RuleLifecycleException("Canary percentage must be between 1 and 99.");
        if (stage != RuleDeploymentStage.Canary && canaryPercentage != 0)
            throw new RuleLifecycleException("Canary percentage only applies to canary stage.");

        string subject = RequireSubject(operatorSubject);
        lock (_gate)
        {
            RuleDeployment current = Get(packId, version);
            int requiredApprovals = stage == RuleDeploymentStage.Enforced ? 2 : 1;
            if (current.Approvals.Select(value => value.ApproverSubject).Distinct(StringComparer.Ordinal).Count() < requiredApprovals)
                throw new RuleLifecycleException($"{stage} requires {requiredApprovals} distinct approvals.");
            if (current.Approvals.Any(value => !CryptographicOperations.FixedTimeEquals(value.PackDigest, current.Pack.Digest)))
                throw new RuleLifecycleException("Approval digest does not match the immutable pack.");

            RuleDeployment promoted = current with { Stage = stage, CanaryPercentage = canaryPercentage,
                UpdatedAt = timeProvider.GetUtcNow(), UpdatedBy = subject };
            _deployments[Key(current.Pack.Document)] = promoted;
            string environment = EnvironmentKey(current.Pack.Document);
            if (stage is RuleDeploymentStage.Canary or RuleDeploymentStage.Enforced)
            {
                if (_activeByEnvironment.TryGetValue(environment, out string? prior) && prior != Key(current.Pack.Document))
                    _history.GetOrAdd(environment, static _ => new Stack<string>()).Push(prior);
                _activeByEnvironment[environment] = Key(current.Pack.Document);
            }
            return promoted;
        }
    }

    public RuleDeployment Rollback(string gameId, string environmentId, string operatorSubject)
    {
        string environment = $"{gameId}\0{environmentId}";
        lock (_gate)
        {
            if (!_history.TryGetValue(environment, out Stack<string>? history) || history.Count == 0)
                throw new RuleLifecycleException("No prior deployment is available.");
            string priorKey = history.Pop();
            RuleDeployment prior = _deployments[priorKey];
            RuleDeployment restored = prior with { Stage = RuleDeploymentStage.Enforced,
                CanaryPercentage = 0, UpdatedAt = timeProvider.GetUtcNow(), UpdatedBy = RequireSubject(operatorSubject) };
            _deployments[priorKey] = restored;
            _activeByEnvironment[environment] = priorKey;
            return restored;
        }
    }

    public bool IsInCanary(RuleDeployment deployment, string sessionId)
    {
        if (deployment.Stage != RuleDeploymentStage.Canary) return deployment.Stage == RuleDeploymentStage.Enforced;
        byte[] digest = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sessionId));
        uint bucket = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(digest) % 100;
        return bucket < deployment.CanaryPercentage;
    }

    public RuleDeployment Get(string packId, string version) =>
        _deployments.TryGetValue($"{packId}\0{version}", out RuleDeployment? value)
            ? value : throw new RuleLifecycleException("Rule pack does not exist.");

    private RuleDeployment Update(string packId, string version, Func<RuleDeployment, RuleDeployment> update)
    {
        string key = $"{packId}\0{version}";
        while (true)
        {
            RuleDeployment current = Get(packId, version);
            RuleDeployment next = update(current);
            if (_deployments.TryUpdate(key, next, current)) return next;
        }
    }

    private static string Key(RulePackDocument value) => $"{value.PackId}\0{value.Version}";
    private static string EnvironmentKey(RulePackDocument value) => $"{value.GameId}\0{value.EnvironmentId}";
    private static string RequireSubject(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 128
        ? value : throw new RuleLifecycleException("Operator subject is invalid.");
}

public sealed class RuleLifecycleException(string message) : Exception(message);
