using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Agent;

public enum AgentPolicyDeploymentStage { Draft, Shadow, Canary, Enforced, Retired }

public sealed record AgentPolicyApproval(
    string ApproverSubject, DateTimeOffset ApprovedAt, byte[] PolicyDigest);

public sealed record AgentPolicyDeployment(
    AgentPolicyClaims Claims,
    SignedAgentPolicy SignedPolicy,
    byte[] PolicyDigest,
    AgentPolicyDeploymentStage Stage,
    int CanaryPercentage,
    IReadOnlyList<AgentPolicyApproval> Approvals,
    DateTimeOffset UpdatedAt,
    string UpdatedBy);

public interface IAgentPolicyResolver
{
    ValueTask<AgentPolicyDeployment> ResolveAsync(string policyId, string tenantId, string gameId,
        string environmentId, string assignmentKey, DateTimeOffset now,
        CancellationToken cancellationToken);
}

public interface IAgentPolicyAdministration
{
    ValueTask<AgentPolicyDeployment> AddDraftAsync(AgentPolicyClaims claims, string author,
        CancellationToken cancellationToken);
    ValueTask<AgentPolicyDeployment> ApproveAsync(string tenantId, string policyId,
        string approver, CancellationToken cancellationToken);
    ValueTask<AgentPolicyDeployment> PromoteAsync(string tenantId, string policyId,
        AgentPolicyDeploymentStage stage, int canaryPercentage, string operatorSubject,
        CancellationToken cancellationToken);
    ValueTask<AgentPolicyDeployment> RetireAsync(string tenantId, string policyId,
        string operatorSubject, CancellationToken cancellationToken);
    ValueTask<AgentPolicyDeployment> GetAsync(string tenantId, string policyId,
        CancellationToken cancellationToken);
}

/// <summary>
/// Signature-producing immutable Agent-policy lifecycle. A workload may select
/// an approved policy ID, but cannot supply or alter its security parameters.
/// Enforced promotion requires two distinct approvals over the exact signed digest.
/// </summary>
public sealed class AgentPolicyLifecycleStore(
    AgentGrantSigner signer,
    TimeProvider timeProvider) : IAgentPolicyResolver, IAgentPolicyAdministration
{
    private readonly ConcurrentDictionary<string, AgentPolicyDeployment> _deployments =
        new(StringComparer.Ordinal);

    public AgentPolicyDeployment AddDraft(AgentPolicyClaims claims, string author)
    {
        string subject = Subject(author);
        DateTimeOffset now = timeProvider.GetUtcNow();
        SignedAgentPolicy signed = signer.IssuePolicy(claims, now);
        byte[] digest = AgentGrantCodec.PolicyDigest(signed);
        var deployment = new AgentPolicyDeployment(claims, signed, digest,
            AgentPolicyDeploymentStage.Draft, 0, [], now, subject);
        if (!_deployments.TryAdd(Key(claims.TenantId, claims.PolicyId), deployment))
            throw new AgentPolicyLifecycleException("Policy ID is immutable and already exists.");
        return Copy(deployment);
    }

    public AgentPolicyDeployment Approve(string tenantId, string policyId, string approver)
    {
        string subject = Subject(approver);
        return Update(tenantId, policyId, current =>
        {
            if (current.Stage == AgentPolicyDeploymentStage.Retired)
                throw new AgentPolicyLifecycleException("A retired policy cannot be approved.");
            if (current.Approvals.Any(value => value.ApproverSubject == subject)) return current;
            return current with
            {
                Approvals = current.Approvals.Append(new AgentPolicyApproval(subject,
                    timeProvider.GetUtcNow(), current.PolicyDigest.ToArray())).ToArray(),
                UpdatedAt = timeProvider.GetUtcNow(),
                UpdatedBy = subject
            };
        });
    }

    public AgentPolicyDeployment Promote(string tenantId, string policyId,
        AgentPolicyDeploymentStage stage,
        int canaryPercentage, string operatorSubject)
    {
        if (stage is AgentPolicyDeploymentStage.Draft or AgentPolicyDeploymentStage.Retired)
            throw new AgentPolicyLifecycleException("Use add or retire for this stage.");
        if (stage == AgentPolicyDeploymentStage.Canary && canaryPercentage is < 1 or > 99)
            throw new AgentPolicyLifecycleException("Canary percentage must be between 1 and 99.");
        if (stage != AgentPolicyDeploymentStage.Canary && canaryPercentage != 0)
            throw new AgentPolicyLifecycleException("Canary percentage only applies to canary stage.");
        string subject = Subject(operatorSubject);
        return Update(tenantId, policyId, current =>
        {
            if (current.Stage == AgentPolicyDeploymentStage.Retired)
                throw new AgentPolicyLifecycleException("A retired policy cannot be promoted.");
            if (stage == AgentPolicyDeploymentStage.Shadow
                && current.Claims.RequirementMode == AgentRequirementMode.Required)
                throw new AgentPolicyLifecycleException(
                    "A shadow policy cannot require Agent enforcement.");
            int required = stage == AgentPolicyDeploymentStage.Enforced ? 2 : 1;
            if (current.Approvals.Select(value => value.ApproverSubject)
                .Distinct(StringComparer.Ordinal).Count() < required)
                throw new AgentPolicyLifecycleException(
                    $"{stage} requires {required} distinct approvals.");
            if (current.Approvals.Any(value => !CryptographicOperations.FixedTimeEquals(
                value.PolicyDigest, current.PolicyDigest)))
                throw new AgentPolicyLifecycleException("Approval does not match the signed policy.");
            return current with
            {
                Stage = stage,
                CanaryPercentage = canaryPercentage,
                UpdatedAt = timeProvider.GetUtcNow(),
                UpdatedBy = subject
            };
        });
    }

    public AgentPolicyDeployment Retire(string tenantId, string policyId, string operatorSubject)
    {
        string subject = Subject(operatorSubject);
        return Update(tenantId, policyId, current => current with
        {
            Stage = AgentPolicyDeploymentStage.Retired,
            CanaryPercentage = 0,
            UpdatedAt = timeProvider.GetUtcNow(),
            UpdatedBy = subject
        });
    }

    public AgentPolicyDeployment Resolve(string policyId, string tenantId, string gameId,
        string environmentId, string assignmentKey, DateTimeOffset now)
    {
        AgentPolicyDeployment deployment = Get(tenantId, policyId);
        if (!string.Equals(deployment.Claims.TenantId, tenantId, StringComparison.Ordinal)
            || !string.Equals(deployment.Claims.GameId, gameId, StringComparison.Ordinal)
            || !string.Equals(deployment.Claims.EnvironmentId, environmentId,
                StringComparison.Ordinal) || deployment.Claims.ExpiresAt <= now)
            throw new AgentPolicyLifecycleException("Policy binding is invalid or expired.");
        bool applies = deployment.Stage is AgentPolicyDeploymentStage.Shadow
                or AgentPolicyDeploymentStage.Enforced
            || deployment.Stage == AgentPolicyDeploymentStage.Canary
                && CanaryBucket(assignmentKey) < deployment.CanaryPercentage;
        if (!applies)
            throw new AgentPolicyLifecycleException("Policy is not approved for this session.");
        return Copy(deployment);
    }

    public ValueTask<AgentPolicyDeployment> ResolveAsync(string policyId, string tenantId,
        string gameId, string environmentId, string assignmentKey, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Resolve(policyId, tenantId, gameId, environmentId,
            assignmentKey, now));
    }

    public ValueTask<AgentPolicyDeployment> AddDraftAsync(AgentPolicyClaims claims,
        string author, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(AddDraft(claims, author));
    }

    public ValueTask<AgentPolicyDeployment> ApproveAsync(string tenantId, string policyId,
        string approver, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Approve(tenantId, policyId, approver));
    }

    public ValueTask<AgentPolicyDeployment> PromoteAsync(string tenantId, string policyId,
        AgentPolicyDeploymentStage stage, int canaryPercentage, string operatorSubject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Promote(tenantId, policyId, stage, canaryPercentage,
            operatorSubject));
    }

    public ValueTask<AgentPolicyDeployment> RetireAsync(string tenantId, string policyId,
        string operatorSubject, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Retire(tenantId, policyId, operatorSubject));
    }

    public ValueTask<AgentPolicyDeployment> GetAsync(string tenantId, string policyId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Get(tenantId, policyId));
    }

    public AgentPolicyDeployment Get(string tenantId, string policyId) =>
        _deployments.TryGetValue(Key(tenantId, policyId), out AgentPolicyDeployment? value)
            ? Copy(value) : throw new AgentPolicyLifecycleException("Policy does not exist.");

    private AgentPolicyDeployment Update(string tenantId, string policyId,
        Func<AgentPolicyDeployment, AgentPolicyDeployment> update)
    {
        while (true)
        {
            string key = Key(tenantId, policyId);
            AgentPolicyDeployment current = _deployments.TryGetValue(key, out var value)
                ? value : throw new AgentPolicyLifecycleException("Policy does not exist.");
            AgentPolicyDeployment next = update(current);
            if (_deployments.TryUpdate(key, next, current)) return Copy(next);
        }
    }

    private static int CanaryBucket(string assignmentKey)
    {
        if (string.IsNullOrWhiteSpace(assignmentKey) || assignmentKey.Length > 512)
            throw new AgentPolicyLifecycleException("Canary assignment key is invalid.");
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(assignmentKey));
        return (int)(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(digest) % 100);
    }

    private static string Key(string tenantId, string policyId)
    {
        if (string.IsNullOrWhiteSpace(tenantId) || tenantId.Length > 128
            || string.IsNullOrWhiteSpace(policyId) || policyId.Length > 128)
            throw new AgentPolicyLifecycleException("Policy key is invalid.");
        return $"{tenantId}\0{policyId}";
    }

    private static string Subject(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 ? value
        : throw new AgentPolicyLifecycleException("Operator subject is invalid.");

    private static AgentPolicyDeployment Copy(AgentPolicyDeployment value) => value with
    {
        SignedPolicy = value.SignedPolicy with
        {
            Claims = value.SignedPolicy.Claims.ToArray(),
            Signature = value.SignedPolicy.Signature.ToArray()
        },
        PolicyDigest = value.PolicyDigest.ToArray(),
        Approvals = value.Approvals.Select(approval => approval with
        { PolicyDigest = approval.PolicyDigest.ToArray() }).ToArray()
    };
}

public sealed class AgentPolicyLifecycleException(string message) : Exception(message);
