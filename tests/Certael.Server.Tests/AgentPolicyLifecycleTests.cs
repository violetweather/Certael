using Certael.Server.Agent;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class AgentPolicyLifecycleTests
{
    [Fact]
    public void RequiresExactApprovalsAndResolvesOnlyApprovedImmutablePolicy()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var store = new AgentPolicyLifecycleStore(new AgentGrantSigner(key, "policy-key"),
            new FixedTimeProvider(now));
        var claims = new AgentPolicyClaims(1, "competitive-v1", "tenant", "game", "prod",
            AgentRequirementMode.Required, 15, 60, 30, "0.1.0", now.AddHours(12));

        AgentPolicyDeployment draft = store.AddDraft(claims, "author");
        Assert.Throws<AgentPolicyLifecycleException>(() => store.AddDraft(claims, "author"));
        Assert.Throws<AgentPolicyLifecycleException>(() => store.Resolve(
            "competitive-v1", "tenant", "game", "prod", "player", now));
        store.Approve("tenant", "competitive-v1", "reviewer-a");
        Assert.Throws<AgentPolicyLifecycleException>(() => store.Promote(
            "tenant", "competitive-v1", AgentPolicyDeploymentStage.Enforced, 0, "operator"));
        store.Approve("tenant", "competitive-v1", "reviewer-b");
        store.Promote("tenant", "competitive-v1", AgentPolicyDeploymentStage.Enforced, 0, "operator");

        AgentPolicyDeployment resolved = store.Resolve(
            "competitive-v1", "tenant", "game", "prod", "player", now);
        Assert.Equal(draft.PolicyDigest, resolved.PolicyDigest);
        Assert.Equal(AgentRequirementMode.Required, resolved.Claims.RequirementMode);
        Assert.Throws<AgentPolicyLifecycleException>(() => store.Resolve(
            "competitive-v1", "other-tenant", "game", "prod", "player", now));
        Assert.Throws<AgentPolicyLifecycleException>(() => store.Resolve(
            "competitive-v1", "tenant", "other-game", "prod", "player", now));
        store.Retire("tenant", "competitive-v1", "operator");
        Assert.Throws<AgentPolicyLifecycleException>(() => store.Resolve(
            "competitive-v1", "tenant", "game", "prod", "player", now));
        Assert.Throws<AgentPolicyLifecycleException>(() => store.Promote(
            "tenant", "competitive-v1", AgentPolicyDeploymentStage.Enforced, 0, "operator"));
    }

    [Fact]
    public void ShadowPoliciesMustRemainNonEnforcing()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        var store = new AgentPolicyLifecycleStore(new AgentGrantSigner(key, "policy-key"),
            new FixedTimeProvider(now));
        var required = new AgentPolicyClaims(1, "required-shadow", "tenant", "game", "prod",
            AgentRequirementMode.Required, 15, 60, 30, "0.1.0", now.AddHours(1));
        store.AddDraft(required, "author");
        store.Approve("tenant", required.PolicyId, "reviewer");
        Assert.Throws<AgentPolicyLifecycleException>(() => store.Promote("tenant",
            required.PolicyId, AgentPolicyDeploymentStage.Shadow, 0, "operator"));

        AgentPolicyClaims optional = required with
        { PolicyId = "optional-shadow", RequirementMode = AgentRequirementMode.Optional };
        store.AddDraft(optional, "author");
        store.Approve("tenant", optional.PolicyId, "reviewer");
        store.Promote("tenant", optional.PolicyId, AgentPolicyDeploymentStage.Shadow, 0,
            "operator");
        Assert.Equal(optional, store.Resolve(optional.PolicyId, "tenant", "game", "prod",
            "player", now).Claims);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
