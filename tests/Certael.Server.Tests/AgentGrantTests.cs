using Certael.Server.Agent;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class AgentGrantTests
{
    [Fact]
    public void SignsBoundPolicyAndShortLivedLaunchGrant()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var signer = new AgentGrantSigner(key, "agent-key-1");
        var policyClaims = new AgentPolicyClaims(1, "competitive", "game", "prod",
            AgentRequirementMode.Required, 15, 60, 30, "0.1.0", now.AddHours(1));
        SignedAgentPolicy policy = signer.IssuePolicy(policyClaims, now);
        Assert.True(SignatureAlgorithm.Ed25519.Verify(key.PublicKey,
            "certael.agent.policy.v1\0"u8.ToArray().Concat(policy.Claims).ToArray(), policy.Signature));
        byte[] digest = AgentGrantCodec.PolicyDigest(policy);
        var grantClaims = new AgentLaunchGrantClaims(1, "grant", "tenant", "game", "prod",
            "player", "match", "build", new byte[32], now, now.AddSeconds(60), digest);
        SignedAgentLaunchGrant grant = signer.IssueLaunchGrant(grantClaims, now);
        Assert.True(SignatureAlgorithm.Ed25519.Verify(key.PublicKey,
            "certael.agent.launch.v1\0"u8.ToArray().Concat(grant.Claims).ToArray(), grant.Signature));
        Assert.Equal(64, grant.Signature.Length);
    }

    [Fact]
    public void RejectsLongLivedOrUnboundGrants()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        var signer = new AgentGrantSigner(key, "key");
        var invalid = new AgentLaunchGrantClaims(1, "grant", "tenant", "game", "prod",
            "player", "match", "build", new byte[31], now, now.AddMinutes(5), new byte[32]);
        Assert.Throws<ArgumentException>(() => signer.IssueLaunchGrant(invalid, now));
    }
}
