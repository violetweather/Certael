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
            "player", "match", "build", new byte[32], now, now.AddSeconds(60), digest, "server");
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
            "player", "match", "build", new byte[31], now, now.AddMinutes(5), new byte[32],
            "server");
        Assert.Throws<ArgumentException>(() => signer.IssueLaunchGrant(invalid, now));
    }

    [Fact]
    public void LaunchGrantMatchesCrossLanguageGoldenVector()
    {
        var claims = new AgentLaunchGrantClaims(1, "grant", "tenant", "game", "prod",
            "player", "match", "build",
            Convert.FromHexString("EA4A6C63E29C520ABEF5507B132EC5F9954776AEBEBE7B92421EEA691446D22C"),
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_060),
            Convert.FromHexString("1CBFC3CDCAD1C8675EE33A31CA90BBEFE6E5BAB3DEC0264F786495F11915A045"),
            "server");
        Assert.Equal(
            "080112056772616e741a0674656e616e74220467616d652a0470726f643206706c617965723a056d6174636842056275696c644a20ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c5080e2cfaa0658bce2cfaa0662201cbfc3cdcad1c8675ee33a31ca90bbefe6e5bab3dec0264f786495f11915a0456a06736572766572",
            Convert.ToHexString(AgentGrantCodec.EncodeLaunchGrantClaims(claims)).ToLowerInvariant());
    }
}
