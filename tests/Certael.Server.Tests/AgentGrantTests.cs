using Certael.Server.Agent;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class AgentGrantTests
{
    [Fact]
    public void MatchesRustGoldenVectorExactly()
    {
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        using Key key = Key.Import(SignatureAlgorithm.Ed25519,
            Enumerable.Repeat((byte)7, 32).ToArray(), KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var signer = new AgentGrantSigner(key, "vector-key");
        SignedAgentPolicy policy = signer.IssuePolicy(new AgentPolicyClaims(1, "competitive",
            "game", "prod", AgentRequirementMode.Required, 15, 60, 30, "1.0.0",
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)), now);
        Assert.Equal("0801120b636f6d70657469746976651a0467616d65220470726f642802300f383c401e4a05312e302e305080a4a7da06",
            Convert.ToHexString(policy.Claims).ToLowerInvariant());
        Assert.Equal("2c6e2be8708bf63e9865faa5b7ce261f49c4e85307bf5eaa65a620a8ed1babf852ea261768b233e87dfc0b95402ffb893b3a58b3582624a8cc9b1f9a72d37a08",
            Convert.ToHexString(policy.Signature).ToLowerInvariant());
        var grantClaims = new AgentLaunchGrantClaims(1, "grant", "tenant", "game", "prod",
            "player", "match", "build", signer.ExportPublicKey(), now, now.AddSeconds(60),
            AgentGrantCodec.PolicyDigest(policy));
        SignedAgentLaunchGrant grant = signer.IssueLaunchGrant(grantClaims, now);
        Assert.Equal("080112056772616e741a0674656e616e74220467616d652a0470726f643206706c617965723a056d6174636842056275696c644a20ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c5080e2cfaa0658bce2cfaa0662201cbfc3cdcad1c8675ee33a31ca90bbefe6e5bab3dec0264f786495f11915a045",
            Convert.ToHexString(grant.Claims).ToLowerInvariant());
        Assert.Equal("72900cb146a4035c5ae6d5767a4f181de695906525ae5647ac3698245717487eec837da79df6f4d9f8121066fab32830bdbdd074e64f49ff56cc89bf48394f04",
            Convert.ToHexString(grant.Signature).ToLowerInvariant());
    }

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
