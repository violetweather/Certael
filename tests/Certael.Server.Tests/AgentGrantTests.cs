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
        var policyClaims = new AgentPolicyClaims(1, "competitive", "tenant", "game", "prod",
            AgentRequirementMode.Required, 15, 60, 30, "0.1.0", now.AddHours(1));
        SignedAgentPolicy policy = signer.IssuePolicy(policyClaims, now);
        Assert.True(SignatureAlgorithm.Ed25519.Verify(key.PublicKey,
            "certael.agent.policy.v1\0"u8.ToArray().Concat(policy.Claims).ToArray(), policy.Signature));
        byte[] digest = AgentGrantCodec.PolicyDigest(policy);
        var grantClaims = new AgentLaunchGrantClaims(1, "grant", "tenant", "game", "prod",
            "player", "match", "build", new byte[32], now, now.AddSeconds(60), digest, "server",
            new byte[32]);
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
            "server", new byte[32]);
        Assert.Throws<ArgumentException>(() => signer.IssueLaunchGrant(invalid, now));
    }

    [Fact]
    public void LaunchGrantMatchesCrossLanguageGoldenVector()
    {
        var policy = new AgentPolicyClaims(1, "competitive", "tenant", "game", "prod",
            AgentRequirementMode.Required, 15, 60, 30, "1.0.0",
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
        Assert.Equal(
            "0801120b636f6d70657469746976651a0467616d65220470726f642802300f383c401e4a05312e302e305080a4a7da065a0674656e616e74",
            Convert.ToHexString(AgentGrantCodec.EncodePolicyClaims(policy)).ToLowerInvariant());
        var claims = new AgentLaunchGrantClaims(1, "grant", "tenant", "game", "prod",
            "player", "match", "build",
            Convert.FromHexString("EA4A6C63E29C520ABEF5507B132EC5F9954776AEBEBE7B92421EEA691446D22C"),
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_060),
            Convert.FromHexString("947CC7A0C10233B2FF5C0AAE415B2E37CFC97915E5747EDCC3EB8245F600F440"),
            "server", Enumerable.Repeat((byte)5, 32).ToArray());
        Assert.Equal(
            "080112056772616e741a0674656e616e74220467616d652a0470726f643206706c617965723a056d6174636842056275696c644a20ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c5080e2cfaa0658bce2cfaa066220947cc7a0c10233b2ff5c0aae415b2e37cfc97915e5747edcc3eb8245f600f4406a0673657276657272200505050505050505050505050505050505050505050505050505050505050505",
            Convert.ToHexString(AgentGrantCodec.EncodeLaunchGrantClaims(claims)).ToLowerInvariant());
    }

    [Fact]
    public void SupportsNonExportingHsmStyleSigningProvider()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        var signer = new AgentGrantSigner(new TestSigningProvider(key));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        SignedAgentPolicy policy = signer.IssuePolicy(new AgentPolicyClaims(1, "policy",
            "tenant", "game", "prod", AgentRequirementMode.Optional, 15, 60, 30,
            "0.1.0", now.AddHours(1)), now);
        Assert.Equal("hsm-key", policy.KeyId);
        Assert.True(SignatureAlgorithm.Ed25519.Verify(key.PublicKey,
            "certael.agent.policy.v1\0"u8.ToArray().Concat(policy.Claims).ToArray(),
            policy.Signature));
    }

    [Fact]
    public void SignsCanonicalWholeBuildManifestAndRevocation()
    {
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        var signer = new AgentGrantSigner(key, "agent-key-1");
        var manifestClaims = new AgentBuildManifestClaims(1, "build-manifest", "tenant",
            "game", "prod", "build", [new("bin/game.exe", 42, new byte[32])],
            now, now.AddDays(30));
        SignedAgentBuildManifest manifest = signer.IssueBuildManifest(manifestClaims, now);
        Assert.True(SignatureAlgorithm.Ed25519.Verify(key.PublicKey,
            "certael.agent.build-manifest.v1\0"u8.ToArray().Concat(manifest.Claims).ToArray(),
            manifest.Signature));
        Assert.InRange(AgentGrantCodec.EncodeSignedBuildManifest(manifest).Length, 1,
            64 * 1024);

        SignedAgentRevocation revocation = signer.IssueRevocation(
            new(1, "tenant", "game", "prod", "session", "SESSION_REVOKED", now,
                now.AddMinutes(5)), now);
        Assert.True(SignatureAlgorithm.Ed25519.Verify(key.PublicKey,
            "certael.agent.revocation.v1\0"u8.ToArray().Concat(revocation.Claims).ToArray(),
            revocation.Signature));
        Assert.Equal(64, revocation.Signature.Length);
    }

    [Fact]
    public void RejectsManifestPathTraversalAndCaseCollisions()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        var signer = new AgentGrantSigner(key, "key");
        AgentBuildManifestClaims Base(IReadOnlyList<ProtectedAgentBuildFile> files) =>
            new(1, "manifest", "tenant", "game", "prod", "build", files, now,
                now.AddDays(1));
        Assert.Throws<ArgumentException>(() => signer.IssueBuildManifest(
            Base([new("../game", 1, new byte[32])]), now));
        Assert.Throws<ArgumentException>(() => signer.IssueBuildManifest(Base([
            new("Game.exe", 1, new byte[32]), new("game.exe", 1, new byte[32])]), now));
    }

    private sealed class TestSigningProvider(Key key) : IAgentGrantSigningProvider
    {
        public AgentGrantSignature Sign(ReadOnlyMemory<byte> domainSeparatedClaims,
            DateTimeOffset now) => new("hsm-key",
                SignatureAlgorithm.Ed25519.Sign(key, domainSeparatedClaims.Span));
    }
}
