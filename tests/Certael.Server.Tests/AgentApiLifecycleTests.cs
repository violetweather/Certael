using Certael.Server.Agent;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class AgentApiLifecycleTests
{
    [Fact]
    public async Task LaunchChallengeReportHealthAndRevocationAreServerBound()
    {
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var clock = new FixedTimeProvider(now);
        using Key serviceKey = Key.Create(SignatureAlgorithm.Ed25519);
        using Key agentKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var store = new InMemoryAgentSessionStore(clock);
        var lifecycle = new AgentApiLifecycle(new AgentGrantSigner(serviceKey, "agent-signing-1"),
            new AgentReportVerifier(), store, clock);
        byte[] publicKey = agentKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var policy = new AgentPolicyClaims(1, "competitive", "game", "prod",
            AgentRequirementMode.Required, 15, 60, 30, "0.1.0", now.AddHours(1));

        AgentLaunchBundle launch = await lifecycle.LaunchAsync(new AgentLaunchParameters(
            "tenant", "game", "prod", "player", "match", "server-a", "build",
            publicKey, policy, TimeSpan.FromHours(1)), TestContext.Current.CancellationToken);
        Assert.Equal(64, launch.Grant.Signature.Length);
        Assert.Null(await lifecycle.ChallengeAsync("tenant", "prod", "server-b",
            launch.AgentSessionId, TestContext.Current.CancellationToken));
        AgentReportChallenge? challenge = await lifecycle.ChallengeAsync("tenant", "prod",
            "server-a", launch.AgentSessionId, TestContext.Current.CancellationToken);
        Assert.NotNull(challenge);

        var unsigned = new AgentIntegrityReport(1, launch.AgentSessionId, 1, challenge.Nonce,
            now.ToUnixTimeSeconds(), "build", new byte[32],
            [new AgentObservation("probe.health", "ok")], new byte[32], new byte[64]);
        byte[] message = "certael.agent.report.v1\0"u8.ToArray()
            .Concat(AgentReportCodec.EncodeSigned(unsigned)).ToArray();
        AgentIntegrityReport report = unsigned with
        { Signature = SignatureAlgorithm.Ed25519.Sign(agentKey, message) };
        Assert.Equal(AgentReportDecision.Accepted, await lifecycle.SubmitAsync("tenant", "prod",
            "server-a", report, TestContext.Current.CancellationToken));
        Assert.NotEqual(AgentReportDecision.Accepted, await lifecycle.SubmitAsync("tenant", "prod",
            "server-a", report, TestContext.Current.CancellationToken));
        Assert.Equal("healthy", (await lifecycle.HealthAsync("tenant", "prod", "server-a",
            launch.AgentSessionId, TimeSpan.FromMinutes(2),
            TestContext.Current.CancellationToken)).State);
        Assert.False(await lifecycle.RevokeAsync("tenant", "prod", "server-b",
            launch.AgentSessionId, "match ended", TestContext.Current.CancellationToken));
        Assert.True(await lifecycle.RevokeAsync("tenant", "prod", "server-a",
            launch.AgentSessionId, "match ended", TestContext.Current.CancellationToken));
        Assert.Equal("revoked", (await lifecycle.HealthAsync("tenant", "prod", "server-a",
            launch.AgentSessionId, TimeSpan.FromMinutes(2),
            TestContext.Current.CancellationToken)).State);
    }

    [Fact]
    public void BinaryApiCodecIsCanonicalAndStrictlyBounded()
    {
        var request = new AgentLaunchApiRequest("tenant", "game", "prod", "player", "match",
            "server", "build", new byte[32], "competitive", AgentRequirementMode.Required,
            15, 60, 30, "0.1.0", 3600, 7200);
        byte[] encoded = AgentApiCodec.EncodeLaunchRequest(request);
        AgentLaunchApiRequest decoded = AgentApiCodec.DecodeLaunchRequest(encoded);
        Assert.Equal(request.TenantId, decoded.TenantId);
        Assert.Equal(request.AuthoritativeServerId, decoded.AuthoritativeServerId);
        Assert.Equal(request.AgentPublicKey, decoded.AgentPublicKey);
        Assert.Equal(request.SessionLifetimeSeconds, decoded.SessionLifetimeSeconds);

        byte[] withUnknownField = encoded.Concat(new byte[] { 0x88, 0x01, 0x01 }).ToArray();
        Assert.Throws<AgentApiException>(() => AgentApiCodec.DecodeLaunchRequest(withUnknownField));
        Assert.Throws<AgentApiException>(() => AgentApiCodec.DecodeLaunchRequest(
            new byte[AgentApiCodec.MaximumBody + 1]));
        Assert.Throws<AgentApiException>(() => AgentApiCodec.DecodeLaunchRequest([0x8a, 0x00, 0x00]));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
