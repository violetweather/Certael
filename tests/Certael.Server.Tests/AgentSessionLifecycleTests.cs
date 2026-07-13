using Certael.Server.Agent;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class AgentSessionLifecycleTests
{
    [Fact]
    public void ChallengeIsSingleUseAndAcceptedReportAdvancesChain()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var clock = new FixedTimeProvider(now);
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var service = new InMemoryAgentSessionLifecycle(new AgentReportVerifier(), clock);
        service.Register(new VerifiedAgentSession("agent", "tenant", "game", "prod", "player",
            "match", "build", key.PublicKey.Export(KeyBlobFormat.RawPublicKey), 0, new byte[32],
            now.AddMinutes(5), "server"));
        AgentReportChallenge challenge = service.IssueChallenge("agent");
        AgentIntegrityReport report = Sign(key, challenge.Nonce, 1, new byte[32], now);

        Assert.Equal(AgentReportDecision.Accepted, service.Submit(report, now));
        Assert.Equal(AgentReportDecision.BindingMismatch, service.Submit(report, now));
        Assert.Equal("healthy", service.Health("agent", now).State);

        AgentReportChallenge next = service.IssueChallenge("agent");
        AgentIntegrityReport chained = Sign(key, next.Nonce, 2, AgentReportCodec.Digest(report), now);
        Assert.Equal(AgentReportDecision.Accepted, service.Submit(chained, now));
    }

    [Fact]
    public void ConcurrentDuplicateSubmissionCommitsOnce()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var service = new InMemoryAgentSessionLifecycle(new AgentReportVerifier(), new FixedTimeProvider(now));
        service.Register(new VerifiedAgentSession("agent", "tenant", "game", "prod", "player",
            "match", "build", key.PublicKey.Export(KeyBlobFormat.RawPublicKey), 0, new byte[32],
            now.AddMinutes(5), "server"));
        AgentReportChallenge challenge = service.IssueChallenge("agent");
        AgentIntegrityReport report = Sign(key, challenge.Nonce, 1, new byte[32], now);
        AgentReportDecision[] decisions = Enumerable.Range(0, 16).AsParallel()
            .Select(_ => service.Submit(report, now)).ToArray();
        Assert.Equal(1, decisions.Count(value => value == AgentReportDecision.Accepted));
    }

    [Fact]
    public void RevocationFailsClosed()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var service = new InMemoryAgentSessionLifecycle(new AgentReportVerifier(), new FixedTimeProvider(now));
        service.Register(new VerifiedAgentSession("agent", "tenant", "game", "prod", "player",
            "match", "build", new byte[32], 0, new byte[32], now.AddMinutes(5), "server"));
        Assert.True(service.Revoke("agent", "operator request", now));
        Assert.Equal("revoked", service.Health("agent", now).State);
        Assert.Throws<InvalidOperationException>(() => service.IssueChallenge("agent"));
    }

    private static AgentIntegrityReport Sign(Key key, byte[] challenge, ulong sequence,
        byte[] previous, DateTimeOffset now)
    {
        var unsigned = new AgentIntegrityReport(1, "agent", sequence, challenge,
            now.ToUnixTimeSeconds(), "build", new byte[32], [], previous, []);
        byte[] signed = "certael.agent.report.v1\0"u8.ToArray()
            .Concat(AgentReportCodec.EncodeSigned(unsigned)).ToArray();
        return unsigned with { Signature = SignatureAlgorithm.Ed25519.Sign(key, signed) };
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    { public override DateTimeOffset GetUtcNow() => now; }
}
