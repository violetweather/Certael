using Certael.Server.Agent;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class AgentIntegrityTests
{
    [Fact]
    public void AcceptsValidReportAndRejectsTampering()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] challenge = Enumerable.Repeat((byte)7, 32).ToArray();
        byte[] previous = Enumerable.Repeat((byte)8, 32).ToArray();
        var unsigned = new AgentIntegrityReport(1, "agent-session", 4, challenge,
            1_700_000_000, "build-1", new byte[32],
            [new AgentObservation("platform", "windows")], previous, []);
        byte[] message = "certael.agent.report.v1\0"u8.ToArray()
            .Concat(AgentReportCodec.EncodeSigned(unsigned)).ToArray();
        AgentIntegrityReport report = unsigned with
            { Signature = SignatureAlgorithm.Ed25519.Sign(key, message) };
        var session = new VerifiedAgentSession("agent-session", "tenant", "game", "prod",
            "player", "match", "build-1", publicKey, 3, previous,
            DateTimeOffset.UtcNow.AddMinutes(5));
        var verifier = new AgentReportVerifier();

        Assert.Equal(AgentReportDecision.Accepted,
            verifier.Verify(report, session, challenge, DateTimeOffset.UtcNow));
        Assert.Equal(AgentReportDecision.InvalidProof,
            verifier.Verify(report with { ExecutableSha256 = Enumerable.Repeat((byte)1, 32).ToArray() },
                session, challenge, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void RejectsReplayBrokenChainAndWrongChallenge()
    {
        byte[] digest = new byte[32];
        var report = new AgentIntegrityReport(1, "agent", 2, new byte[32], 1,
            "build", new byte[32], [], digest, new byte[64]);
        var session = new VerifiedAgentSession("agent", "tenant", "game", "prod", "player",
            "match", "build", new byte[32], 2, digest, DateTimeOffset.UtcNow.AddMinutes(1));
        var verifier = new AgentReportVerifier();
        Assert.Equal(AgentReportDecision.Replay,
            verifier.Verify(report, session, new byte[32], DateTimeOffset.UtcNow));
        Assert.Equal(AgentReportDecision.BindingMismatch,
            verifier.Verify(report with { Sequence = 3 }, session,
                Enumerable.Repeat((byte)1, 32).ToArray(), DateTimeOffset.UtcNow));
        Assert.Equal(AgentReportDecision.BrokenChain,
            verifier.Verify(report with { Sequence = 3, PreviousReportDigest = Enumerable.Repeat((byte)2, 32).ToArray() },
                session, new byte[32], DateTimeOffset.UtcNow));
    }
}
