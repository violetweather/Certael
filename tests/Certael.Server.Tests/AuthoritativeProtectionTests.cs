using System.Collections.Immutable;
using Certael.Server.Evidence;
using Certael.Server.Protections;
using Certael.Persistence.Postgres;
using Certael.Server.Actions;

namespace Certael.Server.Tests;

public sealed class AuthoritativeProtectionTests
{
    [Fact]
    public void MovementUsesServerTimeAndRejectsTeleportAndBlockedPath()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var guard = new AuthoritativeMovementGuard(new MovementPolicy(10, 20, 15, TimeSpan.FromSeconds(2)));
        var state = new MovementState(0, 0, 0, 0, 0, 0, now, 4);

        Assert.Equal("MOVEMENT_STEP_EXCEEDED", guard.Evaluate(Guid.NewGuid(),
            new MovementIntent(100, 0, 0, now, 4), state, now.AddSeconds(1), (_, _) => true).PublicReason);
        Assert.Equal("MOVEMENT_PATH_BLOCKED", guard.Evaluate(Guid.NewGuid(),
            new MovementIntent(1, 0, 0, now, 4), state, now.AddSeconds(1), (_, _) => false).PublicReason);
        Assert.True(guard.Evaluate(Guid.NewGuid(), new MovementIntent(1, 0, 0, now, 4),
            state, now.AddSeconds(1), (_, _) => true).Allowed);
    }

    [Fact]
    public void EconomyAndVisibilityUseAuthoritativeState()
    {
        Assert.False(AuthoritativeEconomyGuard.ValidateDebit(new(101, 2), new(100, 2), 1_000).Passed);
        Assert.False(AuthoritativeEconomyGuard.ValidateDebit(new(5, 1), new(100, 2), 1_000).Passed);
        Assert.True(AuthoritativeEconomyGuard.ValidateDebit(new(5, 2), new(100, 2), 1_000).Passed);
        Assert.False(new AuthoritativeVisibilityGuard().CanTarget("hidden", new HashSet<string> { "visible" }).Passed);
    }

    [Fact]
    public void BehavioralSignalsAreAdvisoryAndClientIntegrityCannotKick()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var samples = Enumerable.Range(0, 10).Select(index => new ServerInputObservation(
            now.AddMilliseconds(index * 10), index % 2 == 0 ? 0 : 90, 0, true)).ToArray();
        Assert.NotEmpty(new BehavioralAnalyzer().Analyze(samples));

        var verifier = new UserModeIntegrityVerifier();
        byte[] expectedHash = new byte[32];
        var expected = new ProtectedBuildManifest("build", [new("game.bin", 10, expectedHash)]);
        var report = new UserModeIntegrityReport("other", new byte[32],
            ImmutableArray<ProtectedBuildFile>.Empty, [], true, now);
        IReadOnlyList<Finding> findings = verifier.Evaluate(report, new byte[32], expected, "tenant", "game", "prod",
            "session", "player", new byte[32], now);
        Verdict verdict = new VerdictEngine(TimeProvider.System).Evaluate(findings);
        Assert.Equal(FindingTrust.ClientOnly, findings[0].Trust);
        Assert.DoesNotContain(verdict.Recommendation,
            new[] { VerdictRecommendation.RecommendKick, VerdictRecommendation.RecommendTemporarySuspension });
    }

    [Fact]
    public void AdvisoryEvidenceRetentionIsCappedAtThirtyDays()
    {
        Finding advisory = new(Guid.NewGuid(), "tenant", "game", "prod", "session", "player",
            "behavior.rule", "1.0.0", new byte[32], null, SignalFamily.BehavioralAnomaly,
            FindingTrust.ClientOnly, 10, 1, DateTimeOffset.UtcNow,
            ImmutableArray<EvidenceField>.Empty);
        Verdict verdict = new VerdictEngine(TimeProvider.System).Evaluate([advisory]);
        EvidenceBundle bundle = EvidenceReplay.Create(verdict, [advisory]);
        Assert.Equal(TimeSpan.FromDays(30),
            PostgresEvidenceStore.RetentionFor(bundle, TimeSpan.FromDays(365)));
    }
}
