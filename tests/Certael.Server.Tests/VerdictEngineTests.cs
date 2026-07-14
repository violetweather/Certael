using System.Collections.Immutable;
using Certael.Server.Actions;
using Certael.Server.Evidence;

namespace Certael.Server.Tests;

public sealed class VerdictEngineTests
{
    [Fact]
    public void ClientOnlySignalsCannotKickOrSuspend()
    {
        var engine = new VerdictEngine(TimeProvider.System);
        Finding[] findings =
        [
            FindingOf(SignalFamily.RuntimeIntegrity, FindingTrust.ClientOnly, 100),
            FindingOf(SignalFamily.PlatformAttestation, FindingTrust.Environmental, 100),
            FindingOf(SignalFamily.BehavioralAnomaly, FindingTrust.ClientOnly, 100)
        ];

        Verdict verdict = engine.Evaluate(findings);

        Assert.Equal(90, verdict.RiskScore);
        Assert.Equal(VerdictRecommendation.RecommendManualReview, verdict.Recommendation);
        Assert.DoesNotContain("Ban", verdict.Recommendation.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IndependentAuthoritativeSignalsCanRecommendTemporarySuspension()
    {
        var engine = new VerdictEngine(TimeProvider.System);
        Verdict verdict = engine.Evaluate([
            FindingOf(SignalFamily.AuthoritativeContradiction, FindingTrust.Authoritative, 70),
            FindingOf(SignalFamily.ProtocolViolation, FindingTrust.Corroborated, 30)
        ]);
        Assert.Equal(VerdictRecommendation.RecommendTemporarySuspension, verdict.Recommendation);
    }

    [Fact]
    public void ReplayIsDeterministicAndDetectsEvidenceTampering()
    {
        var engine = new VerdictEngine(TimeProvider.System);
        Finding[] findings = [FindingOf(SignalFamily.EconomyAnomaly, FindingTrust.Authoritative, 60)];
        Verdict verdict = engine.Evaluate(findings);
        EvidenceBundle bundle = EvidenceReplay.Create(verdict, findings);
        Assert.True(EvidenceReplay.Verify(bundle, engine));

        Finding changed = findings[0] with { RiskContribution = 1 };
        Assert.False(EvidenceReplay.Verify(bundle with { Findings = [changed] }, engine));
    }

    [Fact]
    public async Task StoreEnforcesTenantBoundaryAndDeletion()
    {
        CancellationToken token = TestContext.Current.CancellationToken;
        var engine = new VerdictEngine(TimeProvider.System);
        Finding finding = FindingOf(SignalFamily.EconomyAnomaly, FindingTrust.Authoritative, 60);
        Verdict verdict = engine.Evaluate([finding]);
        EvidenceBundle bundle = EvidenceReplay.Create(verdict, [finding]);
        Finding otherFinding = finding with
        {
            FindingId = Guid.NewGuid(),
            EnvironmentId = "staging",
            SessionId = "other-session"
        };
        Verdict otherVerdict = engine.Evaluate([otherFinding]);
        EvidenceBundle otherBundle = EvidenceReplay.Create(otherVerdict, [otherFinding]);
        var store = new InMemoryEvidenceStore();
        await store.SaveAsync(bundle, token);
        await store.SaveAsync(otherBundle, token);

        Assert.Null(await store.FindAsync("other-tenant", verdict.VerdictId, token));
        Assert.NotNull(await store.FindAsync("tenant", verdict.VerdictId, token));
        await store.DeletePlayerAsync("tenant", "prod", "player", token);
        Assert.Null(await store.FindAsync("tenant", verdict.VerdictId, token));
        Assert.NotNull(await store.FindAsync("tenant", otherVerdict.VerdictId, token));
    }

    private static Finding FindingOf(SignalFamily family, FindingTrust trust, int risk) =>
        new(Guid.NewGuid(), "tenant", "game", "prod", "session", "player",
            $"rule.{family.ToString().ToLowerInvariant()}", "1.0.0", new byte[32], null,
            family, trust, risk, 0.9, DateTimeOffset.UtcNow,
            ImmutableArray.Create(new EvidenceField("reason", "test", Provenance.CertaelDerived)));
}
