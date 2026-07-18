using Certael.Server.Economy;
using System.Security.Cryptography;

namespace Certael.Server.Tests;

public sealed class RelationshipAnalysisTests
{
    [Fact]
    public void CanonicalCodecRoundTripsAndRejectsUnknownOrTrailingFields()
    {
        RelationshipEventV1 value = Edge(1, RelationshipKind.Trade, "a", "b", 10);
        byte[] encoded = RelationshipEventV1Codec.Encode(value);
        RelationshipEventV1 decoded = RelationshipEventV1Codec.Decode(encoded);
        Assert.Equal(value, decoded);
        Assert.Equal(encoded, RelationshipEventV1Codec.Encode(decoded));
        Assert.Throws<EconomyEventException>(() => RelationshipEventV1Codec.Decode(
            encoded.Concat(new byte[] { 0x60, 0x01 }).ToArray()));
        Assert.Throws<EconomyEventException>(() => RelationshipEventV1Codec.Encode(
            value with { SourceSubject = value.TargetSubject }));
    }

    [Fact]
    public void FindingsAreDeterministicAndExplainTheirEdges()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        RelationshipEventV1[] events = Enumerable.Range(0, 4).Select(index => new RelationshipEventV1(
            Guid.Parse($"00000000-0000-0000-0000-{index + 1:D12}"), Guid.Parse(
                $"10000000-0000-0000-0000-{index + 1:D12}"), "tenant", "game", "prod",
            RelationshipKind.Trade, index % 2 == 0 ? "a" : "b", index % 2 == 0 ? "b" : "a",
            10, now.AddHours(-index))).ToArray();
        var baseline = new RelationshipBaseline("baseline-1", 4, 3, 80, 5);

        IReadOnlyList<RelationshipFinding> first = RelationshipAnalyzer.Analyze(events, now, baseline);
        IReadOnlyList<RelationshipFinding> second = RelationshipAnalyzer.Analyze(events.Reverse(), now, baseline);

        RelationshipFinding finding = Assert.Single(first,
            f => f.RuleId == "reciprocal-transfer" && f.WindowDays == 7);
        Assert.Equal(4, finding.ExactEdges.Count);
        Assert.Equal("baseline-1", finding.BaselineVersion);
        Assert.Equal(finding.ReplayDigest, Assert.Single(second,
            f => f.RuleId == "reciprocal-transfer" && f.WindowDays == 7).ReplayDigest);
    }

    [Fact]
    public void SignedProfilesBindWindowsThresholdsAndExpiry()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        RelationshipProtectionProfile profile = Profile();
        var signer = new RelationshipProtectionProfileSigner(key, "relationship-key");
        SignedRelationshipProtectionProfile signed = signer.Sign(profile);
        RelationshipProtectionProfile verified = RelationshipProtectionProfileSigner.Verify(
            signed, new Dictionary<string, ECDsa> { ["relationship-key"] = key },
            DateTimeOffset.Parse("2026-07-18T00:00:00Z"));
        Assert.Equal(profile.ProfileId, verified.ProfileId);
        Assert.Equal(profile.Windows, verified.Windows);
        Assert.Equal(profile.ReciprocalTransferCount, verified.ReciprocalTransferCount);

        Assert.Throws<EconomyEventException>(() => signer.Sign(profile with
            { Windows = [30, 7] }));
        Assert.Throws<EconomyEventException>(() =>
            RelationshipProtectionProfileSigner.Verify(signed,
                new Dictionary<string, ECDsa> { ["relationship-key"] = key },
                profile.ExpiresAt));
    }

    [Fact]
    public void SelectedWindowsAndConflictingIdsAreEnforced()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-07-18T00:00:00Z");
        RelationshipEventV1 first = Edge(1, RelationshipKind.Trade, "a", "b", 10)
            with { OccurredAt = now.AddDays(-20) };
        RelationshipEventV1 second = Edge(2, RelationshipKind.Trade, "b", "a", 10)
            with { OccurredAt = now.AddDays(-19) };
        var baseline = new RelationshipBaseline("baseline-1", 2, 2, 80, 2);
        IReadOnlyList<RelationshipFinding> findings = RelationshipAnalyzer.Analyze(
            [first, second], now, baseline, [30]);
        Assert.NotEmpty(findings);
        Assert.All(findings, finding => Assert.Equal(30, finding.WindowDays));

        Assert.Throws<EconomyEventException>(() => RelationshipAnalyzer.Analyze(
            [first, first with { Weight = 11 }], now, baseline, [30]));
        Assert.Throws<EconomyEventException>(() => RelationshipAnalyzer.Analyze(
            [first], now, baseline, [14]));
    }

    [Fact]
    public void GraphRulesExplainCyclesBeneficiariesOutcomesAndCoordination()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-07-18T00:00:00Z");
        RelationshipEventV1[] events =
        [
            Edge(1, RelationshipKind.Trade, "a", "b", 10),
            Edge(2, RelationshipKind.Trade, "b", "c", 10),
            Edge(3, RelationshipKind.Trade, "c", "a", 10),
            Edge(4, RelationshipKind.Gift, "d", "b", 5),
            Edge(5, RelationshipKind.Outcome, "a", "b", 1),
            Edge(6, RelationshipKind.Outcome, "a", "b", 1),
            Edge(7, RelationshipKind.Outcome, "a", "b", 1),
            Edge(8, RelationshipKind.Party, "a", "b", 1),
            Edge(9, RelationshipKind.Reward, "a", "b", 1)
        ];
        events = events.Select((edge, index) => edge with
            { OccurredAt = now.AddMinutes(-index) }).ToArray();
        var baseline = new RelationshipBaseline("baseline-1", 2, 2, 80, 2);
        IReadOnlyList<RelationshipFinding> findings = RelationshipAnalyzer.Analyze(
            events, now, baseline, [7]);
        Assert.Contains(findings, value => value.RuleId == "transfer-cycle");
        Assert.Contains(findings, value => value.RuleId == "shared-beneficiary");
        Assert.Contains(findings, value => value.RuleId == "opponent-imbalance");
        Assert.Contains(findings, value => value.RuleId == "coordinated-farming");
        Assert.All(findings, value =>
        {
            Assert.NotEmpty(value.ExactEdges);
            Assert.Equal(32, value.ReplayDigest.Length);
            Assert.False(string.IsNullOrWhiteSpace(value.Threshold));
        });
    }

    [Fact]
    public void BoostingAndWinTradingRemainSeparateExplainableRules()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-07-18T00:00:00Z");
        RelationshipEventV1[] events =
        [
            Edge(1, RelationshipKind.Outcome, "a", "b", 1),
            Edge(2, RelationshipKind.Outcome, "a", "b", 1),
            Edge(3, RelationshipKind.Outcome, "a", "b", 1),
            Edge(4, RelationshipKind.Outcome, "a", "b", -1),
            Edge(5, RelationshipKind.Party, "a", "b", 1),
            Edge(6, RelationshipKind.Gift, "b", "a", 10)
        ];
        events = events.Select((edge, index) => edge with
            { OccurredAt = now.AddMinutes(-index) }).ToArray();
        var baseline = new RelationshipBaseline("baseline-1", 2, 2, 75, 4);
        IReadOnlyList<RelationshipFinding> findings = RelationshipAnalyzer.Analyze(
            events, now, baseline, [7]);
        Assert.Contains(findings, value => value.RuleId == "boosting");
        Assert.Contains(findings, value => value.RuleId == "win-trading");
        Assert.NotEqual(
            Assert.Single(findings, value => value.RuleId == "boosting").Threshold,
            Assert.Single(findings, value => value.RuleId == "win-trading").Threshold);
    }

    [Fact]
    public void OrdinaryHighVolumeActivityStaysBelowTransparentThresholds()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-07-18T00:00:00Z");
        RelationshipEventV1[] events = Enumerable.Range(1, 5_000).Select(index =>
            Edge(index, RelationshipKind.Match, $"player-{index * 2}",
                $"player-{index * 2 + 1}", 1) with
            { OccurredAt = now.AddSeconds(-index) }).ToArray();
        var baseline = new RelationshipBaseline("baseline-normal", 100, 100, 95, 100);
        Assert.Empty(RelationshipAnalyzer.Analyze(events, now, baseline, [7]));
    }

    private static RelationshipEventV1 Edge(int id, RelationshipKind kind,
        string source, string target, long weight) => new(
        Guid.Parse($"00000000-0000-0000-0000-{id:D12}"),
        Guid.Parse($"10000000-0000-0000-0000-{id:D12}"), "tenant", "game", "prod",
        kind, source, target, weight, DateTimeOffset.Parse("2026-07-18T00:00:00Z"));

    private static RelationshipProtectionProfile Profile() => new(
        "relationship", "1.0.0", "tenant", "game", "prod", [7, 30, 90],
        4, 3, 80, 5, DateTimeOffset.Parse("2026-08-18T00:00:00Z"));
}
