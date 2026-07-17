using Certael.Server.Economy;

namespace Certael.Server.Tests;

public sealed class RelationshipAnalysisTests
{
    [Fact]
    public void FindingsAreDeterministicAndExplainTheirEdges()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        RelationshipEventV1[] events = Enumerable.Range(0, 4).Select(index => new RelationshipEventV1(
            Guid.Parse($"00000000-0000-0000-0000-{index + 1:D12}"), "tenant", "game", "prod",
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
}
