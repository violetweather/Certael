using Certael.Server.Economy;

namespace Certael.Server.Tests;

public sealed class EconomyProtectionTests
{
    [Fact]
    public void CanonicalCodecAndReplayDigestAreStable()
    {
        EconomyEventV1 value = Transfer("tx-1", "account-a", "account-b", 5);
        byte[] encoded = EconomyEventV1Codec.Encode(value);
        EconomyEventV1 decoded = EconomyEventV1Codec.Decode(encoded);
        Assert.Equal(encoded, EconomyEventV1Codec.Encode(decoded));
        Assert.Equal(value.EventId, decoded.EventId);
        Assert.Equal(value.Transaction!.Lines, decoded.Transaction!.Lines);
        Assert.Equal(EconomyEventV1Codec.ReplayDigest([value]),
            EconomyEventV1Codec.ReplayDigest([EconomyEventV1Codec.Decode(encoded)]));
    }

    [Fact]
    public void EvaluatorExplainsDuplicatesVelocityAndCycles()
    {
        EconomyEventV1 first = Transfer("tx-repeat", "account-a", "account-b", 5);
        EconomyEventV1 second = Transfer("tx-repeat", "account-b", "account-a", 5)
            with { EventId = Guid.NewGuid(), OccurredAt = first.OccurredAt.AddSeconds(1) };
        EconomyProtectionProfile profile = Profile() with { MaximumTransactionsPerWindow = 1 };
        IReadOnlyList<EconomyFinding> findings = EconomyProtectionEvaluator.Evaluate([second, first], profile);
        Assert.Contains(findings, finding => finding.RuleId == "duplicate-transaction");
        Assert.Contains(findings, finding => finding.RuleId == "circular-transfer");
        Assert.All(findings, finding => Assert.Equal(32, finding.ReplayDigest.Length));
    }

    private static EconomyEventV1 Transfer(string id, string source, string sink, long quantity)
    {
        Guid action = Guid.NewGuid();
        return new EconomyEventV1(Guid.NewGuid(), "tenant", "game", "prod", "player-1",
            DateTimeOffset.Parse("2026-07-17T00:00:00Z"), EconomyEventKind.LedgerTransaction,
            new EconomyTransaction(id, action, "trade", source, sink,
                [new EconomyLedgerLine(source, "gold", -quantity),
                 new EconomyLedgerLine(sink, "gold", quantity)]), null);
    }

    private static EconomyProtectionProfile Profile() => new("economy", "1.0.0", "tenant",
        "game", "prod", EconomyProfileStage.Enforced, 100, 100, 1000, 2,
        TimeSpan.FromDays(7), DateTimeOffset.UtcNow.AddDays(1));
}
