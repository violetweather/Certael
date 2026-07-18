using Certael.Server.Economy;
using System.Security.Cryptography;

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
        Assert.Equal(0x08, encoded[0]);
        Assert.Equal(0x01, encoded[1]);
        Assert.Throws<EconomyEventException>(() =>
            EconomyEventV1Codec.Decode(encoded.Concat(new byte[] { 0x58, 0x01 }).ToArray()));
    }

    [Fact]
    public void AuthoritativeBoundaryRejectsNonConservingOrMisboundLedgerLines()
    {
        EconomyEventV1 valid = Transfer("tx-boundary", "source", "sink", 5);
        EconomyTransaction transaction = valid.Transaction!;
        Assert.Throws<EconomyEventException>(() => EconomyEventV1Codec.Encode(valid with
        {
            Transaction = transaction with
            {
                Lines = [new EconomyLedgerLine("source", "gold", -5),
                    new EconomyLedgerLine("sink", "gold", 4)]
            }
        }));
        Assert.Throws<EconomyEventException>(() => EconomyEventV1Codec.Encode(valid with
        {
            Transaction = transaction with
            {
                Lines = [new EconomyLedgerLine("other", "gold", -5),
                    new EconomyLedgerLine("sink", "gold", 5)]
            }
        }));
    }

    [Fact]
    public void ItemLineageOptionalParentRoundTripsCanonically()
    {
        DateTimeOffset occurred = DateTimeOffset.Parse("2026-07-17T00:00:00Z");
        foreach (string? parent in new[] { null, "parent-item" })
        {
            var mutation = new ItemLineageMutation("mutation-1", Guid.Parse(
                "00112233-4455-6677-8899-aabbccddeeff"), ItemMutationKind.Transfer,
                "item-1", "sword", "account-1", parent, "trade");
            var value = new EconomyEventV1(Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100"),
                "tenant", "game", "prod", "player-1", occurred,
                EconomyEventKind.ItemLineageMutation, null, mutation);
            EconomyEventV1 decoded = EconomyEventV1Codec.Decode(EconomyEventV1Codec.Encode(value));
            Assert.Equal(parent, decoded.ItemMutation!.ParentItemId);
        }
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
        Assert.All(findings, finding =>
        {
            Assert.Equal(profile.ProfileId, finding.ProfileId);
            Assert.Equal(profile.Version, finding.ProfileVersion);
            Assert.Equal(EconomyProfileStage.Enforced, finding.ProfileStage);
        });
    }

    [Fact]
    public void SignedProfilesAreCanonicalBoundAndStageDeterministically()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        EconomyProtectionProfile profile = Profile();
        var signer = new EconomyProtectionProfileSigner(key, "economy-key");
        SignedEconomyProtectionProfile signed = signer.Sign(profile);
        EconomyProtectionProfile verified = EconomyProtectionProfileSigner.Verify(signed,
            new Dictionary<string, ECDsa> { ["economy-key"] = key }, DateTimeOffset.UtcNow);
        Assert.Equal(profile, verified);

        byte[] noncanonical = signed.CanonicalProfile.Concat(new byte[] { 0x20 }).ToArray();
        var malformed = signed with
        {
            CanonicalProfile = noncanonical,
            Digest = SHA256.HashData(noncanonical),
            Signature = key.SignData(noncanonical, HashAlgorithmName.SHA256)
        };
        Assert.Throws<EconomyEventException>(() => EconomyProtectionProfileSigner.Verify(malformed,
            new Dictionary<string, ECDsa> { ["economy-key"] = key }, DateTimeOffset.UtcNow));

        EconomyEventV1 first = Transfer("tx-repeat", "account-a", "account-b", 5);
        EconomyEventV1 second = Transfer("tx-repeat", "account-b", "account-a", 5)
            with { EventId = Guid.NewGuid(), OccurredAt = first.OccurredAt.AddSeconds(1) };
        Assert.NotEmpty(EconomyProtectionEvaluator.Evaluate([first, second], profile));
        Assert.Empty(EconomyProtectionEvaluator.Evaluate([first, second], profile,
            EconomyProfileStage.RolledBack));
        Assert.Throws<EconomyEventException>(() => EconomyProtectionEvaluator.Evaluate(
            [first, second], profile, EconomyProfileStage.Canary, 100));

        bool[] selected = Enumerable.Range(0, 256).Select(index =>
        {
            string player = $"player-{index}";
            EconomyEventV1 left = first with { PlayerSubject = player };
            EconomyEventV1 right = second with { PlayerSubject = player };
            return EconomyProtectionEvaluator.Evaluate([left, right], profile,
                EconomyProfileStage.Canary, 50).Count > 0;
        }).ToArray();
        Assert.Contains(true, selected);
        Assert.Contains(false, selected);
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
        "game", "prod", 100, 1000, 2,
        TimeSpan.FromDays(7), DateTimeOffset.UtcNow.AddDays(1));
}
