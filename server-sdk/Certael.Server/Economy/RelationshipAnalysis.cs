using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;

namespace Certael.Server.Economy;

public sealed record RelationshipBaseline(
    string Version, int ReciprocalTransferCount, int SharedBeneficiaryCount,
    int OpponentImbalancePercent, int CoordinatedActivityCount);

public sealed record RelationshipFinding(
    string RuleId, string RuleVersion, int WindowDays,
    IReadOnlyList<RelationshipEventV1> ExactEdges,
    string BaselineVersion, string Threshold, byte[] ReplayDigest);

public static class RelationshipAnalyzer
{
    public const string RuleVersion = "1.0.0";
    public const int MaximumFindings = 10_000;
    public static readonly int[] SupportedWindows = [7, 30, 90];

    public static IReadOnlyList<RelationshipFinding> Analyze(IEnumerable<RelationshipEventV1> source,
        DateTimeOffset asOf, RelationshipBaseline baseline, IReadOnlyList<int>? windows = null)
    {
        RelationshipEventV1[] all = source.OrderBy(e => e.OccurredAt).ThenBy(e => e.EventId).ToArray();
        if (all.Length == 0) return [];
        if (all.Length > 100_000)
            throw new EconomyEventException("Relationship analysis exceeds its event limit.");
        foreach (RelationshipEventV1 edge in all) RelationshipEventV1Codec.Validate(edge);
        foreach (IGrouping<Guid, RelationshipEventV1> duplicate in all.GroupBy(edge => edge.EventId))
            if (duplicate.Skip(1).Any(edge => !RelationshipEventV1Codec.Encode(edge)
                    .AsSpan().SequenceEqual(RelationshipEventV1Codec.Encode(duplicate.First()))))
                throw new EconomyEventException("Relationship event ID has conflicting content.");
        all = all.DistinctBy(edge => edge.EventId).ToArray();
        int[] selectedWindows = (windows ?? SupportedWindows).ToArray();
        if (selectedWindows.Length is < 1 or > 3 || selectedWindows.Distinct().Count() != selectedWindows.Length
            || selectedWindows.Any(window => window is not (7 or 30 or 90)))
            throw new EconomyEventException("Relationship analysis windows are invalid.");
        if (string.IsNullOrWhiteSpace(baseline.Version)
            || baseline.ReciprocalTransferCount < 2 || baseline.SharedBeneficiaryCount < 2
            || baseline.OpponentImbalancePercent is < 51 or > 100
            || baseline.CoordinatedActivityCount < 2)
            throw new EconomyEventException("Relationship baseline is invalid.");
        string boundary = $"{all[0].TenantId}\0{all[0].GameId}\0{all[0].EnvironmentId}";
        if (all.Any(e => $"{e.TenantId}\0{e.GameId}\0{e.EnvironmentId}" != boundary))
            throw new EconomyEventException("Cross-boundary relationship analysis is prohibited.");
        var findings = new List<RelationshipFinding>();
        foreach (int days in selectedWindows.Order())
        {
            RelationshipEventV1[] edges = all.Where(e => e.OccurredAt > asOf.AddDays(-days)
                && e.OccurredAt <= asOf).ToArray();
            AddReciprocal(findings, edges, days, baseline);
            AddCycles(findings, edges, days, baseline);
            AddBeneficiaries(findings, edges, days, baseline);
            AddOpponentImbalance(findings, edges, days, baseline);
            AddBoosting(findings, edges, days, baseline);
            AddWinTrading(findings, edges, days, baseline);
            AddCoordinatedFarming(findings, edges, days, baseline);
            AddMarketplace(findings, edges, days, baseline);
        }
        return findings.OrderBy(f => f.WindowDays).ThenBy(f => f.RuleId)
            .ThenBy(f => f.ExactEdges[0].EventId).ToArray();
    }

    private static void AddReciprocal(List<RelationshipFinding> output, RelationshipEventV1[] edges,
        int days, RelationshipBaseline baseline)
    {
        RelationshipEventV1[] transfers = edges.Where(IsTransfer).ToArray();
        foreach (var pair in transfers.GroupBy(e => Pair(e.SourceSubject, e.TargetSubject)))
        {
            RelationshipEventV1[] exact = pair.ToArray();
            if (exact.Length >= baseline.ReciprocalTransferCount
                && exact.Select(e => e.SourceSubject).Distinct().Count() > 1)
                Add(output, "reciprocal-transfer", exact, days, baseline,
                    $"count>={baseline.ReciprocalTransferCount}");
        }
    }

    private static void AddCycles(List<RelationshipFinding> output, RelationshipEventV1[] edges,
        int days, RelationshipBaseline baseline)
    {
        RelationshipEventV1[] transfers = edges.Where(IsTransfer).ToArray();
        Dictionary<string, Dictionary<string, RelationshipEventV1[]>> outgoing = transfers
            .GroupBy(edge => edge.SourceSubject, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group
                .GroupBy(edge => edge.TargetSubject, StringComparer.Ordinal)
                .ToDictionary(target => target.Key,
                    target => target.OrderBy(edge => edge.EventId).ToArray(),
                    StringComparer.Ordinal), StringComparer.Ordinal);
        foreach ((string firstSubject, Dictionary<string, RelationshipEventV1[]> firstTargets)
                 in outgoing.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        foreach ((string secondSubject, RelationshipEventV1[] firstEdges)
                 in firstTargets.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            // The lexicographically smallest subject owns each directed triangle.
            if (string.CompareOrdinal(firstSubject, secondSubject) >= 0
                || !outgoing.TryGetValue(secondSubject, out var secondTargets)) continue;
            foreach ((string thirdSubject, RelationshipEventV1[] secondEdges)
                     in secondTargets.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                if (thirdSubject == firstSubject || thirdSubject == secondSubject
                    || string.CompareOrdinal(firstSubject, thirdSubject) >= 0
                    || !outgoing.TryGetValue(thirdSubject, out var thirdTargets)
                    || !thirdTargets.TryGetValue(firstSubject, out RelationshipEventV1[]? thirdEdges))
                    continue;
                Add(output, "transfer-cycle", firstEdges.Concat(secondEdges).Concat(thirdEdges),
                    days, baseline, "closed-edges>=3");
                if (output.Count >= MaximumFindings) return;
            }
        }
    }

    private static void AddBeneficiaries(List<RelationshipFinding> output, RelationshipEventV1[] edges,
        int days, RelationshipBaseline baseline)
    {
        foreach (var target in edges.Where(IsTransfer).GroupBy(e => e.TargetSubject))
        {
            RelationshipEventV1[] exact = target.ToArray();
            if (exact.Select(e => e.SourceSubject).Distinct().Count() >= baseline.SharedBeneficiaryCount)
                Add(output, "shared-beneficiary", exact, days, baseline,
                    $"distinct-sources>={baseline.SharedBeneficiaryCount}");
        }
    }

    private static void AddOpponentImbalance(List<RelationshipFinding> output, RelationshipEventV1[] edges,
        int days, RelationshipBaseline baseline)
    {
        foreach (var pair in edges.Where(e => e.Kind == RelationshipKind.Outcome)
                     .GroupBy(e => Pair(e.SourceSubject, e.TargetSubject)))
        {
            RelationshipEventV1[] exact = pair.ToArray();
            if (exact.Length < 3) continue;
            int dominantWins = exact.GroupBy(Winner).Max(group => group.Count());
            int percent = checked(dominantWins * 100 / exact.Length);
            if (percent >= baseline.OpponentImbalancePercent)
                Add(output, "opponent-imbalance", exact, days, baseline,
                    $"win-share>={baseline.OpponentImbalancePercent}%");
        }
    }

    private static void AddBoosting(List<RelationshipFinding> output,
        RelationshipEventV1[] edges, int days, RelationshipBaseline baseline)
    {
        foreach (var pair in edges.GroupBy(e => Pair(e.SourceSubject, e.TargetSubject)))
        {
            RelationshipEventV1[] exact = pair.ToArray();
            RelationshipEventV1[] outcomes = exact.Where(e => e.Kind == RelationshipKind.Outcome).ToArray();
            bool sharedPlay = exact.Any(e => e.Kind is RelationshipKind.Match or RelationshipKind.Party);
            if (outcomes.Length < baseline.CoordinatedActivityCount || !sharedPlay) continue;
            int dominantWins = outcomes.GroupBy(Winner).Max(group => group.Count());
            int percent = checked(dominantWins * 100 / outcomes.Length);
            if (percent >= baseline.OpponentImbalancePercent)
                Add(output, "boosting", exact, days, baseline,
                    $"shared-play-and-win-share>={baseline.OpponentImbalancePercent}%");
        }
    }

    private static void AddWinTrading(List<RelationshipFinding> output,
        RelationshipEventV1[] edges, int days, RelationshipBaseline baseline)
    {
        foreach (var pair in edges.GroupBy(e => Pair(e.SourceSubject, e.TargetSubject)))
        {
            RelationshipEventV1[] exact = pair.ToArray();
            RelationshipEventV1[] outcomes = exact.Where(e => e.Kind == RelationshipKind.Outcome).ToArray();
            bool exchangedValue = exact.Any(e => IsTransfer(e) || e.Kind == RelationshipKind.Reward);
            if (outcomes.Length >= baseline.CoordinatedActivityCount && exchangedValue
                && outcomes.Select(Winner).Distinct(StringComparer.Ordinal).Count() > 1)
                Add(output, "win-trading", exact, days, baseline,
                    $"opposing-winners>1-and-outcomes>={baseline.CoordinatedActivityCount}-with-value-edge");
        }
    }

    private static void AddCoordinatedFarming(List<RelationshipFinding> output,
        RelationshipEventV1[] edges,
        int days, RelationshipBaseline baseline)
    {
        foreach (var party in edges.Where(e => e.Kind is RelationshipKind.Party or RelationshipKind.Match
                     or RelationshipKind.Reward).GroupBy(e => Pair(e.SourceSubject, e.TargetSubject)))
        {
            RelationshipEventV1[] exact = party.ToArray();
            if (exact.Length >= baseline.CoordinatedActivityCount
                && exact.Select(edge => edge.Kind).Distinct().Count() > 1)
                Add(output, "coordinated-farming", exact, days, baseline,
                    $"multi-kind-related-events>={baseline.CoordinatedActivityCount}");
        }
    }

    private static void AddMarketplace(List<RelationshipFinding> output, RelationshipEventV1[] edges,
        int days, RelationshipBaseline baseline)
    {
        foreach (var pair in edges.Where(e => e.Kind == RelationshipKind.Marketplace)
                     .GroupBy(e => Pair(e.SourceSubject, e.TargetSubject)))
        {
            RelationshipEventV1[] exact = pair.ToArray();
            if (exact.Length >= baseline.ReciprocalTransferCount
                && exact.Any(e => e.Weight != 0))
                Add(output, "marketplace-manipulation", exact, days, baseline,
                    $"trades>={baseline.ReciprocalTransferCount}");
        }
    }

    private static void Add(List<RelationshipFinding> output, string rule,
        IEnumerable<RelationshipEventV1> exact, int days, RelationshipBaseline baseline, string threshold)
    {
        if (output.Count >= MaximumFindings) return;
        RelationshipEventV1[] stable = exact.DistinctBy(e => e.EventId).OrderBy(e => e.EventId).ToArray();
        if (stable.Length == 0 || output.Any(f => f.RuleId == rule && f.WindowDays == days
            && f.ExactEdges.Select(e => e.EventId).SequenceEqual(stable.Select(e => e.EventId)))) return;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(
            $"{rule}\0{RuleVersion}\0{days}\0{baseline.Version}\0{threshold}\n"));
        Span<byte> length = stackalloc byte[4];
        foreach (RelationshipEventV1 edge in stable)
        {
            byte[] canonical = RelationshipEventV1Codec.Encode(edge);
            BinaryPrimitives.WriteInt32BigEndian(length, canonical.Length);
            hash.AppendData(length); hash.AppendData(canonical);
        }
        output.Add(new RelationshipFinding(rule, RuleVersion, days, stable,
            baseline.Version, threshold, hash.GetHashAndReset()));
    }

    private static bool IsTransfer(RelationshipEventV1 edge) => edge.Kind is RelationshipKind.Trade
        or RelationshipKind.Gift or RelationshipKind.Marketplace;
    private static string Winner(RelationshipEventV1 edge) => edge.Weight > 0
        ? edge.SourceSubject : edge.TargetSubject;
    private static string Pair(string left, string right) => string.CompareOrdinal(left, right) <= 0
        ? $"{left}\0{right}" : $"{right}\0{left}";
}
