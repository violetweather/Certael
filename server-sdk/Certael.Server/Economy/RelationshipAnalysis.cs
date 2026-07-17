using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Economy;

public enum RelationshipKind { Match, Outcome, Trade, Gift, Marketplace, Reward, Party }

public sealed record RelationshipEventV1(
    Guid EventId, string TenantId, string GameId, string EnvironmentId,
    RelationshipKind Kind, string SourceSubject, string TargetSubject,
    long Weight, DateTimeOffset OccurredAt);

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
    public static readonly int[] SupportedWindows = [7, 30, 90];

    public static IReadOnlyList<RelationshipFinding> Analyze(IEnumerable<RelationshipEventV1> source,
        DateTimeOffset asOf, RelationshipBaseline baseline)
    {
        RelationshipEventV1[] all = source.OrderBy(e => e.OccurredAt).ThenBy(e => e.EventId).ToArray();
        if (all.Length == 0) return [];
        string boundary = $"{all[0].TenantId}\0{all[0].GameId}\0{all[0].EnvironmentId}";
        if (all.Any(e => $"{e.TenantId}\0{e.GameId}\0{e.EnvironmentId}" != boundary))
            throw new EconomyEventException("Cross-boundary relationship analysis is prohibited.");
        var findings = new List<RelationshipFinding>();
        foreach (int days in SupportedWindows)
        {
            RelationshipEventV1[] edges = all.Where(e => e.OccurredAt > asOf.AddDays(-days)
                && e.OccurredAt <= asOf).ToArray();
            AddReciprocal(findings, edges, days, baseline);
            AddCycles(findings, edges, days, baseline);
            AddBeneficiaries(findings, edges, days, baseline);
            AddOpponentImbalance(findings, edges, days, baseline);
            AddCoordinated(findings, edges, days, baseline);
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
        foreach (RelationshipEventV1 first in transfers)
        foreach (RelationshipEventV1 second in transfers.Where(e => e.SourceSubject == first.TargetSubject))
        foreach (RelationshipEventV1 third in transfers.Where(e => e.SourceSubject == second.TargetSubject
                     && e.TargetSubject == first.SourceSubject))
            Add(output, "transfer-cycle", [first, second, third], days, baseline, "closed-edges>=3");
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
            long positive = exact.Count(e => e.Weight > 0);
            int percent = checked((int)(positive * 100 / exact.Length));
            if (percent >= baseline.OpponentImbalancePercent || percent <= 100 - baseline.OpponentImbalancePercent)
                Add(output, "opponent-imbalance", exact, days, baseline,
                    $"win-share>={baseline.OpponentImbalancePercent}%");
        }
    }

    private static void AddCoordinated(List<RelationshipFinding> output, RelationshipEventV1[] edges,
        int days, RelationshipBaseline baseline)
    {
        foreach (var party in edges.Where(e => e.Kind is RelationshipKind.Party or RelationshipKind.Match
                     or RelationshipKind.Reward).GroupBy(e => Pair(e.SourceSubject, e.TargetSubject)))
        {
            RelationshipEventV1[] exact = party.ToArray();
            if (exact.Length >= baseline.CoordinatedActivityCount)
                Add(output, "coordinated-farming-or-boosting", exact, days, baseline,
                    $"related-events>={baseline.CoordinatedActivityCount}");
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
                && exact.Sum(e => Math.Abs(e.Weight)) > 0)
                Add(output, "marketplace-manipulation", exact, days, baseline,
                    $"trades>={baseline.ReciprocalTransferCount}");
        }
    }

    private static void Add(List<RelationshipFinding> output, string rule,
        IEnumerable<RelationshipEventV1> exact, int days, RelationshipBaseline baseline, string threshold)
    {
        RelationshipEventV1[] stable = exact.DistinctBy(e => e.EventId).OrderBy(e => e.EventId).ToArray();
        if (stable.Length == 0 || output.Any(f => f.RuleId == rule && f.WindowDays == days
            && f.ExactEdges.Select(e => e.EventId).SequenceEqual(stable.Select(e => e.EventId)))) return;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (RelationshipEventV1 edge in stable)
            hash.AppendData(Encoding.UTF8.GetBytes($"{edge.EventId:N}|{edge.Kind}|{edge.SourceSubject}|{edge.TargetSubject}|{edge.Weight}|{edge.OccurredAt.ToUnixTimeMilliseconds()}\n"));
        output.Add(new RelationshipFinding(rule, RuleVersion, days, stable,
            baseline.Version, threshold, hash.GetHashAndReset()));
    }

    private static bool IsTransfer(RelationshipEventV1 edge) => edge.Kind is RelationshipKind.Trade
        or RelationshipKind.Gift or RelationshipKind.Marketplace;
    private static string Pair(string left, string right) => string.CompareOrdinal(left, right) <= 0
        ? $"{left}\0{right}" : $"{right}\0{left}";
}
