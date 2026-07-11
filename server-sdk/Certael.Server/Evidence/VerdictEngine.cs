using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Evidence;

public sealed class VerdictEngine(TimeProvider timeProvider)
{
    public Verdict Evaluate(IReadOnlyCollection<Finding> findings)
    {
        if (findings.Count == 0) throw new ArgumentException("At least one finding is required.", nameof(findings));
        Finding first = findings.First();
        if (findings.Any(value => value.TenantId != first.TenantId || value.GameId != first.GameId
            || value.EnvironmentId != first.EnvironmentId || value.SessionId != first.SessionId
            || value.PlayerSubject != first.PlayerSubject))
            throw new ArgumentException("Verdict findings must share one security boundary.", nameof(findings));

        var familyScores = new Dictionary<SignalFamily, int>();
        foreach (Finding finding in findings)
        {
            int contribution = Math.Clamp(finding.RiskContribution, 0, 100);
            if (finding.Trust is FindingTrust.ClientOnly or FindingTrust.Environmental)
                contribution = Math.Min(contribution, 30);
            familyScores[finding.SignalFamily] = Math.Min(100,
                familyScores.GetValueOrDefault(finding.SignalFamily) + contribution);
        }

        int risk = Math.Min(100, familyScores.Values.Sum());
        int independentFamilies = familyScores.Count(value => value.Value > 0);
        bool authoritative = findings.Any(value => value.Trust == FindingTrust.Authoritative);
        bool onlyWeak = findings.All(value => value.Trust is FindingTrust.ClientOnly or FindingTrust.Environmental);
        VerdictRecommendation recommendation = Recommend(risk, independentFamilies, authoritative, onlyWeak);
        double confidence = Math.Clamp(findings.Average(value => value.Confidence), 0, 1);

        return new Verdict(Guid.NewGuid(), first.TenantId, first.GameId, first.EnvironmentId,
            first.SessionId, first.PlayerSubject, risk, confidence, recommendation,
            findings.Select(value => value.FindingId).Order().ToImmutableArray(),
            findings.Select(value => $"{value.RuleId}@{value.RuleVersion}")
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray(),
            timeProvider.GetUtcNow());
    }

    private static VerdictRecommendation Recommend(int risk, int independentFamilies,
        bool authoritative, bool onlyWeak)
    {
        if (onlyWeak) return risk switch
        {
            < 20 => VerdictRecommendation.Observe,
            < 50 => VerdictRecommendation.IncreaseSampling,
            _ => VerdictRecommendation.RecommendManualReview
        };
        if (risk >= 90 && authoritative && independentFamilies >= 2)
            return VerdictRecommendation.RecommendTemporarySuspension;
        if (risk >= 75 && independentFamilies >= 2) return VerdictRecommendation.RecommendKick;
        if (risk >= 50) return VerdictRecommendation.RestrictSession;
        if (risk >= 20) return VerdictRecommendation.IncreaseSampling;
        return VerdictRecommendation.Observe;
    }
}

public static class EvidenceReplay
{
    public static EvidenceBundle Create(Verdict verdict, IEnumerable<Finding> findings)
    {
        Finding[] ordered = findings.OrderBy(value => value.FindingId).ToArray();
        if (!verdict.FindingIds.SequenceEqual(ordered.Select(value => value.FindingId)))
            throw new InvalidOperationException("Evidence does not match the verdict finding set.");
        using var stream = new MemoryStream();
        foreach (Finding finding in ordered)
        {
            Write(stream, finding.FindingId.ToString("N"));
            Write(stream, finding.RuleId); Write(stream, finding.RuleVersion);
            stream.Write(finding.RulePackDigest);
            Write(stream, finding.RiskContribution.ToString(System.Globalization.CultureInfo.InvariantCulture));
            foreach (var field in finding.Fields.OrderBy(value => value.Name, StringComparer.Ordinal))
            {
                Write(stream, field.Name); Write(stream, field.Value); Write(stream, field.Provenance.ToString());
            }
        }
        return new EvidenceBundle(verdict, ordered.ToImmutableArray(), SHA256.HashData(stream.ToArray()));
    }

    public static bool Verify(EvidenceBundle bundle, VerdictEngine engine)
    {
        EvidenceBundle recreated;
        try { recreated = Create(bundle.Verdict, bundle.Findings); }
        catch (InvalidOperationException) { return false; }
        Verdict replayed = engine.Evaluate(bundle.Findings);
        return CryptographicOperations.FixedTimeEquals(recreated.ReplayDigest, bundle.ReplayDigest)
            && replayed.RiskScore == bundle.Verdict.RiskScore
            && replayed.Recommendation == bundle.Verdict.Recommendation
            && replayed.RuleVersions.SequenceEqual(bundle.Verdict.RuleVersions);
    }

    private static void Write(Stream stream, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
        stream.Write(length); stream.Write(bytes);
    }
}
