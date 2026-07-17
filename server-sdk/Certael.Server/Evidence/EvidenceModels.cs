using System.Collections.Immutable;

namespace Certael.Server.Evidence;

public enum SignalFamily
{
    AuthoritativeContradiction,
    ProtocolViolation,
    BuildIntegrity,
    RuntimeIntegrity,
    PlatformAttestation,
    BehavioralAnomaly,
    EconomyAnomaly,
    DeveloperReport
}

public enum FindingTrust { Authoritative, Corroborated, ClientOnly, Environmental }

public sealed record Finding(
    Guid FindingId,
    string TenantId,
    string GameId,
    string EnvironmentId,
    string SessionId,
    string PlayerSubject,
    string RuleId,
    string RuleVersion,
    byte[] RulePackDigest,
    Guid? ActionId,
    SignalFamily SignalFamily,
    FindingTrust Trust,
    int RiskContribution,
    double Confidence,
    DateTimeOffset ObservedAt,
    ImmutableArray<Certael.Server.Actions.EvidenceField> Fields);

public enum VerdictRecommendation
{
    Allow,
    Observe,
    IncreaseSampling,
    RestrictSession,
    RecommendKick,
    RecommendTemporarySuspension,
    RecommendManualReview
}

public sealed record Verdict(
    Guid VerdictId,
    string TenantId,
    string GameId,
    string EnvironmentId,
    string SessionId,
    string PlayerSubject,
    int RiskScore,
    double Confidence,
    VerdictRecommendation Recommendation,
    ImmutableArray<Guid> FindingIds,
    ImmutableArray<string> RuleVersions,
    DateTimeOffset CreatedAt);

public sealed record EvidenceBundle(
    Verdict Verdict,
    ImmutableArray<Finding> Findings,
    byte[] ReplayDigest,
    string SignedPolicyId = "legacy",
    string SignedPolicyVersion = "1");
