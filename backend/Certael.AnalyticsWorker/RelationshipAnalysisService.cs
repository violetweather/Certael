using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Certael.Persistence.Postgres;
using Certael.Server.Actions;
using Certael.Server.Cases;
using Certael.Server.Economy;
using Certael.Server.Evidence;
using Microsoft.Extensions.Options;

namespace Certael.AnalyticsWorker;

/// <summary>Runs deterministic graph rules only under signed, staged profiles.</summary>
public sealed class RelationshipAnalysisService : IDisposable
{
    private readonly PostgresRelationshipStore _store;
    private readonly IEvidenceStore _evidence;
    private readonly ICaseStore _cases;
    private readonly ILogger<RelationshipAnalysisService> _logger;
    private readonly int _maximumEvents;
    private readonly int _maximumFindings;
    private readonly Dictionary<string, ECDsa> _keys = new(StringComparer.Ordinal);

    public RelationshipAnalysisService(PostgresRelationshipStore store,
        IEvidenceStore evidence, ICaseStore cases, IOptions<AnalyticsWorkerOptions> options,
        ILogger<RelationshipAnalysisService> logger)
    {
        _store = store; _evidence = evidence; _cases = cases; _logger = logger;
        _maximumEvents = options.Value.MaximumRelationshipEventsPerWindow;
        _maximumFindings = options.Value.MaximumRelationshipFindingsPerEvent;
        foreach (EconomyProfileVerificationKeyOptions configured
                 in options.Value.RelationshipProfileKeys)
        {
            if (!ValidIdentifier(configured.KeyId) || _keys.ContainsKey(configured.KeyId))
                throw new InvalidOperationException(
                    "Relationship profile verification key ID is invalid or duplicated.");
            try
            {
                byte[] encoded = Convert.FromBase64String(configured.PublicKeySpkiBase64);
                if (encoded.Length is < 64 or > 1024)
                    throw new InvalidOperationException(
                        "Relationship profile public key size is invalid.");
                ECDsa key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(encoded, out int read);
                if (read != encoded.Length || key.KeySize != 256)
                { key.Dispose(); throw new InvalidOperationException(
                    "Relationship profile key must be a P-256 SPKI key."); }
                _keys.Add(configured.KeyId, key);
            }
            catch (Exception exception) when (exception is FormatException
                or CryptographicException)
            { throw new InvalidOperationException(
                "Relationship profile public key is invalid.", exception); }
        }
    }

    public async ValueTask AnalyzeAsync(RelationshipEventV1 latest,
        CancellationToken cancellationToken)
    {
        if (_keys.Count == 0) return;
        IReadOnlyList<RelationshipProfileDeployment> deployments =
            await _store.LoadActiveProfilesAsync(latest.TenantId, latest.GameId,
                latest.EnvironmentId, cancellationToken);
        foreach (RelationshipProfileDeployment deployment in deployments)
        {
            SignedRelationshipProtectionProfile signed = deployment.SignedProfile;
            RelationshipProtectionProfile profile;
            try
            {
                profile = RelationshipProtectionProfileSigner.Verify(signed, _keys,
                    latest.OccurredAt);
                if (profile.TenantId != latest.TenantId || profile.GameId != latest.GameId
                    || profile.EnvironmentId != latest.EnvironmentId)
                    throw new EconomyEventException(
                        "Relationship profile boundary does not match the event.");
                if (deployment.Stage == EconomyProfileStage.Canary
                    && !CanarySelected(profile, latest, deployment.CanaryPercentage))
                    continue;
            }
            catch (EconomyEventException exception)
            {
                _logger.LogError(exception,
                    "Ignored invalid signed relationship profile {KeyId} for tenant {TenantId}.",
                    signed.KeyId, latest.TenantId);
                continue;
            }

            try
            {
                int longestWindow = profile.Windows.Max();
                IReadOnlyList<RelationshipEventV1> window = await _store.LoadWindowAsync(
                    latest.TenantId, latest.GameId, latest.EnvironmentId,
                    latest.OccurredAt.AddDays(-longestWindow), latest.OccurredAt,
                    _maximumEvents, cancellationToken);
                var baseline = new RelationshipBaseline(profile.Version,
                    profile.ReciprocalTransferCount, profile.SharedBeneficiaryCount,
                    profile.OpponentImbalancePercent, profile.CoordinatedActivityCount);
                IReadOnlyList<RelationshipFinding> all = RelationshipAnalyzer.Analyze(window,
                    latest.OccurredAt, baseline, profile.Windows);
                if (all.Count == 0) continue;
                RelationshipFinding[] findings = all.Take(_maximumFindings).ToArray();
                if (all.Count > findings.Length)
                    _logger.LogWarning(
                        "Relationship profile {ProfileId} produced {Count} findings; persisted bounded first {Limit}.",
                        profile.ProfileId, all.Count, findings.Length);
                await _store.SaveFindingsAsync(latest.TenantId, latest.GameId,
                    latest.EnvironmentId, findings.Select(finding =>
                        new PersistedRelationshipFinding(profile.ProfileId, profile.Version,
                            deployment.Stage, finding)), cancellationToken);
                EvidenceBundle bundle = BuildBundle(profile, signed.Digest, deployment.Stage,
                    latest, findings);
                await _evidence.SaveAsync(bundle, cancellationToken);
                if (deployment.Stage != EconomyProfileStage.Shadow
                    && profile.Recommendation is not (VerdictRecommendation.Allow
                        or VerdictRecommendation.Observe))
                    await _cases.OpenOrUpdateAsync(bundle,
                        $"Relationship review: {findings[0].RuleId}",
                        $"Signed relationship profile produced {findings.Length} explainable finding(s).",
                        "certael-analytics-worker", TimeSpan.FromHours(24), cancellationToken);
            }
            catch (EconomyEventException exception)
            {
                _logger.LogError(exception,
                    "Relationship profile {ProfileId} could not evaluate its bounded window.",
                    profile.ProfileId);
            }
        }
    }

    private static EvidenceBundle BuildBundle(RelationshipProtectionProfile profile,
        byte[] profileDigest, EconomyProfileStage stage, RelationshipEventV1 latest,
        IReadOnlyList<RelationshipFinding> findings)
    {
        byte[] replayDigest = SHA256.HashData(profileDigest.Concat(findings
            .SelectMany(finding => finding.ReplayDigest)).ToArray());
        string sessionId = "relationship-" + DigestText(
            latest.SourceSubject + "\0" + latest.TargetSubject)[..32];
        ImmutableArray<Finding> normalized = findings.Select(finding =>
        {
            byte[] identity = SHA256.HashData(replayDigest.Concat(Encoding.UTF8.GetBytes(
                $"{profile.ProfileId}\0{profile.Version}\0{stage}\0{finding.RuleId}\0{finding.WindowDays}"))
                .ToArray());
            var fields = new List<EvidenceField>
            {
                new("profile_id", profile.ProfileId, Provenance.CertaelDerived),
                new("profile_version", profile.Version, Provenance.CertaelDerived),
                new("profile_stage", stage.ToString(), Provenance.CertaelDerived),
                new("window_days", finding.WindowDays.ToString(), Provenance.CertaelDerived),
                new("baseline_version", finding.BaselineVersion, Provenance.CertaelDerived),
                new("threshold", finding.Threshold, Provenance.CertaelDerived),
                new("event_ids", string.Join(',', finding.ExactEdges.Select(edge => edge.EventId)),
                    Provenance.AuthoritativeState),
                new("exact_edges", string.Join(';', finding.ExactEdges.Select(edge =>
                    $"{edge.EventId:N}|{edge.Kind}|{edge.SourceSubject}|{edge.TargetSubject}|{edge.Weight}|{edge.OccurredAt:O}")),
                    Provenance.AuthoritativeState)
            };
            return new Finding(GuidFromDigest(identity), latest.TenantId, latest.GameId,
                latest.EnvironmentId, sessionId, latest.SourceSubject, finding.RuleId,
                finding.RuleVersion, profileDigest, latest.AuthoritativeActionId,
                SignalFamily.EconomyAnomaly, FindingTrust.Authoritative,
                profile.FindingRisk, profile.ConfidenceBasisPoints / 10_000d,
                latest.OccurredAt, fields.ToImmutableArray());
        }).ToImmutableArray();
        byte[] verdictIdentity = SHA256.HashData(replayDigest.Concat(Encoding.UTF8.GetBytes(
            $"{profile.ProfileId}\0{profile.Version}\0{latest.EventId}" )).ToArray());
        VerdictRecommendation effectiveRecommendation = stage == EconomyProfileStage.Shadow
            ? VerdictRecommendation.Observe : profile.Recommendation;
        var verdict = new Verdict(GuidFromDigest(verdictIdentity), latest.TenantId,
            latest.GameId, latest.EnvironmentId, sessionId, latest.SourceSubject,
            profile.FindingRisk, profile.ConfidenceBasisPoints / 10_000d,
            effectiveRecommendation, normalized.Select(value => value.FindingId).ToImmutableArray(),
            normalized.Select(value => $"{value.RuleId}@{value.RuleVersion}")
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray(),
            latest.OccurredAt);
        return new EvidenceBundle(verdict, normalized, replayDigest,
            "relationship:" + profile.ProfileId, profile.Version);
    }

    private static bool CanarySelected(RelationshipProtectionProfile profile,
        RelationshipEventV1 latest, int percentage)
    {
        EconomyProfileDeploymentValidation.Validate(EconomyProfileStage.Canary, percentage);
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{profile.ProfileId}\0{profile.Version}\0{latest.SourceSubject}\0{latest.TargetSubject}"));
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(digest) % 100 < percentage;
    }

    private static Guid GuidFromDigest(ReadOnlySpan<byte> digest)
    {
        Span<byte> bytes = stackalloc byte[16]; digest[..16].CopyTo(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x80);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes, bigEndian: true);
    }

    private static string DigestText(string value) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static bool ValidIdentifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-');

    public void Dispose()
    {
        foreach (ECDsa key in _keys.Values) key.Dispose();
        _keys.Clear();
    }
}
