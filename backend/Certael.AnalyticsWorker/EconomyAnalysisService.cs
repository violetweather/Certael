using System.Security.Cryptography;
using System.Text;
using Certael.Persistence.Postgres;
using Certael.Server.Economy;
using Certael.Server.Evidence;
using Certael.Server.Cases;
using Certael.Server.Actions;
using System.Collections.Immutable;
using Microsoft.Extensions.Options;

namespace Certael.AnalyticsWorker;

/// <summary>Evaluates only signed, tenant-bound profiles after an economy event is durable.</summary>
public sealed class EconomyAnalysisService : IDisposable
{
    private readonly PostgresEconomyStore _store;
    private readonly ILogger<EconomyAnalysisService> _logger;
    private readonly IEvidenceStore _evidence;
    private readonly ICaseStore _cases;
    private readonly int _maximumEvents;
    private readonly Dictionary<string, ECDsa> _keys = new(StringComparer.Ordinal);

    public EconomyAnalysisService(PostgresEconomyStore store,
        IEvidenceStore evidence, ICaseStore cases,
        IOptions<AnalyticsWorkerOptions> options, ILogger<EconomyAnalysisService> logger)
    {
        _store = store;
        _logger = logger;
        _evidence = evidence;
        _cases = cases;
        _maximumEvents = options.Value.MaximumEconomyEventsPerWindow;
        foreach (EconomyProfileVerificationKeyOptions configured in options.Value.EconomyProfileKeys)
        {
            if (!ValidIdentifier(configured.KeyId) || _keys.ContainsKey(configured.KeyId))
                throw new InvalidOperationException("Economy profile verification key ID is invalid or duplicated.");
            try
            {
                byte[] encoded = Convert.FromBase64String(configured.PublicKeySpkiBase64);
                if (encoded.Length is < 64 or > 1024)
                    throw new InvalidOperationException("Economy profile public key size is invalid.");
                ECDsa key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(encoded, out int read);
                if (read != encoded.Length || key.KeySize != 256)
                {
                    key.Dispose();
                    throw new InvalidOperationException("Economy profile key must be a P-256 SPKI key.");
                }
                _keys.Add(configured.KeyId, key);
            }
            catch (Exception exception) when (exception is FormatException or CryptographicException)
            { throw new InvalidOperationException("Economy profile public key is invalid.", exception); }
        }
    }

    public async ValueTask AnalyzeAsync(EconomyEventV1 latest,
        CancellationToken cancellationToken)
    {
        if (_keys.Count == 0) return; // Feature remains disabled until an operator configures trust.
        IReadOnlyList<EconomyProfileDeployment> signedProfiles =
            await _store.LoadActiveProfilesAsync(latest.TenantId, latest.GameId,
                latest.EnvironmentId, cancellationToken);
        foreach (EconomyProfileDeployment deployment in signedProfiles)
        {
            SignedEconomyProtectionProfile signed = deployment.SignedProfile;
            EconomyProtectionProfile profile;
            try
            {
                profile = EconomyProtectionProfileSigner.Verify(signed, _keys, latest.OccurredAt);
                if (profile.TenantId != latest.TenantId || profile.GameId != latest.GameId
                    || profile.EnvironmentId != latest.EnvironmentId)
                    throw new EconomyEventException("Economy profile boundary does not match the event.");
            }
            catch (EconomyEventException exception)
            {
                _logger.LogError(exception,
                    "Ignored invalid signed economy profile {KeyId} for tenant {TenantId}.",
                    signed.KeyId, latest.TenantId);
                continue;
            }

            try
            {
                IReadOnlyList<EconomyEventV1> window = await _store.LoadPlayerWindowAsync(
                    latest.TenantId, latest.GameId, latest.EnvironmentId, latest.PlayerSubject,
                    latest.OccurredAt - profile.Window, latest.OccurredAt, _maximumEvents,
                    cancellationToken);
                IReadOnlyList<EconomyFinding> findings =
                    EconomyProtectionEvaluator.Evaluate(window, profile, deployment.Stage,
                        deployment.CanaryPercentage);
                if (findings.Count == 0) continue;
                await _store.SaveFindingsAsync(latest.TenantId, latest.GameId,
                    latest.EnvironmentId, findings, cancellationToken);
                EvidenceBundle bundle = BuildBundle(profile, signed.Digest, latest, findings);
                await _evidence.SaveAsync(bundle, cancellationToken);
                if (deployment.Stage != EconomyProfileStage.Shadow
                    && profile.Recommendation is not (VerdictRecommendation.Allow
                        or VerdictRecommendation.Observe))
                    await _cases.OpenOrUpdateAsync(bundle,
                        $"Economy review: {findings[0].RuleId}",
                        $"Signed economy profile produced {findings.Count} explainable finding(s).",
                        "certael-analytics-worker", TimeSpan.FromHours(24), cancellationToken);
            }
            catch (EconomyEventException exception)
            {
                _logger.LogError(exception,
                    "Economy profile {ProfileId} could not evaluate its bounded window.",
                    profile.ProfileId);
            }
        }
    }

    private static EvidenceBundle BuildBundle(EconomyProtectionProfile profile,
        byte[] profileDigest, EconomyEventV1 latest, IReadOnlyList<EconomyFinding> findings)
    {
        byte[] replayDigest = SHA256.HashData(profileDigest.Concat(findings
            .SelectMany(finding => finding.ReplayDigest)).ToArray());
        string sessionId = "economy-" + DigestText(latest.PlayerSubject)[..32];
        var normalized = findings.Select(finding =>
        {
            byte[] identity = SHA256.HashData(replayDigest.Concat(Encoding.UTF8.GetBytes(
                $"{finding.RuleId}\0{finding.ProfileId}\0{finding.ProfileVersion}" )).ToArray());
            var fields = new List<EvidenceField>
            {
                new("profile_id", finding.ProfileId, Provenance.CertaelDerived),
                new("profile_version", finding.ProfileVersion, Provenance.CertaelDerived),
                new("profile_stage", finding.ProfileStage.ToString(), Provenance.CertaelDerived),
                new("window_start", finding.WindowStart.ToString("O"), Provenance.CertaelDerived),
                new("window_end", finding.WindowEnd.ToString("O"), Provenance.CertaelDerived),
                new("event_ids", string.Join(',', finding.EventIds), Provenance.AuthoritativeState)
            };
            fields.AddRange(finding.AuthoritativeFields.OrderBy(value => value.Key,
                    StringComparer.Ordinal).Select(value => new EvidenceField(
                    "authoritative_" + value.Key, value.Value, Provenance.AuthoritativeState)));
            return new Finding(GuidFromDigest(identity), latest.TenantId, latest.GameId,
                latest.EnvironmentId, sessionId, latest.PlayerSubject, finding.RuleId,
                finding.RuleVersion, profileDigest, null, SignalFamily.EconomyAnomaly,
                FindingTrust.Authoritative, profile.FindingRisk,
                profile.ConfidenceBasisPoints / 10_000d, finding.WindowEnd,
                fields.ToImmutableArray());
        }).ToImmutableArray();
        byte[] verdictIdentity = SHA256.HashData(replayDigest.Concat(Encoding.UTF8.GetBytes(
            $"{profile.ProfileId}\0{profile.Version}\0{latest.PlayerSubject}")).ToArray());
        VerdictRecommendation effectiveRecommendation = findings[0].ProfileStage
            == EconomyProfileStage.Shadow ? VerdictRecommendation.Observe
            : profile.Recommendation;
        var verdict = new Verdict(GuidFromDigest(verdictIdentity), latest.TenantId,
            latest.GameId, latest.EnvironmentId, sessionId, latest.PlayerSubject,
            profile.FindingRisk, profile.ConfidenceBasisPoints / 10_000d,
            effectiveRecommendation, normalized.Select(value => value.FindingId).ToImmutableArray(),
            normalized.Select(value => $"{value.RuleId}@{value.RuleVersion}")
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray(),
            latest.OccurredAt);
        return new EvidenceBundle(verdict, normalized, replayDigest,
            "economy:" + profile.ProfileId, profile.Version);
    }

    private static Guid GuidFromDigest(ReadOnlySpan<byte> digest)
    {
        Span<byte> bytes = stackalloc byte[16];
        digest[..16].CopyTo(bytes);
        // RFC 4122 variant plus deterministic version 8 (application-defined hash UUID).
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x80);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes, bigEndian: true);
    }

    private static string DigestText(string value) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    public void Dispose()
    {
        foreach (ECDsa key in _keys.Values) key.Dispose();
        _keys.Clear();
    }

    private static bool ValidIdentifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-');
}
