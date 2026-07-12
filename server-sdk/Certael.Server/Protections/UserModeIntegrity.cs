using System.Collections.Immutable;
using System.Security.Cryptography;
using Certael.Server.Actions;
using Certael.Server.Evidence;

namespace Certael.Server.Protections;

public sealed record ProtectedBuildFile(string Path, long Size, byte[] Sha256);
public sealed record ProtectedBuildManifest(string BuildId, ImmutableArray<ProtectedBuildFile> Files);
public sealed record UserModeIntegrityReport(
    string BuildId, byte[] Challenge, ImmutableArray<ProtectedBuildFile> Files,
    ImmutableArray<string> LoadedModuleNames, bool DebuggerObserved, DateTimeOffset ObservedAt);

public sealed class UserModeIntegrityVerifier
{
    public IReadOnlyList<Finding> Evaluate(UserModeIntegrityReport report,
        ReadOnlyMemory<byte> expectedChallenge,
        ProtectedBuildManifest expected, string tenantId, string gameId, string environmentId,
        string sessionId, string playerSubject, byte[] rulePackDigest, DateTimeOffset serverNow)
    {
        if (report.Challenge.Length < 16 || report.Challenge.Length > 256
            || expectedChallenge.Length is < 16 or > 256)
            throw new ArgumentException("Integrity challenge is invalid.", nameof(report));
        var reasons = new List<string>();
        if (!CryptographicOperations.FixedTimeEquals(report.Challenge, expectedChallenge.Span))
            reasons.Add("INTEGRITY_CHALLENGE_MISMATCH");
        if (!string.Equals(report.BuildId, expected.BuildId, StringComparison.Ordinal)) reasons.Add("BUILD_ID_MISMATCH");
        if (Math.Abs((serverNow - report.ObservedAt).TotalMinutes) > 5) reasons.Add("STALE_INTEGRITY_REPORT");
        var actual = new Dictionary<string, ProtectedBuildFile>(StringComparer.Ordinal);
        foreach (ProtectedBuildFile file in report.Files)
        {
            if (string.IsNullOrWhiteSpace(file.Path) || file.Path.Length > 512
                || file.Size < 0 || file.Sha256.Length != 32 || !actual.TryAdd(file.Path, file))
                reasons.Add("INVALID_BUILD_REPORT");
        }
        if (report.LoadedModuleNames.Length > 1024
            || report.LoadedModuleNames.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 512))
            reasons.Add("INVALID_MODULE_REPORT");
        foreach (ProtectedBuildFile file in expected.Files)
        {
            if (!actual.TryGetValue(file.Path, out ProtectedBuildFile? found)
                || found.Size != file.Size
                || !CryptographicOperations.FixedTimeEquals(found.Sha256, file.Sha256))
                reasons.Add("BUILD_FILE_MISMATCH");
        }
        if (report.DebuggerObserved) reasons.Add("DEBUGGER_OBSERVED");
        if (reasons.Count == 0) return [];

        return [new Finding(Guid.NewGuid(), tenantId, gameId, environmentId, sessionId,
            playerSubject, "integrity.user_mode", "1.0.0", rulePackDigest, null,
            SignalFamily.RuntimeIntegrity, FindingTrust.ClientOnly, Math.Min(30, reasons.Count * 10),
            0.5, serverNow, reasons.Distinct(StringComparer.Ordinal).Select(reason =>
                new EvidenceField("integrity_reason", reason, Provenance.ClientTelemetry)).ToImmutableArray())];
    }
}

public interface IPlatformAttestationVerifier
{
    ValueTask<bool> VerifyAsync(string platform, ReadOnlyMemory<byte> statement,
        ReadOnlyMemory<byte> expectedNonce, CancellationToken cancellationToken);
}

public sealed class PlatformAttestationService(IPlatformAttestationVerifier verifier, TimeProvider timeProvider)
{
    public async ValueTask<Finding?> EvaluateAsync(string platform, ReadOnlyMemory<byte> statement,
        ReadOnlyMemory<byte> expectedNonce, string tenantId, string gameId, string environmentId,
        string sessionId, string playerSubject, byte[] rulePackDigest,
        CancellationToken cancellationToken)
    {
        if (expectedNonce.Length < 16 || expectedNonce.Length > 256)
            throw new ArgumentException("Attestation nonce is invalid.", nameof(expectedNonce));
        if (await verifier.VerifyAsync(platform, statement, expectedNonce, cancellationToken)) return null;
        return new Finding(Guid.NewGuid(), tenantId, gameId, environmentId, sessionId, playerSubject,
            "attestation.platform", "1.0.0", rulePackDigest, null,
            SignalFamily.PlatformAttestation, FindingTrust.Environmental, 30, 0.7,
            timeProvider.GetUtcNow(), ImmutableArray.Create(
                new EvidenceField("platform", platform, Provenance.ClientTelemetry),
                new EvidenceField("attestation", "INVALID", Provenance.CertaelDerived)));
    }
}
