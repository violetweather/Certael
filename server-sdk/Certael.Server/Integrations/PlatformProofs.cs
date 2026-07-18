using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Certael.Server.Integrations;

public enum PlatformProofKind { Identity, Attestation }
public enum PlatformProofTrust { Unavailable, Advisory, Verified }

public sealed record PlatformProofRequest(string Provider, string ApplicationId,
    string ExpectedSubject, byte[] Assertion, byte[] Nonce, DateTimeOffset IssuedAt);
public sealed record NormalizedPlatformProof(PlatformProofKind Kind, string Provider,
    string Subject, string ApplicationId, DateTimeOffset IssuedAt, DateTimeOffset VerifiedAt,
    byte[] NonceDigest, byte[] ClaimsDigest, PlatformProofTrust Trust, string PublicReason);

public interface IPlatformIdentityVerifier
{
    string Provider { get; }
    ValueTask<NormalizedPlatformProof> VerifyIdentityAsync(PlatformProofRequest request,
        CancellationToken cancellationToken = default);
}

public interface IPlatformAttestationVerifier
{
    string Provider { get; }
    ValueTask<NormalizedPlatformProof> VerifyAttestationAsync(PlatformProofRequest request,
        CancellationToken cancellationToken = default);
}

public enum PlatformProofRequirement { Optional, Required }
public sealed record PlatformProofPolicy(string Provider, PlatformProofKind Kind,
    PlatformProofRequirement Requirement, TimeSpan MaximumAge, string ApplicationId = "");
public sealed record PlatformProofEvaluation(string PublicReason,
    NormalizedPlatformProof? Proof, bool RequirementSatisfied);

public interface IPlatformProofReplayStore
{
    ValueTask<bool> TryReserveAsync(string replayKey, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}

public sealed class InMemoryPlatformProofReplayStore(TimeProvider clock)
    : IPlatformProofReplayStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries =
        new(StringComparer.Ordinal);

    public ValueTask<bool> TryReserveAsync(string replayKey, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(replayKey) || replayKey.Length > 512
            || expiresAt <= clock.GetUtcNow()) return ValueTask.FromResult(false);
        foreach ((string key, DateTimeOffset expiry) in _entries)
            if (expiry <= clock.GetUtcNow()) _entries.TryRemove(key, out _);
        return ValueTask.FromResult(_entries.TryAdd(replayKey, expiresAt));
    }
}

public sealed class PlatformProofService
{
    private readonly IReadOnlyDictionary<string, IPlatformIdentityVerifier> _identity;
    private readonly IReadOnlyDictionary<string, IPlatformAttestationVerifier> _attestation;
    private readonly IPlatformProofReplayStore _replay;
    private readonly TimeProvider _clock;

    public PlatformProofService(IEnumerable<IPlatformIdentityVerifier> identity,
        IEnumerable<IPlatformAttestationVerifier> attestation,
        IPlatformProofReplayStore replay, TimeProvider clock)
    {
        _identity = Unique(identity, verifier => verifier.Provider);
        _attestation = Unique(attestation, verifier => verifier.Provider);
        _replay = replay; _clock = clock;
    }

    public async ValueTask<PlatformProofEvaluation> VerifyAsync(PlatformProofPolicy policy,
        PlatformProofRequest request, CancellationToken cancellationToken = default)
    {
        ValidatePolicy(policy);
        if (!Identifier(request.Provider) || !Identifier(request.ApplicationId)
            || !Identifier(request.ExpectedSubject) || request.Provider != policy.Provider
            || (!string.IsNullOrEmpty(policy.ApplicationId)
                && request.ApplicationId != policy.ApplicationId)
            || request.Assertion is null or { Length: < 1 or > 1024 * 1024 }
            || request.Nonce is null or { Length: not 32 })
            return new("PLATFORM_PROOF_REQUEST_INVALID", null, false);
        NormalizedPlatformProof? proof;
        try
        {
            proof = policy.Kind switch
            {
                PlatformProofKind.Identity when _identity.TryGetValue(policy.Provider,
                    out IPlatformIdentityVerifier? verifier) =>
                    await verifier.VerifyIdentityAsync(request, cancellationToken),
                PlatformProofKind.Attestation when _attestation.TryGetValue(policy.Provider,
                    out IPlatformAttestationVerifier? verifier) =>
                    await verifier.VerifyAttestationAsync(request, cancellationToken),
                _ => null
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        { throw; }
        catch (Exception)
        { proof = null; }
        string result = PlatformProofPolicyEvaluator.Evaluate(policy, request, proof,
            _clock.GetUtcNow());
        if (result != "VERIFIED" || proof is null)
            return new(result, proof, policy.Requirement == PlatformProofRequirement.Optional
                && result == "OPTIONAL_PROOF_UNAVAILABLE");
        if (proof.Kind == PlatformProofKind.Attestation)
        {
            string replayKey = string.Join(':', proof.Provider, proof.ApplicationId,
                proof.Subject, Convert.ToHexString(proof.NonceDigest));
            if (!await _replay.TryReserveAsync(replayKey,
                    proof.IssuedAt + policy.MaximumAge, cancellationToken))
                return new("PLATFORM_PROOF_REPLAY", proof, false);
        }
        return new("VERIFIED", proof, true);
    }

    private static IReadOnlyDictionary<string, T> Unique<T>(IEnumerable<T> values,
        Func<T, string> provider)
    {
        var result = new Dictionary<string, T>(StringComparer.Ordinal);
        foreach (T value in values)
        {
            string key = provider(value);
            if (!Identifier(key) || !result.TryAdd(key, value))
                throw new PlatformProofException("Platform proof providers are invalid or duplicated.");
        }
        return result;
    }

    internal static void ValidatePolicy(PlatformProofPolicy policy)
    {
        if (!Identifier(policy.Provider) || !Enum.IsDefined(policy.Kind)
            || !Enum.IsDefined(policy.Requirement) || policy.MaximumAge <= TimeSpan.Zero
            || policy.MaximumAge > TimeSpan.FromMinutes(10)
            || (!string.IsNullOrEmpty(policy.ApplicationId)
                && !Identifier(policy.ApplicationId)))
            throw new PlatformProofException("Platform proof policy is invalid.");
    }

    internal static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
}

public static class PlatformProofPolicyEvaluator
{
    public static string Evaluate(PlatformProofPolicy policy, NormalizedPlatformProof? proof,
        DateTimeOffset now)
    {
        PlatformProofService.ValidatePolicy(policy);
        if (proof is null || proof.Trust == PlatformProofTrust.Unavailable)
            return policy.Requirement == PlatformProofRequirement.Required
                ? "PLATFORM_PROOF_REQUIRED" : "OPTIONAL_PROOF_UNAVAILABLE";
        if (proof.Kind != policy.Kind || proof.Provider != policy.Provider)
            return "PLATFORM_PROOF_CLASSIFICATION_MISMATCH";
        if (!string.IsNullOrEmpty(policy.ApplicationId)
            && proof.ApplicationId != policy.ApplicationId)
            return "PLATFORM_PROOF_APPLICATION_MISMATCH";
        if (now - proof.IssuedAt > policy.MaximumAge || proof.IssuedAt > now
            || proof.VerifiedAt < proof.IssuedAt || proof.VerifiedAt > now)
            return "PLATFORM_PROOF_STALE";
        if (proof.ClaimsDigest is not { Length: 32 }
            || !PlatformProofService.Identifier(proof.Subject)
            || !PlatformProofService.Identifier(proof.ApplicationId)
            || !PlatformProofService.Identifier(proof.PublicReason))
            return "PLATFORM_PROOF_MALFORMED";
        if (proof.Kind == PlatformProofKind.Identity && proof.NonceDigest.Length != 0
            || proof.Kind == PlatformProofKind.Attestation && proof.NonceDigest.Length != 32)
            return "PLATFORM_PROOF_CLASSIFICATION_MISMATCH";
        return proof.Trust == PlatformProofTrust.Verified ? "VERIFIED" : "ADVISORY";
    }

    public static string Evaluate(PlatformProofPolicy policy, PlatformProofRequest request,
        NormalizedPlatformProof? proof, DateTimeOffset now)
    {
        string result = Evaluate(policy, proof, now);
        if (result is not ("VERIFIED" or "ADVISORY") || proof is null) return result;
        if (proof.Subject != request.ExpectedSubject
            || proof.ApplicationId != request.ApplicationId
            || proof.IssuedAt != request.IssuedAt)
            return "PLATFORM_PROOF_BINDING_MISMATCH";
        if (proof.Kind == PlatformProofKind.Attestation
            && !CryptographicOperations.FixedTimeEquals(proof.NonceDigest,
                SHA256.HashData(request.Nonce)))
            return "PLATFORM_PROOF_NONCE_MISMATCH";
        return result;
    }
}

public sealed record PlatformProofPolicyProfile(string PolicyId, string Version,
    string TenantId, string GameId, string EnvironmentId, string Provider,
    PlatformProofKind Kind, PlatformProofRequirement Requirement, string ApplicationId,
    int MaximumAgeSeconds, DateTimeOffset ExpiresAt);
public sealed record SignedPlatformProofPolicy(byte[] CanonicalPolicy, byte[] Signature,
    string KeyId, byte[] Digest);

public sealed class PlatformProofPolicySigner(ECDsa key, string keyId)
{
    private static readonly JsonSerializerOptions CanonicalJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public SignedPlatformProofPolicy Sign(PlatformProofPolicyProfile profile)
    {
        Validate(profile);
        if (key.KeySize != 256 || !PlatformProofService.Identifier(keyId))
            throw new PlatformProofException("Platform proof signing key is invalid.");
        byte[] canonical = JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson);
        return new(canonical, key.SignData(canonical, HashAlgorithmName.SHA256), keyId,
            SHA256.HashData(canonical));
    }

    public static PlatformProofPolicyProfile Verify(SignedPlatformProofPolicy signed,
        IReadOnlyDictionary<string, ECDsa> keys, DateTimeOffset now)
    {
        if (signed.CanonicalPolicy is null or { Length: < 1 or > 64 * 1024 }
            || signed.Signature is null or { Length: < 64 or > 512 }
            || signed.Digest is not { Length: 32 }
            || !PlatformProofService.Identifier(signed.KeyId)
            || !keys.TryGetValue(signed.KeyId, out ECDsa? key) || key.KeySize != 256
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(signed.CanonicalPolicy), signed.Digest)
            || !key.VerifyData(signed.CanonicalPolicy, signed.Signature,
                HashAlgorithmName.SHA256))
            throw new PlatformProofException("Platform proof policy signature is invalid.");
        PlatformProofPolicyProfile profile;
        try
        {
            profile = JsonSerializer.Deserialize<PlatformProofPolicyProfile>(
                signed.CanonicalPolicy, CanonicalJson)
                ?? throw new PlatformProofException("Platform proof policy is malformed.");
        }
        catch (JsonException exception)
        { throw new PlatformProofException("Platform proof policy is malformed.", exception); }
        Validate(profile);
        if (profile.ExpiresAt <= now
            || !CryptographicOperations.FixedTimeEquals(signed.CanonicalPolicy,
                JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson)))
            throw new PlatformProofException("Platform proof policy is expired or noncanonical.");
        return profile;
    }

    public static PlatformProofPolicyProfile DecodeCanonical(ReadOnlySpan<byte> canonical)
    {
        if (canonical.IsEmpty || canonical.Length > 64 * 1024)
            throw new PlatformProofException("Platform proof policy size is invalid.");
        PlatformProofPolicyProfile profile;
        try
        {
            profile = JsonSerializer.Deserialize<PlatformProofPolicyProfile>(canonical,
                CanonicalJson) ?? throw new PlatformProofException(
                    "Platform proof policy is malformed.");
        }
        catch (JsonException exception)
        { throw new PlatformProofException("Platform proof policy is malformed.", exception); }
        Validate(profile);
        if (!CryptographicOperations.FixedTimeEquals(canonical,
                JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson)))
            throw new PlatformProofException("Platform proof policy is noncanonical.");
        return profile;
    }

    public static PlatformProofPolicy ToPolicy(PlatformProofPolicyProfile profile) =>
        new(profile.Provider, profile.Kind, profile.Requirement,
            TimeSpan.FromSeconds(profile.MaximumAgeSeconds), profile.ApplicationId);

    private static void Validate(PlatformProofPolicyProfile profile)
    {
        if (!PlatformProofService.Identifier(profile.PolicyId)
            || !PlatformProofService.Identifier(profile.Version)
            || !PlatformProofService.Identifier(profile.TenantId)
            || !PlatformProofService.Identifier(profile.GameId)
            || !PlatformProofService.Identifier(profile.EnvironmentId)
            || !PlatformProofService.Identifier(profile.Provider)
            || !PlatformProofService.Identifier(profile.ApplicationId)
            || !Enum.IsDefined(profile.Kind) || !Enum.IsDefined(profile.Requirement)
            || profile.MaximumAgeSeconds is < 1 or > 600)
            throw new PlatformProofException("Platform proof policy is invalid.");
    }
}

public sealed class PlatformProofException(string message, Exception? inner = null)
    : Exception(message, inner);

public sealed class PlatformProofPolicyVerifier(IReadOnlyDictionary<string, ECDsa> keys,
    TimeProvider clock)
{
    public bool Verify(SignedPlatformProofPolicy signed)
    {
        try { PlatformProofPolicySigner.Verify(signed, keys, clock.GetUtcNow()); return true; }
        catch (PlatformProofException) { return false; }
    }
}
