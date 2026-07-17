namespace Certael.Server.Integrations;

public enum PlatformProofKind { Identity, Attestation }
public enum PlatformProofTrust { Unavailable, Advisory, Verified }

public sealed record PlatformProofRequest(string Provider, string ApplicationId, string ExpectedSubject,
    byte[] Assertion, byte[] Nonce, DateTimeOffset IssuedAt);
public sealed record NormalizedPlatformProof(PlatformProofKind Kind, string Provider, string Subject,
    string ApplicationId, DateTimeOffset IssuedAt, DateTimeOffset VerifiedAt, byte[] NonceDigest,
    byte[] ClaimsDigest, PlatformProofTrust Trust, string PublicReason);

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
    PlatformProofRequirement Requirement, TimeSpan MaximumAge);

public static class PlatformProofPolicyEvaluator
{
    public static string Evaluate(PlatformProofPolicy policy, NormalizedPlatformProof? proof,
        DateTimeOffset now)
    {
        if (proof is null || proof.Trust == PlatformProofTrust.Unavailable)
            return policy.Requirement == PlatformProofRequirement.Required ? "PLATFORM_PROOF_REQUIRED" : "OPTIONAL_PROOF_UNAVAILABLE";
        if (proof.Kind != policy.Kind || proof.Provider != policy.Provider)
            return "PLATFORM_PROOF_CLASSIFICATION_MISMATCH";
        if (now - proof.IssuedAt > policy.MaximumAge || proof.IssuedAt > now)
            return "PLATFORM_PROOF_STALE";
        return proof.Trust == PlatformProofTrust.Verified ? "VERIFIED" : "ADVISORY";
    }
}
