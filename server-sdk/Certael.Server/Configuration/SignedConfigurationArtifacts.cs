using System.Security.Cryptography;
using Certael.Server.Protections;
using Certael.Server.Rules;
using Certael.Server.Integrations;

namespace Certael.Server.Configuration;

public enum SignedConfigurationKind
{
    RulePack = 1,
    ProtectionProfile = 2,
    WasmRuleProfile = 3,
    PlatformProofPolicy = 4
}
public enum SignedConfigurationStage { Draft, Shadow, Canary, Enforced, Retired }

public sealed record SignedConfigurationArtifact(
    SignedConfigurationKind Kind, string TenantId, string ArtifactId, string Version,
    string GameId, string EnvironmentId, byte[] CanonicalDocument, byte[] Digest,
    byte[] Signature, string SigningKeyId)
{
    public static SignedConfigurationArtifact From(SignedRulePack value) => new(
        SignedConfigurationKind.RulePack, value.Document.TenantId, value.Document.PackId,
        value.Document.Version, value.Document.GameId, value.Document.EnvironmentId,
        value.CanonicalDocument, value.Digest, value.Signature, value.SigningKeyId);

    public static SignedConfigurationArtifact From(SignedProtectionProfile value) => new(
        SignedConfigurationKind.ProtectionProfile, value.Profile.TenantId, value.Profile.ProfileId,
        value.Profile.Version, value.Profile.GameId, value.Profile.EnvironmentId,
        value.CanonicalDocument, value.Digest, value.Signature, value.SigningKeyId);

    public static SignedConfigurationArtifact From(SignedWasmRuleProfile value)
    {
        WasmRuleProfile profile = WasmRuleProfileSigner.DecodeCanonical(value.CanonicalProfile);
        return new(SignedConfigurationKind.WasmRuleProfile, profile.TenantId, profile.ProfileId,
            profile.Version, profile.GameId, profile.EnvironmentId, value.CanonicalProfile,
            value.Digest, value.Signature, value.KeyId);
    }

    public static SignedConfigurationArtifact From(SignedPlatformProofPolicy value)
    {
        PlatformProofPolicyProfile profile = PlatformProofPolicySigner.DecodeCanonical(
            value.CanonicalPolicy);
        return new(SignedConfigurationKind.PlatformProofPolicy, profile.TenantId,
            profile.PolicyId, profile.Version, profile.GameId, profile.EnvironmentId,
            value.CanonicalPolicy, value.Digest, value.Signature, value.KeyId);
    }

    public SignedRulePack ToRulePack() => Kind == SignedConfigurationKind.RulePack
        ? new(RulePackCanonicalCodec.Deserialize(CanonicalDocument), CanonicalDocument, Digest,
            Signature, SigningKeyId)
        : throw new SignedConfigurationException("Artifact is not a rule pack.");

    public SignedProtectionProfile ToProtectionProfile() =>
        Kind == SignedConfigurationKind.ProtectionProfile
            ? new(ProtectionProfileCompiler.DeserializeCanonical(CanonicalDocument),
                CanonicalDocument, Digest, Signature, SigningKeyId)
            : throw new SignedConfigurationException("Artifact is not a protection profile.");

    public SignedWasmRuleProfile ToWasmRuleProfile() =>
        Kind == SignedConfigurationKind.WasmRuleProfile
            ? new(CanonicalDocument, Signature, SigningKeyId, Digest)
            : throw new SignedConfigurationException("Artifact is not a WASM rule profile.");

    public SignedPlatformProofPolicy ToPlatformProofPolicy() =>
        Kind == SignedConfigurationKind.PlatformProofPolicy
            ? new(CanonicalDocument, Signature, SigningKeyId, Digest)
            : throw new SignedConfigurationException("Artifact is not a platform proof policy.");
}

public sealed record SignedConfigurationApproval(
    string ApproverSubject, DateTimeOffset ApprovedAt, byte[] ArtifactDigest);

public sealed record SignedConfigurationDeployment(
    SignedConfigurationArtifact Artifact, SignedConfigurationStage Stage,
    int CanaryPercentage, IReadOnlyList<SignedConfigurationApproval> Approvals,
    DateTimeOffset UpdatedAt, string UpdatedBy);

public interface ISignedConfigurationVerifier
{
    bool Verify(SignedConfigurationArtifact artifact);
}

public sealed class SignedConfigurationVerifier(
    RulePackVerifier rulePacks,
    ProtectionProfileVerifier protectionProfiles,
    WasmRuleProfileVerifier wasmRules,
    PlatformProofPolicyVerifier platformProofs) : ISignedConfigurationVerifier
{
    public bool Verify(SignedConfigurationArtifact artifact)
    {
        try
        {
            bool signature = artifact.Kind switch
            {
                SignedConfigurationKind.RulePack => rulePacks.Verify(artifact.ToRulePack()),
                SignedConfigurationKind.ProtectionProfile =>
                    protectionProfiles.Verify(artifact.ToProtectionProfile()),
                SignedConfigurationKind.WasmRuleProfile =>
                    wasmRules.Verify(artifact.ToWasmRuleProfile()),
                SignedConfigurationKind.PlatformProofPolicy =>
                    platformProofs.Verify(artifact.ToPlatformProofPolicy()),
                _ => false
            };
            return signature && MetadataMatches(artifact);
        }
        catch (Exception error) when (error is RulePackValidationException
            or ProtectionProfileException or WasmRuleException
            or PlatformProofException or SignedConfigurationException)
        {
            return false;
        }
    }

    private static bool MetadataMatches(SignedConfigurationArtifact artifact) =>
        artifact.Kind switch
        {
            SignedConfigurationKind.RulePack => Matches(artifact,
                artifact.ToRulePack().Document.TenantId,
                artifact.ToRulePack().Document.PackId,
                artifact.ToRulePack().Document.Version,
                artifact.ToRulePack().Document.GameId,
                artifact.ToRulePack().Document.EnvironmentId),
            SignedConfigurationKind.ProtectionProfile => Matches(artifact,
                artifact.ToProtectionProfile().Profile.TenantId,
                artifact.ToProtectionProfile().Profile.ProfileId,
                artifact.ToProtectionProfile().Profile.Version,
                artifact.ToProtectionProfile().Profile.GameId,
                artifact.ToProtectionProfile().Profile.EnvironmentId),
            SignedConfigurationKind.WasmRuleProfile => WasmRuleProfileSigner.DecodeCanonical(
                artifact.CanonicalDocument) is { } profile && Matches(artifact,
                    profile.TenantId, profile.ProfileId, profile.Version,
                    profile.GameId, profile.EnvironmentId),
            SignedConfigurationKind.PlatformProofPolicy =>
                PlatformProofPolicySigner.DecodeCanonical(artifact.CanonicalDocument) is { } policy
                && Matches(artifact, policy.TenantId, policy.PolicyId, policy.Version,
                    policy.GameId, policy.EnvironmentId),
            _ => false
        };

    private static bool Matches(SignedConfigurationArtifact artifact, string tenantId,
        string artifactId, string version, string gameId, string environmentId) =>
        artifact.TenantId == tenantId && artifact.ArtifactId == artifactId
        && artifact.Version == version && artifact.GameId == gameId
        && artifact.EnvironmentId == environmentId;
}

public interface ISignedConfigurationAdministration
{
    ValueTask<SignedConfigurationDeployment> AddDraftAsync(SignedConfigurationArtifact artifact,
        string author, CancellationToken cancellationToken);
    ValueTask<SignedConfigurationDeployment> ApproveAsync(string tenantId,
        SignedConfigurationKind kind, string artifactId, string version, string approver,
        CancellationToken cancellationToken);
    ValueTask<SignedConfigurationDeployment> PromoteAsync(string tenantId,
        SignedConfigurationKind kind, string artifactId, string version,
        SignedConfigurationStage stage, int canaryPercentage, string operatorSubject,
        CancellationToken cancellationToken);
    ValueTask<SignedConfigurationDeployment> RollbackAsync(string tenantId,
        SignedConfigurationKind kind, string gameId, string environmentId,
        string operatorSubject, CancellationToken cancellationToken);
    ValueTask<SignedConfigurationDeployment> RetireAsync(string tenantId,
        SignedConfigurationKind kind, string artifactId, string version,
        string operatorSubject, CancellationToken cancellationToken);
    ValueTask<SignedConfigurationDeployment> GetAsync(string tenantId,
        SignedConfigurationKind kind, string artifactId, string version,
        CancellationToken cancellationToken);
}

public static class SignedConfigurationValidation
{
    public static void Validate(SignedConfigurationArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        Identifier(artifact.TenantId); Identifier(artifact.ArtifactId); Identifier(artifact.GameId);
        Identifier(artifact.EnvironmentId); Identifier(artifact.SigningKeyId);
        if (artifact.Kind is not (SignedConfigurationKind.RulePack
                or SignedConfigurationKind.ProtectionProfile)
            || !System.Version.TryParse(artifact.Version, out _)
            || artifact.CanonicalDocument.Length is < 1 or > 1_048_576
            || artifact.Digest.Length != 32 || artifact.Signature.Length is < 64 or > 512
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(artifact.CanonicalDocument), artifact.Digest))
            throw new SignedConfigurationException("Signed configuration artifact is invalid.");
    }

    public static string Subject(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && !value.Any(char.IsControl) ? value
        : throw new SignedConfigurationException("Operator subject is invalid.");

    public static void Stage(SignedConfigurationStage stage, int canaryPercentage)
    {
        if (stage is SignedConfigurationStage.Draft or SignedConfigurationStage.Retired)
            throw new SignedConfigurationException("Use add or retire for this stage.");
        if (stage == SignedConfigurationStage.Canary && canaryPercentage is < 1 or > 99
            || stage != SignedConfigurationStage.Canary && canaryPercentage != 0)
            throw new SignedConfigurationException("Canary percentage is invalid.");
    }

    private static void Identifier(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-'))
            throw new SignedConfigurationException("Configuration identifier is invalid.");
    }
}

public sealed class SignedConfigurationException(string message) : Exception(message);
