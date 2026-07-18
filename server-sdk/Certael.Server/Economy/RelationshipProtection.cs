using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Certael.Server.Evidence;

namespace Certael.Server.Economy;

public sealed record RelationshipProtectionProfile(
    string ProfileId,
    string Version,
    string TenantId,
    string GameId,
    string EnvironmentId,
    int[] Windows,
    int ReciprocalTransferCount,
    int SharedBeneficiaryCount,
    int OpponentImbalancePercent,
    int CoordinatedActivityCount,
    DateTimeOffset ExpiresAt,
    int FindingRisk = 60,
    int ConfidenceBasisPoints = 9000,
    VerdictRecommendation Recommendation = VerdictRecommendation.RecommendManualReview);

public sealed record SignedRelationshipProtectionProfile(
    byte[] CanonicalProfile, byte[] Signature, string KeyId, byte[] Digest);

public sealed record RelationshipProfileDeployment(
    SignedRelationshipProtectionProfile SignedProfile,
    EconomyProfileStage Stage,
    int CanaryPercentage);

public sealed class RelationshipProtectionProfileSigner(ECDsa key, string keyId)
{
    private static readonly JsonSerializerOptions CanonicalJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public SignedRelationshipProtectionProfile Sign(RelationshipProtectionProfile profile)
    {
        Validate(profile);
        if (!Identifier(keyId) || key.KeySize != 256)
            throw new EconomyEventException("Relationship profile signing key is invalid.");
        byte[] canonical = EncodeCanonical(profile);
        byte[] digest = SHA256.HashData(canonical);
        return new SignedRelationshipProtectionProfile(canonical,
            key.SignData(canonical, HashAlgorithmName.SHA256), keyId, digest);
    }

    public static RelationshipProtectionProfile Verify(
        SignedRelationshipProtectionProfile signed,
        IReadOnlyDictionary<string, ECDsa> keys, DateTimeOffset now)
    {
        if (signed.CanonicalProfile.Length is < 1 or > 64 * 1024
            || signed.Signature.Length is < 64 or > 512 || !Identifier(signed.KeyId)
            || !keys.TryGetValue(signed.KeyId, out ECDsa? key) || key.KeySize != 256
            || signed.Digest.Length != 32
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(signed.CanonicalProfile), signed.Digest)
            || !key.VerifyData(signed.CanonicalProfile, signed.Signature,
                HashAlgorithmName.SHA256))
            throw new EconomyEventException("Relationship profile signature is invalid.");
        RelationshipProtectionProfile profile = DecodeCanonical(signed.CanonicalProfile);
        if (profile.ExpiresAt <= now)
            throw new EconomyEventException("Relationship profile is expired.");
        return profile;
    }

    public static byte[] EncodeCanonical(RelationshipProtectionProfile profile)
    {
        Validate(profile);
        return JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson);
    }

    public static RelationshipProtectionProfile DecodeCanonical(ReadOnlySpan<byte> canonical)
    {
        if (canonical.IsEmpty || canonical.Length > 64 * 1024)
            throw new EconomyEventException("Relationship profile size is invalid.");
        RelationshipProtectionProfile profile;
        try
        {
            profile = JsonSerializer.Deserialize<RelationshipProtectionProfile>(canonical,
                CanonicalJson) ?? throw new EconomyEventException(
                    "Relationship profile is malformed.");
        }
        catch (JsonException exception)
        { throw new EconomyEventException("Relationship profile is malformed.", exception); }
        Validate(profile);
        if (!CryptographicOperations.FixedTimeEquals(
                JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson), canonical))
            throw new EconomyEventException("Relationship profile encoding is not canonical.");
        return profile;
    }

    private static void Validate(RelationshipProtectionProfile profile)
    {
        if (!Identifier(profile.ProfileId) || !Identifier(profile.Version)
            || !Identifier(profile.TenantId) || !Identifier(profile.GameId)
            || !Identifier(profile.EnvironmentId) || profile.Windows is null
            || profile.Windows.Length is < 1 or > 3
            || !profile.Windows.SequenceEqual(profile.Windows.Order())
            || profile.Windows.Distinct().Count() != profile.Windows.Length
            || profile.Windows.Any(window => window is not (7 or 30 or 90))
            || profile.ReciprocalTransferCount is < 2 or > 100_000
            || profile.SharedBeneficiaryCount is < 2 or > 100_000
            || profile.OpponentImbalancePercent is < 51 or > 100
            || profile.CoordinatedActivityCount is < 2 or > 100_000
            || profile.FindingRisk is < 1 or > 100
            || profile.ConfidenceBasisPoints is < 1 or > 10_000
            || !Enum.IsDefined(profile.Recommendation))
            throw new EconomyEventException("Relationship profile is invalid.");
    }

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
}
