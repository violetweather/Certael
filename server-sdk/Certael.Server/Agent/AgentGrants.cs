using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Certael.Server.Agent;

public enum AgentRequirementMode { Disabled = 0, Optional = 1, Required = 2 }

public sealed record AgentPolicyClaims(
    uint ProtocolVersion, string PolicyId, string TenantId, string GameId, string EnvironmentId,
    AgentRequirementMode RequirementMode, uint HeartbeatSeconds, uint ReportSeconds,
    uint DisconnectGraceSeconds, string MinimumAgentVersion, DateTimeOffset ExpiresAt);

public sealed record SignedAgentPolicy(byte[] Claims, byte[] Signature, string KeyId);

public sealed record AgentLaunchGrantClaims(
    uint ProtocolVersion, string GrantId, string TenantId, string GameId,
    string EnvironmentId, string PlayerSubject, string MatchId, string BuildId,
    byte[] AgentPublicKey, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt,
    byte[] PolicyDigest, string AuthoritativeServerId, byte[] BuildManifestDigest);

public sealed record SignedAgentLaunchGrant(byte[] Claims, byte[] Signature, string KeyId);

public sealed record ProtectedAgentBuildFile(string Path, ulong Size, byte[] Sha256);

public sealed record AgentBuildManifestClaims(
    uint ProtocolVersion, string ManifestId, string TenantId, string GameId,
    string EnvironmentId, string BuildId, IReadOnlyList<ProtectedAgentBuildFile> Files,
    DateTimeOffset NotBefore, DateTimeOffset ExpiresAt);

public sealed record SignedAgentBuildManifest(byte[] Claims, byte[] Signature, string KeyId);

public sealed record AgentRevocationClaims(
    uint ProtocolVersion, string TenantId, string GameId, string EnvironmentId,
    string AgentSessionId, string Reason, DateTimeOffset RevokedAt,
    DateTimeOffset ExpiresAt);

public sealed record SignedAgentRevocation(byte[] Claims, byte[] Signature, string KeyId);

public sealed record AgentGrantSignature(string KeyId, byte[] Signature);

/// <summary>
/// Production implementations delegate Ed25519 signing to an HSM, KMS, or
/// isolated signing service. Private key bytes need not enter the API process.
/// </summary>
public interface IAgentGrantSigningProvider
{
    AgentGrantSignature Sign(ReadOnlyMemory<byte> domainSeparatedClaims, DateTimeOffset now);
}

public sealed class LocalAgentGrantSigningProvider(Key signingKey, string keyId)
    : IAgentGrantSigningProvider
{
    public AgentGrantSignature Sign(ReadOnlyMemory<byte> domainSeparatedClaims,
        DateTimeOffset now) => new(keyId,
            SignatureAlgorithm.Ed25519.Sign(signingKey, domainSeparatedClaims.Span));

    public byte[] ExportPublicKey() => signingKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
}

public sealed class AgentGrantSigner
{
    private static readonly byte[] PolicyDomain = "certael.agent.policy.v1\0"u8.ToArray();
    private static readonly byte[] LaunchDomain = "certael.agent.launch.v1\0"u8.ToArray();
    private static readonly byte[] RevocationDomain =
        "certael.agent.revocation.v1\0"u8.ToArray();
    private static readonly byte[] BuildManifestDomain =
        "certael.agent.build-manifest.v1\0"u8.ToArray();
    private readonly IAgentGrantSigningProvider _provider;

    public AgentGrantSigner(Key signingKey, string keyId)
        : this(new LocalAgentGrantSigningProvider(signingKey, keyId)) { }

    public AgentGrantSigner(IAgentGrantSigningProvider provider) =>
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    public SignedAgentPolicy IssuePolicy(AgentPolicyClaims claims, DateTimeOffset now)
    {
        ValidatePolicy(claims, now);
        byte[] encoded = AgentGrantCodec.EncodePolicyClaims(claims);
        AgentGrantSignature signature = Sign(PolicyDomain, encoded, now);
        return new(encoded, signature.Signature, signature.KeyId);
    }

    public SignedAgentLaunchGrant IssueLaunchGrant(AgentLaunchGrantClaims claims,
        DateTimeOffset now)
    {
        ValidateGrant(claims, now);
        byte[] encoded = AgentGrantCodec.EncodeLaunchGrantClaims(claims);
        AgentGrantSignature signature = Sign(LaunchDomain, encoded, now);
        return new(encoded, signature.Signature, signature.KeyId);
    }

    public SignedAgentRevocation IssueRevocation(AgentRevocationClaims claims,
        DateTimeOffset now)
    {
        ValidateRevocation(claims, now);
        byte[] encoded = AgentGrantCodec.EncodeRevocationClaims(claims);
        AgentGrantSignature signature = Sign(RevocationDomain, encoded, now);
        return new(encoded, signature.Signature, signature.KeyId);
    }

    public SignedAgentBuildManifest IssueBuildManifest(AgentBuildManifestClaims claims,
        DateTimeOffset now)
    {
        ValidateBuildManifest(claims, now);
        byte[] encoded = AgentGrantCodec.EncodeBuildManifestClaims(claims);
        AgentGrantSignature signature = Sign(BuildManifestDomain, encoded, now);
        return new(encoded, signature.Signature, signature.KeyId);
    }

    private AgentGrantSignature Sign(byte[] domain, byte[] encoded, DateTimeOffset now)
    {
        byte[] message = new byte[domain.Length + encoded.Length];
        domain.CopyTo(message, 0);
        encoded.CopyTo(message, domain.Length);
        AgentGrantSignature result = _provider.Sign(message, now);
        CryptographicOperations.ZeroMemory(message);
        if (string.IsNullOrWhiteSpace(result.KeyId) || result.KeyId.Length > 128
            || result.Signature.Length != 64)
            throw new CryptographicException("Agent signing provider returned invalid metadata.");
        return result with { Signature = result.Signature.ToArray() };
    }

    private static void ValidatePolicy(AgentPolicyClaims claims, DateTimeOffset now)
    {
        if (claims.ProtocolVersion != 1 || !Identifier(claims.PolicyId)
            || !Identifier(claims.TenantId)
            || !Identifier(claims.GameId) || !Identifier(claims.EnvironmentId)
            || !Enum.IsDefined(claims.RequirementMode)
            || claims.HeartbeatSeconds is < 5 or > 300
            || claims.ReportSeconds is < 15 or > 3600
            || claims.ReportSeconds < claims.HeartbeatSeconds
            || claims.DisconnectGraceSeconds > 300
            || !Version(claims.MinimumAgentVersion) || claims.ExpiresAt <= now)
            throw new ArgumentException("Agent policy is invalid.");
    }

    private static void ValidateGrant(AgentLaunchGrantClaims claims, DateTimeOffset now)
    {
        if (claims.ProtocolVersion != 1 || !Identifier(claims.GrantId)
            || !Identifier(claims.TenantId) || !Identifier(claims.GameId)
            || !Identifier(claims.EnvironmentId) || !Identifier(claims.PlayerSubject)
            || !Identifier(claims.MatchId) || !Identifier(claims.BuildId)
            || !Identifier(claims.AuthoritativeServerId)
            || claims.AgentPublicKey.Length != 32 || claims.PolicyDigest.Length != 32
            || claims.BuildManifestDigest.Length != 32
            || claims.IssuedAt > now.AddSeconds(30) || claims.ExpiresAt <= claims.IssuedAt
            || claims.ExpiresAt - claims.IssuedAt > TimeSpan.FromMinutes(2)
            || claims.ExpiresAt <= now)
            throw new ArgumentException("Agent launch grant is invalid.");
    }

    private static void ValidateRevocation(AgentRevocationClaims claims, DateTimeOffset now)
    {
        if (claims.ProtocolVersion != 1 || !Identifier(claims.TenantId)
            || !Identifier(claims.GameId) || !Identifier(claims.EnvironmentId)
            || !Identifier(claims.AgentSessionId) || !Identifier(claims.Reason)
            || claims.RevokedAt > now.AddSeconds(30) || claims.ExpiresAt <= now
            || claims.ExpiresAt <= claims.RevokedAt
            || claims.ExpiresAt - claims.RevokedAt > TimeSpan.FromMinutes(5))
            throw new ArgumentException("Agent revocation is invalid.");
    }

    private static void ValidateBuildManifest(AgentBuildManifestClaims claims,
        DateTimeOffset now)
    {
        if (claims.ProtocolVersion != 1 || !Identifier(claims.ManifestId)
            || !Identifier(claims.TenantId) || !Identifier(claims.GameId)
            || !Identifier(claims.EnvironmentId) || !Identifier(claims.BuildId)
            || claims.Files.Count is < 1 or > 16384
            || claims.NotBefore > now.AddSeconds(30) || claims.ExpiresAt <= now
            || claims.ExpiresAt <= claims.NotBefore
            || claims.ExpiresAt - claims.NotBefore > TimeSpan.FromDays(400))
            throw new ArgumentException("Agent build manifest is invalid.");
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (ProtectedAgentBuildFile file in claims.Files)
            if (!SafeRelativePath(file.Path) || file.Sha256.Length != 32
                || !paths.Add(file.Path))
                throw new ArgumentException("Agent build manifest contains an invalid file.");
    }

    private static bool SafeRelativePath(string path) => !string.IsNullOrWhiteSpace(path)
        && path.Length <= 512 && !path.StartsWith('/') && !path.Contains('\\')
        && !(path.Length >= 2 && path[1] == ':')
        && path.Split('/').All(part => part.Length > 0 && part is not "." and not ".."
            && !part.Any(char.IsControl));

    private static bool Identifier(string value) => !string.IsNullOrEmpty(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-');

    private static bool Version(string value) => !string.IsNullOrEmpty(value)
        && value.Length <= 64 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '+' or '-');
}

public static class AgentGrantCodec
{
    public static byte[] EncodePolicyClaims(AgentPolicyClaims value)
    {
        using var stream = new MemoryStream();
        VarintField(stream, 1, value.ProtocolVersion);
        String(stream, 2, value.PolicyId);
        String(stream, 3, value.GameId);
        String(stream, 4, value.EnvironmentId);
        VarintField(stream, 5, (uint)value.RequirementMode);
        VarintField(stream, 6, value.HeartbeatSeconds);
        VarintField(stream, 7, value.ReportSeconds);
        VarintField(stream, 8, value.DisconnectGraceSeconds);
        String(stream, 9, value.MinimumAgentVersion);
        VarintField(stream, 10, checked((ulong)value.ExpiresAt.ToUnixTimeSeconds()));
        String(stream, 11, value.TenantId);
        return stream.ToArray();
    }

    public static byte[] EncodeLaunchGrantClaims(AgentLaunchGrantClaims value)
    {
        using var stream = new MemoryStream();
        VarintField(stream, 1, value.ProtocolVersion);
        String(stream, 2, value.GrantId);
        String(stream, 3, value.TenantId);
        String(stream, 4, value.GameId);
        String(stream, 5, value.EnvironmentId);
        String(stream, 6, value.PlayerSubject);
        String(stream, 7, value.MatchId);
        String(stream, 8, value.BuildId);
        Bytes(stream, 9, value.AgentPublicKey);
        VarintField(stream, 10, checked((ulong)value.IssuedAt.ToUnixTimeSeconds()));
        VarintField(stream, 11, checked((ulong)value.ExpiresAt.ToUnixTimeSeconds()));
        Bytes(stream, 12, value.PolicyDigest);
        String(stream, 13, value.AuthoritativeServerId);
        Bytes(stream, 14, value.BuildManifestDigest);
        return stream.ToArray();
    }

    public static byte[] EncodeSignedPolicy(SignedAgentPolicy value)
    {
        using var stream = new MemoryStream();
        Bytes(stream, 1, value.Claims); Bytes(stream, 2, value.Signature); String(stream, 3, value.KeyId);
        return stream.ToArray();
    }

    public static byte[] EncodeSignedLaunchGrant(SignedAgentLaunchGrant value)
    {
        using var stream = new MemoryStream();
        Bytes(stream, 1, value.Claims); Bytes(stream, 2, value.Signature); String(stream, 3, value.KeyId);
        return stream.ToArray();
    }

    public static byte[] EncodeRevocationClaims(AgentRevocationClaims value)
    {
        using var stream = new MemoryStream();
        VarintField(stream, 1, value.ProtocolVersion);
        String(stream, 2, value.TenantId);
        String(stream, 3, value.GameId);
        String(stream, 4, value.EnvironmentId);
        String(stream, 5, value.AgentSessionId);
        String(stream, 6, value.Reason);
        VarintField(stream, 7, checked((ulong)value.RevokedAt.ToUnixTimeSeconds()));
        VarintField(stream, 8, checked((ulong)value.ExpiresAt.ToUnixTimeSeconds()));
        return stream.ToArray();
    }

    public static byte[] EncodeSignedRevocation(SignedAgentRevocation value)
    {
        using var stream = new MemoryStream();
        Bytes(stream, 1, value.Claims); Bytes(stream, 2, value.Signature);
        String(stream, 3, value.KeyId);
        return stream.ToArray();
    }

    public static byte[] EncodeBuildManifestClaims(AgentBuildManifestClaims value)
    {
        using var stream = new MemoryStream();
        VarintField(stream, 1, value.ProtocolVersion);
        String(stream, 2, value.ManifestId);
        String(stream, 3, value.TenantId);
        String(stream, 4, value.GameId);
        String(stream, 5, value.EnvironmentId);
        String(stream, 6, value.BuildId);
        foreach (ProtectedAgentBuildFile file in value.Files)
        {
            using var nested = new MemoryStream();
            String(nested, 1, file.Path);
            VarintField(nested, 2, file.Size);
            Bytes(nested, 3, file.Sha256);
            Bytes(stream, 7, nested.ToArray());
        }
        VarintField(stream, 8, checked((ulong)value.NotBefore.ToUnixTimeSeconds()));
        VarintField(stream, 9, checked((ulong)value.ExpiresAt.ToUnixTimeSeconds()));
        byte[] encoded = stream.ToArray();
        if (encoded.Length > 64 * 1024)
            throw new ArgumentException("Agent build manifest exceeds 64 KiB.");
        return encoded;
    }

    public static byte[] EncodeSignedBuildManifest(SignedAgentBuildManifest value)
    {
        using var stream = new MemoryStream();
        Bytes(stream, 1, value.Claims); Bytes(stream, 2, value.Signature);
        String(stream, 3, value.KeyId);
        byte[] encoded = stream.ToArray();
        if (encoded.Length > 64 * 1024)
            throw new ArgumentException("Signed Agent build manifest exceeds 64 KiB.");
        return encoded;
    }

    public static byte[] PolicyDigest(SignedAgentPolicy policy) =>
        SHA256.HashData(EncodeSignedPolicy(policy));

    private static void String(Stream stream, uint field, string value) =>
        Bytes(stream, field, Encoding.UTF8.GetBytes(value));

    private static void VarintField(Stream stream, uint field, ulong value)
    { Varint(stream, (ulong)field << 3); Varint(stream, value); }

    private static void Bytes(Stream stream, uint field, ReadOnlySpan<byte> value)
    { Varint(stream, (ulong)field << 3 | 2); Varint(stream, (ulong)value.Length); stream.Write(value); }

    private static void Varint(Stream stream, ulong value)
    {
        while (value >= 0x80) { stream.WriteByte((byte)(value | 0x80)); value >>= 7; }
        stream.WriteByte((byte)value);
    }
}
