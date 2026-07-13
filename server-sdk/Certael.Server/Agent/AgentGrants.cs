using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Certael.Server.Agent;

public enum AgentRequirementMode { Disabled = 0, Optional = 1, Required = 2 }

public sealed record AgentPolicyClaims(
    uint ProtocolVersion, string PolicyId, string GameId, string EnvironmentId,
    AgentRequirementMode RequirementMode, uint HeartbeatSeconds, uint ReportSeconds,
    uint DisconnectGraceSeconds, string MinimumAgentVersion, DateTimeOffset ExpiresAt);

public sealed record SignedAgentPolicy(byte[] Claims, byte[] Signature, string KeyId);

public sealed record AgentLaunchGrantClaims(
    uint ProtocolVersion, string GrantId, string TenantId, string GameId,
    string EnvironmentId, string PlayerSubject, string MatchId, string BuildId,
    byte[] AgentPublicKey, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt,
    byte[] PolicyDigest, string AuthoritativeServerId);

public sealed record SignedAgentLaunchGrant(byte[] Claims, byte[] Signature, string KeyId);

public sealed class AgentGrantSigner(Key signingKey, string keyId)
{
    private static readonly byte[] PolicyDomain = "certael.agent.policy.v1\0"u8.ToArray();
    private static readonly byte[] LaunchDomain = "certael.agent.launch.v1\0"u8.ToArray();

    public SignedAgentPolicy IssuePolicy(AgentPolicyClaims claims, DateTimeOffset now)
    {
        ValidatePolicy(claims, now);
        byte[] encoded = AgentGrantCodec.EncodePolicyClaims(claims);
        return new(encoded, Sign(PolicyDomain, encoded), KeyId());
    }

    public SignedAgentLaunchGrant IssueLaunchGrant(AgentLaunchGrantClaims claims,
        DateTimeOffset now)
    {
        ValidateGrant(claims, now);
        byte[] encoded = AgentGrantCodec.EncodeLaunchGrantClaims(claims);
        return new(encoded, Sign(LaunchDomain, encoded), KeyId());
    }

    public byte[] ExportPublicKey() => signingKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);

    private byte[] Sign(byte[] domain, byte[] encoded) => SignatureAlgorithm.Ed25519.Sign(
        signingKey, domain.Concat(encoded).ToArray());

    private string KeyId()
    {
        if (string.IsNullOrWhiteSpace(keyId) || keyId.Length > 128)
            throw new InvalidOperationException("Agent signing key ID is invalid.");
        return keyId;
    }

    private static void ValidatePolicy(AgentPolicyClaims claims, DateTimeOffset now)
    {
        if (claims.ProtocolVersion != 1 || !Identifier(claims.PolicyId)
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
            || claims.IssuedAt > now.AddSeconds(30) || claims.ExpiresAt <= claims.IssuedAt
            || claims.ExpiresAt - claims.IssuedAt > TimeSpan.FromMinutes(2)
            || claims.ExpiresAt <= now)
            throw new ArgumentException("Agent launch grant is invalid.");
    }

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
