using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Certael.Server.Rules;

public sealed record WasmRuleProfile(string ProfileId, string Version, string TenantId,
    string GameId, string EnvironmentId, string RuleId, string RuleVersion,
    byte[] ModuleDigest, DateTimeOffset ExpiresAt);
public sealed record SignedWasmRuleProfile(byte[] CanonicalProfile, byte[] Signature,
    string KeyId, byte[] Digest);

public sealed class WasmRuleProfileSigner(ECDsa key, string keyId)
{
    private static readonly JsonSerializerOptions CanonicalJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public SignedWasmRuleProfile Sign(WasmRuleProfile profile)
    {
        byte[] canonical = EncodeCanonical(profile);
        if (key.KeySize != 256 || !Identifier(keyId))
            throw new WasmRuleException("WASM profile signing key is invalid.");
        return new(canonical, key.SignData(canonical, HashAlgorithmName.SHA256), keyId,
            SHA256.HashData(canonical));
    }

    public static WasmRuleProfile Verify(SignedWasmRuleProfile signed,
        IReadOnlyDictionary<string, ECDsa> keys, DateTimeOffset now)
    {
        if (signed.CanonicalProfile is null or { Length: < 1 or > 64 * 1024 }
            || signed.Signature is null or { Length: < 64 or > 512 }
            || signed.Digest is not { Length: 32 } || !Identifier(signed.KeyId)
            || !keys.TryGetValue(signed.KeyId, out ECDsa? key) || key.KeySize != 256
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(signed.CanonicalProfile), signed.Digest)
            || !key.VerifyData(signed.CanonicalProfile, signed.Signature,
                HashAlgorithmName.SHA256))
            throw new WasmRuleException("WASM profile signature is invalid.");
        WasmRuleProfile profile = DecodeCanonical(signed.CanonicalProfile);
        if (profile.ExpiresAt <= now)
            throw new WasmRuleException("WASM profile is expired.");
        return profile;
    }

    public static byte[] EncodeCanonical(WasmRuleProfile profile)
    {
        Validate(profile);
        return JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson);
    }

    public static WasmRuleProfile DecodeCanonical(ReadOnlySpan<byte> canonical)
    {
        if (canonical.IsEmpty || canonical.Length > 64 * 1024)
            throw new WasmRuleException("WASM profile size is invalid.");
        WasmRuleProfile profile;
        try
        {
            profile = JsonSerializer.Deserialize<WasmRuleProfile>(canonical, CanonicalJson)
                ?? throw new WasmRuleException("WASM profile is malformed.");
        }
        catch (JsonException exception)
        { throw new WasmRuleException("WASM profile is malformed.", exception); }
        Validate(profile);
        if (!CryptographicOperations.FixedTimeEquals(canonical,
                JsonSerializer.SerializeToUtf8Bytes(profile, CanonicalJson)))
            throw new WasmRuleException("WASM profile encoding is noncanonical.");
        return profile;
    }

    private static void Validate(WasmRuleProfile profile)
    {
        if (!Identifier(profile.ProfileId) || !Identifier(profile.Version)
            || !Identifier(profile.TenantId) || !Identifier(profile.GameId)
            || !Identifier(profile.EnvironmentId) || !Identifier(profile.RuleId)
            || !Identifier(profile.RuleVersion) || profile.ModuleDigest is not { Length: 32 })
            throw new WasmRuleException("WASM profile is invalid.");
    }

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
}

public sealed class WasmRuleProfileVerifier(IReadOnlyDictionary<string, ECDsa> keys,
    TimeProvider clock)
{
    public bool Verify(SignedWasmRuleProfile signed)
    {
        try { WasmRuleProfileSigner.Verify(signed, keys, clock.GetUtcNow()); return true; }
        catch (WasmRuleException) { return false; }
    }
}
