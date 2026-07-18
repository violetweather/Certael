using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using NSec.Cryptography;

namespace Certael.Installer;

public sealed record SignedSuiteManifest(
    [property: JsonPropertyName("schema_version")] uint SchemaVersion,
    [property: JsonPropertyName("key_id")] string KeyId,
    [property: JsonPropertyName("manifest_base64")] string ManifestBase64,
    [property: JsonPropertyName("manifest_sha256")] string ManifestSha256,
    [property: JsonPropertyName("signature_base64")] string SignatureBase64);

public sealed record SuiteVerificationKey(
    string KeyId, byte[] PublicKey, DateTimeOffset NotBefore,
    DateTimeOffset NotAfter, bool Revoked = false);

public sealed class SuiteVerificationKeyRing(IEnumerable<SuiteVerificationKey> keys)
{
    private readonly IReadOnlyDictionary<string, SuiteVerificationKey> values = keys
        .ToDictionary(value => value.KeyId, StringComparer.Ordinal);

    public SuiteVerificationKey Active(string keyId, DateTimeOffset now)
    {
        if (!values.TryGetValue(keyId, out SuiteVerificationKey? key) || key.Revoked
            || now < key.NotBefore || now > key.NotAfter || key.PublicKey.Length != 32)
            throw new CryptographicException("Suite signing key is unavailable, expired, or revoked.");
        return key;
    }
}

public sealed record SuiteTrustStore(
    [property: JsonPropertyName("keys")] IReadOnlyList<SuiteTrustStoreKey> Keys);

public sealed record SuiteTrustStoreKey(
    [property: JsonPropertyName("key_id")] string KeyId,
    [property: JsonPropertyName("public_key_hex")] string PublicKeyHex,
    [property: JsonPropertyName("not_before_unix")] long NotBeforeUnix,
    [property: JsonPropertyName("not_after_unix")] long NotAfterUnix,
    [property: JsonPropertyName("revoked")] bool Revoked);

public static class SuiteTrustStoreCodec
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static SuiteVerificationKeyRing Decode(ReadOnlySpan<byte> content)
    {
        if (content.Length is <= 0 or > 1024 * 1024)
            throw new ConfigurationException("Suite trust store is missing or too large.");
        SuiteTrustStore source;
        try
        {
            source = JsonSerializer.Deserialize<SuiteTrustStore>(content, Json)
                ?? throw new ConfigurationException("Suite trust store is empty.");
        }
        catch (JsonException exception)
        {
            throw new ConfigurationException("Suite trust store JSON is invalid.", exception);
        }
        if (source.Keys.Count is 0 or > 64
            || source.Keys.Select(value => value.KeyId).Distinct(StringComparer.Ordinal).Count()
                != source.Keys.Count)
            throw new ConfigurationException("Suite trust store keys are missing or duplicated.");
        var keys = new List<SuiteVerificationKey>(source.Keys.Count);
        foreach (SuiteTrustStoreKey key in source.Keys)
        {
            byte[] publicKey;
            try { publicKey = Convert.FromHexString(key.PublicKeyHex); }
            catch (FormatException exception)
            {
                throw new ConfigurationException("Suite trust store public key is invalid.", exception);
            }
            if (publicKey.Length != 32 || key.NotAfterUnix <= key.NotBeforeUnix)
                throw new ConfigurationException("Suite trust store key metadata is invalid.");
            keys.Add(new SuiteVerificationKey(key.KeyId, publicKey,
                DateTimeOffset.FromUnixTimeSeconds(key.NotBeforeUnix),
                DateTimeOffset.FromUnixTimeSeconds(key.NotAfterUnix), key.Revoked));
        }
        return new SuiteVerificationKeyRing(keys);
    }

    public static async Task<SuiteVerificationKeyRing> LoadAsync(string path,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > 1024 * 1024)
            throw new ConfigurationException("Suite trust store file is missing or invalid.");
        return Decode(await File.ReadAllBytesAsync(path, cancellationToken));
    }
}

public static class SignedSuiteManifestCodec
{
    private static readonly byte[] Domain = "certael.suite-manifest.v1\0"u8.ToArray();
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static SignedSuiteManifest Sign(ReadOnlySpan<byte> canonicalManifest,
        Key privateKey, string keyId)
    {
        if (canonicalManifest.Length is 0 or > 4 * 1024 * 1024)
            throw new ArgumentException("Suite manifest size is invalid.");
        ValidateKeyId(keyId);
        byte[] signedBytes = Domain.Concat(canonicalManifest.ToArray()).ToArray();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(privateKey, signedBytes);
        return new SignedSuiteManifest(1, keyId,
            Convert.ToBase64String(canonicalManifest),
            Convert.ToHexString(SHA256.HashData(canonicalManifest)).ToLowerInvariant(),
            Convert.ToBase64String(signature));
    }

    public static CertaelSuiteManifest Verify(ReadOnlySpan<byte> envelopeBytes,
        SuiteVerificationKeyRing keyRing, DateTimeOffset now)
    {
        if (envelopeBytes.Length is 0 or > 6 * 1024 * 1024)
            throw new CryptographicException("Signed suite manifest size is invalid.");
        SignedSuiteManifest envelope;
        try { envelope = JsonSerializer.Deserialize<SignedSuiteManifest>(envelopeBytes, Json)!; }
        catch (JsonException exception) { throw new CryptographicException("Signed suite manifest is malformed.", exception); }
        if (envelope is null || envelope.SchemaVersion != 1) throw new CryptographicException("Signed suite manifest is unsupported.");
        ValidateKeyId(envelope.KeyId);
        byte[] manifest;
        byte[] signature;
        try
        {
            manifest = Convert.FromBase64String(envelope.ManifestBase64);
            signature = Convert.FromBase64String(envelope.SignatureBase64);
        }
        catch (FormatException exception) { throw new CryptographicException("Signed suite manifest encoding is invalid.", exception); }
        if (manifest.Length is 0 or > 4 * 1024 * 1024 || signature.Length != 64)
            throw new CryptographicException("Signed suite manifest payload is invalid.");
        byte[] digest = SHA256.HashData(manifest);
        byte[] supplied;
        try { supplied = Convert.FromHexString(envelope.ManifestSha256); }
        catch (FormatException exception) { throw new CryptographicException("Suite manifest digest is invalid.", exception); }
        if (supplied.Length != digest.Length || !CryptographicOperations.FixedTimeEquals(digest, supplied))
            throw new CryptographicException("Suite manifest digest does not match.");
        SuiteVerificationKey verificationKey = keyRing.Active(envelope.KeyId, now);
        PublicKey publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519,
            verificationKey.PublicKey, KeyBlobFormat.RawPublicKey);
        byte[] signedBytes = Domain.Concat(manifest).ToArray();
        if (!SignatureAlgorithm.Ed25519.Verify(publicKey, signedBytes, signature))
            throw new CryptographicException("Suite manifest signature is invalid.");
        CertaelSuiteManifest decoded = CertaelSuiteManifestCodec.Decode(manifest, now);
        byte[] canonical = CertaelSuiteManifestCodec.Encode(decoded, now);
        if (!CryptographicOperations.FixedTimeEquals(manifest, canonical))
            throw new CryptographicException("Suite manifest payload is not canonically encoded.");
        return decoded;
    }

    public static byte[] Encode(SignedSuiteManifest manifest) =>
        JsonSerializer.SerializeToUtf8Bytes(manifest, Json);

    private static void ValidateKeyId(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-')))
            throw new CryptographicException("Suite signing key ID is invalid.");
    }
}
