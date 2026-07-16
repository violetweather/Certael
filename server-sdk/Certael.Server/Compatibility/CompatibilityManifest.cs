using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Certael.Server.Compatibility;

public enum CertaelProduct : uint
{
    Core = 1,
    Agent = 2,
    GodotAdapter = 3,
    UnityAdapter = 4,
    UnrealAdapter = 5,
    DotNetServerSdk = 6,
    NativeServerSdk = 7
}

public enum CompatibilityState
{
    Supported,
    Deprecated,
    UpdateRequired,
    Revoked,
    Unknown,
    Indeterminate
}

public sealed record CompatibilityProductRule(
    CertaelProduct Product, string MinimumSupportedVersion, string RecommendedVersion,
    uint MinimumProtocolVersion, uint MaximumProtocolVersion);

public sealed record CompatibilityRevocation(
    CertaelProduct Product, string Version, DateTimeOffset EffectiveAt, string Reason);

public sealed record CompatibilityManifestClaims(
    uint SchemaVersion, ulong Revision, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt,
    IReadOnlyList<CompatibilityProductRule> Products,
    IReadOnlyList<CompatibilityRevocation> Revocations);

public sealed record SignedCompatibilityManifest(byte[] Claims, byte[] Signature, string KeyId);

public sealed record CompatibilityDecision(
    CompatibilityState State, string PublicReason, string? RecommendedVersion,
    ulong ManifestRevision)
{
    public bool AllowsNewProtectedSession => State is CompatibilityState.Supported
        or CompatibilityState.Deprecated;
}

public sealed record CompatibilityVerificationKey(
    string KeyId, byte[] PublicKey, DateTimeOffset NotBefore, DateTimeOffset NotAfter,
    bool Revoked = false);

public sealed class CompatibilityVerificationKeyRing(
    IEnumerable<CompatibilityVerificationKey> keys)
{
    private readonly IReadOnlyDictionary<string, CompatibilityVerificationKey> _keys = keys
        .ToDictionary(key => key.KeyId, StringComparer.Ordinal);

    public CompatibilityVerificationKey Resolve(string keyId, DateTimeOffset now)
    {
        if (!_keys.TryGetValue(keyId, out CompatibilityVerificationKey? key)
            || key.Revoked || now < key.NotBefore || now >= key.NotAfter
            || key.PublicKey.Length != 32)
            throw new CryptographicException("Compatibility signing key is not trusted.");
        return key;
    }
}

public sealed class CompatibilityManifestSigner(Key key, string keyId)
{
    private static readonly byte[] Domain = "certael.compatibility.v1\0"u8.ToArray();

    public SignedCompatibilityManifest Sign(CompatibilityManifestClaims claims,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(keyId) || keyId.Length > 128
            || keyId.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-'))
            throw new CryptographicException("Compatibility signing key ID is invalid.");
        CompatibilityManifestCodec.Validate(claims, now, requireCurrentlyValid: true);
        byte[] encoded = CompatibilityManifestCodec.EncodeClaims(claims);
        byte[] message = Domain.Concat(encoded).ToArray();
        try
        {
            return new(encoded, SignatureAlgorithm.Ed25519.Sign(key, message), keyId);
        }
        finally { CryptographicOperations.ZeroMemory(message); }
    }

    public static CompatibilityManifestClaims Verify(SignedCompatibilityManifest signed,
        CompatibilityVerificationKeyRing keys, DateTimeOffset now)
    {
        if (signed.Claims.Length is < 1 or > 64 * 1024 || signed.Signature.Length != 64
            || string.IsNullOrWhiteSpace(signed.KeyId) || signed.KeyId.Length > 128)
            throw new CryptographicException("Signed compatibility manifest is malformed.");
        CompatibilityVerificationKey trusted = keys.Resolve(signed.KeyId, now);
        byte[] message = Domain.Concat(signed.Claims).ToArray();
        try
        {
            PublicKey publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519,
                trusted.PublicKey, KeyBlobFormat.RawPublicKey);
            if (!SignatureAlgorithm.Ed25519.Verify(publicKey, message, signed.Signature))
                throw new CryptographicException("Compatibility signature is invalid.");
        }
        finally { CryptographicOperations.ZeroMemory(message); }
        CompatibilityManifestClaims claims = CompatibilityManifestCodec.DecodeClaims(signed.Claims);
        CompatibilityManifestCodec.Validate(claims, now, requireCurrentlyValid: true);
        if (!CompatibilityManifestCodec.EncodeClaims(claims).AsSpan().SequenceEqual(signed.Claims))
            throw new CryptographicException("Compatibility manifest encoding is noncanonical.");
        return claims;
    }
}

public static class CompatibilityEvaluator
{
    public static CompatibilityDecision Evaluate(CompatibilityManifestClaims? manifest,
        CertaelProduct product, string currentVersion, uint protocolVersion,
        DateTimeOffset now)
    {
        if (manifest is null || now < manifest.IssuedAt || now >= manifest.ExpiresAt)
            return new(CompatibilityState.Indeterminate, "COMPATIBILITY_INDETERMINATE", null,
                manifest?.Revision ?? 0);
        if (!SemanticVersion.TryParse(currentVersion, out SemanticVersion current))
            return new(CompatibilityState.Unknown, "VERSION_UNKNOWN", null, manifest.Revision);
        CompatibilityRevocation? revoked = manifest.Revocations.FirstOrDefault(value =>
            value.Product == product && value.Version == currentVersion
            && now >= value.EffectiveAt);
        CompatibilityProductRule? rule = manifest.Products.SingleOrDefault(value =>
            value.Product == product);
        if (revoked is not null)
            return new(CompatibilityState.Revoked, "VERSION_REVOKED",
                rule?.RecommendedVersion, manifest.Revision);
        if (rule is null)
            return new(CompatibilityState.Unknown, "PRODUCT_UNKNOWN", null, manifest.Revision);
        if (protocolVersion < rule.MinimumProtocolVersion)
            return new(CompatibilityState.UpdateRequired, "PROTOCOL_UPDATE_REQUIRED",
                rule.RecommendedVersion, manifest.Revision);
        if (protocolVersion > rule.MaximumProtocolVersion)
            return new(CompatibilityState.Unknown, "PROTOCOL_TOO_NEW",
                rule.RecommendedVersion, manifest.Revision);
        SemanticVersion minimum = SemanticVersion.Parse(rule.MinimumSupportedVersion);
        SemanticVersion recommended = SemanticVersion.Parse(rule.RecommendedVersion);
        if (current < minimum)
            return new(CompatibilityState.UpdateRequired, "VERSION_UPDATE_REQUIRED",
                rule.RecommendedVersion, manifest.Revision);
        if (current < recommended)
            return new(CompatibilityState.Deprecated, "VERSION_DEPRECATED",
                rule.RecommendedVersion, manifest.Revision);
        return new(CompatibilityState.Supported, "SUPPORTED", rule.RecommendedVersion,
            manifest.Revision);
    }
}

public sealed class CompatibilityAdmissionGate(CompatibilityManifestClaims? manifest,
    TimeProvider clock)
{
    public ulong ManifestRevision => manifest?.Revision ?? 0;
    public DateTimeOffset? ExpiresAt => manifest?.ExpiresAt;
    public CompatibilityProductRule? Rule(CertaelProduct product) => manifest?.Products
        .SingleOrDefault(value => value.Product == product);
    public CompatibilityDecision Evaluate(CertaelProduct product, string version,
        uint protocolVersion) => CompatibilityEvaluator.Evaluate(manifest, product, version,
            protocolVersion, clock.GetUtcNow());
}

public readonly record struct SemanticVersion(ulong Major, ulong Minor, ulong Patch,
    string Prerelease) : IComparable<SemanticVersion>
{
    public static SemanticVersion Parse(string value) => TryParse(value, out SemanticVersion parsed)
        ? parsed : throw new FormatException("Version is not valid semantic versioning.");

    public static bool TryParse(string value, out SemanticVersion version)
    {
        version = default;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64) return false;
        string[] buildSplit = value.Split('+', 2);
        string withoutBuild = buildSplit[0];
        if (buildSplit.Length == 2 && !ValidIdentifiers(buildSplit[1], numericLeadingZero: true))
            return false;
        string[] prereleaseSplit = withoutBuild.Split('-', 2);
        string[] numbers = prereleaseSplit[0].Split('.');
        if (numbers.Length != 3 || !ulong.TryParse(numbers[0], out ulong major)
            || !ulong.TryParse(numbers[1], out ulong minor)
            || !ulong.TryParse(numbers[2], out ulong patch)
            || numbers.Any(number => number.Length > 1 && number[0] == '0')) return false;
        string prerelease = prereleaseSplit.Length == 2 ? prereleaseSplit[1] : string.Empty;
        if (prereleaseSplit.Length == 2
            && !ValidIdentifiers(prerelease, numericLeadingZero: false)) return false;
        version = new(major, minor, patch, prerelease);
        return true;
    }

    private static bool ValidIdentifiers(string value, bool numericLeadingZero)
    {
        if (value.Length == 0) return false;
        foreach (string part in value.Split('.'))
        {
            if (part.Length == 0 || part.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character != '-')) return false;
            if (!numericLeadingZero && part.Length > 1 && part[0] == '0'
                && part.All(char.IsAsciiDigit)) return false;
        }
        return true;
    }

    public int CompareTo(SemanticVersion other)
    {
        int result = Major.CompareTo(other.Major);
        if (result == 0) result = Minor.CompareTo(other.Minor);
        if (result == 0) result = Patch.CompareTo(other.Patch);
        if (result != 0) return result;
        if (Prerelease.Length == 0) return other.Prerelease.Length == 0 ? 0 : 1;
        if (other.Prerelease.Length == 0) return -1;
        string[] left = Prerelease.Split('.');
        string[] right = other.Prerelease.Split('.');
        for (int index = 0; index < Math.Max(left.Length, right.Length); index++)
        {
            if (index == left.Length) return -1;
            if (index == right.Length) return 1;
            bool leftNumber = ulong.TryParse(left[index], out ulong leftValue);
            bool rightNumber = ulong.TryParse(right[index], out ulong rightValue);
            int part = leftNumber && rightNumber ? leftValue.CompareTo(rightValue)
                : leftNumber ? -1 : rightNumber ? 1
                : string.CompareOrdinal(left[index], right[index]);
            if (part != 0) return part;
        }
        return 0;
    }

    public static bool operator <(SemanticVersion left, SemanticVersion right) =>
        left.CompareTo(right) < 0;
    public static bool operator >(SemanticVersion left, SemanticVersion right) =>
        left.CompareTo(right) > 0;
}

public static class CompatibilityManifestCodec
{
    public static byte[] EncodeClaims(CompatibilityManifestClaims value)
    {
        using var stream = new MemoryStream();
        VarintField(stream, 1, value.SchemaVersion);
        VarintField(stream, 2, value.Revision);
        VarintField(stream, 3, checked((ulong)value.IssuedAt.ToUnixTimeSeconds()));
        VarintField(stream, 4, checked((ulong)value.ExpiresAt.ToUnixTimeSeconds()));
        foreach (CompatibilityProductRule product in value.Products.OrderBy(p => p.Product))
            Bytes(stream, 5, EncodeProduct(product));
        foreach (CompatibilityRevocation revocation in value.Revocations
            .OrderBy(r => r.Product).ThenBy(r => r.Version, StringComparer.Ordinal))
            Bytes(stream, 6, EncodeRevocation(revocation));
        return stream.ToArray();
    }

    public static byte[] EncodeSigned(SignedCompatibilityManifest value)
    {
        using var stream = new MemoryStream();
        Bytes(stream, 1, value.Claims); Bytes(stream, 2, value.Signature);
        String(stream, 3, value.KeyId); return stream.ToArray();
    }

    public static SignedCompatibilityManifest DecodeSigned(ReadOnlySpan<byte> bytes)
    {
        var reader = new Reader(bytes); byte[]? claims = null; byte[]? signature = null;
        string? keyId = null;
        while (reader.Remaining > 0)
        {
            (uint field, uint wire) = reader.Tag();
            switch (field)
            {
                case 1 when wire == 2: claims = reader.Bytes(); break;
                case 2 when wire == 2: signature = reader.Bytes(); break;
                case 3 when wire == 2: keyId = reader.String(); break;
                default: throw new FormatException("Unknown signed compatibility field.");
            }
        }
        return new(claims ?? throw new FormatException("Claims are missing."),
            signature ?? throw new FormatException("Signature is missing."),
            keyId ?? throw new FormatException("Key ID is missing."));
    }

    public static CompatibilityManifestClaims DecodeClaims(ReadOnlySpan<byte> bytes)
    {
        var reader = new Reader(bytes); uint? schema = null; ulong? revision = null;
        ulong? issued = null; ulong? expires = null; var products = new List<CompatibilityProductRule>();
        var revocations = new List<CompatibilityRevocation>();
        while (reader.Remaining > 0)
        {
            (uint field, uint wire) = reader.Tag();
            switch (field)
            {
                case 1 when wire == 0: schema = checked((uint)reader.Varint()); break;
                case 2 when wire == 0: revision = reader.Varint(); break;
                case 3 when wire == 0: issued = reader.Varint(); break;
                case 4 when wire == 0: expires = reader.Varint(); break;
                case 5 when wire == 2: products.Add(DecodeProduct(reader.Bytes())); break;
                case 6 when wire == 2: revocations.Add(DecodeRevocation(reader.Bytes())); break;
                default: throw new FormatException("Unknown compatibility claims field.");
            }
        }
        return new(schema ?? throw new FormatException("Schema is missing."),
            revision ?? throw new FormatException("Revision is missing."),
            DateTimeOffset.FromUnixTimeSeconds(checked((long)(issued
                ?? throw new FormatException("Issued time is missing.")))),
            DateTimeOffset.FromUnixTimeSeconds(checked((long)(expires
                ?? throw new FormatException("Expiry is missing.")))), products, revocations);
    }

    public static void Validate(CompatibilityManifestClaims value, DateTimeOffset now,
        bool requireCurrentlyValid)
    {
        if (value.SchemaVersion != 1 || value.Revision == 0 || value.Products.Count is < 1 or > 64
            || value.Revocations.Count > 4096 || value.IssuedAt > now.AddMinutes(5)
            || value.ExpiresAt <= value.IssuedAt
            || value.ExpiresAt - value.IssuedAt > TimeSpan.FromDays(32)
            || (requireCurrentlyValid && value.ExpiresAt <= now)
            || value.Products.Select(product => product.Product).Distinct().Count()
                != value.Products.Count) throw new FormatException("Compatibility manifest is invalid.");
        foreach (CompatibilityProductRule product in value.Products)
        {
            if (!Enum.IsDefined(product.Product)
                || !SemanticVersion.TryParse(product.MinimumSupportedVersion, out SemanticVersion min)
                || !SemanticVersion.TryParse(product.RecommendedVersion, out SemanticVersion recommended)
                || recommended < min || product.MinimumProtocolVersion == 0
                || product.MaximumProtocolVersion < product.MinimumProtocolVersion)
                throw new FormatException("Compatibility product rule is invalid.");
        }
        foreach (CompatibilityRevocation revocation in value.Revocations)
            if (!Enum.IsDefined(revocation.Product)
                || !SemanticVersion.TryParse(revocation.Version, out _)
                || string.IsNullOrWhiteSpace(revocation.Reason) || revocation.Reason.Length > 128
                || revocation.EffectiveAt < value.IssuedAt.AddDays(-1)
                || revocation.EffectiveAt > value.ExpiresAt)
                throw new FormatException("Compatibility revocation is invalid.");
    }

    private static byte[] EncodeProduct(CompatibilityProductRule value)
    {
        using var stream = new MemoryStream(); VarintField(stream, 1, (uint)value.Product);
        String(stream, 2, value.MinimumSupportedVersion); String(stream, 3, value.RecommendedVersion);
        VarintField(stream, 4, value.MinimumProtocolVersion); VarintField(stream, 5, value.MaximumProtocolVersion);
        return stream.ToArray();
    }

    private static CompatibilityProductRule DecodeProduct(ReadOnlySpan<byte> bytes)
    {
        var reader = new Reader(bytes); uint? product = null, minimumProtocol = null, maximumProtocol = null;
        string? minimum = null, recommended = null;
        while (reader.Remaining > 0)
        {
            (uint field, uint wire) = reader.Tag();
            switch (field)
            {
                case 1 when wire == 0: product = checked((uint)reader.Varint()); break;
                case 2 when wire == 2: minimum = reader.String(); break;
                case 3 when wire == 2: recommended = reader.String(); break;
                case 4 when wire == 0: minimumProtocol = checked((uint)reader.Varint()); break;
                case 5 when wire == 0: maximumProtocol = checked((uint)reader.Varint()); break;
                default: throw new FormatException("Unknown compatibility product field.");
            }
        }
        return new((CertaelProduct)(product ?? 0), minimum ?? string.Empty,
            recommended ?? string.Empty, minimumProtocol ?? 0, maximumProtocol ?? 0);
    }

    private static byte[] EncodeRevocation(CompatibilityRevocation value)
    {
        using var stream = new MemoryStream(); VarintField(stream, 1, (uint)value.Product);
        String(stream, 2, value.Version); VarintField(stream, 3,
            checked((ulong)value.EffectiveAt.ToUnixTimeSeconds())); String(stream, 4, value.Reason);
        return stream.ToArray();
    }

    private static CompatibilityRevocation DecodeRevocation(ReadOnlySpan<byte> bytes)
    {
        var reader = new Reader(bytes); uint? product = null; string? version = null, reason = null;
        ulong? effective = null;
        while (reader.Remaining > 0)
        {
            (uint field, uint wire) = reader.Tag();
            switch (field)
            {
                case 1 when wire == 0: product = checked((uint)reader.Varint()); break;
                case 2 when wire == 2: version = reader.String(); break;
                case 3 when wire == 0: effective = reader.Varint(); break;
                case 4 when wire == 2: reason = reader.String(); break;
                default: throw new FormatException("Unknown compatibility revocation field.");
            }
        }
        return new((CertaelProduct)(product ?? 0), version ?? string.Empty,
            DateTimeOffset.FromUnixTimeSeconds(checked((long)(effective ?? 0))), reason ?? string.Empty);
    }

    private static void VarintField(Stream stream, uint field, ulong value)
    { Varint(stream, ((ulong)field << 3)); Varint(stream, value); }
    private static void Bytes(Stream stream, uint field, ReadOnlySpan<byte> value)
    { Varint(stream, ((ulong)field << 3) | 2); Varint(stream, (ulong)value.Length); stream.Write(value); }
    private static void String(Stream stream, uint field, string value) => Bytes(stream, field,
        Encoding.UTF8.GetBytes(value));
    private static void Varint(Stream stream, ulong value)
    { while (value >= 0x80) { stream.WriteByte((byte)(value | 0x80)); value >>= 7; } stream.WriteByte((byte)value); }

    private ref struct Reader(ReadOnlySpan<byte> input)
    {
        private ReadOnlySpan<byte> _input = input; private int _offset;
        public int Remaining => _input.Length - _offset;
        public (uint Field, uint Wire) Tag()
        { ulong tag = Varint(); if ((tag >> 3) == 0 || (tag & 7) is not (0 or 2)) throw new FormatException("Invalid protobuf tag."); return (checked((uint)(tag >> 3)), (uint)(tag & 7)); }
        public ulong Varint()
        {
            ulong value = 0; for (int shift = 0; shift < 64; shift += 7)
            { if (_offset >= _input.Length) throw new FormatException("Truncated varint."); byte next = _input[_offset++]; value |= (ulong)(next & 0x7f) << shift; if ((next & 0x80) == 0) { if (shift > 0 && next == 0) throw new FormatException("Noncanonical varint."); return value; } }
            throw new FormatException("Varint overflow.");
        }
        public byte[] Bytes()
        { ulong length = Varint(); if (length > (ulong)Remaining || length > 64 * 1024) throw new FormatException("Invalid field length."); byte[] result = _input.Slice(_offset, checked((int)length)).ToArray(); _offset += result.Length; return result; }
        public string String()
        { string value = new UTF8Encoding(false, true).GetString(Bytes()); if (value.Length > 256) throw new FormatException("String is too long."); return value; }
    }
}
