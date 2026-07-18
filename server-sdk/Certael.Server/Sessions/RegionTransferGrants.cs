using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Sessions;

public sealed record RegionTransferGrantV1(Guid GrantId, string TenantId, string GameId,
    string EnvironmentId, string MatchId, string PlayerSubject, string SourceRegion,
    string DestinationRegion, long LeaseEpoch, byte[] Nonce, DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);
public sealed record SignedRegionTransferGrant(byte[] CanonicalGrant, byte[] Digest,
    byte[] Signature, string KeyId);

public static class RegionTransferGrantV1Codec
{
    public const uint SchemaVersion = 1;
    public const int MaximumBytes = 4096;

    public static byte[] Encode(RegionTransferGrantV1 value)
    {
        Validate(value);
        using var output = new MemoryStream();
        WriteUnsigned(output, 1, SchemaVersion);
        Span<byte> grantId = stackalloc byte[16];
        value.GrantId.TryWriteBytes(grantId, bigEndian: true, out _);
        WriteBytes(output, 2, grantId);
        WriteString(output, 3, value.TenantId); WriteString(output, 4, value.GameId);
        WriteString(output, 5, value.EnvironmentId); WriteString(output, 6, value.MatchId);
        WriteString(output, 7, value.PlayerSubject); WriteString(output, 8, value.SourceRegion);
        WriteString(output, 9, value.DestinationRegion);
        WriteUnsigned(output, 10, checked((ulong)value.LeaseEpoch));
        WriteBytes(output, 11, value.Nonce);
        WriteUnsigned(output, 12, checked((ulong)value.IssuedAt.ToUnixTimeMilliseconds()));
        WriteUnsigned(output, 13, checked((ulong)value.ExpiresAt.ToUnixTimeMilliseconds()));
        byte[] result = output.ToArray();
        if (result.Length > MaximumBytes)
            throw new RegionTransferGrantException("Region transfer grant exceeds 4 KiB.");
        return result;
    }

    public static RegionTransferGrantV1 Decode(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty || input.Length > MaximumBytes)
            throw new RegionTransferGrantException("Region transfer grant size is invalid.");
        try
        {
            var reader = new Reader(input.ToArray());
            if (reader.UInt32(1) != SchemaVersion)
                throw new RegionTransferGrantException("Region transfer grant schema is unsupported.");
            byte[] grantBytes = reader.Bytes(2, 16);
            if (grantBytes.Length != 16)
                throw new RegionTransferGrantException("Region transfer grant ID is invalid.");
            var value = new RegionTransferGrantV1(new Guid(grantBytes, bigEndian: true),
                reader.String(3), reader.String(4), reader.String(5), reader.String(6),
                reader.String(7), reader.String(8), reader.String(9),
                checked((long)reader.Unsigned(10)), reader.Bytes(11, 32),
                DateTimeOffset.FromUnixTimeMilliseconds(checked((long)reader.Unsigned(12))),
                DateTimeOffset.FromUnixTimeMilliseconds(checked((long)reader.Unsigned(13))));
            reader.RequireEnd(); Validate(value);
            if (!CryptographicOperations.FixedTimeEquals(input, Encode(value)))
                throw new RegionTransferGrantException("Region transfer grant is noncanonical.");
            return value;
        }
        catch (Exception exception) when (exception is not RegionTransferGrantException)
        { throw new RegionTransferGrantException("Region transfer grant is invalid.", exception); }
    }

    private static void Validate(RegionTransferGrantV1 value)
    {
        string[] fields = [value.TenantId, value.GameId, value.EnvironmentId, value.MatchId,
            value.PlayerSubject, value.SourceRegion, value.DestinationRegion];
        if (value.GrantId == Guid.Empty || value.LeaseEpoch < 1 || value.Nonce is not { Length: 32 }
            || fields.Any(field => !Identifier(field))
            || value.SourceRegion == value.DestinationRegion || value.IssuedAt.ToUnixTimeMilliseconds() < 0
            || value.ExpiresAt <= value.IssuedAt
            || value.ExpiresAt - value.IssuedAt > TimeSpan.FromSeconds(60))
            throw new RegionTransferGrantException("Region transfer grant fields are invalid.");
    }

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && Encoding.UTF8.GetByteCount(value) <= 128
        && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
    private static void WriteString(Stream output, uint field, string value) =>
        WriteBytes(output, field, Encoding.UTF8.GetBytes(value));
    private static void WriteUnsigned(Stream output, uint field, ulong value)
    { WriteVarint(output, (ulong)field << 3); WriteVarint(output, value); }
    private static void WriteBytes(Stream output, uint field, ReadOnlySpan<byte> value)
    { WriteVarint(output, ((ulong)field << 3) | 2); WriteVarint(output, (ulong)value.Length); output.Write(value); }
    private static void WriteVarint(Stream output, ulong value)
    { while (value >= 0x80) { output.WriteByte((byte)(value | 0x80)); value >>= 7; } output.WriteByte((byte)value); }

    private sealed class Reader(byte[] input)
    {
        private int _offset; private uint _lastField;
        public uint UInt32(uint field)
        { ulong value = Unsigned(field); return value <= uint.MaxValue ? (uint)value : throw Error(); }
        public ulong Unsigned(uint field) { Key(field, 0); return Varint(); }
        public string String(uint field) => new UTF8Encoding(false, true).GetString(Bytes(field, 128));
        public byte[] Bytes(uint field, int maximum)
        {
            Key(field, 2); ulong raw = Varint();
            if (raw > (ulong)maximum || raw > int.MaxValue) throw Error();
            int length = (int)raw;
            if (_offset > input.Length - length) throw Error();
            byte[] value = input.AsSpan(_offset, length).ToArray(); _offset += length; return value;
        }
        public void RequireEnd() { if (_offset != input.Length) throw Error(); }
        private void Key(uint expected, ulong wire)
        {
            ulong key = Varint();
            if (key >> 3 != expected || expected <= _lastField || (key & 7) != wire) throw Error();
            _lastField = expected;
        }
        private ulong Varint()
        {
            int start = _offset; ulong value = 0;
            for (int shift = 0; shift <= 63; shift += 7)
            {
                if (_offset >= input.Length) throw Error();
                byte current = input[_offset++];
                if (shift == 63 && current > 1) throw Error();
                value |= (ulong)(current & 0x7f) << shift;
                if ((current & 0x80) == 0)
                {
                    using var canonical = new MemoryStream(); WriteVarint(canonical, value);
                    if (!canonical.ToArray().AsSpan().SequenceEqual(input.AsSpan(start,
                            _offset - start))) throw Error();
                    return value;
                }
            }
            throw Error();
        }
        private static InvalidDataException Error() => new("Invalid region transfer protobuf.");
    }
}

public sealed class RegionTransferGrantSigner
{
    private readonly ECDsa _key; private readonly string _keyId;
    public RegionTransferGrantSigner(ECDsa key, string keyId)
    {
        if (key.KeySize != 256 || string.IsNullOrWhiteSpace(keyId) || keyId.Length > 128
            || keyId.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not ('.' or '_' or '-' or ':')))
            throw new RegionTransferGrantException("Region transfer signing key is invalid.");
        _key = key; _keyId = keyId;
    }
    public SignedRegionTransferGrant Sign(RegionTransferGrantV1 value)
    {
        byte[] canonical = RegionTransferGrantV1Codec.Encode(value);
        byte[] digest = SHA256.HashData(canonical);
        return new(canonical, digest, _key.SignHash(digest), _keyId);
    }
    public static RegionTransferGrantV1 Verify(SignedRegionTransferGrant signed,
        IReadOnlyDictionary<string, ECDsa> keys, DateTimeOffset now)
    {
        if (signed.CanonicalGrant is null or { Length: < 1 or > RegionTransferGrantV1Codec.MaximumBytes }
            || signed.Digest is not { Length: 32 }
            || signed.Signature is null or { Length: < 64 or > 512 }
            || string.IsNullOrWhiteSpace(signed.KeyId) || signed.KeyId.Length > 128
            || !keys.TryGetValue(signed.KeyId, out ECDsa? key) || key.KeySize != 256
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(signed.CanonicalGrant), signed.Digest)
            || !key.VerifyHash(signed.Digest, signed.Signature))
            throw new RegionTransferGrantException("Region transfer signature is invalid.");
        RegionTransferGrantV1 grant = RegionTransferGrantV1Codec.Decode(signed.CanonicalGrant);
        if (grant.ExpiresAt <= now || grant.IssuedAt > now
            || now - grant.IssuedAt > TimeSpan.FromSeconds(60))
            throw new RegionTransferGrantException(
                "Region transfer grant is expired or not yet valid.");
        return grant;
    }
}

public sealed class RegionTransferGrantException(string message, Exception? inner = null)
    : Exception(message, inner);
