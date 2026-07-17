using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Sessions;

public sealed record RegionTransferGrantV1(Guid GrantId, string TenantId, string GameId,
    string EnvironmentId, string MatchId, string PlayerSubject, string SourceRegion,
    string DestinationRegion, long LeaseEpoch, byte[] Nonce, DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);
public sealed record SignedRegionTransferGrant(byte[] CanonicalGrant, byte[] Signature, string KeyId);

public static class RegionTransferGrantV1Codec
{
    public const uint SchemaVersion = 1;
    public static byte[] Encode(RegionTransferGrantV1 value)
    {
        Validate(value);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), true);
        writer.Write(SchemaVersion); writer.Write(value.GrantId.ToByteArray());
        foreach (string text in new[] { value.TenantId, value.GameId, value.EnvironmentId, value.MatchId,
                     value.PlayerSubject, value.SourceRegion, value.DestinationRegion }) Write(writer, text);
        writer.Write(value.LeaseEpoch); writer.Write(value.Nonce.Length); writer.Write(value.Nonce);
        writer.Write(value.IssuedAt.ToUnixTimeMilliseconds()); writer.Write(value.ExpiresAt.ToUnixTimeMilliseconds());
        writer.Flush(); return stream.ToArray();
    }
    public static RegionTransferGrantV1 Decode(ReadOnlySpan<byte> input)
    {
        try
        {
            using var stream = new MemoryStream(input.ToArray(), false); using var reader = new BinaryReader(stream, new UTF8Encoding(false, true));
            if (reader.ReadUInt32() != SchemaVersion) throw new InvalidDataException();
            var value = new RegionTransferGrantV1(new Guid(reader.ReadBytes(16)), Read(reader), Read(reader), Read(reader), Read(reader), Read(reader),
                Read(reader), Read(reader), reader.ReadInt64(), reader.ReadBytes(reader.ReadInt32()),
                DateTimeOffset.FromUnixTimeMilliseconds(reader.ReadInt64()), DateTimeOffset.FromUnixTimeMilliseconds(reader.ReadInt64()));
            if (stream.Position != stream.Length) throw new InvalidDataException(); Validate(value);
            if (!CryptographicOperations.FixedTimeEquals(input, Encode(value))) throw new InvalidDataException(); return value;
        }
        catch (Exception exception) when (exception is not RegionTransferGrantException)
        { throw new RegionTransferGrantException("Region transfer grant is invalid.", exception); }
    }
    private static void Validate(RegionTransferGrantV1 value)
    {
        string[] fields = [value.TenantId,value.GameId,value.EnvironmentId,value.MatchId,value.PlayerSubject,value.SourceRegion,value.DestinationRegion];
        if (value.GrantId == Guid.Empty || value.LeaseEpoch < 1 || value.Nonce.Length != 32
            || fields.Any(v => string.IsNullOrWhiteSpace(v) || Encoding.UTF8.GetByteCount(v) > 128 || v.Any(char.IsControl))
            || value.SourceRegion == value.DestinationRegion || value.ExpiresAt <= value.IssuedAt
            || value.ExpiresAt - value.IssuedAt > TimeSpan.FromSeconds(60))
            throw new RegionTransferGrantException("Region transfer grant fields are invalid.");
    }
    private static void Write(BinaryWriter writer, string value) { byte[] bytes = Encoding.UTF8.GetBytes(value); writer.Write((ushort)bytes.Length); writer.Write(bytes); }
    private static string Read(BinaryReader reader) { int length = reader.ReadUInt16(); if (length is < 1 or > 128) throw new InvalidDataException(); return new UTF8Encoding(false,true).GetString(reader.ReadBytes(length)); }
}

public sealed class RegionTransferGrantSigner(ECDsa key, string keyId)
{
    public SignedRegionTransferGrant Sign(RegionTransferGrantV1 value) { byte[] canonical = RegionTransferGrantV1Codec.Encode(value); return new(canonical, key.SignData(canonical, HashAlgorithmName.SHA256), keyId); }
    public static RegionTransferGrantV1 Verify(SignedRegionTransferGrant signed, IReadOnlyDictionary<string,ECDsa> keys, DateTimeOffset now)
    {
        if (!keys.TryGetValue(signed.KeyId, out ECDsa? key) || !key.VerifyData(signed.CanonicalGrant, signed.Signature, HashAlgorithmName.SHA256)) throw new RegionTransferGrantException("Region transfer signature is invalid.");
        RegionTransferGrantV1 grant = RegionTransferGrantV1Codec.Decode(signed.CanonicalGrant); if (grant.ExpiresAt <= now || grant.IssuedAt > now) throw new RegionTransferGrantException("Region transfer grant is expired or not yet valid."); return grant;
    }
}
public sealed class RegionTransferGrantException(string message, Exception? inner = null) : Exception(message, inner);
