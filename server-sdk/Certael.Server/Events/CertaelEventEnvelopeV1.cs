using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Events;

public sealed record CertaelEventEnvelopeV1(
    Guid EventId,
    string TenantId,
    string GameId,
    string EnvironmentId,
    string SessionId,
    Guid ActionId,
    string EventType,
    uint PayloadSchemaVersion,
    byte[] Payload,
    DateTimeOffset OccurredAt);

/// <summary>Strict deterministic Protobuf-wire codec for canonical Certael events.</summary>
public static class CertaelEventEnvelopeV1Codec
{
    public const uint SchemaVersion = 1;
    public const int MaximumPayload = 1024 * 1024;
    public const int MaximumEnvelope = MaximumPayload + 2048;

    public static byte[] Encode(CertaelEventEnvelopeV1 value)
    {
        Validate(value);
        using var stream = new MemoryStream(256 + value.Payload.Length);
        WriteUnsigned(stream, 1, SchemaVersion);
        WriteGuid(stream, 2, value.EventId);
        WriteString(stream, 3, value.TenantId);
        WriteString(stream, 4, value.GameId);
        WriteString(stream, 5, value.EnvironmentId);
        WriteString(stream, 6, value.SessionId);
        WriteGuid(stream, 7, value.ActionId);
        WriteString(stream, 8, value.EventType);
        WriteUnsigned(stream, 9, value.PayloadSchemaVersion);
        WriteBytes(stream, 10, value.Payload);
        WriteUnsigned(stream, 11, checked((ulong)value.OccurredAt.ToUnixTimeMilliseconds()));
        return stream.ToArray();
    }

    public static CertaelEventEnvelopeV1 Decode(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty || input.Length > MaximumEnvelope)
            throw new CertaelEventEnvelopeException("Event envelope size is invalid.");

        var reader = new Reader(input.ToArray());
        uint schemaVersion = reader.UInt32(1);
        Guid eventId = reader.Guid(2);
        string tenantId = reader.String(3);
        string gameId = reader.String(4);
        string environmentId = reader.String(5);
        string sessionId = reader.String(6);
        Guid actionId = reader.Guid(7);
        string eventType = reader.String(8);
        uint payloadSchemaVersion = reader.UInt32(9);
        byte[] payload = reader.Bytes(10, MaximumPayload);
        ulong occurredAtMilliseconds = reader.Unsigned(11);
        reader.RequireEnd();

        if (schemaVersion != SchemaVersion || occurredAtMilliseconds > long.MaxValue)
            throw new CertaelEventEnvelopeException("Event envelope version or timestamp is invalid.");

        DateTimeOffset occurredAt;
        try { occurredAt = DateTimeOffset.FromUnixTimeMilliseconds((long)occurredAtMilliseconds); }
        catch (ArgumentOutOfRangeException)
        { throw new CertaelEventEnvelopeException("Event timestamp is invalid."); }

        var result = new CertaelEventEnvelopeV1(eventId, tenantId, gameId, environmentId,
            sessionId, actionId, eventType, payloadSchemaVersion, payload, occurredAt);
        Validate(result);
        if (!CryptographicOperations.FixedTimeEquals(Encode(result), input))
            throw new CertaelEventEnvelopeException("Event envelope is not canonical.");
        return result;
    }

    private static void Validate(CertaelEventEnvelopeV1 value)
    {
        if (value.EventId == Guid.Empty || value.ActionId == Guid.Empty
            || !Identifier(value.TenantId) || !Identifier(value.GameId)
            || !Identifier(value.EnvironmentId) || !Identifier(value.SessionId)
            || !Identifier(value.EventType) || value.PayloadSchemaVersion == 0
            || value.Payload.Length > MaximumPayload || value.OccurredAt.ToUnixTimeMilliseconds() < 0)
            throw new CertaelEventEnvelopeException("Event envelope field is invalid.");
    }

    private static bool Identifier(string value) => !string.IsNullOrEmpty(value) && value.Length <= 128
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-');

    private static void WriteGuid(Stream stream, uint field, Guid value)
    {
        Span<byte> bytes = stackalloc byte[16];
        value.TryWriteBytes(bytes, bigEndian: true, out _);
        WriteBytes(stream, field, bytes);
    }

    private static void WriteString(Stream stream, uint field, string value) =>
        WriteBytes(stream, field, Encoding.UTF8.GetBytes(value));

    private static void WriteUnsigned(Stream stream, uint field, ulong value)
    { WriteVarint(stream, (ulong)field << 3); WriteVarint(stream, value); }

    private static void WriteBytes(Stream stream, uint field, ReadOnlySpan<byte> value)
    {
        WriteVarint(stream, ((ulong)field << 3) | 2);
        WriteVarint(stream, checked((ulong)value.Length));
        stream.Write(value);
    }

    private static void WriteVarint(Stream stream, ulong value)
    {
        while (value >= 0x80) { stream.WriteByte((byte)(value | 0x80)); value >>= 7; }
        stream.WriteByte((byte)value);
    }

    private sealed class Reader(byte[] input)
    {
        private int _offset;
        private uint _lastField;

        public uint UInt32(uint field)
        {
            ulong value = Unsigned(field);
            return value <= uint.MaxValue ? (uint)value
                : throw new CertaelEventEnvelopeException("Integer overflow.");
        }

        public ulong Unsigned(uint field) { Key(field, 0); return Varint(); }

        public Guid Guid(uint field) => new(Bytes(field, 16, exact: true), bigEndian: true);

        public string String(uint field)
        {
            byte[] bytes = Bytes(field, 128);
            try { return new UTF8Encoding(false, true).GetString(bytes); }
            catch (DecoderFallbackException)
            { throw new CertaelEventEnvelopeException("String is not valid UTF-8."); }
        }

        public byte[] Bytes(uint field, int maximum, bool exact = false)
        {
            Key(field, 2);
            ulong rawLength = Varint();
            if (rawLength > int.MaxValue) throw new CertaelEventEnvelopeException("Length is invalid.");
            int length = (int)rawLength;
            if (length > maximum || (exact && length != maximum) || _offset > input.Length - length)
                throw new CertaelEventEnvelopeException("Field length is invalid.");
            byte[] value = input.AsSpan(_offset, length).ToArray();
            _offset += length;
            return value;
        }

        public void RequireEnd()
        {
            if (_offset != input.Length)
                throw new CertaelEventEnvelopeException("Unknown or trailing fields are prohibited.");
        }

        private void Key(uint expected, ulong wireType)
        {
            ulong key = Varint();
            ulong rawField = key >> 3;
            if (rawField > uint.MaxValue) throw new CertaelEventEnvelopeException("Field number overflows.");
            uint field = (uint)rawField;
            if (field != expected || field <= _lastField || (key & 7) != wireType)
                throw new CertaelEventEnvelopeException("Fields must be unique and canonically ordered.");
            _lastField = field;
        }

        private ulong Varint()
        {
            int start = _offset;
            ulong value = 0;
            for (int shift = 0; shift <= 63; shift += 7)
            {
                if (_offset >= input.Length) throw new CertaelEventEnvelopeException("Truncated varint.");
                byte current = input[_offset++];
                if (shift == 63 && current > 1) throw new CertaelEventEnvelopeException("Varint overflow.");
                value |= (ulong)(current & 0x7f) << shift;
                if ((current & 0x80) == 0)
                {
                    using var canonical = new MemoryStream();
                    WriteVarint(canonical, value);
                    if (!canonical.ToArray().AsSpan().SequenceEqual(input.AsSpan(start, _offset - start)))
                        throw new CertaelEventEnvelopeException("Non-minimal varint.");
                    return value;
                }
            }
            throw new CertaelEventEnvelopeException("Varint overflow.");
        }
    }
}

public sealed class CertaelEventEnvelopeException(string message) : Exception(message);
