using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Actions;

/// <summary>Strict canonical Protobuf-wire codec for Certael protocol v1.</summary>
public static class BinaryActionEnvelopeCodec
{
    public const uint ProtocolMajor = 1;
    public const uint ProtocolMinor = 0;
    public const int MaximumPayload = 64 * 1024;
    public const int MaximumEnvelope = MaximumPayload + 2048;

    public static byte[] Encode<T>(AuthorizedAction<T> action)
    {
        if (action.PossessionProof.Length != 64) throw new ActionEnvelopeException("Proof must be 64 bytes.");
        using var stream = new MemoryStream(192 + action.RawPayload.Length);
        WriteSigned(stream, action);
        WriteBytes(stream, 13, action.PossessionProof.Span);
        return stream.ToArray();
    }

    public static byte[] EncodeSigned<T>(AuthorizedAction<T> action)
    {
        using var stream = new MemoryStream(192 + action.RawPayload.Length);
        WriteSigned(stream, action);
        return stream.ToArray();
    }

    public static AuthorizedAction<byte[]> Decode(ReadOnlySpan<byte> input, DateTimeOffset receivedAt)
    {
        if (input.IsEmpty || input.Length > MaximumEnvelope) throw new ActionEnvelopeException("Envelope size is invalid.");
        var decoder = new Decoder(input.ToArray());
        uint major = decoder.UInt32(1);
        uint minor = decoder.UInt32(2);
        string sessionId = decoder.String(3, 128);
        ulong sequence = decoder.UInt64(4);
        byte[] actionBytes = decoder.Bytes(5, 16, exact: true);
        string actionType = decoder.String(6, 128);
        string schema = decoder.String(7, 128);
        uint schemaVersion = decoder.UInt32(8);
        byte[] bindingDigest = decoder.Bytes(9, 32, exact: true);
        ulong monotonic = decoder.UInt64(10);
        if (monotonic > long.MaxValue) throw new ActionEnvelopeException("Monotonic value is invalid.");
        byte[] payload = decoder.Bytes(11, MaximumPayload);
        byte[] previous = decoder.Bytes(12, 32, exact: true);
        byte[] proof = decoder.Bytes(13, 64, exact: true);
        decoder.RequireEnd();

        var action = new AuthorizedAction<byte[]>(sessionId, sequence,
            new Guid(actionBytes, bigEndian: true), actionType, schemaVersion, receivedAt,
            (long)monotonic, payload, payload, previous, proof, major, minor, schema, bindingDigest);
        Validate(action);
        byte[] canonical = Encode(action);
        if (!CryptographicOperations.FixedTimeEquals(canonical, input))
            throw new ActionEnvelopeException("Envelope is not canonical.");
        return action;
    }

    private static void WriteSigned<T>(Stream stream, AuthorizedAction<T> action)
    {
        Validate(action);
        WriteVarintField(stream, 1, action.ProtocolMajor);
        WriteVarintField(stream, 2, action.ProtocolMinor);
        WriteBytes(stream, 3, Encoding.UTF8.GetBytes(action.SessionId));
        WriteVarintField(stream, 4, action.Sequence);
        Span<byte> id = stackalloc byte[16];
        action.ActionId.TryWriteBytes(id, bigEndian: true, out _);
        WriteBytes(stream, 5, id);
        WriteBytes(stream, 6, Encoding.UTF8.GetBytes(action.ActionType));
        WriteBytes(stream, 7, Encoding.UTF8.GetBytes(action.RequestSchema));
        WriteVarintField(stream, 8, action.SchemaVersion);
        WriteBytes(stream, 9, action.SessionBindingDigest.Span);
        WriteVarintField(stream, 10, checked((ulong)action.ClientMonotonicMicros));
        WriteBytes(stream, 11, action.RawPayload.Span);
        WriteBytes(stream, 12, action.PreviousDigest.Span);
    }

    private static void Validate<T>(AuthorizedAction<T> action)
    {
        if (action.ProtocolMajor != ProtocolMajor || action.ProtocolMinor > ProtocolMinor
            || !Identifier(action.SessionId) || !Identifier(action.ActionType)
            || !Identifier(action.RequestSchema) || action.SchemaVersion == 0
            || action.ActionId == Guid.Empty || action.ClientMonotonicMicros < 0
            || action.RawPayload.Length > MaximumPayload || action.PreviousDigest.Length != 32
            || action.SessionBindingDigest.Length != 32)
            throw new ActionEnvelopeException("Envelope field is invalid.");
    }

    private static bool Identifier(string value) => !string.IsNullOrEmpty(value) && value.Length <= 128
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-');

    private static void WriteVarintField(Stream stream, uint field, ulong value)
    { WriteVarint(stream, ((ulong)field << 3)); WriteVarint(stream, value); }

    private static void WriteBytes(Stream stream, uint field, ReadOnlySpan<byte> value)
    { WriteVarint(stream, ((ulong)field << 3) | 2); WriteVarint(stream, checked((ulong)value.Length)); stream.Write(value); }

    private static void WriteVarint(Stream stream, ulong value)
    {
        while (value >= 0x80) { stream.WriteByte((byte)(value | 0x80)); value >>= 7; }
        stream.WriteByte((byte)value);
    }

    private sealed class Decoder(byte[] input)
    {
        private int _offset;
        private uint _lastField;

        public uint UInt32(uint field)
        { ulong value = UInt64(field); return value <= uint.MaxValue ? (uint)value : throw new ActionEnvelopeException("Integer overflow."); }

        public ulong UInt64(uint field) { Key(field, 0); return Varint(); }

        public string String(uint field, int maximum)
        {
            byte[] bytes = Bytes(field, maximum);
            try { return new UTF8Encoding(false, true).GetString(bytes); }
            catch (DecoderFallbackException) { throw new ActionEnvelopeException("String is not valid UTF-8."); }
        }

        public byte[] Bytes(uint field, int maximum, bool exact = false)
        {
            Key(field, 2);
            ulong rawLength = Varint();
            if (rawLength > int.MaxValue) throw new ActionEnvelopeException("Length is invalid.");
            int length = (int)rawLength;
            if (length > maximum || (exact && length != maximum) || _offset > input.Length - length)
                throw new ActionEnvelopeException("Field length is invalid.");
            byte[] result = input.AsSpan(_offset, length).ToArray(); _offset += length; return result;
        }

        public void RequireEnd()
        { if (_offset != input.Length) throw new ActionEnvelopeException("Unknown or trailing fields are prohibited."); }

        private void Key(uint expected, ulong wire)
        {
            ulong key = Varint();
            ulong fieldNumber = key >> 3;
            if (fieldNumber > uint.MaxValue)
                throw new ActionEnvelopeException("Field number overflows.");
            uint field = (uint)fieldNumber;
            if (field != expected || field <= _lastField || (key & 7) != wire)
                throw new ActionEnvelopeException("Fields must be unique and canonically ordered.");
            _lastField = field;
        }

        private ulong Varint()
        {
            int start = _offset; ulong value = 0;
            for (int shift = 0; shift <= 63; shift += 7)
            {
                if (_offset >= input.Length) throw new ActionEnvelopeException("Truncated varint.");
                byte current = input[_offset++];
                if (shift == 63 && current > 1) throw new ActionEnvelopeException("Varint overflow.");
                value |= (ulong)(current & 0x7f) << shift;
                if ((current & 0x80) == 0)
                {
                    using var canonical = new MemoryStream(); WriteVarint(canonical, value);
                    if (!canonical.ToArray().AsSpan().SequenceEqual(input.AsSpan(start, _offset - start)))
                        throw new ActionEnvelopeException("Non-minimal varint.");
                    return value;
                }
            }
            throw new ActionEnvelopeException("Varint overflow.");
        }
    }
}

public sealed class ActionEnvelopeException(string message) : Exception(message);
