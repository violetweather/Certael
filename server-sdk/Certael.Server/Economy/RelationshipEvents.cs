using System.Security.Cryptography;
using System.Text;
using Certael.Server.Actions;

namespace Certael.Server.Economy;

public enum RelationshipKind : byte
{
    Match = 1, Outcome = 2, Trade = 3, Gift = 4,
    Marketplace = 5, Reward = 6, Party = 7
}

public sealed record RelationshipEventV1(
    Guid EventId, Guid AuthoritativeActionId, string TenantId, string GameId,
    string EnvironmentId, RelationshipKind Kind, string SourceSubject,
    string TargetSubject, long Weight, DateTimeOffset OccurredAt);

/// <summary>Strict deterministic Protobuf-wire codec for relationship edges.</summary>
public static class RelationshipEventV1Codec
{
    public const uint SchemaVersion = 1;
    public const int MaximumEncodedSize = 4096;

    public static byte[] Encode(RelationshipEventV1 value)
    {
        Validate(value);
        using var output = new MemoryStream();
        WriteUnsigned(output, 1, SchemaVersion);
        WriteGuid(output, 2, value.EventId);
        WriteGuid(output, 3, value.AuthoritativeActionId);
        WriteString(output, 4, value.TenantId);
        WriteString(output, 5, value.GameId);
        WriteString(output, 6, value.EnvironmentId);
        WriteUnsigned(output, 7, (byte)value.Kind);
        WriteString(output, 8, value.SourceSubject);
        WriteString(output, 9, value.TargetSubject);
        WriteSigned(output, 10, value.Weight);
        WriteUnsigned(output, 11, checked((ulong)value.OccurredAt.ToUnixTimeMilliseconds()));
        return output.ToArray();
    }

    public static RelationshipEventV1 Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > MaximumEncodedSize)
            throw new EconomyEventException("Relationship event size is invalid.");
        try
        {
            var reader = new Reader(encoded.ToArray());
            if (reader.UInt32(1) != SchemaVersion)
                throw new EconomyEventException("Relationship schema is unsupported.");
            Guid eventId = reader.Guid(2);
            Guid actionId = reader.Guid(3);
            string tenant = reader.String(4);
            string game = reader.String(5);
            string environment = reader.String(6);
            RelationshipKind kind = (RelationshipKind)reader.UInt32(7);
            string source = reader.String(8);
            string target = reader.String(9);
            long weight = reader.Signed(10);
            ulong timestamp = reader.Unsigned(11);
            if (timestamp > long.MaxValue)
                throw new EconomyEventException("Relationship timestamp is invalid.");
            reader.RequireEnd();
            var value = new RelationshipEventV1(eventId, actionId, tenant, game, environment,
                kind, source, target, weight,
                DateTimeOffset.FromUnixTimeMilliseconds((long)timestamp));
            Validate(value);
            if (!CryptographicOperations.FixedTimeEquals(Encode(value), encoded))
                throw new EconomyEventException("Relationship event is not canonical.");
            return value;
        }
        catch (Exception exception) when (exception is ArgumentOutOfRangeException
            or DecoderFallbackException or OverflowException)
        { throw new EconomyEventException("Relationship event is malformed.", exception); }
    }

    public static void Validate(RelationshipEventV1 value)
    {
        if (value.EventId == Guid.Empty || value.AuthoritativeActionId == Guid.Empty
            || !Identifier(value.TenantId) || !Identifier(value.GameId)
            || !Identifier(value.EnvironmentId) || !Identifier(value.SourceSubject)
            || !Identifier(value.TargetSubject) || value.SourceSubject == value.TargetSubject
            || !Enum.IsDefined(value.Kind) || value.Weight == 0
            || value.OccurredAt.ToUnixTimeMilliseconds() < 0)
            throw new EconomyEventException("Relationship event fields are invalid.");
    }

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
    private static void WriteGuid(Stream output, uint field, Guid value)
    { Span<byte> bytes = stackalloc byte[16]; value.TryWriteBytes(bytes, true, out _); WriteBytes(output, field, bytes); }
    private static void WriteString(Stream output, uint field, string value) =>
        WriteBytes(output, field, Encoding.UTF8.GetBytes(value));
    private static void WriteSigned(Stream output, uint field, long value) =>
        WriteUnsigned(output, field, unchecked((ulong)((value << 1) ^ (value >> 63))));
    private static void WriteUnsigned(Stream output, uint field, ulong value)
    { WriteVarint(output, (ulong)field << 3); WriteVarint(output, value); }
    private static void WriteBytes(Stream output, uint field, ReadOnlySpan<byte> value)
    { WriteVarint(output, ((ulong)field << 3) | 2); WriteVarint(output, (ulong)value.Length); output.Write(value); }
    private static void WriteVarint(Stream output, ulong value)
    { while (value >= 0x80) { output.WriteByte((byte)(value | 0x80)); value >>= 7; } output.WriteByte((byte)value); }

    private sealed class Reader(byte[] input)
    {
        private int _offset;
        private uint _lastField;
        public uint UInt32(uint field)
        { ulong value = Unsigned(field); return value <= uint.MaxValue ? (uint)value : throw Error("integer"); }
        public ulong Unsigned(uint field) { Key(field, 0); return Varint(); }
        public long Signed(uint field)
        { ulong value = Unsigned(field); return unchecked((long)(value >> 1) ^ -((long)value & 1)); }
        public Guid Guid(uint field) => new(Bytes(field, 16, true), true);
        public string String(uint field) => new UTF8Encoding(false, true).GetString(Bytes(field, 128, false));
        public void RequireEnd() { if (_offset != input.Length) throw Error("trailing field"); }
        private byte[] Bytes(uint field, int maximum, bool exact)
        {
            Key(field, 2); ulong raw = Varint();
            if (raw > int.MaxValue) throw Error("length");
            int length = (int)raw;
            if (length > maximum || exact && length != maximum || _offset > input.Length - length)
                throw Error("length");
            byte[] value = input.AsSpan(_offset, length).ToArray(); _offset += length; return value;
        }
        private void Key(uint expected, ulong wire)
        {
            ulong key = Varint();
            if (key >> 3 > uint.MaxValue) throw Error("field");
            uint field = (uint)(key >> 3);
            if (field != expected || field <= _lastField || (key & 7) != wire) throw Error("field order");
            _lastField = field;
        }
        private ulong Varint()
        {
            int start = _offset; ulong value = 0;
            for (int shift = 0; shift <= 63; shift += 7)
            {
                if (_offset >= input.Length) throw Error("truncated varint");
                byte current = input[_offset++];
                if (shift == 63 && current > 1) throw Error("varint overflow");
                value |= (ulong)(current & 0x7f) << shift;
                if ((current & 0x80) == 0)
                {
                    using var canonical = new MemoryStream(); WriteVarint(canonical, value);
                    if (!canonical.ToArray().AsSpan().SequenceEqual(input.AsSpan(start, _offset - start)))
                        throw Error("non-minimal varint");
                    return value;
                }
            }
            throw Error("varint overflow");
        }
        private static EconomyEventException Error(string detail) =>
            new($"Relationship event has invalid {detail}.");
    }
}

public interface IRelationshipEventSink
{
    ValueTask StageAsync(RelationshipEventV1 value,
        CancellationToken cancellationToken = default);
}

public sealed class AuthoritativeTransactionRelationshipEventSink<TState>(
    IAuthoritativeTransaction<TState> transaction) : IRelationshipEventSink
{
    public ValueTask StageAsync(RelationshipEventV1 value,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        transaction.EnqueueAuthoritativeEvent(new AuthoritativeEvent(value.EventId,
            value.AuthoritativeActionId, "relationship.v1", RelationshipEventV1Codec.SchemaVersion,
            RelationshipEventV1Codec.Encode(value), value.OccurredAt));
        return ValueTask.CompletedTask;
    }
}
