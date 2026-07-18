using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Economy;

public enum EconomyEventKind : byte { LedgerTransaction = 1, ItemLineageMutation = 2 }
public enum ItemMutationKind : byte { Create = 1, Transfer = 2, Destroy = 3 }

public sealed record EconomyLedgerLine(string AccountId, string AssetId, long Quantity);

public sealed record EconomyTransaction(
    string TransactionId,
    Guid AuthoritativeActionId,
    string ReasonCode,
    string SourceAccountId,
    string SinkAccountId,
    IReadOnlyList<EconomyLedgerLine> Lines);

public sealed record ItemLineageMutation(
    string MutationId,
    Guid AuthoritativeActionId,
    ItemMutationKind MutationKind,
    string ItemId,
    string AssetId,
    string AccountId,
    string? ParentItemId,
    string ReasonCode);

public sealed record EconomyEventV1(
    Guid EventId,
    string TenantId,
    string GameId,
    string EnvironmentId,
    string PlayerSubject,
    DateTimeOffset OccurredAt,
    EconomyEventKind Kind,
    EconomyTransaction? Transaction,
    ItemLineageMutation? ItemMutation);

/// <summary>Strict deterministic Protobuf-wire codec for authoritative economy events.</summary>
public static class EconomyEventV1Codec
{
    public const uint SchemaVersion = 1;
    public const int MaximumLines = 256;
    public const int MaximumEncodedSize = 128 * 1024;

    public static byte[] Encode(EconomyEventV1 value)
    {
        Validate(value);
        using var output = new MemoryStream();
        Proto.WriteUnsigned(output, 1, SchemaVersion);
        Proto.WriteGuid(output, 2, value.EventId);
        Proto.WriteString(output, 3, value.TenantId);
        Proto.WriteString(output, 4, value.GameId);
        Proto.WriteString(output, 5, value.EnvironmentId);
        Proto.WriteString(output, 6, value.PlayerSubject);
        Proto.WriteUnsigned(output, 7, checked((ulong)value.OccurredAt.ToUnixTimeMilliseconds()));
        Proto.WriteUnsigned(output, 8, (byte)value.Kind);
        if (value.Kind == EconomyEventKind.LedgerTransaction)
            Proto.WriteBytes(output, 9, EncodeTransaction(value.Transaction!));
        else
            Proto.WriteBytes(output, 10, EncodeMutation(value.ItemMutation!));
        byte[] encoded = output.ToArray();
        if (encoded.Length > MaximumEncodedSize)
            throw new EconomyEventException("Economy event exceeds the encoded size limit.");
        return encoded;
    }

    public static EconomyEventV1 Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > MaximumEncodedSize)
            throw new EconomyEventException("Economy event size is invalid.");
        try
        {
            var reader = new Proto.Reader(encoded.ToArray());
            if (reader.UInt32(1) != SchemaVersion)
                throw new EconomyEventException("Economy event schema is unsupported.");
            Guid eventId = reader.Guid(2);
            string tenant = reader.String(3);
            string game = reader.String(4);
            string environment = reader.String(5);
            string player = reader.String(6);
            ulong rawTimestamp = reader.Unsigned(7);
            if (rawTimestamp > long.MaxValue)
                throw new EconomyEventException("Economy event timestamp is invalid.");
            DateTimeOffset occurredAt = DateTimeOffset.FromUnixTimeMilliseconds((long)rawTimestamp);
            EconomyEventKind kind = (EconomyEventKind)reader.UInt32(8);
            EconomyTransaction? transaction = null;
            ItemLineageMutation? mutation = null;
            if (kind == EconomyEventKind.LedgerTransaction)
                transaction = DecodeTransaction(reader.Bytes(9, MaximumEncodedSize));
            else if (kind == EconomyEventKind.ItemLineageMutation)
                mutation = DecodeMutation(reader.Bytes(10, MaximumEncodedSize));
            else
                throw new EconomyEventException("Economy event kind is invalid.");
            reader.RequireEnd();
            var value = new EconomyEventV1(eventId, tenant, game, environment, player,
                occurredAt, kind, transaction, mutation);
            Validate(value);
            if (!CryptographicOperations.FixedTimeEquals(Encode(value), encoded))
                throw new EconomyEventException("Economy event is not canonical.");
            return value;
        }
        catch (Exception exception) when (exception is ArgumentOutOfRangeException
            or DecoderFallbackException or OverflowException)
        {
            throw new EconomyEventException("Economy event is malformed.", exception);
        }
    }

    public static byte[] ReplayDigest(IEnumerable<EconomyEventV1> events)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (EconomyEventV1 value in events.OrderBy(value => value.OccurredAt)
                     .ThenBy(value => value.EventId))
        {
            byte[] encoded = Encode(value);
            BinaryPrimitives.WriteInt32BigEndian(length, encoded.Length);
            hash.AppendData(length);
            hash.AppendData(encoded);
        }
        return hash.GetHashAndReset();
    }

    public static void Validate(EconomyEventV1 value)
    {
        if (value.EventId == Guid.Empty || !Identifier(value.TenantId) || !Identifier(value.GameId)
            || !Identifier(value.EnvironmentId) || !Identifier(value.PlayerSubject)
            || value.OccurredAt.ToUnixTimeMilliseconds() < 0)
            throw new EconomyEventException("Economy event identity is invalid.");
        if (value.Kind == EconomyEventKind.LedgerTransaction)
        {
            EconomyTransaction transaction = value.Transaction
                ?? throw new EconomyEventException("Ledger transaction is required.");
            if (value.ItemMutation is not null || !Identifier(transaction.TransactionId)
                || transaction.AuthoritativeActionId == Guid.Empty || !Identifier(transaction.ReasonCode)
                || !Identifier(transaction.SourceAccountId) || !Identifier(transaction.SinkAccountId)
                || transaction.SourceAccountId == transaction.SinkAccountId
                || transaction.Lines.Count is < 2 or > MaximumLines
                || transaction.Lines.Any(line => !Identifier(line.AccountId)
                    || !Identifier(line.AssetId) || line.Quantity == 0))
                throw new EconomyEventException("Ledger transaction is invalid.");
            ValidateDoubleEntry(transaction);
        }
        else if (value.Kind == EconomyEventKind.ItemLineageMutation)
        {
            ItemLineageMutation mutation = value.ItemMutation
                ?? throw new EconomyEventException("Item mutation is required.");
            if (value.Transaction is not null || !Identifier(mutation.MutationId)
                || mutation.AuthoritativeActionId == Guid.Empty || !Identifier(mutation.ItemId)
                || !Identifier(mutation.AssetId) || !Identifier(mutation.AccountId)
                || !Identifier(mutation.ReasonCode)
                || mutation.MutationKind is < ItemMutationKind.Create or > ItemMutationKind.Destroy
                || mutation.ParentItemId is not null && !Identifier(mutation.ParentItemId))
                throw new EconomyEventException("Item mutation is invalid.");
        }
        else throw new EconomyEventException("Economy event kind is invalid.");
    }

    private static void ValidateDoubleEntry(EconomyTransaction transaction)
    {
        if (!transaction.Lines.Any(line => line.AccountId == transaction.SourceAccountId
                && line.Quantity < 0)
            || !transaction.Lines.Any(line => line.AccountId == transaction.SinkAccountId
                && line.Quantity > 0))
            throw new EconomyEventException("Ledger source and sink entries are missing.");
        try
        {
            foreach (IGrouping<string, EconomyLedgerLine> asset in transaction.Lines
                         .GroupBy(line => line.AssetId, StringComparer.Ordinal))
                if (asset.Aggregate(0L, (sum, line) => checked(sum + line.Quantity)) != 0)
                    throw new EconomyEventException("Ledger quantities do not conserve an asset.");
        }
        catch (OverflowException exception)
        { throw new EconomyEventException("Ledger quantity accumulation overflowed.", exception); }
    }

    private static byte[] EncodeTransaction(EconomyTransaction value)
    {
        using var output = new MemoryStream();
        Proto.WriteString(output, 1, value.TransactionId);
        Proto.WriteGuid(output, 2, value.AuthoritativeActionId);
        Proto.WriteString(output, 3, value.ReasonCode);
        Proto.WriteString(output, 4, value.SourceAccountId);
        Proto.WriteString(output, 5, value.SinkAccountId);
        foreach (EconomyLedgerLine line in value.Lines)
        {
            using var nested = new MemoryStream();
            Proto.WriteString(nested, 1, line.AccountId);
            Proto.WriteString(nested, 2, line.AssetId);
            Proto.WriteSigned(nested, 3, line.Quantity);
            Proto.WriteBytes(output, 6, nested.ToArray());
        }
        return output.ToArray();
    }

    private static EconomyTransaction DecodeTransaction(byte[] encoded)
    {
        var reader = new Proto.Reader(encoded);
        string id = reader.String(1);
        Guid action = reader.Guid(2);
        string reason = reader.String(3);
        string source = reader.String(4);
        string sink = reader.String(5);
        var lines = new List<EconomyLedgerLine>();
        while (!reader.End)
        {
            if (lines.Count == MaximumLines)
                throw new EconomyEventException("Economy line count is invalid.");
            var line = new Proto.Reader(reader.RepeatedBytes(6, 1024));
            lines.Add(new EconomyLedgerLine(line.String(1), line.String(2), line.Signed(3)));
            line.RequireEnd();
        }
        if (lines.Count < 2) throw new EconomyEventException("Economy line count is invalid.");
        return new EconomyTransaction(id, action, reason, source, sink, lines);
    }

    private static byte[] EncodeMutation(ItemLineageMutation value)
    {
        using var output = new MemoryStream();
        Proto.WriteString(output, 1, value.MutationId);
        Proto.WriteGuid(output, 2, value.AuthoritativeActionId);
        Proto.WriteUnsigned(output, 3, (byte)value.MutationKind);
        Proto.WriteString(output, 4, value.ItemId);
        Proto.WriteString(output, 5, value.AssetId);
        Proto.WriteString(output, 6, value.AccountId);
        if (value.ParentItemId is not null) Proto.WriteString(output, 7, value.ParentItemId);
        Proto.WriteString(output, 8, value.ReasonCode);
        return output.ToArray();
    }

    private static ItemLineageMutation DecodeMutation(byte[] encoded)
    {
        var reader = new Proto.Reader(encoded);
        string id = reader.String(1);
        Guid action = reader.Guid(2);
        ItemMutationKind kind = (ItemMutationKind)reader.UInt32(3);
        string item = reader.String(4);
        string asset = reader.String(5);
        string account = reader.String(6);
        string? parent = reader.PeekField() == 7 ? reader.String(7) : null;
        string reason = reader.String(8);
        reader.RequireEnd();
        return new ItemLineageMutation(id, action, kind, item, asset, account, parent, reason);
    }

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');

    private static class Proto
    {
        public static void WriteGuid(Stream output, uint field, Guid value)
        {
            Span<byte> bytes = stackalloc byte[16];
            value.TryWriteBytes(bytes, bigEndian: true, out _);
            WriteBytes(output, field, bytes);
        }
        public static void WriteString(Stream output, uint field, string value) =>
            WriteBytes(output, field, Encoding.UTF8.GetBytes(value));
        public static void WriteSigned(Stream output, uint field, long value) =>
            WriteUnsigned(output, field, unchecked((ulong)((value << 1) ^ (value >> 63))));
        public static void WriteUnsigned(Stream output, uint field, ulong value)
        { WriteVarint(output, (ulong)field << 3); WriteVarint(output, value); }
        public static void WriteBytes(Stream output, uint field, ReadOnlySpan<byte> value)
        {
            WriteVarint(output, ((ulong)field << 3) | 2);
            WriteVarint(output, checked((ulong)value.Length));
            output.Write(value);
        }
        private static void WriteVarint(Stream output, ulong value)
        {
            while (value >= 0x80) { output.WriteByte((byte)(value | 0x80)); value >>= 7; }
            output.WriteByte((byte)value);
        }

        public sealed class Reader(byte[] input)
        {
            private int _offset;
            private uint _lastField;
            public bool End => _offset == input.Length;
            public uint UInt32(uint field)
            {
                ulong value = Unsigned(field);
                return value <= uint.MaxValue ? (uint)value
                    : throw new EconomyEventException("Economy integer overflows.");
            }
            public ulong Unsigned(uint field) { Key(field, 0, repeated: false); return Varint(); }
            public long Signed(uint field)
            {
                ulong value = Unsigned(field);
                return unchecked((long)(value >> 1) ^ -((long)value & 1));
            }
            public Guid Guid(uint field) => new(Bytes(field, 16, exact: true), bigEndian: true);
            public string String(uint field)
            {
                byte[] bytes = Bytes(field, 128);
                return new UTF8Encoding(false, true).GetString(bytes);
            }
            public byte[] Bytes(uint field, int maximum, bool exact = false)
            { Key(field, 2, repeated: false); return ReadBytes(maximum, exact); }
            public byte[] RepeatedBytes(uint field, int maximum)
            { Key(field, 2, repeated: true); return ReadBytes(maximum, exact: false); }
            public uint PeekField()
            {
                if (End) return 0;
                int saved = _offset;
                ulong key = Varint();
                _offset = saved;
                return key >> 3 <= uint.MaxValue ? (uint)(key >> 3)
                    : throw new EconomyEventException("Economy field number overflows.");
            }
            public void RequireEnd()
            {
                if (!End) throw new EconomyEventException("Unknown or trailing economy fields are prohibited.");
            }
            private byte[] ReadBytes(int maximum, bool exact)
            {
                ulong raw = Varint();
                if (raw > int.MaxValue) throw new EconomyEventException("Economy field length is invalid.");
                int length = (int)raw;
                if (length > maximum || exact && length != maximum || _offset > input.Length - length)
                    throw new EconomyEventException("Economy field length is invalid.");
                byte[] value = input.AsSpan(_offset, length).ToArray();
                _offset += length;
                return value;
            }
            private void Key(uint expected, ulong wireType, bool repeated)
            {
                ulong key = Varint();
                uint field = key >> 3 <= uint.MaxValue ? (uint)(key >> 3)
                    : throw new EconomyEventException("Economy field number overflows.");
                bool ordered = repeated ? field >= _lastField : field > _lastField;
                if (field != expected || !ordered || (key & 7) != wireType)
                    throw new EconomyEventException("Economy fields are not canonically ordered.");
                _lastField = field;
            }
            private ulong Varint()
            {
                int start = _offset;
                ulong value = 0;
                for (int shift = 0; shift <= 63; shift += 7)
                {
                    if (_offset >= input.Length) throw new EconomyEventException("Economy varint is truncated.");
                    byte current = input[_offset++];
                    if (shift == 63 && current > 1) throw new EconomyEventException("Economy varint overflows.");
                    value |= (ulong)(current & 0x7f) << shift;
                    if ((current & 0x80) == 0)
                    {
                        using var canonical = new MemoryStream();
                        WriteVarint(canonical, value);
                        if (!canonical.ToArray().AsSpan().SequenceEqual(input.AsSpan(start, _offset - start)))
                            throw new EconomyEventException("Economy varint is not minimal.");
                        return value;
                    }
                }
                throw new EconomyEventException("Economy varint overflows.");
            }
        }
    }
}

public sealed class EconomyEventException(string message, Exception? inner = null)
    : Exception(message, inner);
