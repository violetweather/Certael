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

public static class EconomyEventV1Codec
{
    public const uint SchemaVersion = 1;
    public const int MaximumLines = 256;
    public const int MaximumEncodedSize = 128 * 1024;

    public static byte[] Encode(EconomyEventV1 value)
    {
        Validate(value);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), leaveOpen: true);
        writer.Write(SchemaVersion);
        WriteGuid(writer, value.EventId);
        WriteText(writer, value.TenantId);
        WriteText(writer, value.GameId);
        WriteText(writer, value.EnvironmentId);
        WriteText(writer, value.PlayerSubject);
        writer.Write(value.OccurredAt.ToUnixTimeMilliseconds());
        writer.Write((byte)value.Kind);
        if (value.Kind == EconomyEventKind.LedgerTransaction)
        {
            EconomyTransaction transaction = value.Transaction!;
            WriteText(writer, transaction.TransactionId);
            WriteGuid(writer, transaction.AuthoritativeActionId);
            WriteText(writer, transaction.ReasonCode);
            WriteText(writer, transaction.SourceAccountId);
            WriteText(writer, transaction.SinkAccountId);
            writer.Write(transaction.Lines.Count);
            foreach (EconomyLedgerLine line in transaction.Lines)
            {
                WriteText(writer, line.AccountId);
                WriteText(writer, line.AssetId);
                writer.Write(line.Quantity);
            }
        }
        else
        {
            ItemLineageMutation mutation = value.ItemMutation!;
            WriteText(writer, mutation.MutationId);
            WriteGuid(writer, mutation.AuthoritativeActionId);
            writer.Write((byte)mutation.MutationKind);
            WriteText(writer, mutation.ItemId);
            WriteText(writer, mutation.AssetId);
            WriteText(writer, mutation.AccountId);
            WriteText(writer, mutation.ParentItemId ?? "");
            WriteText(writer, mutation.ReasonCode);
        }
        writer.Flush();
        byte[] encoded = stream.ToArray();
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
            using var stream = new MemoryStream(encoded.ToArray(), writable: false);
            using var reader = new BinaryReader(stream, new UTF8Encoding(false, true));
            if (reader.ReadUInt32() != SchemaVersion)
                throw new EconomyEventException("Economy event schema is unsupported.");
            Guid eventId = ReadGuid(reader);
            string tenant = ReadText(reader);
            string game = ReadText(reader);
            string environment = ReadText(reader);
            string player = ReadText(reader);
            DateTimeOffset occurredAt = DateTimeOffset.FromUnixTimeMilliseconds(reader.ReadInt64());
            EconomyEventKind kind = (EconomyEventKind)reader.ReadByte();
            EconomyTransaction? transaction = null;
            ItemLineageMutation? mutation = null;
            if (kind == EconomyEventKind.LedgerTransaction)
            {
                string transactionId = ReadText(reader);
                Guid actionId = ReadGuid(reader);
                string reason = ReadText(reader);
                string source = ReadText(reader);
                string sink = ReadText(reader);
                int count = reader.ReadInt32();
                if (count is < 2 or > MaximumLines)
                    throw new EconomyEventException("Economy line count is invalid.");
                var lines = new EconomyLedgerLine[count];
                for (int index = 0; index < count; index++)
                    lines[index] = new EconomyLedgerLine(ReadText(reader), ReadText(reader), reader.ReadInt64());
                transaction = new EconomyTransaction(transactionId, actionId, reason, source, sink, lines);
            }
            else if (kind == EconomyEventKind.ItemLineageMutation)
            {
                mutation = new ItemLineageMutation(ReadText(reader), ReadGuid(reader),
                    (ItemMutationKind)reader.ReadByte(), ReadText(reader), ReadText(reader),
                    ReadText(reader), EmptyToNull(ReadText(reader)), ReadText(reader));
            }
            else throw new EconomyEventException("Economy event kind is invalid.");
            if (stream.Position != stream.Length)
                throw new EconomyEventException("Economy event has trailing data.");
            var result = new EconomyEventV1(eventId, tenant, game, environment, player,
                occurredAt, kind, transaction, mutation);
            Validate(result);
            if (!CryptographicOperations.FixedTimeEquals(Encode(result), encoded))
                throw new EconomyEventException("Economy event is not canonical.");
            return result;
        }
        catch (Exception exception) when (exception is EndOfStreamException or IOException
            or DecoderFallbackException or ArgumentOutOfRangeException)
        {
            throw new EconomyEventException("Economy event is malformed.");
        }
    }

    public static byte[] ReplayDigest(IEnumerable<EconomyEventV1> events)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (EconomyEventV1 value in events.OrderBy(value => value.OccurredAt)
                     .ThenBy(value => value.EventId))
        {
            byte[] encoded = Encode(value);
            hash.AppendData(BitConverter.GetBytes(encoded.Length));
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

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
    private static void WriteGuid(BinaryWriter writer, Guid value)
    { Span<byte> bytes = stackalloc byte[16]; value.TryWriteBytes(bytes, bigEndian: true, out _); writer.Write(bytes); }
    private static Guid ReadGuid(BinaryReader reader) => new(reader.ReadBytes(16), bigEndian: true);
    private static void WriteText(BinaryWriter writer, string value)
    { byte[] bytes = Encoding.UTF8.GetBytes(value); writer.Write((ushort)bytes.Length); writer.Write(bytes); }
    private static string ReadText(BinaryReader reader)
    { int length = reader.ReadUInt16(); return new UTF8Encoding(false, true).GetString(reader.ReadBytes(length)); }
    private static string? EmptyToNull(string value) => value.Length == 0 ? null : value;
}

public sealed class EconomyEventException(string message) : Exception(message);
