using System.Security.Cryptography;
using System.Text;

namespace Certael.Server.Rules;

public static class WasmRuleV1Codec
{
    public const uint SchemaVersion = 1;
    public const int MaximumInputBytes = 1024 * 1024;
    public const int MaximumOutputBytes = 64 * 1024;

    public static byte[] EncodeInput(WasmRuleInputV1 value)
    {
        ValidateInput(value);
        using var output = new MemoryStream();
        WriteUnsigned(output, 1, SchemaVersion);
        WriteString(output, 2, value.TenantId); WriteString(output, 3, value.GameId);
        WriteString(output, 4, value.EnvironmentId); WriteString(output, 5, value.RuleId);
        WriteString(output, 6, value.RuleVersion); WriteBytes(output, 7, value.CanonicalAction);
        WriteBytes(output, 8, value.CanonicalState);
        byte[] result = output.ToArray();
        if (result.Length > MaximumInputBytes)
            throw new WasmRuleException("WASM input exceeds 1 MiB.");
        return result;
    }

    public static WasmRuleInputV1 DecodeInput(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > MaximumInputBytes)
            throw new WasmRuleException("WASM input size is invalid.");
        var reader = new Reader(encoded.ToArray());
        if (reader.UInt32(1) != SchemaVersion)
            throw new WasmRuleException("WASM input schema is unsupported.");
        var value = new WasmRuleInputV1(reader.String(2), reader.String(3),
            reader.String(4), reader.String(5), reader.String(6),
            reader.Bytes(7, MaximumInputBytes), reader.Bytes(8, MaximumInputBytes));
        reader.RequireEnd(); ValidateInput(value);
        if (!CryptographicOperations.FixedTimeEquals(EncodeInput(value), encoded))
            throw new WasmRuleException("WASM input is not canonical.");
        return value;
    }

    public static byte[] EncodeDecision(WasmRuleDecisionV1 value)
    {
        ValidateDecision(value);
        using var output = new MemoryStream();
        WriteUnsigned(output, 1, SchemaVersion); WriteUnsigned(output, 2, (byte)value.Outcome);
        WriteString(output, 3, value.PublicReason); WriteUnsigned(output, 4, (uint)value.BoundedRisk);
        foreach ((string key, string entryValue) in value.BoundedEvidence
                     .OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            using var entry = new MemoryStream();
            WriteString(entry, 1, key); WriteString(entry, 2, entryValue);
            WriteBytes(output, 5, entry.ToArray());
        }
        byte[] result = output.ToArray();
        if (result.Length > MaximumOutputBytes)
            throw new WasmRuleException("WASM decision exceeds 64 KiB.");
        return result;
    }

    public static WasmRuleDecisionV1 DecodeDecision(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > MaximumOutputBytes)
            throw new WasmRuleException("WASM decision size is invalid.");
        var reader = new Reader(encoded.ToArray());
        if (reader.UInt32(1) != SchemaVersion)
            throw new WasmRuleException("WASM decision schema is unsupported.");
        WasmRuleOutcome outcome = (WasmRuleOutcome)reader.UInt32(2);
        string reason = reader.String(3);
        int risk = checked((int)reader.UInt32(4));
        var evidence = new SortedDictionary<string, string>(StringComparer.Ordinal);
        while (!reader.End)
        {
            byte[] bytes = reader.Bytes(5, MaximumOutputBytes, allowRepeated: true);
            var entry = new Reader(bytes);
            string key = entry.String(1); string value = entry.String(2);
            entry.RequireEnd();
            if (!evidence.TryAdd(key, value))
                throw new WasmRuleException("WASM decision has duplicate evidence.");
        }
        var decision = new WasmRuleDecisionV1(outcome, reason, risk, evidence);
        ValidateDecision(decision);
        if (!CryptographicOperations.FixedTimeEquals(EncodeDecision(decision), encoded))
            throw new WasmRuleException("WASM decision is not canonical.");
        return decision;
    }

    private static void ValidateInput(WasmRuleInputV1 value)
    {
        if (!Identifier(value.TenantId) || !Identifier(value.GameId)
            || !Identifier(value.EnvironmentId) || !Identifier(value.RuleId)
            || !Identifier(value.RuleVersion) || value.CanonicalAction is null
            || value.CanonicalState is null || value.CanonicalAction.Length < 1
            || value.CanonicalAction.Length + (long)value.CanonicalState.Length > MaximumInputBytes)
            throw new WasmRuleException("WASM input fields are invalid.");
    }

    private static void ValidateDecision(WasmRuleDecisionV1 value)
    {
        if (!Enum.IsDefined(value.Outcome) || !Reason(value.PublicReason)
            || value.BoundedRisk is < 0 or > 100 || value.BoundedEvidence is null
            || value.BoundedEvidence.Count > 64 || value.BoundedEvidence.Any(entry =>
                !Identifier(entry.Key, 64) || entry.Value is null || entry.Value.Length > 4096
                || entry.Value.Any(char.IsControl)))
            throw new WasmRuleException("WASM decision fields are invalid.");
    }

    private static bool Identifier(string value, int maximum = 128) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum
        && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
    private static bool Reason(string value) => Identifier(value, 64);
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
        public bool End => _offset == input.Length;
        public uint UInt32(uint field)
        { ulong value = Unsigned(field); return value <= uint.MaxValue ? (uint)value : throw Error("integer"); }
        public ulong Unsigned(uint field) { Key(field, 0, false); return Varint(); }
        public string String(uint field) => new UTF8Encoding(false, true)
            .GetString(Bytes(field, 4096));
        public byte[] Bytes(uint field, int maximum, bool allowRepeated = false)
        {
            Key(field, 2, allowRepeated); ulong raw = Varint();
            if (raw > int.MaxValue) throw Error("length");
            int length = (int)raw;
            if (length > maximum || _offset > input.Length - length) throw Error("length");
            byte[] value = input.AsSpan(_offset, length).ToArray(); _offset += length; return value;
        }
        public void RequireEnd() { if (!End) throw Error("trailing field"); }
        private void Key(uint expected, ulong wire, bool allowRepeated)
        {
            ulong key = Varint();
            if (key >> 3 > uint.MaxValue) throw Error("field");
            uint field = (uint)(key >> 3);
            if (field != expected || field < _lastField
                || field == _lastField && !allowRepeated || (key & 7) != wire)
                throw Error("field order");
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
                    if (!canonical.ToArray().AsSpan().SequenceEqual(
                            input.AsSpan(start, _offset - start))) throw Error("non-minimal varint");
                    return value;
                }
            }
            throw Error("varint overflow");
        }
        private static WasmRuleException Error(string detail) =>
            new($"WASM protobuf has invalid {detail}.");
    }
}

public sealed class WasmRuleException(string message, Exception? inner = null)
    : Exception(message, inner);
