using System.Text;

namespace Certael.Server.Agent;

public sealed record AgentLaunchApiRequest(
    string TenantId, string GameId, string EnvironmentId, string PlayerSubject,
    string MatchId, string AuthoritativeServerId, string BuildId, byte[] AgentPublicKey,
    string PolicyId, AgentRequirementMode RequirementMode, uint HeartbeatSeconds,
    uint ReportSeconds, uint DisconnectGraceSeconds, string MinimumAgentVersion,
    uint PolicyLifetimeSeconds, uint SessionLifetimeSeconds);

public sealed record AgentOperationRequest(
    string TenantId, string EnvironmentId, string AuthoritativeServerId);

public sealed record AgentReportSubmission(
    string TenantId, string EnvironmentId, string AuthoritativeServerId,
    AgentIntegrityReport Report);

public sealed record AgentRevocationRequest(
    string TenantId, string EnvironmentId, string AuthoritativeServerId, string Reason);

public static class AgentApiCodec
{
    public const string ContentType = "application/x-protobuf";
    public const int MaximumBody = 64 * 1024;

    public static AgentLaunchApiRequest DecodeLaunchRequest(ReadOnlySpan<byte> input)
    {
        var reader = new Reader(input);
        var value = new AgentLaunchApiRequest(reader.String(1), reader.String(2), reader.String(3),
            reader.String(4), reader.String(5), reader.String(6), reader.String(7), reader.Bytes(8),
            reader.String(9), (AgentRequirementMode)reader.UInt32(10), reader.UInt32(11),
            reader.UInt32(12), reader.UInt32(13), reader.String(14), reader.UInt32(15),
            reader.UInt32(16));
        reader.End();
        Canonical(input, EncodeLaunchRequest(value));
        return value;
    }

    public static byte[] EncodeLaunchRequest(AgentLaunchApiRequest value)
    {
        using var stream = New();
        String(stream, 1, value.TenantId); String(stream, 2, value.GameId);
        String(stream, 3, value.EnvironmentId); String(stream, 4, value.PlayerSubject);
        String(stream, 5, value.MatchId); String(stream, 6, value.AuthoritativeServerId);
        String(stream, 7, value.BuildId); Bytes(stream, 8, value.AgentPublicKey);
        String(stream, 9, value.PolicyId); UInt(stream, 10, (uint)value.RequirementMode);
        UInt(stream, 11, value.HeartbeatSeconds); UInt(stream, 12, value.ReportSeconds);
        UInt(stream, 13, value.DisconnectGraceSeconds);
        String(stream, 14, value.MinimumAgentVersion);
        UInt(stream, 15, value.PolicyLifetimeSeconds); UInt(stream, 16, value.SessionLifetimeSeconds);
        return Finish(stream);
    }

    public static byte[] EncodeLaunchResponse(AgentLaunchBundle value)
    {
        using var stream = New();
        String(stream, 1, value.AgentSessionId);
        Bytes(stream, 2, AgentGrantCodec.EncodeSignedPolicy(value.Policy));
        Bytes(stream, 3, AgentGrantCodec.EncodeSignedLaunchGrant(value.Grant));
        UInt(stream, 4, checked((ulong)value.ExpiresAt.ToUnixTimeSeconds()));
        Bytes(stream, 5, value.SignedBuildManifest);
        return Finish(stream);
    }

    /// <summary>Canonical payload relayed over the inherited local Agent channel.</summary>
    public static byte[] EncodeLaunchChannelBundle(AgentLaunchBundle value)
    {
        using var stream = New();
        Bytes(stream, 1, AgentGrantCodec.EncodeSignedPolicy(value.Policy));
        Bytes(stream, 2, AgentGrantCodec.EncodeSignedLaunchGrant(value.Grant));
        Bytes(stream, 3, value.SignedBuildManifest);
        return Finish(stream);
    }

    public static AgentOperationRequest DecodeOperationRequest(ReadOnlySpan<byte> input)
    {
        var reader = new Reader(input);
        var value = new AgentOperationRequest(reader.String(1), reader.String(2), reader.String(3));
        reader.End(); Canonical(input, EncodeOperationRequest(value)); return value;
    }

    public static byte[] EncodeOperationRequest(AgentOperationRequest value)
    {
        using var stream = New();
        String(stream, 1, value.TenantId); String(stream, 2, value.EnvironmentId);
        String(stream, 3, value.AuthoritativeServerId); return Finish(stream);
    }

    public static AgentReportSubmission DecodeReportSubmission(ReadOnlySpan<byte> input)
    {
        var reader = new Reader(input);
        string tenantId = reader.String(1); string environmentId = reader.String(2);
        string serverId = reader.String(3); byte[] reportBytes = reader.Bytes(4); reader.End();
        var value = new AgentReportSubmission(tenantId, environmentId, serverId,
            AgentReportCodec.Decode(reportBytes));
        Canonical(input, EncodeReportSubmission(value)); return value;
    }

    public static byte[] EncodeReportSubmission(AgentReportSubmission value)
    {
        using var stream = New();
        String(stream, 1, value.TenantId); String(stream, 2, value.EnvironmentId);
        String(stream, 3, value.AuthoritativeServerId);
        Bytes(stream, 4, AgentReportCodec.Encode(value.Report)); return Finish(stream);
    }

    public static AgentRevocationRequest DecodeRevocationRequest(ReadOnlySpan<byte> input)
    {
        var reader = new Reader(input);
        var value = new AgentRevocationRequest(reader.String(1), reader.String(2),
            reader.String(3), reader.String(4));
        reader.End(); Canonical(input, EncodeRevocationRequest(value)); return value;
    }

    public static byte[] EncodeRevocationRequest(AgentRevocationRequest value)
    {
        using var stream = New();
        String(stream, 1, value.TenantId); String(stream, 2, value.EnvironmentId);
        String(stream, 3, value.AuthoritativeServerId); String(stream, 4, value.Reason);
        return Finish(stream);
    }

    public static byte[] EncodeChallenge(AgentReportChallenge value)
    {
        using var stream = New();
        String(stream, 1, value.AgentSessionId); Bytes(stream, 2, value.Nonce);
        UInt(stream, 3, checked((ulong)value.ExpiresAt.ToUnixTimeSeconds()));
        return Finish(stream);
    }

    public static byte[] EncodeHealth(AgentSessionHealth value)
    {
        using var stream = New();
        String(stream, 1, value.AgentSessionId); String(stream, 2, value.State);
        if (value.LastReportAt is not null)
            UInt(stream, 3, checked((ulong)value.LastReportAt.Value.ToUnixTimeSeconds()));
        foreach (string reason in value.PublicReasons) String(stream, 4, reason);
        return Finish(stream);
    }

    private static MemoryStream New() => new(256);

    private static byte[] Finish(MemoryStream stream)
    {
        if (stream.Length is < 1 or > MaximumBody) throw new AgentApiException("Agent API body is invalid.");
        return stream.ToArray();
    }

    private static void String(Stream stream, uint field, string value) =>
        Bytes(stream, field, Encoding.UTF8.GetBytes(value));

    private static void Bytes(Stream stream, uint field, ReadOnlySpan<byte> value)
    {
        Varint(stream, (ulong)field << 3 | 2); Varint(stream, (ulong)value.Length); stream.Write(value);
    }

    private static void UInt(Stream stream, uint field, ulong value)
    {
        Varint(stream, (ulong)field << 3); Varint(stream, value);
    }

    private static void Varint(Stream stream, ulong value)
    {
        while (value >= 0x80) { stream.WriteByte((byte)(value | 0x80)); value >>= 7; }
        stream.WriteByte((byte)value);
    }

    private static void Canonical(ReadOnlySpan<byte> supplied, ReadOnlySpan<byte> encoded)
    {
        if (!supplied.SequenceEqual(encoded)) throw new AgentApiException("Agent API body is not canonical.");
    }

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> _input;
        private int _offset;
        private uint _lastField;

        internal Reader(ReadOnlySpan<byte> input)
        {
            if (input.Length is < 1 or > MaximumBody) throw new AgentApiException("Agent API body is invalid.");
            _input = input; _offset = 0; _lastField = 0;
        }

        internal string String(uint field)
        {
            byte[] bytes = Bytes(field);
            try { return new UTF8Encoding(false, true).GetString(bytes); }
            catch (DecoderFallbackException) { throw new AgentApiException("Agent API string is not UTF-8."); }
        }

        internal byte[] Bytes(uint field)
        {
            Tag(field, 2); ulong rawLength = ReadVarint();
            if (rawLength > int.MaxValue) throw new AgentApiException("Agent API length overflows.");
            int length = (int)rawLength;
            if (length > _input.Length - _offset) throw new AgentApiException("Agent API body is truncated.");
            byte[] value = _input.Slice(_offset, length).ToArray(); _offset += length; return value;
        }

        internal uint UInt32(uint field)
        {
            Tag(field, 0); ulong value = ReadVarint();
            return value <= uint.MaxValue ? (uint)value : throw new AgentApiException("Agent API integer overflows.");
        }

        internal void End()
        {
            if (_offset != _input.Length) throw new AgentApiException("Unknown Agent API fields are prohibited.");
        }

        private void Tag(uint expected, uint wire)
        {
            ulong raw = ReadVarint(); uint field = checked((uint)(raw >> 3));
            if (field != expected || (raw & 7) != wire || field <= _lastField)
                throw new AgentApiException("Agent API fields are invalid or out of order.");
            _lastField = field;
        }

        private ulong ReadVarint()
        {
            int start = _offset; ulong value = 0;
            for (int shift = 0; shift <= 63; shift += 7)
            {
                if (_offset >= _input.Length) throw new AgentApiException("Agent API varint is truncated.");
                byte current = _input[_offset++];
                if (shift == 63 && current > 1) throw new AgentApiException("Agent API varint overflows.");
                value |= (ulong)(current & 0x7f) << shift;
                if ((current & 0x80) == 0)
                {
                    using var canonical = new MemoryStream(); Varint(canonical, value);
                    if (!_input.Slice(start, _offset - start).SequenceEqual(canonical.ToArray()))
                        throw new AgentApiException("Agent API varint is not minimal.");
                    return value;
                }
            }
            throw new AgentApiException("Agent API varint overflows.");
        }
    }
}

public sealed class AgentApiException(string message) : Exception(message);
