using System.Buffers;
using System.Text;

namespace Certael.Server.Sessions;

/// <summary>Strict deterministic Protobuf-wire codec for protocol-v1 bootstrap claims.</summary>
public static class BinaryBootstrapTicketClaimsCodec
{
    public const int MaximumClaimsLength = 4096;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static byte[] Encode(BootstrapTicketClaims claims)
    {
        Validate(claims);
        var writer = new ArrayBufferWriter<byte>();
        WriteText(writer, 1, claims.Issuer);
        WriteText(writer, 2, claims.Audience);
        WriteText(writer, 3, claims.TicketId.ToString("N"));
        WriteText(writer, 4, claims.TenantId);
        WriteText(writer, 5, claims.GameId);
        WriteText(writer, 6, claims.EnvironmentId);
        WriteText(writer, 7, claims.PlayerSubject);
        WriteText(writer, 8, claims.MatchId);
        WriteText(writer, 9, claims.AuthoritativeServerId);
        WriteText(writer, 10, claims.BuildId);
        WriteText(writer, 11, claims.ProtectionProfile);
        WriteBytes(writer, 12, claims.EphemeralPublicKey);
        WriteUnsigned(writer, 13, checked((ulong)claims.IssuedAt.ToUnixTimeSeconds()));
        WriteUnsigned(writer, 14, checked((ulong)claims.NotBefore.ToUnixTimeSeconds()));
        WriteUnsigned(writer, 15, checked((ulong)claims.ExpiresAt.ToUnixTimeSeconds()));
        WriteUnsigned(writer, 16, claims.ProtocolMinimum);
        WriteUnsigned(writer, 17, claims.ProtocolMaximum);
        if (writer.WrittenCount > MaximumClaimsLength)
            throw new TicketClaimsException("Ticket claims exceed the production size limit.");
        return writer.WrittenSpan.ToArray();
    }

    public static BootstrapTicketClaims Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > MaximumClaimsLength)
            throw new TicketClaimsException("Ticket claims length is invalid.");
        var reader = new Reader(encoded);
        string issuer = reader.Text(1);
        string audience = reader.Text(2);
        string ticketText = reader.Text(3);
        string tenant = reader.Text(4);
        string game = reader.Text(5);
        string environment = reader.Text(6);
        string player = reader.Text(7);
        string match = reader.Text(8);
        string server = reader.Text(9);
        string build = reader.Text(10);
        string profile = reader.Text(11);
        byte[] ephemeral = reader.Bytes(12, 32);
        long issued = ToInt64(reader.Unsigned(13));
        long notBefore = ToInt64(reader.Unsigned(14));
        long expires = ToInt64(reader.Unsigned(15));
        uint protocolMinimum = ToUInt32(reader.Unsigned(16));
        uint protocolMaximum = ToUInt32(reader.Unsigned(17));
        if (!reader.End)
            throw new TicketClaimsException("Unknown, duplicate, or trailing fields are prohibited.");
        if (!Guid.TryParseExact(ticketText, "N", out Guid ticketId))
            throw new TicketClaimsException("Ticket ID is noncanonical.");
        try
        {
            var claims = new BootstrapTicketClaims(issuer, audience, ticketId, tenant, game,
                environment, player, match, server, build, profile, ephemeral,
                DateTimeOffset.FromUnixTimeSeconds(issued), DateTimeOffset.FromUnixTimeSeconds(notBefore),
                DateTimeOffset.FromUnixTimeSeconds(expires), protocolMinimum, protocolMaximum);
            Validate(claims);
            if (!encoded.SequenceEqual(Encode(claims)))
                throw new TicketClaimsException("Ticket claims are not canonically encoded.");
            return claims;
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new TicketClaimsException("Ticket timestamp is invalid.", exception);
        }
        catch (OverflowException exception)
        {
            throw new TicketClaimsException("Ticket numeric field is invalid.", exception);
        }
    }

    public static void Validate(BootstrapTicketClaims claims)
    {
        Text(claims.Issuer, 512, nameof(claims.Issuer));
        Text(claims.Audience, 256, nameof(claims.Audience));
        Identifier(claims.TenantId, nameof(claims.TenantId));
        Identifier(claims.GameId, nameof(claims.GameId));
        Identifier(claims.EnvironmentId, nameof(claims.EnvironmentId));
        Identifier(claims.PlayerSubject, nameof(claims.PlayerSubject));
        Identifier(claims.MatchId, nameof(claims.MatchId));
        Identifier(claims.AuthoritativeServerId, nameof(claims.AuthoritativeServerId));
        Identifier(claims.BuildId, nameof(claims.BuildId));
        Identifier(claims.ProtectionProfile, nameof(claims.ProtectionProfile));
        if (claims.TicketId == Guid.Empty || claims.EphemeralPublicKey.Length != 32)
            throw new TicketClaimsException("Ticket ID or ephemeral key is invalid.");
        if (claims.IssuedAt < DateTimeOffset.UnixEpoch || claims.IssuedAt > claims.NotBefore
            || claims.NotBefore >= claims.ExpiresAt)
            throw new TicketClaimsException("Ticket timestamp ordering is invalid.");
        if (claims.ProtocolMinimum == 0 || claims.ProtocolMaximum < claims.ProtocolMinimum)
            throw new TicketClaimsException("Ticket protocol range is invalid.");
    }

    private static void Identifier(string value, string name)
    {
        Text(value, 256, name);
        if (value.Any(character => char.IsControl(character)))
            throw new TicketClaimsException($"{name} contains a prohibited character.");
    }

    private static void Text(string value, int maximumBytes, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new TicketClaimsException($"{name} is required.");
        int length;
        try { length = StrictUtf8.GetByteCount(value); }
        catch (EncoderFallbackException exception)
        { throw new TicketClaimsException($"{name} is not valid UTF-8.", exception); }
        if (length > maximumBytes) throw new TicketClaimsException($"{name} is too long.");
    }

    private static void WriteText(IBufferWriter<byte> writer, uint field, string value) =>
        WriteBytes(writer, field, StrictUtf8.GetBytes(value));

    private static void WriteBytes(IBufferWriter<byte> writer, uint field, ReadOnlySpan<byte> value)
    {
        WriteVarint(writer, ((ulong)field << 3) | 2);
        WriteVarint(writer, checked((ulong)value.Length));
        writer.Write(value);
    }

    private static void WriteUnsigned(IBufferWriter<byte> writer, uint field, ulong value)
    {
        WriteVarint(writer, (ulong)field << 3);
        WriteVarint(writer, value);
    }

    private static void WriteVarint(IBufferWriter<byte> writer, ulong value)
    {
        Span<byte> bytes = stackalloc byte[10];
        int count = 0;
        do
        {
            byte next = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0) next |= 0x80;
            bytes[count++] = next;
        } while (value != 0);
        writer.Write(bytes[..count]);
    }

    private static long ToInt64(ulong value) => value <= long.MaxValue
        ? (long)value : throw new TicketClaimsException("Ticket integer overflows Int64.");

    private static uint ToUInt32(ulong value) => value <= uint.MaxValue
        ? (uint)value : throw new TicketClaimsException("Ticket integer overflows UInt32.");

    private ref struct Reader(ReadOnlySpan<byte> encoded)
    {
        private ReadOnlySpan<byte> _remaining = encoded;
        public bool End => _remaining.IsEmpty;

        public string Text(uint field)
        {
            byte[] bytes = Bytes(field, 512);
            try { return StrictUtf8.GetString(bytes); }
            catch (DecoderFallbackException exception)
            { throw new TicketClaimsException("Ticket text is not valid UTF-8.", exception); }
        }

        public byte[] Bytes(uint field, int maximum)
        {
            ExpectTag(field, 2);
            ulong unsignedLength = Varint();
            if (unsignedLength > (ulong)maximum || unsignedLength > (ulong)_remaining.Length)
                throw new TicketClaimsException("Ticket field length is invalid.");
            int length = checked((int)unsignedLength);
            byte[] value = _remaining[..length].ToArray();
            _remaining = _remaining[length..];
            return value;
        }

        public ulong Unsigned(uint field)
        {
            ExpectTag(field, 0);
            return Varint();
        }

        private void ExpectTag(uint field, uint wire)
        {
            ulong actual = Varint();
            ulong expected = ((ulong)field << 3) | wire;
            if (actual != expected)
                throw new TicketClaimsException("Ticket fields are missing, duplicated, or out of order.");
        }

        private ulong Varint()
        {
            ulong result = 0;
            for (int index = 0; index < 10; index++)
            {
                if (_remaining.IsEmpty) throw new TicketClaimsException("Ticket varint is truncated.");
                byte value = _remaining[0];
                _remaining = _remaining[1..];
                if (index == 9 && value > 1) throw new TicketClaimsException("Ticket varint overflows.");
                result |= (ulong)(value & 0x7f) << (index * 7);
                if ((value & 0x80) == 0)
                {
                    if (index > 0 && value == 0)
                        throw new TicketClaimsException("Ticket varint is not minimally encoded.");
                    return result;
                }
            }
            throw new TicketClaimsException("Ticket varint is invalid.");
        }
    }
}

public sealed class TicketClaimsException : Exception
{
    public TicketClaimsException(string message) : base(message) { }
    public TicketClaimsException(string message, Exception innerException) : base(message, innerException) { }
}
