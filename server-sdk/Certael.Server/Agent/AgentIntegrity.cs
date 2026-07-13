using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Certael.Server.Agent;

public sealed record AgentObservation(string Code, string Value);

public sealed record AgentIntegrityReport(
    uint ProtocolVersion,
    string AgentSessionId,
    ulong Sequence,
    byte[] ChallengeNonce,
    long ObservedAtUnix,
    string BuildId,
    byte[] ExecutableSha256,
    IReadOnlyList<AgentObservation> Observations,
    byte[] PreviousReportDigest,
    byte[] Signature);

public sealed record VerifiedAgentSession(
    string AgentSessionId,
    string TenantId,
    string GameId,
    string EnvironmentId,
    string PlayerSubject,
    string MatchId,
    string BuildId,
    byte[] AgentPublicKey,
    ulong LastSequence,
    byte[] LastReportDigest,
    DateTimeOffset ExpiresAt,
    string AuthoritativeServerId = "legacy");

public enum AgentReportDecision
{
    Accepted,
    Invalid,
    Expired,
    BindingMismatch,
    Replay,
    BrokenChain,
    InvalidProof
}

/// <summary>
/// Verifies Agent transport evidence. Acceptance confirms admission integrity only;
/// it never authorizes gameplay or proves the client is honest.
/// </summary>
public sealed class AgentReportVerifier
{
    private static readonly byte[] Domain = "certael.agent.report.v1\0"u8.ToArray();

    public AgentReportDecision Verify(
        AgentIntegrityReport report,
        VerifiedAgentSession session,
        ReadOnlySpan<byte> expectedChallenge,
        DateTimeOffset now)
    {
        if (!Valid(report) || session.AgentPublicKey.Length != 32
            || expectedChallenge.Length is < 16 or > 256)
            return AgentReportDecision.Invalid;
        if (session.ExpiresAt <= now) return AgentReportDecision.Expired;
        DateTimeOffset observedAt;
        try { observedAt = DateTimeOffset.FromUnixTimeSeconds(report.ObservedAtUnix); }
        catch (ArgumentOutOfRangeException) { return AgentReportDecision.Invalid; }
        if (observedAt < now.AddMinutes(-5) || observedAt > now.AddSeconds(30))
            return AgentReportDecision.Invalid;
        if (!string.Equals(report.AgentSessionId, session.AgentSessionId, StringComparison.Ordinal)
            || !string.Equals(report.BuildId, session.BuildId, StringComparison.Ordinal)
            || !CryptographicOperations.FixedTimeEquals(report.ChallengeNonce, expectedChallenge))
            return AgentReportDecision.BindingMismatch;
        if (report.Sequence != session.LastSequence + 1) return AgentReportDecision.Replay;
        if (!CryptographicOperations.FixedTimeEquals(report.PreviousReportDigest, session.LastReportDigest))
            return AgentReportDecision.BrokenChain;
        try
        {
            PublicKey key = PublicKey.Import(SignatureAlgorithm.Ed25519,
                session.AgentPublicKey, KeyBlobFormat.RawPublicKey);
            byte[] canonical = AgentReportCodec.EncodeSigned(report);
            byte[] signed = new byte[Domain.Length + canonical.Length];
            Domain.CopyTo(signed, 0);
            canonical.CopyTo(signed, Domain.Length);
            return SignatureAlgorithm.Ed25519.Verify(key, signed, report.Signature)
                ? AgentReportDecision.Accepted : AgentReportDecision.InvalidProof;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return AgentReportDecision.InvalidProof;
        }
    }

    private static bool Valid(AgentIntegrityReport report) => report.ProtocolVersion == 1
        && Identifier(report.AgentSessionId) && report.Sequence > 0
        && report.ChallengeNonce.Length is >= 16 and <= 256
        && Identifier(report.BuildId) && report.ExecutableSha256.Length == 32
        && report.PreviousReportDigest.Length == 32 && report.Signature.Length == 64
        && report.Observations.Count <= 1024
        && report.Observations.All(value => Identifier(value.Code) && value.Value.Length <= 512
            && !value.Value.Any(char.IsControl));

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-');
}

public static class AgentReportCodec
{
    public const int MaximumReport = 64 * 1024;

    public static byte[] Encode(AgentIntegrityReport report)
    {
        if (report.Signature.Length != 64)
            throw new AgentReportException("Agent report signature must be 64 bytes.");
        using var stream = new MemoryStream(256);
        stream.Write(EncodeSigned(report));
        Bytes(stream, 10, report.Signature);
        if (stream.Length > MaximumReport) throw new AgentReportException("Agent report exceeds 64 KiB.");
        return stream.ToArray();
    }

    public static byte[] EncodeSigned(AgentIntegrityReport report)
    {
        using var stream = new MemoryStream(256);
        VarintField(stream, 1, report.ProtocolVersion);
        Bytes(stream, 2, Encoding.UTF8.GetBytes(report.AgentSessionId));
        VarintField(stream, 3, report.Sequence);
        Bytes(stream, 4, report.ChallengeNonce);
        VarintField(stream, 5, checked((ulong)report.ObservedAtUnix));
        Bytes(stream, 6, Encoding.UTF8.GetBytes(report.BuildId));
        Bytes(stream, 7, report.ExecutableSha256);
        foreach (AgentObservation observation in report.Observations)
        {
            using var nested = new MemoryStream();
            Bytes(nested, 1, Encoding.UTF8.GetBytes(observation.Code));
            Bytes(nested, 2, Encoding.UTF8.GetBytes(observation.Value));
            Bytes(stream, 8, nested.ToArray());
        }
        Bytes(stream, 9, report.PreviousReportDigest);
        if (stream.Length > MaximumReport) throw new AgentReportException("Agent report exceeds 64 KiB.");
        return stream.ToArray();
    }

    public static AgentIntegrityReport Decode(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty || input.Length > MaximumReport)
            throw new AgentReportException("Agent report size is invalid.");
        var decoder = new Decoder(input.ToArray());
        uint protocol = decoder.UInt32(1);
        string sessionId = decoder.String(2, 128);
        ulong sequence = decoder.UInt64(3);
        byte[] challenge = decoder.Bytes(4, 256, minimum: 16);
        ulong rawObservedAt = decoder.UInt64(5);
        if (rawObservedAt > long.MaxValue) throw new AgentReportException("Observed time overflows.");
        string buildId = decoder.String(6, 128);
        byte[] executable = decoder.Bytes(7, 32, exact: true);
        var observations = new List<AgentObservation>();
        while (decoder.NextFieldIs(8))
        {
            byte[] nested = decoder.Bytes(8, 1024);
            var observation = new Decoder(nested);
            string code = observation.String(1, 128);
            string value = observation.String(2, 512);
            observation.RequireEnd();
            observations.Add(new AgentObservation(code, value));
            if (observations.Count > 1024) throw new AgentReportException("Too many observations.");
        }
        byte[] previous = decoder.Bytes(9, 32, exact: true);
        byte[] signature = decoder.Bytes(10, 64, exact: true);
        decoder.RequireEnd();
        var report = new AgentIntegrityReport(protocol, sessionId, sequence, challenge,
            (long)rawObservedAt, buildId, executable, observations, previous, signature);
        if (!CryptographicOperations.FixedTimeEquals(Encode(report), input))
            throw new AgentReportException("Agent report is not canonical.");
        return report;
    }

    public static byte[] Digest(AgentIntegrityReport report)
    {
        return SHA256.HashData(Encode(report));
    }

    private static void VarintField(Stream stream, uint field, ulong value)
    { Varint(stream, (ulong)field << 3); Varint(stream, value); }

    private static void Bytes(Stream stream, uint field, ReadOnlySpan<byte> value)
    { Varint(stream, ((ulong)field << 3) | 2); Varint(stream, (ulong)value.Length); stream.Write(value); }

    private static void Varint(Stream stream, ulong value)
    {
        while (value >= 0x80) { stream.WriteByte((byte)(value | 0x80)); value >>= 7; }
        stream.WriteByte((byte)value);
    }

    private sealed class Decoder(byte[] input)
    {
        private int _offset;
        private uint _lastField;

        internal bool NextFieldIs(uint field)
        {
            if (_offset >= input.Length) return false;
            int saved = _offset;
            ulong key = Varint();
            _offset = saved;
            return key >> 3 == field;
        }

        internal uint UInt32(uint field)
        {
            ulong value = UInt64(field);
            return value <= uint.MaxValue ? (uint)value
                : throw new AgentReportException("Integer overflows.");
        }

        internal ulong UInt64(uint field)
        { Key(field, 0, allowRepeated: false); return Varint(); }

        internal string String(uint field, int maximum)
        {
            byte[] bytes = Bytes(field, maximum);
            try { return new UTF8Encoding(false, true).GetString(bytes); }
            catch (DecoderFallbackException) { throw new AgentReportException("String is not valid UTF-8."); }
        }

        internal byte[] Bytes(uint field, int maximum, int minimum = 0, bool exact = false)
        {
            Key(field, 2, allowRepeated: field == 8);
            ulong rawLength = Varint();
            if (rawLength > int.MaxValue) throw new AgentReportException("Length overflows.");
            int length = (int)rawLength;
            if (length < minimum || length > maximum || (exact && length != maximum)
                || _offset > input.Length - length)
                throw new AgentReportException("Field length is invalid.");
            byte[] result = input.AsSpan(_offset, length).ToArray();
            _offset += length;
            return result;
        }

        internal void RequireEnd()
        { if (_offset != input.Length) throw new AgentReportException("Unknown or trailing fields are prohibited."); }

        private void Key(uint expected, ulong wire, bool allowRepeated)
        {
            ulong key = Varint();
            ulong rawField = key >> 3;
            if (rawField > uint.MaxValue) throw new AgentReportException("Field number overflows.");
            uint field = (uint)rawField;
            bool orderValid = allowRepeated ? field >= _lastField : field > _lastField;
            if (field != expected || !orderValid || (key & 7) != wire)
                throw new AgentReportException("Fields must be canonical and ordered.");
            _lastField = field;
        }

        private ulong Varint()
        {
            int start = _offset;
            ulong value = 0;
            for (int shift = 0; shift <= 63; shift += 7)
            {
                if (_offset >= input.Length) throw new AgentReportException("Truncated varint.");
                byte current = input[_offset++];
                if (shift == 63 && current > 1) throw new AgentReportException("Varint overflows.");
                value |= (ulong)(current & 0x7f) << shift;
                if ((current & 0x80) == 0)
                {
                    using var canonical = new MemoryStream();
                    AgentReportCodec.Varint(canonical, value);
                    if (!canonical.ToArray().AsSpan().SequenceEqual(input.AsSpan(start, _offset - start)))
                        throw new AgentReportException("Varint is not minimally encoded.");
                    return value;
                }
            }
            throw new AgentReportException("Varint overflows.");
        }
    }
}

public sealed class AgentReportException(string message) : Exception(message);
