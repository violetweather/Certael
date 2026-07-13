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
    DateTimeOffset ExpiresAt);

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
        if (stream.Length > 64 * 1024) throw new ArgumentException("Agent report exceeds 64 KiB.");
        return stream.ToArray();
    }

    public static byte[] Digest(AgentIntegrityReport report)
    {
        using var stream = new MemoryStream(256);
        byte[] signed = EncodeSigned(report);
        stream.Write(signed);
        Bytes(stream, 10, report.Signature);
        return SHA256.HashData(stream.ToArray());
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
}
