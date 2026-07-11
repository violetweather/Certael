using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using NSec.Cryptography;

namespace Certael.Server.Sessions;

public sealed record BootstrapTicketClaims(
    string Issuer,
    string Audience,
    Guid TicketId,
    string TenantId,
    string GameId,
    string EnvironmentId,
    string PlayerSubject,
    string MatchId,
    string AuthoritativeServerId,
    string BuildId,
    string ProtectionProfile,
    byte[] EphemeralPublicKey,
    DateTimeOffset IssuedAt,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt,
    uint ProtocolMinimum,
    uint ProtocolMaximum);

public sealed record SignedBootstrapTicket(byte[] Claims, byte[] Signature, string KeyId);

public sealed class BootstrapTicketSigner(ECDsa signingKey, string keyId)
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public SignedBootstrapTicket Issue(BootstrapTicketClaims claims, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(claims.Issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(claims.Audience);
        if (claims.TicketId == Guid.Empty || claims.EphemeralPublicKey.Length < 32)
            throw new ArgumentException("Ticket ID and ephemeral public key are required.", nameof(claims));
        if (claims.NotBefore < now.AddSeconds(-5) || claims.ExpiresAt > now.AddSeconds(60)
            || claims.ExpiresAt <= claims.NotBefore)
            throw new ArgumentException("Ticket validity must fit the 60-second bootstrap window.", nameof(claims));

        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(claims, Json);
        byte[] signature = signingKey.SignData(payload, HashAlgorithmName.SHA256);
        return new SignedBootstrapTicket(payload, signature, keyId);
    }
}

public interface ITicketRedemptionStore
{
    ValueTask<bool> TryRedeemAsync(Guid ticketId, DateTimeOffset expiresAt, CancellationToken cancellationToken);
}

public sealed class InMemoryTicketRedemptionStore : ITicketRedemptionStore
{
    private readonly ConcurrentDictionary<Guid, DateTimeOffset> _redeemed = new();

    public ValueTask<bool> TryRedeemAsync(Guid ticketId, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(_redeemed.TryAdd(ticketId, expiresAt));
    }
}

public sealed class BootstrapTicketValidator(
    ECDsa verificationKey,
    string expectedKeyId,
    string expectedIssuer,
    string expectedAudience,
    ITicketRedemptionStore redemptions,
    TimeProvider timeProvider)
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public async ValueTask<TicketValidationResult> ValidateAndRedeemAsync(
        SignedBootstrapTicket ticket,
        ReadOnlyMemory<byte> presentedEphemeralPublicKey,
        ReadOnlyMemory<byte> challenge,
        ReadOnlyMemory<byte> possessionSignature,
        CancellationToken cancellationToken = default)
    {
        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(ticket.KeyId),
                System.Text.Encoding.UTF8.GetBytes(expectedKeyId)))
            return TicketValidationResult.Reject("UNKNOWN_SIGNING_KEY");
        if (!verificationKey.VerifyData(ticket.Claims, ticket.Signature, HashAlgorithmName.SHA256))
            return TicketValidationResult.Reject("INVALID_SIGNATURE");

        BootstrapTicketClaims? claims;
        try { claims = JsonSerializer.Deserialize<BootstrapTicketClaims>(ticket.Claims, Json); }
        catch (JsonException) { return TicketValidationResult.Reject("INVALID_CLAIMS"); }
        if (claims is null) return TicketValidationResult.Reject("INVALID_CLAIMS");
        if (!string.Equals(claims.Issuer, expectedIssuer, StringComparison.Ordinal)
            || !string.Equals(claims.Audience, expectedAudience, StringComparison.Ordinal))
            return TicketValidationResult.Reject("ISSUER_OR_AUDIENCE_MISMATCH");

        DateTimeOffset now = timeProvider.GetUtcNow();
        if (now < claims.NotBefore.AddSeconds(-5) || now >= claims.ExpiresAt.AddSeconds(5))
            return TicketValidationResult.Reject("TICKET_EXPIRED_OR_NOT_YET_VALID");
        if (!CryptographicOperations.FixedTimeEquals(claims.EphemeralPublicKey, presentedEphemeralPublicKey.Span))
            return TicketValidationResult.Reject("PROOF_KEY_MISMATCH");
        if (!VerifyPossession(claims.TicketId, presentedEphemeralPublicKey.Span,
                challenge.Span, possessionSignature.Span))
            return TicketValidationResult.Reject("INVALID_POSSESSION_PROOF");
        if (!await redemptions.TryRedeemAsync(claims.TicketId, claims.ExpiresAt, cancellationToken))
            return TicketValidationResult.Reject("TICKET_ALREADY_REDEEMED");
        return TicketValidationResult.Allow(claims);
    }

    private static bool VerifyPossession(Guid ticketId, ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64 || challenge.Length is < 16 or > 256)
            return false;
        try
        {
            PublicKey key = PublicKey.Import(SignatureAlgorithm.Ed25519, publicKey, KeyBlobFormat.RawPublicKey);
            byte[] message = CreateRedemptionMessage(ticketId, challenge);
            return SignatureAlgorithm.Ed25519.Verify(key, message, signature);
        }
        catch (ArgumentException) { return false; }
        catch (CryptographicException) { return false; }
    }

    internal static byte[] CreateRedemptionMessage(Guid ticketId, ReadOnlySpan<byte> challenge)
    {
        using var stream = new MemoryStream(64 + challenge.Length);
        stream.Write("certael.redeem.v1\0"u8);
        Span<byte> id = stackalloc byte[16];
        ticketId.TryWriteBytes(id, bigEndian: true, out _);
        stream.Write(id);
        Span<byte> length = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)challenge.Length));
        stream.Write(length);
        stream.Write(challenge);
        return stream.ToArray();
    }
}

public sealed record TicketValidationResult(bool Valid, string PublicReason, BootstrapTicketClaims? Claims)
{
    public static TicketValidationResult Allow(BootstrapTicketClaims claims) => new(true, "VALID", claims);
    public static TicketValidationResult Reject(string reason) => new(false, reason, null);
}
