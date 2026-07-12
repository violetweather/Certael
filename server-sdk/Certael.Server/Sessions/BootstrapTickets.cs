using System.Collections.Concurrent;
using System.Security.Cryptography;
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

public sealed record BootstrapSignature(string KeyId, byte[] Signature);

/// <summary>
/// Production implementations may delegate signing to a KMS or HSM. Private
/// key bytes do not need to enter the Certael process.
/// </summary>
public interface IBootstrapSigningProvider
{
    BootstrapSignature Sign(ReadOnlyMemory<byte> domainSeparatedClaims,
        string tenantId, string environmentId, DateTimeOffset now);
}

public sealed record BootstrapSigningKey(
    string KeyId, ECDsa Key, DateTimeOffset NotBefore, DateTimeOffset NotAfter,
    bool Revoked = false, string Usage = "ticket-signing",
    string TenantId = "*", string EnvironmentId = "*");

public sealed class BootstrapSigningKeyRing : IDisposable
{
    private readonly IReadOnlyDictionary<string, BootstrapSigningKey> _keys;
    public string ActiveKeyId { get; }

    public BootstrapSigningKeyRing(IEnumerable<BootstrapSigningKey> keys, string activeKeyId)
    {
        BootstrapSigningKey[] materialized = keys.ToArray();
        if (materialized.Length == 0 || materialized.Any(key => string.IsNullOrWhiteSpace(key.KeyId)
            || key.KeyId.Length > 128 || key.NotAfter <= key.NotBefore
            || key.Usage != "ticket-signing" || string.IsNullOrWhiteSpace(key.TenantId)
            || string.IsNullOrWhiteSpace(key.EnvironmentId))
            || materialized.Select(key => key.KeyId).Distinct(StringComparer.Ordinal).Count() != materialized.Length)
            throw new ArgumentException("Signing key ring is invalid.", nameof(keys));
        _keys = materialized.ToDictionary(key => key.KeyId, StringComparer.Ordinal);
        ActiveKeyId = activeKeyId;
        if (!_keys.ContainsKey(activeKeyId)) throw new ArgumentException("Active key does not exist.", nameof(activeKeyId));
    }

    public BootstrapSigningKey Active(DateTimeOffset now)
    {
        BootstrapSigningKey key = _keys[ActiveKeyId];
        return !key.Revoked && now >= key.NotBefore && now < key.NotAfter
            ? key : throw new CryptographicException("Active signing key is unavailable.");
    }

    public BootstrapSigningKey Active(DateTimeOffset now, string tenantId, string environmentId)
    {
        BootstrapSigningKey key = Active(now);
        return key.Usage == "ticket-signing"
            && (key.TenantId == "*" || key.TenantId == tenantId)
            && (key.EnvironmentId == "*" || key.EnvironmentId == environmentId)
            ? key : throw new CryptographicException("Active signing key scope is unavailable.");
    }

    public BootstrapSigningKey? Verification(string keyId, DateTimeOffset now) =>
        _keys.GetValueOrDefault(keyId) is { } key && !key.Revoked && key.Usage == "ticket-signing"
            && now >= (key.NotBefore == DateTimeOffset.MinValue ? key.NotBefore : key.NotBefore.AddMinutes(-5))
            && now < key.NotAfter ? key : null;

    public void Dispose()
    {
        foreach (ECDsa key in _keys.Values.Select(value => value.Key).Distinct()) key.Dispose();
    }
}

public sealed class KeyRingBootstrapSigningProvider(BootstrapSigningKeyRing keyRing)
    : IBootstrapSigningProvider
{
    public BootstrapSignature Sign(ReadOnlyMemory<byte> domainSeparatedClaims,
        string tenantId, string environmentId, DateTimeOffset now)
    {
        BootstrapSigningKey key = keyRing.Active(now, tenantId, environmentId);
        return new BootstrapSignature(key.KeyId,
            key.Key.SignData(domainSeparatedClaims.Span, HashAlgorithmName.SHA256));
    }
}

public sealed class BootstrapTicketSigner
{
    private readonly IBootstrapSigningProvider _provider;

    public BootstrapTicketSigner(ECDsa signingKey, string keyId) : this(new BootstrapSigningKeyRing([
        new BootstrapSigningKey(keyId, signingKey, DateTimeOffset.MinValue, DateTimeOffset.MaxValue)
    ], keyId)) { }

    public BootstrapTicketSigner(BootstrapSigningKeyRing keyRing)
        : this(new KeyRingBootstrapSigningProvider(keyRing)) { }

    public BootstrapTicketSigner(IBootstrapSigningProvider provider) => _provider = provider;

    public SignedBootstrapTicket Issue(BootstrapTicketClaims claims, DateTimeOffset now)
    {
        BinaryBootstrapTicketClaimsCodec.Validate(claims);
        if (claims.NotBefore < now.AddSeconds(-5) || claims.ExpiresAt > now.AddSeconds(60)
            || claims.ExpiresAt <= claims.NotBefore)
            throw new ArgumentException("Ticket validity must fit the 60-second bootstrap window.", nameof(claims));

        byte[] payload = BinaryBootstrapTicketClaimsCodec.Encode(claims);
        BootstrapSignature signature = _provider.Sign(CreateSigningMessage(payload),
            claims.TenantId, claims.EnvironmentId, now);
        if (string.IsNullOrWhiteSpace(signature.KeyId) || signature.KeyId.Length > 128
            || signature.Signature.Length is < 64 or > 256)
            throw new CryptographicException("Signing provider returned invalid metadata.");
        return new SignedBootstrapTicket(payload, signature.Signature, signature.KeyId);
    }

    internal static byte[] CreateSigningMessage(ReadOnlySpan<byte> canonicalClaims)
    {
        byte[] domain = "certael.ticket.v1\0"u8.ToArray();
        byte[] message = new byte[domain.Length + canonicalClaims.Length];
        domain.CopyTo(message, 0); canonicalClaims.CopyTo(message.AsSpan(domain.Length));
        return message;
    }
}

public interface ITicketRedemptionStore
{
    ValueTask<bool> TryRedeemAsync(string tenantId, string environmentId, Guid ticketId,
        DateTimeOffset expiresAt, CancellationToken cancellationToken);
}

public sealed class InMemoryTicketRedemptionStore : ITicketRedemptionStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _redeemed = new(StringComparer.Ordinal);

    public ValueTask<bool> TryRedeemAsync(string tenantId, string environmentId, Guid ticketId,
        DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(_redeemed.TryAdd(
            $"{tenantId}\0{environmentId}\0{ticketId:N}", expiresAt));
    }
}

public sealed class BootstrapTicketValidator
{
    private readonly BootstrapSigningKeyRing _keyRing;
    private readonly string _expectedIssuer;
    private readonly string _expectedAudience;
    private readonly ITicketRedemptionStore _redemptions;
    private readonly TimeProvider _timeProvider;

    public BootstrapTicketValidator(ECDsa verificationKey, string expectedKeyId,
        string expectedIssuer, string expectedAudience, ITicketRedemptionStore redemptions,
        TimeProvider timeProvider) : this(new BootstrapSigningKeyRing([
            new BootstrapSigningKey(expectedKeyId, verificationKey, DateTimeOffset.MinValue, DateTimeOffset.MaxValue)
        ], expectedKeyId), expectedIssuer, expectedAudience, redemptions, timeProvider) { }

    public BootstrapTicketValidator(BootstrapSigningKeyRing keyRing, string expectedIssuer,
        string expectedAudience, ITicketRedemptionStore redemptions, TimeProvider timeProvider)
    {
        _keyRing = keyRing; _expectedIssuer = expectedIssuer; _expectedAudience = expectedAudience;
        _redemptions = redemptions; _timeProvider = timeProvider;
    }

    public async ValueTask<TicketValidationResult> ValidateAndRedeemAsync(
        SignedBootstrapTicket ticket,
        ReadOnlyMemory<byte> presentedEphemeralPublicKey,
        ReadOnlyMemory<byte> challenge,
        ReadOnlyMemory<byte> possessionSignature,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (ticket.Claims.Length is < 1 or > BinaryBootstrapTicketClaimsCodec.MaximumClaimsLength
            || ticket.Signature.Length is < 64 or > 256
            || string.IsNullOrWhiteSpace(ticket.KeyId) || ticket.KeyId.Length > 128)
            return TicketValidationResult.Reject("INVALID_TICKET");
        BootstrapSigningKey? verificationKey = _keyRing.Verification(ticket.KeyId, now);
        if (verificationKey is null)
            return TicketValidationResult.Reject("UNKNOWN_SIGNING_KEY");
        try
        {
            if (!verificationKey.Key.VerifyData(BootstrapTicketSigner.CreateSigningMessage(ticket.Claims),
                    ticket.Signature, HashAlgorithmName.SHA256))
                return TicketValidationResult.Reject("INVALID_SIGNATURE");
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        { return TicketValidationResult.Reject("INVALID_SIGNATURE"); }

        BootstrapTicketClaims? claims;
        try { claims = BinaryBootstrapTicketClaimsCodec.Decode(ticket.Claims); }
        catch (TicketClaimsException) { return TicketValidationResult.Reject("INVALID_CLAIMS"); }
        if ((verificationKey.TenantId != "*" && verificationKey.TenantId != claims.TenantId)
            || (verificationKey.EnvironmentId != "*"
                && verificationKey.EnvironmentId != claims.EnvironmentId))
            return TicketValidationResult.Reject("SIGNING_KEY_SCOPE_MISMATCH");
        if (!string.Equals(claims.Issuer, _expectedIssuer, StringComparison.Ordinal)
            || !string.Equals(claims.Audience, _expectedAudience, StringComparison.Ordinal))
            return TicketValidationResult.Reject("ISSUER_OR_AUDIENCE_MISMATCH");

        if (now < claims.NotBefore.AddSeconds(-5) || now >= claims.ExpiresAt.AddSeconds(5))
            return TicketValidationResult.Reject("TICKET_EXPIRED_OR_NOT_YET_VALID");
        if (!CryptographicOperations.FixedTimeEquals(claims.EphemeralPublicKey, presentedEphemeralPublicKey.Span))
            return TicketValidationResult.Reject("PROOF_KEY_MISMATCH");
        if (!VerifyPossession(claims.TicketId, presentedEphemeralPublicKey.Span,
                challenge.Span, possessionSignature.Span))
            return TicketValidationResult.Reject("INVALID_POSSESSION_PROOF");
        if (!await _redemptions.TryRedeemAsync(claims.TenantId, claims.EnvironmentId,
                claims.TicketId, claims.ExpiresAt, cancellationToken))
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
