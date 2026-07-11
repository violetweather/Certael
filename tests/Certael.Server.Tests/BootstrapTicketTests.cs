using System.Security.Cryptography;
using Certael.Server.Sessions;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class BootstrapTicketTests
{
    [Fact]
    public async Task TicketIsBoundAndSingleUse()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using Key ephemeralKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
        byte[] ephemeral = ephemeralKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var claims = new BootstrapTicketClaims("issuer", "audience", Guid.NewGuid(), "tenant", "game", "prod",
            "player", "match", "server", "build", "competitive", ephemeral, now, now, now.AddSeconds(60), 1, 1);
        var signer = new BootstrapTicketSigner(key, "key-1");
        SignedBootstrapTicket ticket = signer.Issue(claims, now);
        var validator = new BootstrapTicketValidator(key, "key-1", "issuer", "audience",
            new InMemoryTicketRedemptionStore(), TimeProvider.System);

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(ephemeralKey,
            BootstrapTicketValidator.CreateRedemptionMessage(claims.TicketId, challenge));
        TicketValidationResult wrongKey = await validator.ValidateAndRedeemAsync(ticket,
            RandomNumberGenerator.GetBytes(32), challenge, signature, cancellationToken);
        TicketValidationResult wrongProof = await validator.ValidateAndRedeemAsync(ticket,
            ephemeral, challenge, RandomNumberGenerator.GetBytes(64), cancellationToken);
        TicketValidationResult accepted = await validator.ValidateAndRedeemAsync(ticket,
            ephemeral, challenge, signature, cancellationToken);
        TicketValidationResult replay = await validator.ValidateAndRedeemAsync(ticket,
            ephemeral, challenge, signature, cancellationToken);

        Assert.False(wrongKey.Valid);
        Assert.False(wrongProof.Valid);
        Assert.True(accepted.Valid);
        Assert.False(replay.Valid);
        Assert.Equal("TICKET_ALREADY_REDEEMED", replay.PublicReason);
    }
}
