using Certael.Server.Actions;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class ActionProofVerifierTests
{
    [Fact]
    public void ValidProofAcceptedAndPayloadSubstitutionRejected()
    {
        var unsigned = new AuthorizedAction<string>("session", 9,
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), "inventory.craft", 1,
            DateTimeOffset.UtcNow, 123456, "request", new byte[] { 1, 2, 3 }, new byte[32],
            new byte[64], RequestSchema: "example.Craft.v1", SessionBindingDigest: new byte[32]);
        byte[] canonical = Ed25519ActionProofVerifier.Canonicalize(unsigned);
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] message = "certael.action.v1\0"u8.ToArray().Concat(canonical).ToArray();
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(key, message);
        AuthorizedAction<string> valid = unsigned with { PossessionProof = signature };
        var verifier = new Ed25519ActionProofVerifier();

        Assert.True(verifier.Verify(valid, publicKey));
        Assert.False(verifier.Verify(valid with { RawPayload = new byte[] { 1, 2, 4 } }, publicKey));
        byte[] encoded = BinaryActionEnvelopeCodec.Encode(valid);
        AuthorizedAction<byte[]> decoded = BinaryActionEnvelopeCodec.Decode(encoded, DateTimeOffset.UtcNow);
        Assert.Equal(valid.ActionId, decoded.ActionId);
        Assert.Equal(valid.RequestSchema, decoded.RequestSchema);
    }
}
