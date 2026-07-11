using Certael.Server.Actions;

namespace Certael.Server.Tests;

public sealed class ActionProofVerifierTests
{
    [Fact]
    public void ValidProofAcceptedAndPayloadSubstitutionRejected()
    {
        byte[] publicKey = Convert.FromHexString("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c");
        byte[] signature = Convert.FromHexString("5e6a512a9ce540f2ba62d6897e3b07926b8a12b8f77cf1af918c48f7aefe97862fccb586b873d3e0351b52f74b953af16a7b9d2f147e8d3284cccb8d0d7a4f0c");
        byte[] expectedCanonical = Convert.FromHexString("000000000000000773657373696f6e000000000000000900112233445566778899aabbccddeeff000000000000000f696e76656e746f72792e637261667400000001000000000001e24000000000000000030102030000000000000000000000000000000000000000000000000000000000000000");
        var unsigned = new AuthorizedAction<string>("session", 9,
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), "inventory.craft", 1,
            DateTimeOffset.UtcNow, 123456, "request", new byte[] { 1, 2, 3 }, new byte[32], new byte[64]);
        byte[] canonical = Ed25519ActionProofVerifier.Canonicalize(unsigned);
        AuthorizedAction<string> valid = unsigned with { PossessionProof = signature };
        var verifier = new Ed25519ActionProofVerifier();

        Assert.Equal(expectedCanonical, canonical);
        Assert.True(verifier.Verify(valid, publicKey));
        Assert.False(verifier.Verify(valid with { RawPayload = new byte[] { 1, 2, 4 } }, publicKey));
    }
}
