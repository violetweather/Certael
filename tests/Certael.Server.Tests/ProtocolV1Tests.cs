using Certael.Server.Actions;

namespace Certael.Server.Tests;

public sealed class ProtocolV1Tests
{
    private const string GoldenEnvelope = "080110001a0773657373696f6e20092a1000112233445566778899aabbccddeeff320f696e76656e746f72792e63726166743a106578616d706c652e43726166742e763140014a20070707070707070707070707070707070707070707070707070707070707070750c0c4075a03010203622000000000000000000000000000000000000000000000000000000000000000006a4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    [Fact]
    public void CSharpMatchesRustGoldenEnvelopeAndRejectsNonCanonicalInput()
    {
        var action = new AuthorizedAction<byte[]>("session", 9,
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), "inventory.craft", 1,
            DateTimeOffset.UnixEpoch, 123456, new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 3 }, new byte[32],
            new byte[64], 1, 0, "example.Craft.v1", Enumerable.Repeat((byte)7, 32).ToArray());
        byte[] encoded = BinaryActionEnvelopeCodec.Encode(action);
        Assert.Equal(GoldenEnvelope, Convert.ToHexString(encoded).ToLowerInvariant());
        Assert.Equal(action.ActionId, BinaryActionEnvelopeCodec.Decode(encoded, DateTimeOffset.UtcNow).ActionId);

        byte[] unknown = [.. encoded, 0x70, 0x01];
        Assert.Throws<ActionEnvelopeException>(() => BinaryActionEnvelopeCodec.Decode(unknown, DateTimeOffset.UtcNow));
        byte[] nonMinimal = [0x08, 0x81, 0x00, .. encoded.AsSpan(2).ToArray()];
        Assert.Throws<ActionEnvelopeException>(() => BinaryActionEnvelopeCodec.Decode(nonMinimal, DateTimeOffset.UtcNow));
        byte[] overflowingField = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        Assert.Throws<ActionEnvelopeException>(() =>
            BinaryActionEnvelopeCodec.Decode(overflowingField, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void MalformedEnvelopeCorpusNeverEscapesAsAnUnexpectedException()
    {
        var random = new Random(0xCE47AE1);
        for (int index = 0; index < 10_000; index++)
        {
            byte[] candidate = new byte[random.Next(0, 512)];
            random.NextBytes(candidate);
            try { _ = BinaryActionEnvelopeCodec.Decode(candidate, DateTimeOffset.UnixEpoch); }
            catch (ActionEnvelopeException) { }
        }
    }
}
