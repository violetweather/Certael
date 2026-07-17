using Certael.Server.Events;

namespace Certael.Server.Tests;

public sealed class EventEnvelopeTests
{
    private const string GoldenEnvelope =
        "0801121000112233445566778899aabbccddeeff1a0874656e616e742d61220467616d652a0470726f64320973657373696f6e2d313a10ffeeddccbbaa998877665544332211004211696e76656e746f72792e63726166746564480152030102035880d095ffbc31";

    [Fact]
    public void EventEnvelopeMatchesGoldenVectorAndRoundTrips()
    {
        var envelope = new CertaelEventEnvelopeV1(
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
            "tenant-a", "game", "prod", "session-1",
            Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100"),
            "inventory.crafted", 1, [1, 2, 3],
            DateTimeOffset.FromUnixTimeMilliseconds(1_700_000_000_000));

        byte[] encoded = CertaelEventEnvelopeV1Codec.Encode(envelope);
        Assert.Equal(GoldenEnvelope, Convert.ToHexString(encoded).ToLowerInvariant());
        CertaelEventEnvelopeV1 decoded = CertaelEventEnvelopeV1Codec.Decode(encoded);
        Assert.Equal(envelope.EventId, decoded.EventId);
        Assert.Equal(envelope.TenantId, decoded.TenantId);
        Assert.Equal(envelope.ActionId, decoded.ActionId);
        Assert.Equal(envelope.EventType, decoded.EventType);
        Assert.Equal(envelope.Payload, decoded.Payload);
        Assert.Equal(envelope.OccurredAt, decoded.OccurredAt);
    }

    [Fact]
    public void EventEnvelopeRejectsUnknownAndNonCanonicalFields()
    {
        byte[] encoded = Convert.FromHexString(GoldenEnvelope);
        Assert.Throws<CertaelEventEnvelopeException>(() =>
            CertaelEventEnvelopeV1Codec.Decode([.. encoded, 0x60, 0x01]));

        byte[] nonMinimalVersion = [0x08, 0x81, 0x00, .. encoded.AsSpan(2).ToArray()];
        Assert.Throws<CertaelEventEnvelopeException>(() =>
            CertaelEventEnvelopeV1Codec.Decode(nonMinimalVersion));
    }
}
