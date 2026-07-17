using Certael.Persistence.Postgres;
using Certael.Server.Events;
using NATS.Client.JetStream;

namespace Certael.EventWorker;

public sealed class JetStreamOutboxPublisher(INatsJSContext jetStream) : IOutboxPublisher
{
    public async ValueTask PublishAsync(OutboxMessage message, CancellationToken cancellationToken)
    {
        var envelope = new CertaelEventEnvelopeV1(
            message.EventId, message.TenantId, message.GameId, message.EnvironmentId,
            message.SessionId, message.ActionId, message.EventType,
            checked((uint)message.SchemaVersion), message.Payload, message.OccurredAt);
        byte[] payload = CertaelEventEnvelopeV1Codec.Encode(envelope);
        string subject = $"certael.events.{message.TenantId}.{message.GameId}.{message.EnvironmentId}";
        var options = new NatsJSPubOpts { MsgId = message.EventId.ToString("N") };
        var acknowledgement = await jetStream.PublishAsync(
            subject, payload, opts: options, cancellationToken: cancellationToken);
        acknowledgement.EnsureSuccess();
    }
}
