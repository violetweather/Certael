using System.Text.Json;
using Certael.Persistence.Postgres;
using Certael.Server.Events;
using Certael.Server.Economy;
using Microsoft.Extensions.Options;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using Npgsql;

namespace Certael.AnalyticsWorker;

public sealed class AnalyticsConsumerService(
    INatsJSContext jetStream,
    NpgsqlDataSource dataSource,
    ClickHouseEventProjection projection,
    PostgresEventReceiptStore receipts,
    PostgresEconomyStore economy,
    PostgresTenantCatalog catalog,
    IOptions<AnalyticsWorkerOptions> options,
    ILogger<AnalyticsConsumerService> logger) : BackgroundService
{
    private readonly AnalyticsWorkerOptions _options = options.Value;
    private HashSet<string> _activeTenants = new(StringComparer.Ordinal);
    private DateTimeOffset _catalogRefreshAt = DateTimeOffset.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await new PostgresMigrationRunner(dataSource).ApplyAsync(stoppingToken);
        ValidateOptions();
        await projection.InitializeAsync(stoppingToken);
        await EnsureQuarantineStreamAsync(stoppingToken);
        var config = new ConsumerConfig(_options.ConsumerName)
        {
            DurableName = _options.ConsumerName,
            FilterSubject = "certael.events.>",
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            AckWait = TimeSpan.FromSeconds(_options.AcknowledgementWaitSeconds),
            MaxDeliver = _options.MaximumDeliveries,
        };
        INatsJSConsumer consumer = await jetStream.CreateOrUpdateConsumerAsync(
            "CERTAEL_EVENTS", config, stoppingToken);

        await foreach (NatsJSMsg<byte[]> message in consumer
            .ConsumeAsync<byte[]>(cancellationToken: stoppingToken))
        {
            try
            {
                CertaelEventEnvelopeV1 envelope = CertaelEventEnvelopeV1Codec.Decode(message.Data);
                await EnsureAuthorizedAsync(envelope, message.Subject, stoppingToken);
                if (!await receipts.ExistsAsync(envelope.TenantId, _options.ConsumerName,
                        envelope.EventId, stoppingToken))
                {
                    if (string.Equals(envelope.EventType, "economy.v1", StringComparison.Ordinal))
                    {
                        EconomyEventV1 economyEvent = EconomyEventV1Codec.Decode(envelope.Payload);
                        if (economyEvent.EventId != envelope.EventId
                            || economyEvent.TenantId != envelope.TenantId
                            || economyEvent.GameId != envelope.GameId
                            || economyEvent.EnvironmentId != envelope.EnvironmentId
                            || economyEvent.OccurredAt != envelope.OccurredAt)
                            throw new EconomyEventException("Economy payload does not match its authoritative envelope.");
                        await economy.ProjectAsync(economyEvent, stoppingToken);
                    }
                    await projection.ProjectAsync(envelope, stoppingToken);
                    await receipts.RecordAsync(envelope.TenantId, _options.ConsumerName,
                        envelope.EventId, stoppingToken);
                }
                await message.AckAsync(cancellationToken: stoppingToken);
            }
            catch (Exception exception) when (exception is CertaelEventEnvelopeException
                or EconomyEventException or UnauthorizedEventException)
            {
                await QuarantineAsync(message, exception, stoppingToken);
                await message.AckTerminateAsync(cancellationToken: stoppingToken);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "Analytics projection failed; event will be retried.");
                await message.NakAsync(cancellationToken: stoppingToken);
                await Task.Delay(TimeSpan.FromSeconds(_options.RetryDelaySeconds), stoppingToken);
            }
        }
    }

    private async ValueTask EnsureAuthorizedAsync(CertaelEventEnvelopeV1 envelope,
        string subject, CancellationToken cancellationToken)
    {
        string expected = $"certael.events.{envelope.TenantId}.{envelope.GameId}.{envelope.EnvironmentId}";
        if (!string.Equals(subject, expected, StringComparison.Ordinal))
            throw new UnauthorizedEventException("Event subject does not match its canonical envelope.");
        if (DateTimeOffset.UtcNow >= _catalogRefreshAt)
        {
            var configured = _options.AuthorizedTenants.ToHashSet(StringComparer.Ordinal);
            IReadOnlyList<string> active = await catalog.ListAnalyticsProcessingTenantsAsync(
                configured, cancellationToken);
            _activeTenants = active.ToHashSet(StringComparer.Ordinal);
            _catalogRefreshAt = DateTimeOffset.UtcNow.AddSeconds(_options.CatalogRefreshSeconds);
        }
        if (!_activeTenants.Contains(envelope.TenantId))
            throw new UnauthorizedEventException("Tenant is not authorized for analytics processing.");
    }

    private void ValidateOptions()
    {
        if (_options.AuthorizedTenants.Length == 0
            || _options.AuthorizedTenants.Any(string.IsNullOrWhiteSpace)
            || _options.MaximumDeliveries is < 1 or > 100
            || _options.AcknowledgementWaitSeconds is < 5 or > 600
            || _options.RetryDelaySeconds is < 1 or > 300
            || _options.RawEventRetentionDays is < 1 or > 30
            || _options.CatalogRefreshSeconds is < 1 or > 3600)
            throw new InvalidOperationException("AnalyticsWorker configuration is invalid.");
    }

    private async ValueTask EnsureQuarantineStreamAsync(CancellationToken cancellationToken)
    {
        var stream = new StreamConfig("CERTAEL_QUARANTINE", ["certael.quarantine.>"])
        {
            Storage = StreamConfigStorage.File,
            Retention = StreamConfigRetention.Limits,
            MaxAge = TimeSpan.FromDays(30),
        };
        await jetStream.CreateOrUpdateStreamAsync(stream, cancellationToken);
    }

    private async ValueTask QuarantineAsync(NatsJSMsg<byte[]> message, Exception exception,
        CancellationToken cancellationToken)
    {
        byte[] sanitized = JsonSerializer.SerializeToUtf8Bytes(new
        {
            consumer = _options.ConsumerName,
            subject = message.Subject,
            reason = exception.GetType().Name,
            observedAt = DateTimeOffset.UtcNow,
        });
        var acknowledgement = await jetStream.PublishAsync(
            "certael.quarantine.analytics", sanitized, cancellationToken: cancellationToken);
        acknowledgement.EnsureSuccess();
        logger.LogWarning("Quarantined malformed analytics event from {Subject}.", message.Subject);
    }
}

public sealed class UnauthorizedEventException(string message) : Exception(message);
