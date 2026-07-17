using Certael.Persistence.Postgres;
using Microsoft.Extensions.Options;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using Npgsql;

namespace Certael.EventWorker;

public sealed class EventDispatchService(
    NpgsqlDataSource dataSource,
    PostgresTenantCatalog catalog,
    IOutboxPublisher publisher,
    INatsJSContext jetStream,
    IOptions<EventWorkerOptions> configuredOptions,
    ILogger<EventDispatchService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        EventWorkerOptions options = Validate(configuredOptions.Value);
        var authorized = options.AuthorizedTenants.ToHashSet(StringComparer.Ordinal);
        if (authorized.Count == 0)
            throw new InvalidOperationException("EventWorker:AuthorizedTenants must contain at least one tenant.");

        await new PostgresMigrationRunner(dataSource).ApplyAsync(stoppingToken);
        await jetStream.CreateOrUpdateStreamAsync(new StreamConfig(
            "CERTAEL_EVENTS", ["certael.events.>"])
        {
            Description = "Canonical replayable Certael gameplay events",
            MaxAge = TimeSpan.FromDays(options.RawEventRetentionDays),
            MaxMsgSize = Certael.Server.Events.CertaelEventEnvelopeV1Codec.MaximumEnvelope,
            DuplicateWindow = TimeSpan.FromMinutes(2)
        }, stoppingToken);

        IReadOnlyList<string> tenants = [];
        DateTimeOffset refreshAt = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            if (DateTimeOffset.UtcNow >= refreshAt)
            {
                tenants = await catalog.ListEventProcessingTenantsAsync(authorized, stoppingToken);
                refreshAt = DateTimeOffset.UtcNow.AddSeconds(options.CatalogRefreshSeconds);
            }
            int dispatched = 0;
            foreach (string tenant in tenants)
            {
                var dispatcher = new PostgresOutboxDispatcher(dataSource, publisher, tenant,
                    new PostgresOutboxDispatcherOptions
                    {
                        LeaseDuration = TimeSpan.FromSeconds(options.LeaseSeconds),
                        MaximumAttempts = options.MaximumAttempts
                    });
                OutboxDispatchResult result = await dispatcher.DispatchBatchDetailedAsync(
                    options.BatchSize, stoppingToken);
                dispatched += result.Claimed;
                EventWorkerTelemetry.Record(result, tenant);
            }

            if (dispatched == 0)
                await Task.Delay(options.IdleDelayMilliseconds, stoppingToken);
            else
                logger.LogInformation("Dispatched {EventCount} outbox events for {TenantCount} tenants.",
                    dispatched, tenants.Count);
        }
    }

    private static EventWorkerOptions Validate(EventWorkerOptions options)
    {
        if (options.BatchSize is < 1 or > 1000
            || options.IdleDelayMilliseconds is < 10 or > 60_000
            || options.CatalogRefreshSeconds is < 1 or > 3600
            || options.MaximumAttempts is < 1 or > 100
            || options.LeaseSeconds is < 5 or > 600
            || options.RawEventRetentionDays is < 1 or > 30
            || options.AuthorizedTenants.Any(value => string.IsNullOrWhiteSpace(value)))
            throw new InvalidOperationException("EventWorker configuration is invalid.");
        return options;
    }
}
