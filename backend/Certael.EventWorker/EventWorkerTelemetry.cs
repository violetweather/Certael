using System.Diagnostics.Metrics;
using Certael.Persistence.Postgres;

namespace Certael.EventWorker;

internal static class EventWorkerTelemetry
{
    private static readonly Meter Meter = new("Certael.EventWorker", "1.0.0");
    private static readonly Counter<long> Published = Meter.CreateCounter<long>("certael.events.published");
    private static readonly Counter<long> Retried = Meter.CreateCounter<long>("certael.events.retried");
    private static readonly Counter<long> DeadLettered = Meter.CreateCounter<long>("certael.events.dead_lettered");

    public static void Record(OutboxDispatchResult result, string tenantId)
    {
        var tenant = new KeyValuePair<string, object?>("certael.tenant.id", tenantId);
        Published.Add(result.Published, tenant);
        Retried.Add(result.Retried, tenant);
        DeadLettered.Add(result.DeadLettered, tenant);
    }
}
