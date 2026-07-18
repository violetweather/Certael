using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Certael.Server.Integrations;

public static class IntegrationTelemetry
{
    private static readonly Meter Meter = new("Certael.Integrations", "1.0.0");
    private static readonly Counter<long> Operations = Meter.CreateCounter<long>(
        "certael.integration.operations", unit: "{operation}");
    private static readonly Histogram<double> Duration = Meter.CreateHistogram<double>(
        "certael.integration.duration", unit: "ms");

    public static long Start() => Stopwatch.GetTimestamp();

    public static void Record(string operation, string playerProvider,
        string serverProvider, string outcome, long started)
    {
        TagList tags = new()
        {
            { "operation", operation }, { "player.provider", playerProvider },
            { "server.provider", serverProvider }, { "outcome", outcome }
        };
        Operations.Add(1, tags);
        Duration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds, tags);
    }
}
