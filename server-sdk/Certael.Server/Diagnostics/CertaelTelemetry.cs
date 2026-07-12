using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Certael.Server.Diagnostics;

public static class CertaelTelemetry
{
    public const string SourceName = "Certael.Server";
    public static readonly ActivitySource Activities = new(SourceName);
    public static readonly Meter Meter = new(SourceName);
    public static readonly Counter<long> Actions = Meter.CreateCounter<long>("certael.actions");
    public static readonly Counter<long> SessionOperations = Meter.CreateCounter<long>("certael.session.operations");
    public static readonly Histogram<double> ActionMilliseconds = Meter.CreateHistogram<double>("certael.action.duration", "ms");

    public static void RecordAction(string tenantId, string gameId, string environmentId,
        string buildId, string actionType, string outcome, string publicReason, double milliseconds) {
        TagList tags = default;
        tags.Add("certael.tenant", tenantId); tags.Add("certael.game", gameId);
        tags.Add("certael.environment", environmentId); tags.Add("certael.action_type", actionType);
        tags.Add("certael.build", buildId); tags.Add("certael.outcome", outcome);
        tags.Add("certael.public_reason", publicReason);
        Actions.Add(1, tags); ActionMilliseconds.Record(milliseconds, tags);
    }

    public static void RecordSession(string operation, string outcome, string tenantId,
        string environmentId)
    {
        TagList tags = default;
        tags.Add("certael.operation", operation); tags.Add("certael.outcome", outcome);
        tags.Add("certael.tenant", tenantId); tags.Add("certael.environment", environmentId);
        SessionOperations.Add(1, tags);
    }
}
