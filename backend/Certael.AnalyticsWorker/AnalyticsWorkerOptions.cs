namespace Certael.AnalyticsWorker;

public sealed record AnalyticsWorkerOptions
{
    public string[] AuthorizedTenants { get; init; } = [];
    public string ConsumerName { get; init; } = "certael-clickhouse-v1";
    public int MaximumDeliveries { get; init; } = 12;
    public int AcknowledgementWaitSeconds { get; init; } = 30;
    public int RetryDelaySeconds { get; init; } = 5;
    public int RawEventRetentionDays { get; init; } = 30;
    public int CatalogRefreshSeconds { get; init; } = 30;
}

public sealed record ClickHouseOptions
{
    public string Url { get; init; } = "http://clickhouse:8123";
    public string Database { get; init; } = "default";
    public string Username { get; init; } = "default";
    public string Password { get; init; } = "";
}
