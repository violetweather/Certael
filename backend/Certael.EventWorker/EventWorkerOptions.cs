namespace Certael.EventWorker;

public sealed record EventWorkerOptions
{
    public string[] AuthorizedTenants { get; init; } = [];
    public int BatchSize { get; init; } = 100;
    public int IdleDelayMilliseconds { get; init; } = 500;
    public int CatalogRefreshSeconds { get; init; } = 30;
    public int MaximumAttempts { get; init; } = 12;
    public int LeaseSeconds { get; init; } = 30;
    public int RawEventRetentionDays { get; init; } = 30;
}
