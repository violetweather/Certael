namespace Certael.AnalyticsWorker;

public sealed record AnalyticsWorkerOptions
{
    public string[] AuthorizedTenants { get; init; } = [];
    public string ConsumerName { get; init; } = "certael-clickhouse-v1";
    public int MaximumDeliveries { get; init; } = 12;
    public int AcknowledgementWaitSeconds { get; init; } = 30;
    public int RetryDelaySeconds { get; init; } = 5;
    public int RawEventRetentionDays { get; init; } = 30;
    public int DerivedAnalyticsRetentionDays { get; init; } = 90;
    public int CatalogRefreshSeconds { get; init; } = 30;
    public int MaximumEconomyEventsPerWindow { get; init; } = 50_000;
    public EconomyProfileVerificationKeyOptions[] EconomyProfileKeys { get; init; } = [];
    public int MaximumRelationshipEventsPerWindow { get; init; } = 50_000;
    public int MaximumRelationshipFindingsPerEvent { get; init; } = 250;
    public EconomyProfileVerificationKeyOptions[] RelationshipProfileKeys { get; init; } = [];
    public int RedisEconomyRetentionDays { get; init; } = 90;
    public int RedisEconomyMaximumEntriesPerSubject { get; init; } = 100_000;
}

public sealed record EconomyProfileVerificationKeyOptions
{
    public string KeyId { get; init; } = "";
    public string PublicKeySpkiBase64 { get; init; } = "";
}

public sealed record ClickHouseOptions
{
    public string Url { get; init; } = "http://clickhouse:8123";
    public string Database { get; init; } = "default";
    public string Username { get; init; } = "default";
    public string Password { get; init; } = "";
}
