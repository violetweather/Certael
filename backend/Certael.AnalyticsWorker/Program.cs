using Certael.AnalyticsWorker;
using Certael.Persistence.Postgres;
using Certael.Server.Cases;
using Certael.Server.Evidence;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using Npgsql;
using StackExchange.Redis;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
string postgres = builder.Configuration.GetConnectionString("Postgres")
    ?? throw new InvalidOperationException("ConnectionStrings:Postgres is required.");
string natsUrl = builder.Configuration["Nats:Url"]
    ?? throw new InvalidOperationException("Nats:Url is required.");
string redis = builder.Configuration.GetConnectionString("Redis")
    ?? throw new InvalidOperationException("ConnectionStrings:Redis is required.");

builder.Services.Configure<AnalyticsWorkerOptions>(
    builder.Configuration.GetSection("AnalyticsWorker"));
builder.Services.Configure<ClickHouseOptions>(builder.Configuration.GetSection("ClickHouse"));
builder.Services.AddSingleton(NpgsqlDataSource.Create(postgres));
builder.Services.AddSingleton<PostgresEventReceiptStore>();
builder.Services.AddSingleton<PostgresEconomyStore>();
builder.Services.AddSingleton<PostgresRelationshipStore>();
builder.Services.AddSingleton<PostgresTenantCatalog>();
builder.Services.AddSingleton<EconomyAnalysisService>();
builder.Services.AddSingleton<RelationshipAnalysisService>();
builder.Services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(redis));
builder.Services.AddSingleton<RedisEconomyProjection>();
builder.Services.AddSingleton<IEvidenceStore>(services => new PostgresEvidenceStore(
    services.GetRequiredService<NpgsqlDataSource>(), TimeSpan.FromDays(90)));
builder.Services.AddSingleton<ICaseStore>(services => new PostgresCaseStore(
    services.GetRequiredService<NpgsqlDataSource>(), TimeSpan.FromDays(180)));
builder.Services.AddSingleton(_ => new NatsClient(new NatsOpts
{
    Url = natsUrl,
    Name = "certael-analytics-worker",
}));
builder.Services.AddSingleton<INatsJSContext>(services =>
    services.GetRequiredService<NatsClient>().CreateJetStreamContext());
builder.Services.AddHttpClient<ClickHouseEventProjection>();
builder.Services.AddHostedService<AnalyticsConsumerService>();

await builder.Build().RunAsync();
