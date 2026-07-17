using Certael.AnalyticsWorker;
using Certael.Persistence.Postgres;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using Npgsql;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
string postgres = builder.Configuration.GetConnectionString("Postgres")
    ?? throw new InvalidOperationException("ConnectionStrings:Postgres is required.");
string natsUrl = builder.Configuration["Nats:Url"]
    ?? throw new InvalidOperationException("Nats:Url is required.");

builder.Services.Configure<AnalyticsWorkerOptions>(
    builder.Configuration.GetSection("AnalyticsWorker"));
builder.Services.Configure<ClickHouseOptions>(builder.Configuration.GetSection("ClickHouse"));
builder.Services.AddSingleton(NpgsqlDataSource.Create(postgres));
builder.Services.AddSingleton<PostgresEventReceiptStore>();
builder.Services.AddSingleton<PostgresEconomyStore>();
builder.Services.AddSingleton<PostgresTenantCatalog>();
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
