using Certael.EventWorker;
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

builder.Services.AddSingleton(NpgsqlDataSource.Create(postgres));
builder.Services.AddSingleton<PostgresTenantCatalog>();
builder.Services.AddSingleton(_ => new NatsClient(new NatsOpts
{
    Url = natsUrl,
    Name = "certael-event-worker"
}));
builder.Services.AddSingleton<INatsJSContext>(service =>
    service.GetRequiredService<NatsClient>().CreateJetStreamContext());
builder.Services.AddSingleton<IOutboxPublisher, JetStreamOutboxPublisher>();
builder.Services.Configure<EventWorkerOptions>(builder.Configuration.GetSection("EventWorker"));
builder.Services.AddHostedService<EventDispatchService>();

await builder.Build().RunAsync();
