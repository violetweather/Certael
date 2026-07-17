using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Certael.Server.Events;
using Microsoft.Extensions.Options;

namespace Certael.AnalyticsWorker;

public sealed class ClickHouseEventProjection(HttpClient client,
    IOptions<ClickHouseOptions> clickHouse, IOptions<AnalyticsWorkerOptions> analytics)
{
    private readonly ClickHouseOptions _options = Validate(clickHouse.Value);
    private readonly AnalyticsWorkerOptions _analytics = analytics.Value;

    public async ValueTask InitializeAsync(CancellationToken cancellationToken)
    {
        ConfigureClient();
        string sql = $"""
            CREATE TABLE IF NOT EXISTS {_options.Database}.certael_events_v1
            (
                event_id UUID,
                tenant_id LowCardinality(String),
                game_id LowCardinality(String),
                environment_id LowCardinality(String),
                session_id String,
                action_id UUID,
                event_type LowCardinality(String),
                payload_schema_version UInt32,
                payload String,
                occurred_at DateTime64(3, 'UTC'),
                projected_at DateTime64(3, 'UTC') DEFAULT now64(3)
            )
            ENGINE = ReplacingMergeTree(projected_at)
            PARTITION BY toYYYYMM(occurred_at)
            ORDER BY (tenant_id, game_id, environment_id, event_id)
            TTL occurred_at + INTERVAL {_analytics.RawEventRetentionDays} DAY DELETE
            SETTINGS index_granularity = 8192
            """;
        using var content = new StringContent(sql, Encoding.UTF8, "text/plain");
        using HttpResponseMessage response = await client.PostAsync("/", content, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async ValueTask ProjectAsync(CertaelEventEnvelopeV1 envelope,
        CancellationToken cancellationToken)
    {
        ConfigureClient();
        string json = JsonSerializer.Serialize(new
        {
            event_id = envelope.EventId,
            tenant_id = envelope.TenantId,
            game_id = envelope.GameId,
            environment_id = envelope.EnvironmentId,
            session_id = envelope.SessionId,
            action_id = envelope.ActionId,
            event_type = envelope.EventType,
            payload_schema_version = envelope.PayloadSchemaVersion,
            payload = Convert.ToBase64String(envelope.Payload),
            occurred_at = envelope.OccurredAt.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff"),
        });
        string query = Uri.EscapeDataString(
            $"INSERT INTO {_options.Database}.certael_events_v1 FORMAT JSONEachRow");
        using var content = new StringContent(json + "\n", Encoding.UTF8, "application/x-ndjson");
        using HttpResponseMessage response = await client.PostAsync($"/?query={query}", content,
            cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private void ConfigureClient()
    {
        client.BaseAddress ??= new Uri(_options.Url, UriKind.Absolute);
        if (client.DefaultRequestHeaders.Authorization is null)
        {
            string credentials = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{_options.Username}:{_options.Password}"));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        }
    }

    private static ClickHouseOptions Validate(ClickHouseOptions value)
    {
        if (!Uri.TryCreate(value.Url, UriKind.Absolute, out Uri? uri)
            || uri.Scheme is not ("http" or "https")
            || string.IsNullOrWhiteSpace(value.Database)
            || !value.Database.All(character => char.IsAsciiLetterOrDigit(character) || character == '_'))
            throw new InvalidOperationException("ClickHouse configuration is invalid.");
        return value;
    }
}
