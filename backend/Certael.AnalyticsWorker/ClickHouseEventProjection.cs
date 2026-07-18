using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Certael.Server.Events;
using Certael.Server.Economy;
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
        await ExecuteSqlAsync(sql, cancellationToken);
        await ExecuteSqlAsync($"""
            CREATE TABLE IF NOT EXISTS {_options.Database}.certael_economy_lines_v1
            (
                event_id UUID,
                line_number UInt16,
                tenant_id LowCardinality(String),
                game_id LowCardinality(String),
                environment_id LowCardinality(String),
                player_subject String,
                transaction_id String,
                authoritative_action_id UUID,
                reason_code LowCardinality(String),
                source_account_id String,
                sink_account_id String,
                account_id String,
                asset_id LowCardinality(String),
                quantity Int64,
                occurred_at DateTime64(3, 'UTC'),
                projected_at DateTime64(3, 'UTC') DEFAULT now64(3)
            )
            ENGINE = ReplacingMergeTree(projected_at)
            PARTITION BY toYYYYMM(occurred_at)
            ORDER BY (tenant_id,game_id,environment_id,event_id,line_number)
            TTL occurred_at + INTERVAL {_analytics.DerivedAnalyticsRetentionDays} DAY DELETE
            """, cancellationToken);
        await ExecuteSqlAsync($"""
            CREATE TABLE IF NOT EXISTS {_options.Database}.certael_item_lineage_v1
            (
                event_id UUID,
                tenant_id LowCardinality(String),
                game_id LowCardinality(String),
                environment_id LowCardinality(String),
                player_subject String,
                mutation_id String,
                authoritative_action_id UUID,
                mutation_kind LowCardinality(String),
                item_id String,
                parent_item_id Nullable(String),
                asset_id LowCardinality(String),
                account_id String,
                reason_code LowCardinality(String),
                occurred_at DateTime64(3, 'UTC'),
                projected_at DateTime64(3, 'UTC') DEFAULT now64(3)
            )
            ENGINE = ReplacingMergeTree(projected_at)
            PARTITION BY toYYYYMM(occurred_at)
            ORDER BY (tenant_id,game_id,environment_id,event_id)
            TTL occurred_at + INTERVAL {_analytics.DerivedAnalyticsRetentionDays} DAY DELETE
            """, cancellationToken);
        await ExecuteSqlAsync($"""
            CREATE TABLE IF NOT EXISTS {_options.Database}.certael_relationship_edges_v1
            (
                event_id UUID,
                tenant_id LowCardinality(String),
                game_id LowCardinality(String),
                environment_id LowCardinality(String),
                authoritative_action_id UUID,
                edge_kind LowCardinality(String),
                source_subject String,
                target_subject String,
                weight Int64,
                occurred_at DateTime64(3, 'UTC'),
                projected_at DateTime64(3, 'UTC') DEFAULT now64(3)
            )
            ENGINE = ReplacingMergeTree(projected_at)
            PARTITION BY toYYYYMM(occurred_at)
            ORDER BY (tenant_id,game_id,environment_id,event_id)
            TTL occurred_at + INTERVAL {_analytics.DerivedAnalyticsRetentionDays} DAY DELETE
            """, cancellationToken);
    }

    public async ValueTask ProjectRelationshipAsync(RelationshipEventV1 value,
        CancellationToken cancellationToken)
    {
        ConfigureClient();
        string row = JsonSerializer.Serialize(new
        {
            event_id = value.EventId,
            tenant_id = value.TenantId,
            game_id = value.GameId,
            environment_id = value.EnvironmentId,
            authoritative_action_id = value.AuthoritativeActionId,
            edge_kind = value.Kind.ToString(),
            source_subject = value.SourceSubject,
            target_subject = value.TargetSubject,
            weight = value.Weight,
            occurred_at = value.OccurredAt.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
        }) + "\n";
        await InsertJsonRowsAsync("certael_relationship_edges_v1", row, cancellationToken);
    }

    public async ValueTask ProjectEconomyAsync(EconomyEventV1 value,
        CancellationToken cancellationToken)
    {
        ConfigureClient();
        if (value.Transaction is not null)
        {
            EconomyTransaction transaction = value.Transaction;
            string rows = string.Join('\n', transaction.Lines.Select((line, index) =>
                JsonSerializer.Serialize(new
                {
                    event_id = value.EventId,
                    line_number = index,
                    tenant_id = value.TenantId,
                    game_id = value.GameId,
                    environment_id = value.EnvironmentId,
                    player_subject = value.PlayerSubject,
                    transaction_id = transaction.TransactionId,
                    authoritative_action_id = transaction.AuthoritativeActionId,
                    reason_code = transaction.ReasonCode,
                    source_account_id = transaction.SourceAccountId,
                    sink_account_id = transaction.SinkAccountId,
                    account_id = line.AccountId,
                    asset_id = line.AssetId,
                    quantity = line.Quantity,
                    occurred_at = value.OccurredAt.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
                }))) + "\n";
            await InsertJsonRowsAsync("certael_economy_lines_v1", rows, cancellationToken);
        }
        else
        {
            ItemLineageMutation mutation = value.ItemMutation!;
            string row = JsonSerializer.Serialize(new
            {
                event_id = value.EventId,
                tenant_id = value.TenantId,
                game_id = value.GameId,
                environment_id = value.EnvironmentId,
                player_subject = value.PlayerSubject,
                mutation_id = mutation.MutationId,
                authoritative_action_id = mutation.AuthoritativeActionId,
                mutation_kind = mutation.MutationKind.ToString(),
                item_id = mutation.ItemId,
                parent_item_id = mutation.ParentItemId,
                asset_id = mutation.AssetId,
                account_id = mutation.AccountId,
                reason_code = mutation.ReasonCode,
                occurred_at = value.OccurredAt.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
            }) + "\n";
            await InsertJsonRowsAsync("certael_item_lineage_v1", row, cancellationToken);
        }
    }

    private async ValueTask ExecuteSqlAsync(string sql, CancellationToken cancellationToken)
    {
        using var content = new StringContent(sql, Encoding.UTF8, "text/plain");
        using HttpResponseMessage response = await client.PostAsync("/", content, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private async ValueTask InsertJsonRowsAsync(string table, string rows,
        CancellationToken cancellationToken)
    {
        string query = Uri.EscapeDataString(
            $"INSERT INTO {_options.Database}.{table} FORMAT JSONEachRow");
        using var content = new StringContent(rows, Encoding.UTF8, "application/x-ndjson");
        using HttpResponseMessage response = await client.PostAsync($"/?query={query}", content,
            cancellationToken);
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
