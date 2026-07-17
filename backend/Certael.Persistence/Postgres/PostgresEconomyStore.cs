using System.Security.Cryptography;
using System.Text.Json;
using Certael.Server.Economy;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed class PostgresEconomyStore(NpgsqlDataSource dataSource, TimeSpan? retention = null)
{
    private readonly TimeSpan _retention = retention ?? TimeSpan.FromDays(90);

    public async ValueTask ProjectAsync(EconomyEventV1 value, CancellationToken cancellationToken)
    {
        if (_retention <= TimeSpan.Zero || _retention > TimeSpan.FromDays(90))
            throw new InvalidOperationException("Economy retention must be between one tick and 90 days.");
        byte[] payload = EconomyEventV1Codec.Encode(value);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, value.TenantId, cancellationToken);
        const string insertEvent = """
            INSERT INTO certael_economy_events(tenant_id,event_id,game_id,environment_id,player_subject,
              event_kind,authoritative_action_id,transaction_id,mutation_id,reason_code,canonical_payload,
              replay_digest,occurred_at,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            ON CONFLICT (tenant_id,event_id) DO NOTHING
            """;
        await using (var command = new NpgsqlCommand(insertEvent, connection, transaction))
        {
            command.Parameters.AddWithValue(value.TenantId); command.Parameters.AddWithValue(value.EventId);
            command.Parameters.AddWithValue(value.GameId); command.Parameters.AddWithValue(value.EnvironmentId);
            command.Parameters.AddWithValue(value.PlayerSubject); command.Parameters.AddWithValue(value.Kind.ToString());
            command.Parameters.AddWithValue(value.Transaction?.AuthoritativeActionId ?? value.ItemMutation!.AuthoritativeActionId);
            command.Parameters.Add(new NpgsqlParameter { Value = (object?)value.Transaction?.TransactionId ?? DBNull.Value });
            command.Parameters.Add(new NpgsqlParameter { Value = (object?)value.ItemMutation?.MutationId ?? DBNull.Value });
            command.Parameters.AddWithValue(value.Transaction?.ReasonCode ?? value.ItemMutation!.ReasonCode);
            command.Parameters.AddWithValue(payload); command.Parameters.AddWithValue(SHA256.HashData(payload));
            command.Parameters.AddWithValue(value.OccurredAt); command.Parameters.AddWithValue(value.OccurredAt + _retention);
            if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            { await transaction.CommitAsync(cancellationToken); return; }
        }
        if (value.Transaction is not null)
        {
            const string insertLine = """
                INSERT INTO certael_economy_ledger_lines(tenant_id,event_id,line_number,account_id,asset_id,quantity,occurred_at)
                VALUES($1,$2,$3,$4,$5,$6,$7)
                """;
            for (int index = 0; index < value.Transaction.Lines.Count; index++)
            {
                EconomyLedgerLine line = value.Transaction.Lines[index];
                await using var command = new NpgsqlCommand(insertLine, connection, transaction);
                command.Parameters.AddWithValue(value.TenantId); command.Parameters.AddWithValue(value.EventId);
                command.Parameters.AddWithValue(index); command.Parameters.AddWithValue(line.AccountId);
                command.Parameters.AddWithValue(line.AssetId); command.Parameters.AddWithValue(line.Quantity);
                command.Parameters.AddWithValue(value.OccurredAt); await command.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        else
        {
            ItemLineageMutation item = value.ItemMutation!;
            const string insertItem = """
                INSERT INTO certael_item_lineage(tenant_id,event_id,item_id,parent_item_id,asset_id,account_id,mutation_kind,occurred_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                """;
            await using var command = new NpgsqlCommand(insertItem, connection, transaction);
            command.Parameters.AddWithValue(value.TenantId); command.Parameters.AddWithValue(value.EventId);
            command.Parameters.AddWithValue(item.ItemId);
            command.Parameters.Add(new NpgsqlParameter { Value = (object?)item.ParentItemId ?? DBNull.Value });
            command.Parameters.AddWithValue(item.AssetId); command.Parameters.AddWithValue(item.AccountId);
            command.Parameters.AddWithValue(item.MutationKind.ToString()); command.Parameters.AddWithValue(value.OccurredAt);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask SaveFindingsAsync(string tenantId, string gameId, string environmentId,
        IEnumerable<EconomyFinding> findings, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        const string sql = """
            INSERT INTO certael_economy_findings(tenant_id,finding_id,game_id,environment_id,rule_id,
              rule_version,event_ids,authoritative_fields,window_start,window_end,replay_digest,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            ON CONFLICT (tenant_id,finding_id) DO NOTHING
            """;
        foreach (EconomyFinding finding in findings)
        {
            byte[] identity = SHA256.HashData(finding.ReplayDigest.Concat(
                System.Text.Encoding.UTF8.GetBytes(finding.RuleId)).ToArray());
            Guid findingId = new(identity.AsSpan(0, 16));
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(findingId);
            command.Parameters.AddWithValue(gameId); command.Parameters.AddWithValue(environmentId);
            command.Parameters.AddWithValue(finding.RuleId); command.Parameters.AddWithValue(finding.RuleVersion);
            command.Parameters.AddWithValue(finding.EventIds.ToArray());
            command.Parameters.AddWithValue(NpgsqlDbType.Jsonb, JsonSerializer.Serialize(finding.AuthoritativeFields));
            command.Parameters.AddWithValue(finding.WindowStart); command.Parameters.AddWithValue(finding.WindowEnd);
            command.Parameters.AddWithValue(finding.ReplayDigest); command.Parameters.AddWithValue(finding.WindowEnd + _retention);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private static async ValueTask SetTenantAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT set_config('certael.tenant_id',$1,true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId); await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
