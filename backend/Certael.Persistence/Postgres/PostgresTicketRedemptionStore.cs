using Certael.Server.Sessions;
using Npgsql;

namespace Certael.Persistence.Postgres;

/// <summary>
/// Durable single-use bootstrap admission. Redis loss must never make an
/// already redeemed ticket reusable.
/// </summary>
public sealed class PostgresTicketRedemptionStore(NpgsqlDataSource dataSource)
    : ITicketRedemptionStore
{
    public async ValueTask<bool> TryRedeemAsync(string tenantId, string environmentId,
        Guid ticketId, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(tenantId) || tenantId.Length > 128
            || string.IsNullOrWhiteSpace(environmentId) || environmentId.Length > 128
            || !Identifier(tenantId) || !Identifier(environmentId)
            || ticketId == Guid.Empty || expiresAt <= DateTimeOffset.UtcNow)
            return false;
        await using NpgsqlConnection connection =
            await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction =
            await connection.BeginTransactionAsync(cancellationToken);
        await using (var tenant = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction))
        {
            tenant.Parameters.AddWithValue(tenantId);
            await tenant.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var purge = new NpgsqlCommand("""
            DELETE FROM certael_ticket_redemptions
            WHERE tenant_id=$1 AND environment_id=$2 AND expires_at <= now()
            """, connection, transaction))
        {
            purge.Parameters.AddWithValue(tenantId);
            purge.Parameters.AddWithValue(environmentId);
            await purge.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_ticket_redemptions(tenant_id, environment_id, ticket_id,
              expires_at) VALUES($1,$2,$3,$4)
            ON CONFLICT(tenant_id, environment_id, ticket_id) DO NOTHING
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(environmentId);
        command.Parameters.AddWithValue(ticketId); command.Parameters.AddWithValue(expiresAt);
        bool inserted = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        await transaction.CommitAsync(cancellationToken);
        return inserted;
    }

    private static bool Identifier(string value) => value.All(character =>
        char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-');
}
