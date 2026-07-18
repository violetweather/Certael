using System.Security.Cryptography;
using Npgsql;

namespace Certael.Persistence.Postgres;

public enum EventReceiptStatus { Missing, Duplicate, Conflict }

public sealed class PostgresEventReceiptStore(NpgsqlDataSource dataSource)
{
    public async ValueTask<EventReceiptStatus> CheckAsync(string tenantId, string consumerName,
        Guid eventId, ReadOnlyMemory<byte> envelopeDigest, CancellationToken cancellationToken)
    {
        ValidateDigest(envelopeDigest.Span);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT envelope_digest FROM certael_event_receipts
            WHERE tenant_id=$1 AND consumer_name=$2 AND event_id=$3
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(consumerName);
        command.Parameters.AddWithValue(eventId);
        object? stored = await command.ExecuteScalarAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        if (stored is null) return EventReceiptStatus.Missing;
        // A null digest is a receipt written by a rolling predecessor. It may be safely
        // upgraded only after this exact envelope is projected and RecordAsync runs.
        if (stored is DBNull) return EventReceiptStatus.Missing;
        return CryptographicOperations.FixedTimeEquals((byte[])stored, envelopeDigest.Span)
            ? EventReceiptStatus.Duplicate : EventReceiptStatus.Conflict;
    }

    public async ValueTask RecordAsync(string tenantId, string consumerName, Guid eventId,
        ReadOnlyMemory<byte> envelopeDigest, CancellationToken cancellationToken)
    {
        ValidateDigest(envelopeDigest.Span);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO certael_event_receipts
              (tenant_id,consumer_name,event_id,envelope_digest)
            VALUES($1,$2,$3,$4)
            ON CONFLICT (tenant_id,consumer_name,event_id) DO UPDATE
              SET envelope_digest=COALESCE(certael_event_receipts.envelope_digest,
                EXCLUDED.envelope_digest)
            RETURNING envelope_digest
            """, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(consumerName);
        command.Parameters.AddWithValue(eventId); command.Parameters.AddWithValue(envelopeDigest.ToArray());
        byte[] stored = (byte[])(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Event receipt was not returned."));
        if (!CryptographicOperations.FixedTimeEquals(stored, envelopeDigest.Span))
        {
            await transaction.RollbackAsync(cancellationToken);
            throw new EventReceiptConflictException("Event ID was already bound to another envelope digest.");
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private static void ValidateDigest(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != 32) throw new ArgumentException("Envelope digest must be SHA-256.");
    }

    private static async ValueTask SetTenantAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}

public sealed class EventReceiptConflictException(string message) : Exception(message);
