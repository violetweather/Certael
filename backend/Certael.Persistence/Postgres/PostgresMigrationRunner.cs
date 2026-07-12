using System.Reflection;
using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresMigrationRunner(NpgsqlDataSource dataSource)
{
    public async Task ApplyAsync(CancellationToken cancellationToken = default)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (NpgsqlCommand advisory = new("SELECT pg_advisory_xact_lock(8327491021)", connection, transaction))
            await advisory.ExecuteNonQueryAsync(cancellationToken);
        await using (NpgsqlCommand createJournal = new("""
            CREATE TABLE IF NOT EXISTS certael_schema_migrations(
              migration_id text PRIMARY KEY,
              applied_at timestamptz NOT NULL DEFAULT now()
            )
            """, connection, transaction))
            await createJournal.ExecuteNonQueryAsync(cancellationToken);
        Assembly assembly = typeof(PostgresMigrationRunner).Assembly;
        foreach (string resource in assembly.GetManifestResourceNames()
            .Where(name => name.Contains(".Migrations.", StringComparison.Ordinal) && name.EndsWith(".sql", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal))
        {
            await using (var exists = new NpgsqlCommand(
                "SELECT EXISTS(SELECT 1 FROM certael_schema_migrations WHERE migration_id=$1)",
                connection, transaction))
            {
                exists.Parameters.AddWithValue(resource);
                if ((bool)(await exists.ExecuteScalarAsync(cancellationToken))!) continue;
            }
            await using Stream stream = assembly.GetManifestResourceStream(resource)
                ?? throw new InvalidOperationException($"Missing migration resource {resource}.");
            using var reader = new StreamReader(stream);
            string sql = await reader.ReadToEndAsync(cancellationToken);
            await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 60 };
            await command.ExecuteNonQueryAsync(cancellationToken);
            await using var record = new NpgsqlCommand(
                "INSERT INTO certael_schema_migrations(migration_id) VALUES($1)", connection, transaction);
            record.Parameters.AddWithValue(resource);
            await record.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }
}
