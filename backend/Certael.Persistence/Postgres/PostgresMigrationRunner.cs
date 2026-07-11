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
        Assembly assembly = typeof(PostgresMigrationRunner).Assembly;
        foreach (string resource in assembly.GetManifestResourceNames()
            .Where(name => name.Contains(".Migrations.", StringComparison.Ordinal) && name.EndsWith(".sql", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal))
        {
            await using Stream stream = assembly.GetManifestResourceStream(resource)
                ?? throw new InvalidOperationException($"Missing migration resource {resource}.");
            using var reader = new StreamReader(stream);
            string sql = await reader.ReadToEndAsync(cancellationToken);
            await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 60 };
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }
}
