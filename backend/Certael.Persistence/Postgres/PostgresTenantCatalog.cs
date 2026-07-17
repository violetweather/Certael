using Npgsql;

namespace Certael.Persistence.Postgres;

public sealed class PostgresTenantCatalog(NpgsqlDataSource dataSource)
{
    public async Task<IReadOnlyList<string>> ListEventProcessingTenantsAsync(
        IReadOnlySet<string> authorizedTenants, CancellationToken cancellationToken = default)
    {
        if (authorizedTenants.Count == 0) return [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        const string sql = """
            SELECT tenant_id
            FROM certael_tenant_catalog
            WHERE enabled AND event_processing_enabled AND tenant_id = ANY($1)
            ORDER BY tenant_id
            """;
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue(authorizedTenants.ToArray());
        var tenants = new List<string>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) tenants.Add(reader.GetString(0));
        return tenants;
    }

    public async Task<IReadOnlyList<string>> ListAnalyticsProcessingTenantsAsync(
        IReadOnlySet<string> authorizedTenants, CancellationToken cancellationToken = default)
    {
        if (authorizedTenants.Count == 0) return [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        const string sql = """
            SELECT tenant_id
            FROM certael_tenant_catalog
            WHERE enabled AND analytics_processing_enabled AND tenant_id = ANY($1)
            ORDER BY tenant_id
            """;
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue(authorizedTenants.ToArray());
        var tenants = new List<string>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) tenants.Add(reader.GetString(0));
        return tenants;
    }
}
