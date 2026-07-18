using System.Text.Json;
using Certael.Server.Cases;
using Npgsql;
using NpgsqlTypes;

namespace Certael.Persistence.Postgres;

public sealed class PostgresCaseSettingsStore(NpgsqlDataSource dataSource) : ICaseSettingsStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async ValueTask<CaseSettingsSnapshot> GetAsync(
        CaseSettingsScope scope, CancellationToken cancellationToken)
    {
        CaseSettingsValidator.ValidateScope(scope);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, scope.TenantId, cancellationToken);

        const string categorySql = """
            SELECT category_key, display_name, description, enabled, sort_order, version, updated_at
            FROM certael_case_categories
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3
            ORDER BY sort_order, display_name, category_key
            """;
        var categories = new List<CaseCategoryDefinition>();
        await using (var command = new NpgsqlCommand(categorySql, connection, transaction))
        {
            AddScope(command, scope);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                categories.Add(ReadCategory(reader));
        }

        const string metadataSql = """
            SELECT metadata_key, label, value_type, enumeration_values::text,
                   sensitive, searchable, required, enabled, version, updated_at
            FROM certael_case_metadata_definitions
            WHERE tenant_id=$1 AND game_id=$2 AND environment_id=$3
            ORDER BY label, metadata_key
            """;
        var definitions = new List<CaseMetadataDefinition>();
        await using (var command = new NpgsqlCommand(metadataSql, connection, transaction))
        {
            AddScope(command, scope);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                definitions.Add(ReadMetadata(reader));
        }

        await transaction.CommitAsync(cancellationToken);
        return new CaseSettingsSnapshot(scope, categories, definitions);
    }

    public async ValueTask<CaseCategoryDefinition?> UpsertCategoryAsync(
        CaseSettingsScope scope, CaseCategoryDefinition definition,
        long expectedVersion, string actorSubject, string reason,
        CancellationToken cancellationToken)
    {
        CaseSettingsValidator.ValidateScope(scope);
        CaseSettingsValidator.ValidateCategory(definition);
        CaseSettingsValidator.ValidateMutation(expectedVersion, actorSubject, reason);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, scope.TenantId, cancellationToken);
        const string sql = """
            INSERT INTO certael_case_categories
                (tenant_id, game_id, environment_id, category_key, display_name,
                 description, enabled, sort_order, version, updated_at)
            SELECT $1,$2,$3,$4,$5,$6,$7,$8,1,now()
            WHERE $9::bigint = 0
            ON CONFLICT (tenant_id, game_id, environment_id, category_key)
            DO UPDATE SET display_name=EXCLUDED.display_name,
                          description=EXCLUDED.description,
                          enabled=EXCLUDED.enabled,
                          sort_order=EXCLUDED.sort_order,
                          version=certael_case_categories.version+1,
                          updated_at=now()
            WHERE certael_case_categories.version=$9
            RETURNING category_key, display_name, description, enabled,
                      sort_order, version, updated_at
            """;
        CaseCategoryDefinition? updated;
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        {
            AddScope(command, scope);
            command.Parameters.AddWithValue(definition.Key);
            command.Parameters.AddWithValue(definition.DisplayName.Trim());
            command.Parameters.AddWithValue(definition.Description.Trim());
            command.Parameters.AddWithValue(definition.Enabled);
            command.Parameters.AddWithValue(definition.SortOrder);
            command.Parameters.AddWithValue(expectedVersion);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            updated = await reader.ReadAsync(cancellationToken) ? ReadCategory(reader) : null;
        }
        if (updated is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }
        await WriteAuditAsync(connection, transaction, scope, "Category", updated.Key,
            actorSubject, reason, updated.Version, new
            {
                updated.DisplayName, updated.Enabled, updated.SortOrder
            }, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return updated;
    }

    public async ValueTask<CaseMetadataDefinition?> UpsertMetadataDefinitionAsync(
        CaseSettingsScope scope, CaseMetadataDefinition definition,
        long expectedVersion, string actorSubject, string reason,
        CancellationToken cancellationToken)
    {
        CaseSettingsValidator.ValidateScope(scope);
        CaseSettingsValidator.ValidateMetadata(definition);
        CaseSettingsValidator.ValidateMutation(expectedVersion, actorSubject, reason);
        string[] enumerationValues = definition.EnumerationValues.Select(value => value.Trim()).ToArray();
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await SetTenantAsync(connection, transaction, scope.TenantId, cancellationToken);
        const string sql = """
            INSERT INTO certael_case_metadata_definitions
                (tenant_id, game_id, environment_id, metadata_key, label, value_type,
                 enumeration_values, sensitive, searchable, required, enabled, version, updated_at)
            SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,now()
            WHERE $12::bigint = 0
            ON CONFLICT (tenant_id, game_id, environment_id, metadata_key)
            DO UPDATE SET label=EXCLUDED.label,
                          value_type=EXCLUDED.value_type,
                          enumeration_values=EXCLUDED.enumeration_values,
                          sensitive=EXCLUDED.sensitive,
                          searchable=EXCLUDED.searchable,
                          required=EXCLUDED.required,
                          enabled=EXCLUDED.enabled,
                          version=certael_case_metadata_definitions.version+1,
                          updated_at=now()
            WHERE certael_case_metadata_definitions.version=$12
            RETURNING metadata_key, label, value_type, enumeration_values::text,
                      sensitive, searchable, required, enabled, version, updated_at
            """;
        CaseMetadataDefinition? updated;
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        {
            AddScope(command, scope);
            command.Parameters.AddWithValue(definition.Key);
            command.Parameters.AddWithValue(definition.Label.Trim());
            command.Parameters.AddWithValue(definition.Type.ToString());
            command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb,
                Value = JsonSerializer.Serialize(enumerationValues, Json) });
            command.Parameters.AddWithValue(definition.Sensitive);
            command.Parameters.AddWithValue(definition.Searchable);
            command.Parameters.AddWithValue(definition.Required);
            command.Parameters.AddWithValue(definition.Enabled);
            command.Parameters.AddWithValue(expectedVersion);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            updated = await reader.ReadAsync(cancellationToken) ? ReadMetadata(reader) : null;
        }
        if (updated is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }
        await WriteAuditAsync(connection, transaction, scope, "Metadata", updated.Key,
            actorSubject, reason, updated.Version, new
            {
                updated.Label, Type = updated.Type.ToString(), updated.Sensitive,
                updated.Searchable, updated.Required, updated.Enabled,
                EnumerationValueCount = updated.EnumerationValues.Count
            }, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return updated;
    }

    private static CaseCategoryDefinition ReadCategory(NpgsqlDataReader reader) => new(
        reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetBoolean(3),
        reader.GetInt32(4), reader.GetInt64(5), reader.GetFieldValue<DateTimeOffset>(6));

    private static CaseMetadataDefinition ReadMetadata(NpgsqlDataReader reader) => new(
        reader.GetString(0), reader.GetString(1), Enum.Parse<CaseMetadataType>(reader.GetString(2)),
        JsonSerializer.Deserialize<string[]>(reader.GetString(3), Json) ?? [],
        reader.GetBoolean(4), reader.GetBoolean(5), reader.GetBoolean(6), reader.GetBoolean(7),
        reader.GetInt64(8), reader.GetFieldValue<DateTimeOffset>(9));

    private static async Task WriteAuditAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CaseSettingsScope scope, string kind, string key,
        string actorSubject, string reason, long version, object details,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO certael_case_settings_activity
                (activity_id, tenant_id, game_id, environment_id, setting_kind,
                 setting_key, actor_subject, reason, version, details)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue(Guid.NewGuid());
        AddScope(command, scope);
        command.Parameters.AddWithValue(kind);
        command.Parameters.AddWithValue(key);
        command.Parameters.AddWithValue(actorSubject);
        command.Parameters.AddWithValue(reason);
        command.Parameters.AddWithValue(version);
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb,
            Value = JsonSerializer.Serialize(details, Json) });
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddScope(NpgsqlCommand command, CaseSettingsScope scope)
    {
        command.Parameters.AddWithValue(scope.TenantId);
        command.Parameters.AddWithValue(scope.GameId);
        command.Parameters.AddWithValue(scope.EnvironmentId);
    }

    private static async Task SetTenantAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string tenantId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id', $1, true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
