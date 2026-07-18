using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace Certael.Server.Cases;

public sealed record CaseSettingsScope(
    string TenantId, string GameId, string EnvironmentId);

public sealed record CaseCategoryDefinition(
    string Key, string DisplayName, string Description, bool Enabled,
    int SortOrder, long Version, DateTimeOffset UpdatedAt);

public sealed record CaseMetadataDefinition(
    string Key, string Label, CaseMetadataType Type,
    IReadOnlyList<string> EnumerationValues, bool Sensitive, bool Searchable,
    bool Required, bool Enabled, long Version, DateTimeOffset UpdatedAt);

public sealed record CaseSettingsSnapshot(
    CaseSettingsScope Scope,
    IReadOnlyList<CaseCategoryDefinition> Categories,
    IReadOnlyList<CaseMetadataDefinition> MetadataDefinitions);

public interface ICaseSettingsStore
{
    ValueTask<CaseSettingsSnapshot> GetAsync(
        CaseSettingsScope scope, CancellationToken cancellationToken);

    ValueTask<CaseCategoryDefinition?> UpsertCategoryAsync(
        CaseSettingsScope scope, CaseCategoryDefinition definition,
        long expectedVersion, string actorSubject, string reason,
        CancellationToken cancellationToken);

    ValueTask<CaseMetadataDefinition?> UpsertMetadataDefinitionAsync(
        CaseSettingsScope scope, CaseMetadataDefinition definition,
        long expectedVersion, string actorSubject, string reason,
        CancellationToken cancellationToken);
}

public static partial class CaseSettingsValidator
{
    public static void ValidateScope(CaseSettingsScope scope)
    {
        ValidateBounded(scope.TenantId, 1, 128, nameof(scope.TenantId));
        ValidateBounded(scope.GameId, 1, 128, nameof(scope.GameId));
        ValidateBounded(scope.EnvironmentId, 1, 128, nameof(scope.EnvironmentId));
    }

    public static void ValidateCategory(CaseCategoryDefinition definition)
    {
        ValidateKey(definition.Key);
        ValidateBounded(definition.DisplayName, 1, 128, nameof(definition.DisplayName));
        ValidateBounded(definition.Description, 0, 1024, nameof(definition.Description));
        if (definition.SortOrder is < -10_000 or > 10_000)
            throw new ArgumentOutOfRangeException(nameof(definition.SortOrder));
    }

    public static void ValidateMetadata(CaseMetadataDefinition definition)
    {
        ValidateKey(definition.Key);
        ValidateBounded(definition.Label, 1, 128, nameof(definition.Label));
        if (definition.Sensitive && definition.Searchable)
            throw new ArgumentException("Sensitive metadata cannot be searchable.");
        if (definition.EnumerationValues.Count > 100)
            throw new ArgumentException("Enumeration metadata supports at most 100 values.");
        string[] values = definition.EnumerationValues
            .Select(value => value?.Trim() ?? string.Empty).ToArray();
        foreach (string value in values)
            ValidateBounded(value, 1, 128, nameof(definition.EnumerationValues));
        if (values.Distinct(StringComparer.OrdinalIgnoreCase).Count() != values.Length)
            throw new ArgumentException("Enumeration values must be unique.");
        if (definition.Type == CaseMetadataType.Enumeration && values.Length == 0)
            throw new ArgumentException("Enumeration metadata requires values.");
        if (definition.Type != CaseMetadataType.Enumeration && values.Length != 0)
            throw new ArgumentException("Only enumeration metadata accepts enumeration values.");
    }

    public static void ValidateMutation(long expectedVersion, string actorSubject, string reason)
    {
        if (expectedVersion < 0) throw new ArgumentOutOfRangeException(nameof(expectedVersion));
        ValidateBounded(actorSubject, 1, 256, nameof(actorSubject));
        ValidateBounded(reason, 1, 1024, nameof(reason));
    }

    private static void ValidateKey(string value)
    {
        ValidateBounded(value, 1, 96, "key");
        if (!SettingsKey().IsMatch(value))
            throw new ArgumentException("Keys must start with a letter and use lowercase letters, digits, '.', '_' or '-'.");
    }

    private static void ValidateBounded(string value, int minimum, int maximum, string name)
    {
        if (value is null || value.Length < minimum || value.Length > maximum)
            throw new ArgumentException($"{name} must contain between {minimum} and {maximum} characters.", name);
    }

    [GeneratedRegex("^[a-z][a-z0-9._-]{0,95}$", RegexOptions.CultureInvariant)]
    private static partial Regex SettingsKey();
}

public sealed class InMemoryCaseSettingsStore(TimeProvider timeProvider) : ICaseSettingsStore
{
    private readonly ConcurrentDictionary<(string Tenant, string Game, string Environment, string Key),
        CaseCategoryDefinition> _categories = new();
    private readonly ConcurrentDictionary<(string Tenant, string Game, string Environment, string Key),
        CaseMetadataDefinition> _metadata = new();
    private readonly object _gate = new();

    public ValueTask<CaseSettingsSnapshot> GetAsync(
        CaseSettingsScope scope, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CaseSettingsValidator.ValidateScope(scope);
        CaseCategoryDefinition[] categories = _categories
            .Where(entry => Matches(entry.Key, scope))
            .Select(entry => entry.Value)
            .OrderBy(value => value.SortOrder).ThenBy(value => value.DisplayName,
                StringComparer.OrdinalIgnoreCase).ToArray();
        CaseMetadataDefinition[] metadata = _metadata
            .Where(entry => Matches(entry.Key, scope))
            .Select(entry => entry.Value).OrderBy(value => value.Label,
                StringComparer.OrdinalIgnoreCase).ToArray();
        return ValueTask.FromResult(new CaseSettingsSnapshot(scope, categories, metadata));
    }

    public ValueTask<CaseCategoryDefinition?> UpsertCategoryAsync(
        CaseSettingsScope scope, CaseCategoryDefinition definition,
        long expectedVersion, string actorSubject, string reason,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CaseSettingsValidator.ValidateScope(scope);
        CaseSettingsValidator.ValidateCategory(definition);
        CaseSettingsValidator.ValidateMutation(expectedVersion, actorSubject, reason);
        lock (_gate)
        {
            var key = Key(scope, definition.Key);
            _categories.TryGetValue(key, out CaseCategoryDefinition? current);
            if ((current?.Version ?? 0) != expectedVersion) return ValueTask.FromResult<CaseCategoryDefinition?>(null);
            CaseCategoryDefinition updated = definition with
            {
                Version = expectedVersion + 1,
                UpdatedAt = timeProvider.GetUtcNow()
            };
            _categories[key] = updated;
            return ValueTask.FromResult<CaseCategoryDefinition?>(updated);
        }
    }

    public ValueTask<CaseMetadataDefinition?> UpsertMetadataDefinitionAsync(
        CaseSettingsScope scope, CaseMetadataDefinition definition,
        long expectedVersion, string actorSubject, string reason,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CaseSettingsValidator.ValidateScope(scope);
        CaseSettingsValidator.ValidateMetadata(definition);
        CaseSettingsValidator.ValidateMutation(expectedVersion, actorSubject, reason);
        lock (_gate)
        {
            var key = Key(scope, definition.Key);
            _metadata.TryGetValue(key, out CaseMetadataDefinition? current);
            if ((current?.Version ?? 0) != expectedVersion) return ValueTask.FromResult<CaseMetadataDefinition?>(null);
            CaseMetadataDefinition updated = definition with
            {
                EnumerationValues = definition.EnumerationValues.Select(value => value.Trim()).ToArray(),
                Version = expectedVersion + 1,
                UpdatedAt = timeProvider.GetUtcNow()
            };
            _metadata[key] = updated;
            return ValueTask.FromResult<CaseMetadataDefinition?>(updated);
        }
    }

    private static (string Tenant, string Game, string Environment, string Key) Key(
        CaseSettingsScope scope, string key) =>
        (scope.TenantId, scope.GameId, scope.EnvironmentId, key);

    private static bool Matches(
        (string Tenant, string Game, string Environment, string Key) key,
        CaseSettingsScope scope) => key.Tenant == scope.TenantId
        && key.Game == scope.GameId && key.Environment == scope.EnvironmentId;
}
