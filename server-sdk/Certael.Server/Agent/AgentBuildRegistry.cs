using System.Collections.Concurrent;

namespace Certael.Server.Agent;

public sealed record ApprovedAgentBuild(
    string TenantId, string GameId, string EnvironmentId, string BuildId,
    DateTimeOffset RegisteredAt, string RegisteredBy, DateTimeOffset? RevokedAt = null,
    string? RevokedBy = null);

public interface IAgentBuildRegistry
{
    ValueTask<bool> IsApprovedAsync(string tenantId, string gameId, string environmentId,
        string buildId, CancellationToken cancellationToken);
}

public interface IAgentBuildAdministration
{
    ValueTask<ApprovedAgentBuild> RegisterAsync(string tenantId, string gameId,
        string environmentId, string buildId, string operatorSubject,
        CancellationToken cancellationToken);
    ValueTask<bool> RevokeAsync(string tenantId, string gameId, string environmentId,
        string buildId, string operatorSubject, CancellationToken cancellationToken);
}

public sealed class InMemoryAgentBuildRegistry(TimeProvider timeProvider)
    : IAgentBuildRegistry, IAgentBuildAdministration
{
    private readonly ConcurrentDictionary<string, ApprovedAgentBuild> _builds =
        new(StringComparer.Ordinal);

    public ValueTask<ApprovedAgentBuild> RegisterAsync(string tenantId, string gameId,
        string environmentId, string buildId, string operatorSubject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Validate(tenantId, gameId, environmentId, buildId, operatorSubject);
        var value = new ApprovedAgentBuild(tenantId, gameId, environmentId, buildId,
            timeProvider.GetUtcNow(), operatorSubject);
        if (!_builds.TryAdd(Key(tenantId, gameId, environmentId, buildId), value))
            throw new AgentBuildRegistryException("Build is already registered.");
        return ValueTask.FromResult(value);
    }

    public ValueTask<bool> RevokeAsync(string tenantId, string gameId, string environmentId,
        string buildId, string operatorSubject, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Validate(tenantId, gameId, environmentId, buildId, operatorSubject);
        string key = Key(tenantId, gameId, environmentId, buildId);
        while (_builds.TryGetValue(key, out ApprovedAgentBuild? current))
        {
            if (current.RevokedAt is not null) return ValueTask.FromResult(false);
            var revoked = current with { RevokedAt = timeProvider.GetUtcNow(),
                RevokedBy = operatorSubject };
            if (_builds.TryUpdate(key, revoked, current)) return ValueTask.FromResult(true);
        }
        return ValueTask.FromResult(false);
    }

    public ValueTask<bool> IsApprovedAsync(string tenantId, string gameId,
        string environmentId, string buildId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(_builds.TryGetValue(
            Key(tenantId, gameId, environmentId, buildId), out ApprovedAgentBuild? value)
            && value.RevokedAt is null);
    }

    private static string Key(string tenantId, string gameId, string environmentId,
        string buildId) => string.Join('\0', tenantId, gameId, environmentId, buildId);

    public static void Validate(params string[] values)
    {
        if (values.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 128
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-')))
            throw new AgentBuildRegistryException("Build registration is invalid.");
    }
}

public sealed class AgentBuildRegistryException(string message) : Exception(message);
