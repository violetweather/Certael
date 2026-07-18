using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace Certael.Installer;

public enum InstallerEventLevel { Trace, Information, Warning, Error }
public enum InstallerEventKind { Plan, OperationStarted, OperationProgress, OperationCompleted, Rollback, Verification }

public sealed record InstallerEvent(
    DateTimeOffset OccurredAt,
    InstallerEventLevel Level,
    InstallerEventKind Kind,
    string OperationId,
    string Message,
    IReadOnlyDictionary<string, string> Details);

public interface IInstallerObserver
{
    ValueTask ReportAsync(InstallerEvent value, CancellationToken cancellationToken);
}

public sealed class InstallerEventBuffer : IInstallerObserver
{
    private readonly List<InstallerEvent> values = [];
    public IReadOnlyList<InstallerEvent> Events => new ReadOnlyCollection<InstallerEvent>(values);
    public ValueTask ReportAsync(InstallerEvent value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        values.Add(value);
        return ValueTask.CompletedTask;
    }
}

public static partial class InstallerSecretRedactor
{
    private static readonly string[] SensitiveKeys =
        ["password", "secret", "token", "private_key", "privatekey", "connection_string", "credential"];

    public static IReadOnlyDictionary<string, string> Redact(IReadOnlyDictionary<string, string>? details)
    {
        if (details is null || details.Count == 0) return new Dictionary<string, string>();
        return details.ToDictionary(pair => pair.Key, pair => IsSensitiveKey(pair.Key)
            ? "[REDACTED]" : Redact(pair.Value), StringComparer.Ordinal);
    }

    public static string Redact(string value)
    {
        string redacted = AssignmentPattern().Replace(value, match => $"{match.Groups[1].Value}=[REDACTED]");
        redacted = BearerPattern().Replace(redacted, "Bearer [REDACTED]");
        return PrivateKeyPattern().Replace(redacted, "[REDACTED PRIVATE KEY]");
    }

    private static bool IsSensitiveKey(string key) => SensitiveKeys.Any(value =>
        key.Contains(value, StringComparison.OrdinalIgnoreCase));

    [GeneratedRegex("(?i)(password|client_secret|access_token|refresh_token|connection_string)\\s*[=:]\\s*([^\\s;&]+)")]
    private static partial Regex AssignmentPattern();
    [GeneratedRegex("(?i)Bearer\\s+[A-Za-z0-9._~+/-]+=*")]
    private static partial Regex BearerPattern();
    [GeneratedRegex("-----BEGIN PRIVATE KEY-----[\\s\\S]*?-----END PRIVATE KEY-----")]
    private static partial Regex PrivateKeyPattern();
}
