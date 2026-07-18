using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Certael.Installer;

public sealed record InstalledSuiteState(
    [property: JsonPropertyName("schema_version")] uint SchemaVersion,
    [property: JsonPropertyName("suite_version")] string SuiteVersion,
    [property: JsonPropertyName("runtime_identifier")] string RuntimeIdentifier,
    [property: JsonPropertyName("components")] IReadOnlyList<InstalledSuiteComponent> Components,
    [property: JsonPropertyName("files")] IReadOnlyList<InstalledSuiteFile> Files,
    [property: JsonPropertyName("plan_id")] Guid PlanId,
    [property: JsonPropertyName("installed_at")] DateTimeOffset InstalledAt,
    [property: JsonPropertyName("updated_at")] DateTimeOffset UpdatedAt);

public sealed record InstalledSuiteComponent(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("artifact_sha256")] string ArtifactSha256);

public sealed record InstalledSuiteFile(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("component_id")] string ComponentId,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("preserve_on_uninstall")] bool PreserveOnUninstall = false);

public enum InstalledFileHealth { Healthy, Missing, Modified, SymbolicLink }

public sealed record InstalledFileInspection(
    InstalledSuiteFile File, InstalledFileHealth Health, long? ActualSize,
    string? ActualSha256);

public sealed record SuiteInstallationInspection(
    InstalledSuiteState State, IReadOnlyList<InstalledFileInspection> Files)
{
    public bool Healthy => Files.All(value => value.Health == InstalledFileHealth.Healthy);
}

public static partial class InstalledSuiteStateCodec
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true
    };

    public static byte[] Encode(InstalledSuiteState state, string rootPath)
    {
        Validate(state, rootPath);
        return JsonSerializer.SerializeToUtf8Bytes(state, Json);
    }

    public static InstalledSuiteState Decode(ReadOnlySpan<byte> content, string rootPath)
    {
        if (content.Length is <= 0 or > 16 * 1024 * 1024)
            throw new ConfigurationException("Installed suite state is missing or too large.");
        InstalledSuiteState state;
        try
        {
            state = JsonSerializer.Deserialize<InstalledSuiteState>(content, Json)
                ?? throw new ConfigurationException("Installed suite state is empty.");
        }
        catch (JsonException exception)
        {
            throw new ConfigurationException("Installed suite state JSON is invalid.", exception);
        }
        Validate(state, rootPath);
        return state;
    }

    public static void Validate(InstalledSuiteState state, string rootPath)
    {
        if (state.SchemaVersion != 1 || state.PlanId == Guid.Empty
            || state.UpdatedAt < state.InstalledAt || state.UpdatedAt > DateTimeOffset.UtcNow.AddMinutes(5))
            throw new ConfigurationException("Installed suite state header is invalid.");
        ValidateVersion(state.SuiteVersion);
        ValidateToken(state.RuntimeIdentifier, 96, "Runtime identifier");
        if (state.Components.Count is 0 or > 256 || state.Files.Count > 100_000)
            throw new ConfigurationException("Installed suite state is too large.");
        if (state.Components.Select(value => value.Id).Distinct(StringComparer.Ordinal).Count()
            != state.Components.Count)
            throw new ConfigurationException("Installed suite components are duplicated.");
        var components = new HashSet<string>(StringComparer.Ordinal);
        foreach (InstalledSuiteComponent component in state.Components)
        {
            ValidateToken(component.Id, 96, "Component ID");
            ValidateVersion(component.Version);
            ValidateDigest(component.ArtifactSha256);
            components.Add(component.Id);
        }
        string root = Path.GetFullPath(rootPath);
        var paths = new HashSet<string>(OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (InstalledSuiteFile file in state.Files)
        {
            if (!components.Contains(file.ComponentId) || file.Size < 0
                || file.Size > 16L * 1024 * 1024 * 1024)
                throw new ConfigurationException("Installed suite file metadata is invalid.");
            ValidateDigest(file.Sha256);
            string normalized = file.Path.Replace('/', Path.DirectorySeparatorChar);
            string full = InstallationPlan.ResolveInside(root, normalized);
            string relative = Path.GetRelativePath(root, full).Replace(Path.DirectorySeparatorChar, '/');
            if (!string.Equals(relative, file.Path, StringComparison.Ordinal)
                || relative.StartsWith(".certael/transactions/", StringComparison.Ordinal)
                || !paths.Add(full))
                throw new ConfigurationException("Installed suite file path is invalid or duplicated.");
        }
    }

    private static void ValidateToken(string value, int maximum, string label)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-')))
            throw new ConfigurationException($"{label} is invalid.");
    }

    private static void ValidateVersion(string value)
    {
        if (value.Length > 64 || !VersionPattern().IsMatch(value))
            throw new ConfigurationException("Installed suite version is invalid.");
    }

    private static void ValidateDigest(string value)
    {
        if (value.Length != 64 || !value.All(character => char.IsAsciiHexDigit(character)
            && !char.IsAsciiLetterUpper(character)))
            throw new ConfigurationException("Installed suite digest is invalid.");
    }

    [GeneratedRegex("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();
}

public static class CertaelInstallationLifecycle
{
    public static async Task<InstalledSuiteState> LoadStateAsync(string rootPath,
        CancellationToken cancellationToken)
    {
        string root = Path.GetFullPath(rootPath);
        string path = InstallationPlan.ResolveInside(root,
            CertaelSuiteInstaller.InstalledStatePath.Replace('/', Path.DirectorySeparatorChar));
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > 16 * 1024 * 1024)
            throw new ConfigurationException("Installed suite inventory is missing or invalid.");
        return InstalledSuiteStateCodec.Decode(
            await File.ReadAllBytesAsync(path, cancellationToken), root);
    }

    public static async Task<SuiteInstallationInspection> InspectAsync(string rootPath,
        InstalledSuiteState state, CancellationToken cancellationToken)
    {
        InstalledSuiteStateCodec.Validate(state, rootPath);
        string root = Path.GetFullPath(rootPath);
        var results = new List<InstalledFileInspection>(state.Files.Count);
        foreach (InstalledSuiteFile file in state.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string path = InstallationPlan.ResolveInside(root,
                file.Path.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(path))
            {
                results.Add(new InstalledFileInspection(file, InstalledFileHealth.Missing, null, null));
                continue;
            }
            var info = new FileInfo(path);
            if (info.LinkTarget is not null)
            {
                results.Add(new InstalledFileInspection(file, InstalledFileHealth.SymbolicLink,
                    info.Length, null));
                continue;
            }
            await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            string digest = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken))
                .ToLowerInvariant();
            InstalledFileHealth health = info.Length == file.Size
                && CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(digest),
                    System.Text.Encoding.ASCII.GetBytes(file.Sha256))
                ? InstalledFileHealth.Healthy : InstalledFileHealth.Modified;
            results.Add(new InstalledFileInspection(file, health, info.Length, digest));
        }
        return new SuiteInstallationInspection(state, results);
    }

    public static InstallationPlan CreateUninstallPlan(string rootPath,
        InstalledSuiteState state, bool forceModified, DateTimeOffset now)
    {
        InstalledSuiteStateCodec.Validate(state, rootPath);
        DeleteFileOperation[] operations = state.Files
            .Where(file => !file.PreserveOnUninstall)
            .OrderByDescending(file => file.Path.Length).ThenBy(file => file.Path, StringComparer.Ordinal)
            .Select((file, index) => new DeleteFileOperation($"uninstall-{index:D6}",
                $"Remove {file.ComponentId} managed file", file.Path, file.Sha256, forceModified))
            .ToArray();
        InstallerOperation[] complete = [.. operations,
            new DeleteFileOperation("uninstall-state", "Remove installed suite inventory",
                CertaelSuiteInstaller.InstalledStatePath, ForceModified: true)];
        return new InstallationPlan(Guid.NewGuid(), Path.GetFullPath(rootPath), complete, now);
    }
}
