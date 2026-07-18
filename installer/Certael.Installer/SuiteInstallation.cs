using System.IO.Compression;
using System.Security.Cryptography;

namespace Certael.Installer;

public sealed record SuiteInstallResult(
    CertaelSuiteManifest Manifest,
    InstalledSuiteState State,
    InstallationResult Installation);

public sealed class CertaelSuiteInstaller(HttpClient client, TimeProvider timeProvider)
{
    public const string InstalledStatePath = ".certael/installed-state.json";
    private const int MaximumEntries = 100_000;
    private const long MaximumExpandedBytes = 8L * 1024 * 1024 * 1024;

    public async Task<SuiteInstallResult> InstallAsync(
        ReadOnlyMemory<byte> signedManifest,
        SuiteVerificationKeyRing keyRing,
        CertaelProjectConfiguration configuration,
        string runtimeIdentifier,
        string rootPath,
        string cachePath,
        IInstallerObserver observer,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = timeProvider.GetUtcNow();
        string root = Path.GetFullPath(rootPath);
        PreparedSuite prepared = await PrepareAsync(signedManifest, keyRing, configuration,
            runtimeIdentifier, root, cachePath, observer, cancellationToken);
        string statePath = InstallationPlan.ResolveInside(root,
            InstalledStatePath.Replace('/', Path.DirectorySeparatorChar));
        if (File.Exists(statePath) || Directory.Exists(statePath))
            throw new IOException("A Certael suite is already installed at the selected root.");
        Guid planId = Guid.NewGuid();
        var state = new InstalledSuiteState(1, prepared.Manifest.SuiteVersion, runtimeIdentifier,
            prepared.Components.Select(component => new InstalledSuiteComponent(component.Id,
                component.Version, component.Artifact.Sha256)).ToArray(),
            prepared.Files, planId, now, now);
        List<InstallerOperation> operations = CreateExtractionOperations(prepared, overwrite: false,
            "Install");
        operations.Add(StateOperation(state, root, overwrite: false));
        var plan = new InstallationPlan(planId, root, operations, now);
        InstallationResult installation = await new CertaelInstallerEngine(timeProvider)
            .ApplyAsync(plan, observer, cancellationToken);
        return new SuiteInstallResult(prepared.Manifest, state, installation);
    }

    public async Task<SuiteInstallResult> UpdateAsync(
        ReadOnlyMemory<byte> signedManifest,
        SuiteVerificationKeyRing keyRing,
        CertaelProjectConfiguration configuration,
        string rootPath,
        string cachePath,
        bool forceModified,
        IInstallerObserver observer,
        CancellationToken cancellationToken)
    {
        string root = Path.GetFullPath(rootPath);
        InstalledSuiteState current = await LoadStateAsync(root, cancellationToken);
        DateTimeOffset now = timeProvider.GetUtcNow();
        PreparedSuite prepared = await PrepareAsync(signedManifest, keyRing, configuration,
            current.RuntimeIdentifier, root, cachePath, observer, cancellationToken);
        SuiteInstallationInspection inspection = await CertaelInstallationLifecycle.InspectAsync(
            root, current, cancellationToken);
        RejectUnsafeDrift(inspection, forceModified);
        var currentFiles = current.Files.ToDictionary(file => file.Path,
            StringComparer.OrdinalIgnoreCase);
        var nextPaths = new HashSet<string>(prepared.Files.Select(file => file.Path),
            StringComparer.OrdinalIgnoreCase);
        foreach (InstalledSuiteFile file in prepared.Files)
        {
            string target = InstallationPlan.ResolveInside(root,
                file.Path.Replace('/', Path.DirectorySeparatorChar));
            if (currentFiles.TryGetValue(file.Path, out InstalledSuiteFile? existing))
            {
                if (existing.PreserveOnUninstall)
                    throw new IOException($"Update cannot overwrite operator-owned file: {file.Path}");
            }
            else if (File.Exists(target) || Directory.Exists(target))
                throw new IOException($"Update would overwrite an unmanaged path: {file.Path}");
        }
        Guid planId = Guid.NewGuid();
        InstalledSuiteFile[] preservedFiles = current.Files.Where(file =>
            file.PreserveOnUninstall && !nextPaths.Contains(file.Path)).ToArray();
        var stateComponents = prepared.Components.Select(component =>
            new InstalledSuiteComponent(component.Id, component.Version,
                component.Artifact.Sha256)).ToList();
        var stateComponentIds = new HashSet<string>(stateComponents.Select(value => value.Id),
            StringComparer.Ordinal);
        foreach (InstalledSuiteComponent component in current.Components.Where(component =>
            preservedFiles.Any(file => file.ComponentId == component.Id)
                && !stateComponentIds.Contains(component.Id)))
            stateComponents.Add(component);
        var state = new InstalledSuiteState(1, prepared.Manifest.SuiteVersion,
            current.RuntimeIdentifier, stateComponents,
            [.. prepared.Files, .. preservedFiles], planId,
            current.InstalledAt, now);
        var operations = current.Files.Where(file => !file.PreserveOnUninstall
                && !nextPaths.Contains(file.Path))
            .OrderByDescending(file => file.Path.Length).ThenBy(file => file.Path,
                StringComparer.Ordinal)
            .Select((file, index) => (InstallerOperation)new DeleteFileOperation(
                $"update-remove-{index:D6}", $"Remove retired {file.ComponentId} file",
                file.Path, file.Sha256, forceModified)).ToList();
        operations.AddRange(CreateExtractionOperations(prepared, overwrite: true, "Update"));
        operations.Add(StateOperation(state, root, overwrite: true));
        var plan = new InstallationPlan(planId, root, operations, now);
        InstallationResult installation = await new CertaelInstallerEngine(timeProvider)
            .ApplyAsync(plan, observer, cancellationToken);
        return new SuiteInstallResult(prepared.Manifest, state, installation);
    }

    public async Task<SuiteInstallResult> RepairAsync(
        ReadOnlyMemory<byte> signedManifest,
        SuiteVerificationKeyRing keyRing,
        CertaelProjectConfiguration configuration,
        string rootPath,
        string cachePath,
        bool forceModified,
        IInstallerObserver observer,
        CancellationToken cancellationToken)
    {
        string root = Path.GetFullPath(rootPath);
        InstalledSuiteState current = await LoadStateAsync(root, cancellationToken);
        DateTimeOffset now = timeProvider.GetUtcNow();
        PreparedSuite prepared = await PrepareAsync(signedManifest, keyRing, configuration,
            current.RuntimeIdentifier, root, cachePath, observer, cancellationToken);
        EnsureRepairMatchesInstalledState(current, prepared);
        SuiteInstallationInspection inspection = await CertaelInstallationLifecycle.InspectAsync(
            root, current, cancellationToken);
        RejectUnsafeDrift(inspection, forceModified);
        Guid planId = Guid.NewGuid();
        var state = current with { PlanId = planId, UpdatedAt = now };
        List<InstallerOperation> operations = CreateExtractionOperations(prepared,
            overwrite: true, "Repair");
        operations.Add(StateOperation(state, root, overwrite: true));
        var plan = new InstallationPlan(planId, root, operations, now);
        InstallationResult installation = await new CertaelInstallerEngine(timeProvider)
            .ApplyAsync(plan, observer, cancellationToken);
        return new SuiteInstallResult(prepared.Manifest, state, installation);
    }

    private async Task<PreparedSuite> PrepareAsync(ReadOnlyMemory<byte> signedManifest,
        SuiteVerificationKeyRing keyRing, CertaelProjectConfiguration configuration,
        string runtimeIdentifier, string root, string cachePath, IInstallerObserver observer,
        CancellationToken cancellationToken)
    {
        configuration.Validate();
        if (Path.GetPathRoot(root) == root)
            throw new ConfigurationException("Installation root cannot be a filesystem root.");
        CertaelSuiteManifest manifest = SignedSuiteManifestCodec.Verify(signedManifest.Span,
            keyRing, timeProvider.GetUtcNow());
        IReadOnlyList<CertaelResolvedComponent> components = CertaelSuiteResolver.Resolve(
            manifest, configuration.RequiredComponents(), runtimeIdentifier);
        var downloader = new CertaelArtifactDownloader(client, timeProvider);
        var artifacts = new List<(CertaelResolvedComponent Component, DownloadedArtifact Download)>();
        foreach (CertaelResolvedComponent component in components)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DownloadedArtifact download = await downloader.DownloadAsync(component.Artifact,
                cachePath, observer, cancellationToken);
            artifacts.Add((component, download));
        }
        IReadOnlyList<InstalledSuiteFile> files = await InspectArtifactsAsync(
            artifacts, root, cancellationToken);
        return new PreparedSuite(manifest, components, artifacts, files);
    }

    private static List<InstallerOperation> CreateExtractionOperations(PreparedSuite prepared,
        bool overwrite, string verb)
    {
        var operations = new List<InstallerOperation>(prepared.Artifacts.Count + 1);
        for (int index = 0; index < prepared.Artifacts.Count; index++)
        {
            (CertaelResolvedComponent component, DownloadedArtifact download) =
                prepared.Artifacts[index];
            operations.Add(new ExtractZipOperation($"extract-{index:D4}",
                $"{verb} {component.Id}@{component.Version}", ".", download.Path,
                overwrite, MaximumExpandedBytes, component.Artifact.Sha256));
        }
        return operations;
    }

    private static WriteFileOperation StateOperation(InstalledSuiteState state, string root,
        bool overwrite) => new("installed-state", "Record installed suite inventory",
            InstalledStatePath, InstalledSuiteStateCodec.Encode(state, root), overwrite);

    private static async Task<InstalledSuiteState> LoadStateAsync(string root,
        CancellationToken cancellationToken)
    {
        string path = InstallationPlan.ResolveInside(root,
            InstalledStatePath.Replace('/', Path.DirectorySeparatorChar));
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > 16 * 1024 * 1024)
            throw new ConfigurationException("Installed suite inventory is missing or invalid.");
        return InstalledSuiteStateCodec.Decode(await File.ReadAllBytesAsync(path,
            cancellationToken), root);
    }

    private static void RejectUnsafeDrift(SuiteInstallationInspection inspection,
        bool forceModified)
    {
        InstalledFileInspection? link = inspection.Files.FirstOrDefault(value =>
            value.Health == InstalledFileHealth.SymbolicLink);
        if (link is not null)
            throw new IOException($"Managed file is a symbolic link: {link.File.Path}");
        InstalledFileInspection? modified = inspection.Files.FirstOrDefault(value =>
            value.Health == InstalledFileHealth.Modified && !forceModified);
        if (modified is not null)
            throw new IOException($"Managed file was modified; use explicit force to replace it: {modified.File.Path}");
    }

    private static void EnsureRepairMatchesInstalledState(InstalledSuiteState current,
        PreparedSuite prepared)
    {
        if (!string.Equals(current.SuiteVersion, prepared.Manifest.SuiteVersion,
            StringComparison.Ordinal))
            throw new ConfigurationException("Repair manifest does not match the installed suite version.");
        InstalledSuiteComponent[] components = prepared.Components.Select(component =>
            new InstalledSuiteComponent(component.Id, component.Version,
                component.Artifact.Sha256)).OrderBy(value => value.Id, StringComparer.Ordinal).ToArray();
        InstalledSuiteComponent[] installedComponents = current.Components.OrderBy(
            value => value.Id, StringComparer.Ordinal).ToArray();
        if (!components.SequenceEqual(installedComponents))
            throw new ConfigurationException("Repair manifest components do not match the installed suite.");
        InstalledSuiteFile[] files = prepared.Files.OrderBy(value => value.Path,
            StringComparer.Ordinal).ToArray();
        InstalledSuiteFile[] installedFiles = current.Files.OrderBy(value => value.Path,
            StringComparer.Ordinal).ToArray();
        if (files.Length != installedFiles.Length || files.Where((file, index) =>
                file.Path != installedFiles[index].Path
                || file.ComponentId != installedFiles[index].ComponentId
                || file.Size != installedFiles[index].Size
                || file.Sha256 != installedFiles[index].Sha256).Any())
            throw new ConfigurationException("Repair artifacts do not match the installed inventory.");
    }

    private sealed record PreparedSuite(CertaelSuiteManifest Manifest,
        IReadOnlyList<CertaelResolvedComponent> Components,
        IReadOnlyList<(CertaelResolvedComponent Component, DownloadedArtifact Download)> Artifacts,
        IReadOnlyList<InstalledSuiteFile> Files);

    private static async Task<IReadOnlyList<InstalledSuiteFile>> InspectArtifactsAsync(
        IReadOnlyList<(CertaelResolvedComponent Component, DownloadedArtifact Download)> artifacts,
        string root,
        CancellationToken cancellationToken)
    {
        var files = new List<InstalledSuiteFile>();
        var targets = new HashSet<string>(OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        var portablePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long expanded = 0;
        int entries = 0;
        foreach ((CertaelResolvedComponent component, DownloadedArtifact download) in artifacts)
        {
            int componentFiles = 0;
            using ZipArchive archive = ZipFile.OpenRead(download.Path);
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                entries = checked(entries + 1);
                if (entries > MaximumEntries)
                    throw new IOException("Suite archives contain too many entries.");
                string path = NormalizeArchivePath(entry.FullName);
                bool directory = entry.FullName.EndsWith("/", StringComparison.Ordinal);
                RejectReservedPath(path);
                int unixType = (entry.ExternalAttributes >> 16) & 0xF000;
                if (unixType == 0xA000)
                    throw new IOException("Suite archives cannot contain symbolic links.");
                if (unixType != 0 && unixType != 0x8000 && unixType != 0x4000)
                    throw new IOException("Suite archives cannot contain special files.");
                if (directory)
                {
                    if (unixType == 0x8000)
                        throw new IOException("Suite archive entry type is inconsistent.");
                    continue;
                }
                if (unixType == 0x4000)
                    throw new IOException("Suite archive entry type is inconsistent.");
                string target = InstallationPlan.ResolveInside(root,
                    path.Replace('/', Path.DirectorySeparatorChar));
                if (!targets.Add(target) || !portablePaths.Add(path))
                    throw new IOException($"Suite components contain duplicate path: {path}");
                RejectFileDirectoryCollision(path, portablePaths);
                expanded = checked(expanded + entry.Length);
                if (expanded > MaximumExpandedBytes)
                    throw new IOException("Suite archives exceed the expanded-size limit.");
                await using Stream input = entry.Open();
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] buffer = new byte[128 * 1024];
                long actual = 0;
                while (true)
                {
                    int read = await input.ReadAsync(buffer, cancellationToken);
                    if (read == 0) break;
                    actual = checked(actual + read);
                    if (actual > entry.Length)
                        throw new IOException("Suite archive entry exceeded its declared size.");
                    hash.AppendData(buffer.AsSpan(0, read));
                }
                if (actual != entry.Length)
                    throw new IOException("Suite archive entry size is invalid.");
                files.Add(new InstalledSuiteFile(path, component.Id, actual,
                    Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant()));
                componentFiles++;
            }
            if (componentFiles == 0)
                throw new IOException($"Suite component {component.Id} contains no installable files.");
        }
        return files.OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
    }

    private static string NormalizeArchivePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4096 || value.Contains('\\'))
            throw new IOException("Suite archive path is invalid.");
        string path = value.TrimEnd('/');
        string[] segments = path.Split('/');
        if (path.Length == 0 || path.StartsWith("/", StringComparison.Ordinal)
            || segments.Any(segment => segment.Length == 0 || segment is "." or ".."
                || segment.EndsWith(' ') || segment.EndsWith('.') || segment.Contains(':')
                || segment.IndexOfAny(['<', '>', '"', '|', '?', '*']) >= 0
                || segment.Any(character => char.IsControl(character))
                || IsWindowsDeviceName(segment)))
            throw new IOException("Suite archive path is invalid.");
        return path;
    }

    private static bool IsWindowsDeviceName(string segment)
    {
        string stem = segment.Split('.', 2)[0];
        return stem.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            || stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase)
                || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase))
                && stem[3] is >= '1' and <= '9';
    }

    private static void RejectReservedPath(string path)
    {
        if (path.Equals(".certael", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(".certael/", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Suite artifacts cannot write installer state paths.");
    }

    private static void RejectFileDirectoryCollision(string path, HashSet<string> paths)
    {
        int separator = path.IndexOf('/');
        while (separator >= 0)
        {
            if (paths.Contains(path[..separator]))
                throw new IOException("Suite archive contains a file/directory path collision.");
            separator = path.IndexOf('/', separator + 1);
        }
        string prefix = path + "/";
        if (paths.Any(value => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("Suite archive contains a file/directory path collision.");
    }
}
