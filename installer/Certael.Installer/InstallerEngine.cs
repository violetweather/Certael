using System.Text.Json;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Certael.Installer;

public abstract record InstallerOperation(string Id, string Description, string RelativePath);
public sealed record CreateDirectoryOperation(string Id, string Description, string RelativePath)
    : InstallerOperation(Id, Description, RelativePath);
public sealed record WriteFileOperation(string Id, string Description, string RelativePath,
    ReadOnlyMemory<byte> Content, bool Overwrite = false, bool Private = false)
    : InstallerOperation(Id, Description, RelativePath);
public sealed record ExtractZipOperation(string Id, string Description, string RelativePath,
    string ArchivePath, bool Overwrite = false, long MaximumExpandedBytes = 8L * 1024 * 1024 * 1024,
    string? ExpectedArchiveSha256 = null)
    : InstallerOperation(Id, Description, RelativePath);
public sealed record DeleteFileOperation(string Id, string Description, string RelativePath,
    string? ExpectedSha256 = null, bool ForceModified = false)
    : InstallerOperation(Id, Description, RelativePath);

public sealed record InstallationPlan(Guid PlanId, string RootPath,
    IReadOnlyList<InstallerOperation> Operations, DateTimeOffset CreatedAt)
{
    public void Validate()
    {
        if (PlanId == Guid.Empty || Operations.Count > 100_001)
            throw new ConfigurationException("Installation plan is invalid.");
        string root = Path.GetFullPath(RootPath);
        if (Path.GetPathRoot(root) == root) throw new ConfigurationException("Installation root cannot be a filesystem root.");
        if (Operations.Select(operation => operation.Id).Distinct(StringComparer.Ordinal).Count() != Operations.Count)
            throw new ConfigurationException("Installation plan contains duplicate operation IDs.");
        foreach (InstallerOperation operation in Operations)
        {
            if (string.IsNullOrWhiteSpace(operation.Id) || operation.Id.Length > 128
                || operation.Id.Any(character => !(char.IsAsciiLetterOrDigit(character)
                    || character is '.' or '_' or '-'))
                || string.IsNullOrWhiteSpace(operation.Description) || operation.Description.Length > 512)
                throw new ConfigurationException("Installation operation metadata is invalid.");
            if (operation is ExtractZipOperation
                && string.Equals(operation.RelativePath, ".", StringComparison.Ordinal))
                ResolveInsideOrRoot(root, operation.RelativePath);
            else
                ResolveInside(root, operation.RelativePath);
            if (operation is WriteFileOperation write && write.Content.Length > 64 * 1024 * 1024)
                throw new ConfigurationException("Generated installation file is too large.");
            if (operation is ExtractZipOperation extract
                && (string.IsNullOrWhiteSpace(extract.ArchivePath) || !Path.IsPathFullyQualified(extract.ArchivePath)
                    || extract.MaximumExpandedBytes <= 0 || extract.MaximumExpandedBytes > 16L * 1024 * 1024 * 1024))
                throw new ConfigurationException("Archive installation operation is invalid.");
            if (operation is ExtractZipOperation verified && verified.ExpectedArchiveSha256 is not null
                && (verified.ExpectedArchiveSha256.Length != 64
                    || !verified.ExpectedArchiveSha256.All(character => char.IsAsciiHexDigit(character)
                        && !char.IsAsciiLetterUpper(character))))
                throw new ConfigurationException("Archive installation digest is invalid.");
            if (operation is DeleteFileOperation delete && delete.ExpectedSha256 is not null
                && (delete.ExpectedSha256.Length != 64 || !delete.ExpectedSha256.All(Uri.IsHexDigit)))
                throw new ConfigurationException("Delete operation digest is invalid.");
        }
    }

    public static string ResolveInside(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative))
            throw new ConfigurationException("Installation path must be relative.");
        string full = Path.GetFullPath(relative, root);
        string prefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        if (!full.StartsWith(prefix, OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new ConfigurationException("Installation path escapes the selected project.");
        return full;
    }

    internal static string ResolveInsideOrRoot(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative))
            throw new ConfigurationException("Installation path must be relative.");
        string fullRoot = Path.GetFullPath(root);
        string full = Path.GetFullPath(relative, fullRoot);
        if (string.Equals(full, fullRoot, OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            return full;
        return ResolveInside(fullRoot, relative);
    }
}

public sealed record InstallationResult(Guid PlanId, bool Succeeded, bool RolledBack,
    int CompletedOperations, string JournalPath);

public sealed class CertaelInstallerEngine(TimeProvider timeProvider)
{
    public async Task<InstallationResult> ApplyAsync(InstallationPlan plan, IInstallerObserver observer,
        CancellationToken cancellationToken)
    {
        plan.Validate();
        string root = Path.GetFullPath(plan.RootPath);
        Directory.CreateDirectory(root);
        EnsureNoReparsePoint(root, root);
        string transactionRoot = InstallationPlan.ResolveInside(root,
            Path.Combine(".certael", "transactions", plan.PlanId.ToString("N")));
        Directory.CreateDirectory(transactionRoot);
        var journal = new List<JournalEntry>();
        string journalPath = Path.Combine(transactionRoot, "journal.json");
        int completed = 0;
        try
        {
            foreach (InstallerOperation operation in plan.Operations)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Report(observer, InstallerEventLevel.Information, InstallerEventKind.OperationStarted,
                    operation, operation.Description, null, cancellationToken);
                string target = operation is ExtractZipOperation
                    && string.Equals(operation.RelativePath, ".", StringComparison.Ordinal)
                    ? InstallationPlan.ResolveInsideOrRoot(root, operation.RelativePath)
                    : InstallationPlan.ResolveInside(root, operation.RelativePath);
                EnsureNoReparsePoint(root, Path.GetDirectoryName(target)!);
                IReadOnlyList<JournalEntry> operationEntries = operation switch
                {
                    CreateDirectoryOperation => [await CreateDirectory(target, operation,
                        journal, journalPath, cancellationToken)],
                    WriteFileOperation write => [await WriteFile(target, transactionRoot, write,
                        journal, journalPath, cancellationToken)],
                    ExtractZipOperation extract => await ExtractZip(root, target, transactionRoot,
                        extract, journal, journalPath, cancellationToken),
                    DeleteFileOperation delete => [await DeleteFile(root, target, transactionRoot,
                        delete, journal, journalPath, cancellationToken)],
                    _ => throw new ConfigurationException("Installation operation type is unsupported.")
                };
                journal.AddRange(operationEntries);
                await PersistJournal(journalPath, journal, cancellationToken);
                completed++;
                await Report(observer, InstallerEventLevel.Information, InstallerEventKind.OperationCompleted,
                    operation, "Completed", new Dictionary<string, string> { ["path"] = operation.RelativePath }, cancellationToken);
            }
            return new InstallationResult(plan.PlanId, true, false, completed, journalPath);
        }
        catch
        {
            await Rollback(root, journal, observer, CancellationToken.None);
            throw;
        }
    }

    public async Task<InstallationResult> RecoverAsync(string rootPath, Guid planId,
        IInstallerObserver observer, CancellationToken cancellationToken)
    {
        if (planId == Guid.Empty) throw new ConfigurationException("Recovery plan ID is invalid.");
        string root = Path.GetFullPath(rootPath);
        string transactionRoot = InstallationPlan.ResolveInside(root,
            Path.Combine(".certael", "transactions", planId.ToString("N")));
        string journalPath = Path.Combine(transactionRoot, "journal.json");
        var file = new FileInfo(journalPath);
        if (!file.Exists || file.Length is <= 0 or > 64 * 1024 * 1024 || file.LinkTarget is not null)
            throw new ConfigurationException("Recovery journal is missing or invalid.");
        EnsureNoReparsePoint(root, transactionRoot);
        List<JournalEntry>? journal = JsonSerializer.Deserialize<List<JournalEntry>>(
            await File.ReadAllBytesAsync(journalPath, cancellationToken));
        if (journal is null || journal.Count > 100_000)
            throw new ConfigurationException("Recovery journal is invalid.");
        foreach (JournalEntry entry in journal)
        {
            EnsureInside(root, entry.TargetPath);
            if (entry.BackupPath is not null) EnsureInside(transactionRoot, entry.BackupPath);
        }
        await Rollback(root, journal, observer, cancellationToken);
        string marker = Path.Combine(transactionRoot, "recovered.json");
        await PersistAtomic(marker, JsonSerializer.SerializeToUtf8Bytes(new
        {
            planId,
            recoveredAt = timeProvider.GetUtcNow(),
            operations = journal.Count
        }, new JsonSerializerOptions { WriteIndented = true }), cancellationToken);
        return new InstallationResult(planId, false, true, journal.Count, journalPath);
    }

    private static async Task<JournalEntry> CreateDirectory(string target,
        InstallerOperation operation, IReadOnlyList<JournalEntry> journal, string journalPath,
        CancellationToken cancellationToken)
    {
        bool existed = Directory.Exists(target);
        var entry = new JournalEntry(operation.Id, "directory", target, existed, null);
        await PersistWithEntry(journalPath, journal, entry, cancellationToken);
        Directory.CreateDirectory(target);
        return entry;
    }

    private static async Task<JournalEntry> WriteFile(string target, string transactionRoot,
        WriteFileOperation operation, IReadOnlyList<JournalEntry> journal, string journalPath,
        CancellationToken cancellationToken)
    {
        bool existed = File.Exists(target);
        if (existed && !operation.Overwrite)
            throw new IOException($"Installation target already exists: {operation.RelativePath}");
        string? backup = null;
        if (existed)
        {
            backup = Path.Combine(transactionRoot, "backup-" + operation.Id);
            File.Copy(target, backup, overwrite: false);
        }
        var entry = new JournalEntry(operation.Id, "file", target, existed, backup);
        await PersistWithEntry(journalPath, journal, entry, cancellationToken);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        string temporary = target + ".certael-" + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllBytesAsync(temporary, operation.Content.ToArray(), cancellationToken);
            File.Move(temporary, target, overwrite: operation.Overwrite);
            if (operation.Private && !OperatingSystem.IsWindows())
                File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        return entry;
    }

    private static async Task<JournalEntry> DeleteFile(string root, string target,
        string transactionRoot, DeleteFileOperation operation,
        IReadOnlyList<JournalEntry> journal, string journalPath,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(target))
        {
            var missing = new JournalEntry(operation.Id, "delete-file", target, false, null);
            await PersistWithEntry(journalPath, journal, missing, cancellationToken);
            return missing;
        }
        var info = new FileInfo(target);
        if (info.LinkTarget is not null) throw new IOException("Installer-managed files cannot be symbolic links.");
        if (operation.ExpectedSha256 is not null && !operation.ForceModified)
        {
            await using FileStream stream = new(target, FileMode.Open, FileAccess.Read,
                FileShare.Read, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            string actual = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken))
                .ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(actual),
                System.Text.Encoding.ASCII.GetBytes(operation.ExpectedSha256.ToLowerInvariant())))
                throw new IOException($"Managed file was modified and will not be removed: {Path.GetRelativePath(root, target)}");
        }
        string backup = Path.Combine(transactionRoot, "deleted-" + operation.Id);
        if (File.Exists(backup)) throw new IOException("Delete backup already exists.");
        var entry = new JournalEntry(operation.Id, "delete-file", target, true, backup);
        await PersistWithEntry(journalPath, journal, entry, cancellationToken);
        File.Move(target, backup);
        return entry;
    }

    private static async Task<IReadOnlyList<JournalEntry>> ExtractZip(string root,
        string destination, string transactionRoot, ExtractZipOperation operation,
        List<JournalEntry> committedJournal, string journalPath,
        CancellationToken cancellationToken)
    {
        var produced = new List<JournalEntry>();
        var seen = new HashSet<string>(OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        long expanded = 0;
        await using var archiveStream = new FileStream(operation.ArchivePath, FileMode.Open,
            FileAccess.Read, FileShare.Read, 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await VerifyArchiveDigest(archiveStream, operation.ExpectedArchiveSha256,
            cancellationToken);
        using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read, leaveOpen: true);
        if (archive.Entries.Count > 100_000) throw new IOException("Archive contains too many entries.");
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string normalized = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
            bool directory = normalized.EndsWith(Path.DirectorySeparatorChar);
            string entryRelative = normalized.TrimEnd(Path.DirectorySeparatorChar);
            if (entryRelative.Length == 0) continue;
            string target = InstallationPlan.ResolveInside(destination, entryRelative);
            if (!seen.Add(target)) throw new IOException("Archive contains duplicate target paths.");
            int unixMode = (entry.ExternalAttributes >> 16) & 0xF000;
            if (unixMode == 0xA000) throw new IOException("Archive symbolic links are prohibited.");
            EnsureNoReparsePoint(root, Path.GetDirectoryName(target)!);
            if (directory)
            {
                bool existed = Directory.Exists(target);
                var directoryJournal = new JournalEntry($"{operation.Id}:{entry.FullName}",
                    "directory", target, existed, null);
                await PersistWithEntry(journalPath, committedJournal, directoryJournal,
                    cancellationToken);
                Directory.CreateDirectory(target);
                produced.Add(directoryJournal);
                committedJournal.Add(directoryJournal);
                continue;
            }
            expanded = checked(expanded + entry.Length);
            if (expanded > operation.MaximumExpandedBytes)
                throw new IOException("Archive exceeds the configured expanded-size limit.");
            bool fileExisted = File.Exists(target);
            if (fileExisted && !operation.Overwrite)
                throw new IOException($"Archive target already exists: {Path.GetRelativePath(root, target)}");
            string journalId = operation.Id + ":" + Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(entry.FullName)))
                .ToLowerInvariant()[..16];
            string? backup = null;
            if (fileExisted)
            {
                backup = Path.Combine(transactionRoot, "backup-" + journalId.Replace(':', '-'));
                File.Copy(target, backup, false);
            }
            var fileJournal = new JournalEntry(journalId, "file", target, fileExisted, backup);
            await PersistWithEntry(journalPath, committedJournal, fileJournal,
                cancellationToken);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            string temporary = target + ".certael-" + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                await using Stream input = entry.Open();
                await using var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                    FileShare.None, 128 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
                await input.CopyToAsync(output, cancellationToken);
                await output.FlushAsync(cancellationToken);
                await output.DisposeAsync();
                File.Move(temporary, target, operation.Overwrite);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            produced.Add(fileJournal);
            committedJournal.Add(fileJournal);
        }
        archive.Dispose();
        await VerifyArchiveDigest(archiveStream, operation.ExpectedArchiveSha256,
            cancellationToken);
        foreach (JournalEntry entry in produced) committedJournal.Remove(entry);
        return produced;
    }

    private static async Task VerifyArchiveDigest(FileStream stream, string? expected,
        CancellationToken cancellationToken)
    {
        if (expected is null) return;
        stream.Position = 0;
        string actual = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken))
            .ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(actual),
            System.Text.Encoding.ASCII.GetBytes(expected)))
            throw new CryptographicException("Archive digest changed after verification.");
        stream.Position = 0;
    }

    private async Task Rollback(string root, IReadOnlyList<JournalEntry> journal,
        IInstallerObserver observer, CancellationToken cancellationToken)
    {
        foreach (JournalEntry entry in journal.Reverse())
        {
            try
            {
                if (entry.Kind == "file")
                {
                    if (entry.Existed && entry.BackupPath is not null) File.Copy(entry.BackupPath, entry.TargetPath, true);
                    else if (File.Exists(entry.TargetPath)) File.Delete(entry.TargetPath);
                }
                else if (entry.Kind == "delete-file")
                {
                    if (entry.Existed && entry.BackupPath is not null && File.Exists(entry.BackupPath))
                        File.Copy(entry.BackupPath, entry.TargetPath, true);
                }
                else if (!entry.Existed && Directory.Exists(entry.TargetPath)
                    && !Directory.EnumerateFileSystemEntries(entry.TargetPath).Any())
                    Directory.Delete(entry.TargetPath);
                await observer.ReportAsync(new InstallerEvent(timeProvider.GetUtcNow(),
                    InstallerEventLevel.Warning, InstallerEventKind.Rollback, entry.OperationId,
                    "Rolled back operation", InstallerSecretRedactor.Redact(
                        new Dictionary<string, string> { ["path"] = Path.GetRelativePath(root, entry.TargetPath) })), cancellationToken);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                await observer.ReportAsync(new InstallerEvent(timeProvider.GetUtcNow(),
                    InstallerEventLevel.Error, InstallerEventKind.Rollback, entry.OperationId,
                    "Rollback operation failed", InstallerSecretRedactor.Redact(
                        new Dictionary<string, string> { ["error"] = exception.Message })), cancellationToken);
            }
        }
    }

    private static async Task PersistJournal(string path, IReadOnlyList<JournalEntry> journal,
        CancellationToken cancellationToken)
    {
        byte[] content = JsonSerializer.SerializeToUtf8Bytes(journal,
            new JsonSerializerOptions { WriteIndented = true });
        await PersistAtomic(path, content, cancellationToken);
    }

    private static async Task PersistWithEntry(string path, IReadOnlyList<JournalEntry> journal,
        JournalEntry entry, CancellationToken cancellationToken)
    {
        var pending = new List<JournalEntry>(journal.Count + 1);
        pending.AddRange(journal);
        pending.Add(entry);
        await PersistJournal(path, pending, cancellationToken);
    }

    private static async Task PersistAtomic(string path, byte[] content,
        CancellationToken cancellationToken)
    {
        string temporary = path + ".tmp";
        await File.WriteAllBytesAsync(temporary, content, cancellationToken);
        File.Move(temporary, path, true);
    }

    private async Task Report(IInstallerObserver observer, InstallerEventLevel level,
        InstallerEventKind kind, InstallerOperation operation, string message,
        IReadOnlyDictionary<string, string>? details, CancellationToken cancellationToken) =>
        await observer.ReportAsync(new InstallerEvent(timeProvider.GetUtcNow(), level, kind,
            operation.Id, InstallerSecretRedactor.Redact(message),
            InstallerSecretRedactor.Redact(details)), cancellationToken);

    private static void EnsureNoReparsePoint(string root, string path)
    {
        string current = Path.GetFullPath(path);
        while (current.Length >= root.Length)
        {
            if (Directory.Exists(current) && new DirectoryInfo(current).LinkTarget is not null)
                throw new IOException("Installation paths cannot traverse symbolic links or junctions.");
            if (string.Equals(current, root, OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) break;
            string? parent = Path.GetDirectoryName(current);
            if (parent is null) break;
            current = parent;
        }
    }

    private static void EnsureInside(string root, string path)
    {
        string fullRoot = Path.GetFullPath(root);
        string fullPath = Path.GetFullPath(path);
        string prefix = fullRoot.EndsWith(Path.DirectorySeparatorChar)
            ? fullRoot : fullRoot + Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(prefix, OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new ConfigurationException("Recovery journal path escapes its transaction boundary.");
    }

    private sealed record JournalEntry(string OperationId, string Kind, string TargetPath,
        bool Existed, string? BackupPath);
}
