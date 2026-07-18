using System.Buffers;
using System.Security.Cryptography;

namespace Certael.Installer;

public sealed record DownloadedArtifact(string Path, long Size, string Sha256);

public sealed class CertaelArtifactDownloader(HttpClient client, TimeProvider timeProvider)
{
    public async Task<DownloadedArtifact> DownloadAsync(CertaelSuiteArtifact artifact,
        string cacheRoot, IInstallerObserver observer, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(artifact.Uri, UriKind.Absolute, out Uri? uri)
            || uri.Scheme != Uri.UriSchemeHttps)
            throw new ConfigurationException("Artifact download requires HTTPS.");
        string root = Path.GetFullPath(cacheRoot);
        if (Path.GetPathRoot(root) == root) throw new ConfigurationException("Artifact cache cannot be a filesystem root.");
        Directory.CreateDirectory(root);
        string destination = Path.Combine(root, artifact.Sha256 + ".artifact");
        if (File.Exists(destination))
        {
            DownloadedArtifact existing = await VerifyFile(destination, artifact, cancellationToken);
            await Report(observer, InstallerEventKind.Verification, "cache", "Verified cached artifact",
                artifact, existing.Size, cancellationToken);
            return existing;
        }

        string temporary = destination + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using HttpResponseMessage response = await client.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long advertised && advertised != artifact.Size)
                throw new IOException("Artifact response size does not match the signed suite manifest.");
            await using Stream input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 128 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
            long total = 0;
            try
            {
                while (true)
                {
                    int read = await input.ReadAsync(buffer, cancellationToken);
                    if (read == 0) break;
                    total = checked(total + read);
                    if (total > artifact.Size) throw new IOException("Artifact exceeded its signed size.");
                    hash.AppendData(buffer.AsSpan(0, read));
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
            await output.FlushAsync(cancellationToken);
            if (total != artifact.Size) throw new IOException("Artifact size does not match the signed suite manifest.");
            string digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(digest),
                System.Text.Encoding.ASCII.GetBytes(artifact.Sha256)))
                throw new CryptographicException("Artifact digest does not match the signed suite manifest.");
            await output.DisposeAsync();
            File.Move(temporary, destination, false);
            var result = new DownloadedArtifact(destination, total, digest);
            await Report(observer, InstallerEventKind.OperationCompleted, "download", "Downloaded and verified artifact",
                artifact, total, cancellationToken);
            return result;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static async Task<DownloadedArtifact> VerifyFile(string path,
        CertaelSuiteArtifact artifact, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (info.Length != artifact.Size) throw new IOException("Cached artifact size is invalid.");
        await using FileStream stream = File.OpenRead(path);
        string digest = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(digest),
            System.Text.Encoding.ASCII.GetBytes(artifact.Sha256)))
            throw new CryptographicException("Cached artifact digest is invalid.");
        return new DownloadedArtifact(path, info.Length, digest);
    }

    private async Task Report(IInstallerObserver observer, InstallerEventKind kind,
        string operation, string message, CertaelSuiteArtifact artifact, long completed,
        CancellationToken cancellationToken) => await observer.ReportAsync(new InstallerEvent(
            timeProvider.GetUtcNow(), InstallerEventLevel.Information, kind, operation, message,
            InstallerSecretRedactor.Redact(new Dictionary<string, string>
            {
                ["uri"] = artifact.Uri,
                ["bytes"] = completed.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["sha256"] = artifact.Sha256
            })), cancellationToken);
}
