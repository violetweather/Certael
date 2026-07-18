using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace Certael.Installer;

public sealed record SuiteAssemblyDefinition(
    [property: JsonPropertyName("components")] IReadOnlyList<SuiteAssemblyComponent> Components);

public sealed record SuiteAssemblyComponent(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("dependencies")] IReadOnlyDictionary<string, string> Dependencies,
    [property: JsonPropertyName("artifacts")] IReadOnlyList<SuiteAssemblyArtifact> Artifacts);

public sealed record SuiteAssemblyArtifact(
    [property: JsonPropertyName("runtime_identifier")] string RuntimeIdentifier,
    [property: JsonPropertyName("file_path")] string FilePath,
    [property: JsonPropertyName("release_name")] string ReleaseName,
    [property: JsonPropertyName("signature_release_name")] string? SignatureReleaseName = null,
    [property: JsonPropertyName("attestation_release_name")] string? AttestationReleaseName = null);

public static class CertaelSuiteManifestAssembler
{
    public static async Task<CertaelSuiteManifest> AssembleAsync(string suiteVersion,
        DateTimeOffset issuedAt, DateTimeOffset expiresAt, Uri releaseBaseUri,
        SuiteAssemblyDefinition definition, CancellationToken cancellationToken)
    {
        if (releaseBaseUri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(releaseBaseUri.UserInfo)
            || !string.IsNullOrEmpty(releaseBaseUri.Query) || !string.IsNullOrEmpty(releaseBaseUri.Fragment))
            throw new ConfigurationException("Release base URI must use HTTPS without credentials, query, or fragment.");
        if (definition.Components.Count is 0 or > 256)
            throw new ConfigurationException("Suite assembly component count is invalid.");
        var components = new List<CertaelSuiteComponent>(definition.Components.Count);
        foreach (SuiteAssemblyComponent component in definition.Components)
        {
            var artifacts = new List<CertaelSuiteArtifact>(component.Artifacts.Count);
            foreach (SuiteAssemblyArtifact artifact in component.Artifacts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ValidateReleaseName(artifact.ReleaseName);
                ValidateOptionalReleaseName(artifact.SignatureReleaseName);
                ValidateOptionalReleaseName(artifact.AttestationReleaseName);
                string path = Path.GetFullPath(artifact.FilePath);
                var info = new FileInfo(path);
                if (!info.Exists || info.LinkTarget is not null || info.Length <= 0
                    || info.Length > 8L * 1024 * 1024 * 1024)
                    throw new ConfigurationException($"Suite assembly artifact is missing or invalid: {artifact.FilePath}");
                await using FileStream stream = new(path, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 128 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                string digest = Convert.ToHexString(await SHA256.HashDataAsync(stream,
                    cancellationToken)).ToLowerInvariant();
                artifacts.Add(new CertaelSuiteArtifact(artifact.RuntimeIdentifier,
                    Resolve(releaseBaseUri, artifact.ReleaseName), info.Length, digest,
                    ResolveOptional(releaseBaseUri, artifact.SignatureReleaseName),
                    ResolveOptional(releaseBaseUri, artifact.AttestationReleaseName)));
            }
            components.Add(new CertaelSuiteComponent(component.Id, component.Version,
                component.Dependencies, artifacts));
        }
        var manifest = new CertaelSuiteManifest(1, suiteVersion, issuedAt, expiresAt, components);
        CertaelSuiteManifestCodec.Validate(manifest, issuedAt);
        return manifest;
    }

    private static string Resolve(Uri baseUri, string name) =>
        new Uri(EnsureTrailingSlash(baseUri), Uri.EscapeDataString(name)).AbsoluteUri;

    private static string? ResolveOptional(Uri baseUri, string? name) =>
        name is null ? null : Resolve(baseUri, name);

    private static Uri EnsureTrailingSlash(Uri uri) => uri.AbsoluteUri.EndsWith("/",
        StringComparison.Ordinal) ? uri : new Uri(uri.AbsoluteUri + "/");

    private static void ValidateOptionalReleaseName(string? value)
    {
        if (value is not null) ValidateReleaseName(value);
    }

    private static void ValidateReleaseName(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 256
            || value is "." or ".." || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-')))
            throw new ConfigurationException("Suite release artifact name is invalid.");
    }
}
