using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Certael.Installer;

public sealed record CertaelSuiteManifest(
    [property: JsonPropertyName("schema_version")] uint SchemaVersion,
    [property: JsonPropertyName("suite_version")] string SuiteVersion,
    [property: JsonPropertyName("issued_at")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
    [property: JsonPropertyName("components")] IReadOnlyList<CertaelSuiteComponent> Components);

public sealed record CertaelSuiteComponent(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("dependencies")] IReadOnlyDictionary<string, string> Dependencies,
    [property: JsonPropertyName("artifacts")] IReadOnlyList<CertaelSuiteArtifact> Artifacts);

public sealed record CertaelSuiteArtifact(
    [property: JsonPropertyName("runtime_identifier")] string RuntimeIdentifier,
    [property: JsonPropertyName("uri")] string Uri,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("signature_uri")] string? SignatureUri = null,
    [property: JsonPropertyName("attestation_uri")] string? AttestationUri = null);

public static partial class CertaelSuiteManifestCodec
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static CertaelSuiteManifest Decode(ReadOnlySpan<byte> content, DateTimeOffset now)
    {
        if (content.Length > 4 * 1024 * 1024) throw new ConfigurationException("Suite manifest is too large.");
        CertaelSuiteManifest manifest;
        try { manifest = JsonSerializer.Deserialize<CertaelSuiteManifest>(content, Json)!; }
        catch (JsonException exception) { throw new ConfigurationException("Suite manifest JSON is invalid.", exception); }
        if (manifest is null) throw new ConfigurationException("Suite manifest is empty.");
        Validate(manifest, now);
        return manifest;
    }

    public static byte[] Encode(CertaelSuiteManifest manifest, DateTimeOffset? validationTime = null)
    {
        Validate(manifest, validationTime ?? DateTimeOffset.UtcNow);
        var canonical = manifest with
        {
            Components = manifest.Components.OrderBy(component => component.Id,
                StringComparer.Ordinal).Select(component => component with
                {
                    Dependencies = component.Dependencies.OrderBy(pair => pair.Key,
                        StringComparer.Ordinal).ToDictionary(pair => pair.Key,
                            pair => pair.Value, StringComparer.Ordinal),
                    Artifacts = component.Artifacts.OrderBy(artifact => artifact.RuntimeIdentifier,
                        StringComparer.Ordinal).ToArray()
                }).ToArray()
        };
        return JsonSerializer.SerializeToUtf8Bytes(canonical, Json);
    }

    public static void Validate(CertaelSuiteManifest manifest, DateTimeOffset now)
    {
        if (manifest.SchemaVersion != 1) throw new ConfigurationException("Unsupported suite manifest schema.");
        ValidateVersion(manifest.SuiteVersion, "Suite version");
        if (manifest.ExpiresAt <= manifest.IssuedAt || manifest.IssuedAt > now.AddMinutes(5)
            || manifest.ExpiresAt <= now)
            throw new ConfigurationException("Suite manifest validity window is invalid or expired.");
        if (manifest.Components.Count is 0 or > 256)
            throw new ConfigurationException("Suite manifest component count is invalid.");
        if (manifest.Components.Select(component => component.Id).Distinct(StringComparer.Ordinal).Count()
            != manifest.Components.Count)
            throw new ConfigurationException("Suite manifest contains duplicate component IDs.");

        var versions = manifest.Components.ToDictionary(component => component.Id,
            component => component.Version, StringComparer.Ordinal);
        foreach (CertaelSuiteComponent component in manifest.Components)
        {
            ValidateToken(component.Id, "Component ID", 96);
            ValidateVersion(component.Version, $"Component {component.Id} version");
            if (component.Dependencies.Count > 64 || component.Artifacts.Count is 0 or > 64)
                throw new ConfigurationException($"Component {component.Id} is too large.");
            foreach ((string dependency, string requiredVersion) in component.Dependencies)
            {
                ValidateToken(dependency, "Dependency ID", 96);
                ValidateVersion(requiredVersion, "Dependency version");
                if (!versions.TryGetValue(dependency, out string? suppliedVersion)
                    || !string.Equals(suppliedVersion, requiredVersion, StringComparison.Ordinal))
                    throw new ConfigurationException($"Component {component.Id} requires {dependency}@{requiredVersion}.");
            }
            foreach (CertaelSuiteArtifact artifact in component.Artifacts)
                ValidateArtifact(component.Id, artifact);
        }
    }

    private static void ValidateArtifact(string component, CertaelSuiteArtifact artifact)
    {
        ValidateToken(artifact.RuntimeIdentifier, "Runtime identifier", 96);
        if (!System.Uri.TryCreate(artifact.Uri, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new ConfigurationException($"Component {component} artifact URI must use HTTPS.");
        if (artifact.Size <= 0 || artifact.Size > 8L * 1024 * 1024 * 1024)
            throw new ConfigurationException($"Component {component} artifact size is invalid.");
        if (!Sha256Pattern().IsMatch(artifact.Sha256))
            throw new ConfigurationException($"Component {component} artifact digest is invalid.");
        ValidateOptionalHttps(artifact.SignatureUri, component, "signature");
        ValidateOptionalHttps(artifact.AttestationUri, component, "attestation");
    }

    private static void ValidateOptionalHttps(string? value, string component, string label)
    {
        if (value is not null && (!System.Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)
            || uri.Scheme != Uri.UriSchemeHttps))
            throw new ConfigurationException($"Component {component} {label} URI must use HTTPS.");
    }

    private static void ValidateToken(string value, string label, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-')))
            throw new ConfigurationException($"{label} is invalid.");
    }

    private static void ValidateVersion(string value, string label)
    {
        if (value.Length > 64 || !VersionPattern().IsMatch(value))
            throw new ConfigurationException($"{label} is not a valid semantic version.");
    }

    [GeneratedRegex("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();
    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();
}

public sealed record CertaelResolvedComponent(string Id, string Version, CertaelSuiteArtifact Artifact);

public static class CertaelSuiteResolver
{
    public static IReadOnlyList<CertaelResolvedComponent> Resolve(CertaelSuiteManifest manifest,
        IEnumerable<string> requestedComponents, string runtimeIdentifier)
    {
        var components = manifest.Components.ToDictionary(component => component.Id, StringComparer.Ordinal);
        var resolved = new Dictionary<string, CertaelResolvedComponent>(StringComparer.Ordinal);
        var visiting = new HashSet<string>(StringComparer.Ordinal);
        foreach (string requested in requestedComponents.Distinct(StringComparer.Ordinal)) Visit(requested);
        return resolved.Values.OrderBy(value => value.Id, StringComparer.Ordinal).ToArray();

        void Visit(string id)
        {
            if (resolved.ContainsKey(id)) return;
            if (!components.TryGetValue(id, out CertaelSuiteComponent? component))
                throw new ConfigurationException($"Suite does not contain requested component {id}.");
            if (!visiting.Add(id)) throw new ConfigurationException("Suite dependency graph contains a cycle.");
            foreach (string dependency in component.Dependencies.Keys.OrderBy(value => value, StringComparer.Ordinal))
                Visit(dependency);
            CertaelSuiteArtifact artifact = component.Artifacts.SingleOrDefault(value =>
                string.Equals(value.RuntimeIdentifier, runtimeIdentifier, StringComparison.Ordinal))
                ?? component.Artifacts.SingleOrDefault(value =>
                    string.Equals(value.RuntimeIdentifier, "any", StringComparison.Ordinal))
                ?? throw new ConfigurationException($"Component {id} has no artifact for {runtimeIdentifier}.");
            resolved.Add(id, new CertaelResolvedComponent(id, component.Version, artifact));
            visiting.Remove(id);
        }
    }
}
