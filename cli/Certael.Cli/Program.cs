using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Certael.Server.Compatibility;
using Certael.Server.Rules;
using NSec.Cryptography;

return await CertaelCli.RunAsync(args, Console.Out, Console.Error);

internal static class CertaelCli
{
    public static async Task<int> RunAsync(string[] arguments, TextWriter output, TextWriter error)
    {
        try
        {
            return arguments switch
            {
                ["rules", "validate", string input] => await ValidateRules(input, output),
                ["rules", "sign", string input, string privateKey, string keyId, string destination] =>
                    await SignRules(input, privateKey, keyId, destination, output),
                ["manifest", "generate", string root, string destination] =>
                    await GenerateManifest(root, destination, output),
                ["agent-build", "request", string root, string tenant, string game,
                    string environment, string build, string engineAdapter,
                    string adapterVersion, string coreSdkVersion, string expiresAt,
                    string reason, string destination] => await GenerateAgentBuildRequest(root,
                        tenant, game, environment, build, engineAdapter, adapterVersion,
                        coreSdkVersion, expiresAt, reason, destination, output),
                ["agent-key", "generate-development", string keyId, string privateKey,
                    string trustStore] => await GenerateDevelopmentAgentKey(keyId, privateKey,
                        trustStore, output),
                ["compatibility", "generate-development-key", string keyId,
                    string privateKey, string trustStore] => await GenerateDevelopmentAgentKey(
                        keyId, privateKey, trustStore, output, "compatibility"),
                ["compatibility", "sign", string input, string privateKey, string keyId,
                    string destination] => await SignCompatibility(input, privateKey, keyId,
                        destination, output),
                ["compatibility", "check", string signedPath, string trustStore,
                    string product, string version, string protocol] => await CheckCompatibility(
                        signedPath, trustStore, product, version, protocol, output),
                ["doctor"] => await Doctor(output),
                _ => Usage(error)
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or CryptographicException or RulePackValidationException or ArgumentException
            or FormatException or JsonException)
        {
            await error.WriteLineAsync($"error: {exception.Message}");
            return 2;
        }
    }

    private static async Task<int> ValidateRules(string path, TextWriter output)
    {
        RulePackDocument document = new RulePackYamlParser().Parse(await File.ReadAllTextAsync(path));
        RulePackCompiler.Validate(document);
        await output.WriteLineAsync($"valid {document.PackId}@{document.Version} ({document.Rules.Count} rules)");
        return 0;
    }

    private static async Task<int> SignRules(string input, string keyPath, string keyId,
        string destination, TextWriter output)
    {
        RulePackDocument document = new RulePackYamlParser().Parse(await File.ReadAllTextAsync(input));
        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(await File.ReadAllTextAsync(keyPath));
        SignedRulePack signed = new RulePackCompiler(key, keyId).CompileAndSign(document);
        var envelope = new SignedRulePackEnvelope(
            document.PackId, document.Version, keyId,
            Convert.ToBase64String(signed.CanonicalDocument), Convert.ToHexString(signed.Digest).ToLowerInvariant(),
            Convert.ToBase64String(signed.Signature));
        await WriteAtomic(destination, JsonSerializer.SerializeToUtf8Bytes(envelope,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true }));
        await output.WriteLineAsync($"signed {document.PackId}@{document.Version} sha256:{envelope.DigestSha256}");
        return 0;
    }

    private static async Task<int> GenerateManifest(string rootPath, string destination, TextWriter output)
    {
        string root = Path.GetFullPath(rootPath);
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException("Manifest root does not exist.");
        string destinationFull = Path.GetFullPath(destination);
        BuildFile[] files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(path => Path.GetFullPath(path) != destinationFull)
            .Select(path =>
            {
                var info = new FileInfo(path);
                if (info.LinkTarget is not null) throw new IOException("Symbolic links are prohibited in protected manifests.");
                string relative = Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');
                if (relative.StartsWith("../", StringComparison.Ordinal) || Path.IsPathRooted(relative))
                    throw new IOException("Manifest path escapes the root.");
                using FileStream stream = File.OpenRead(path);
                return new BuildFile(relative, info.Length,
                    Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant());
            })
            .OrderBy(file => file.Path, StringComparer.Ordinal)
            .ToArray();
        var manifest = new BuildManifest(1, "sha256", files);
        await WriteAtomic(destination, JsonSerializer.SerializeToUtf8Bytes(manifest,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true }));
        await output.WriteLineAsync($"manifested {files.Length} files");
        return 0;
    }

    private static async Task<int> GenerateAgentBuildRequest(string rootPath, string tenantId,
        string gameId, string environmentId, string buildId, string engineAdapter,
        string adapterVersion, string coreSdkVersion, string expiresAtText, string reason,
        string destination, TextWriter output)
    {
        if (!DateTimeOffset.TryParse(expiresAtText, out DateTimeOffset expiresAt))
            throw new ArgumentException("expires-at must be an ISO-8601 timestamp.");
        if (engineAdapter is not ("godot" or "unity" or "unreal" or "native")
            || !SemanticVersion.TryParse(adapterVersion, out _)
            || !SemanticVersion.TryParse(coreSdkVersion, out _))
            throw new ArgumentException("Engine adapter or SDK version is invalid.");
        string root = Path.GetFullPath(rootPath);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException("Manifest root does not exist.");
        string destinationFull = Path.GetFullPath(destination);
        AgentBuildFile[] files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(path => Path.GetFullPath(path) != destinationFull)
            .Select(path =>
            {
                var info = new FileInfo(path);
                if (info.LinkTarget is not null)
                    throw new IOException("Symbolic links are prohibited in protected manifests.");
                string relative = Path.GetRelativePath(root, path)
                    .Replace(Path.DirectorySeparatorChar, '/');
                using FileStream stream = File.OpenRead(path);
                return new AgentBuildFile(relative, checked((ulong)info.Length),
                    SHA256.HashData(stream));
            })
            .OrderBy(file => file.Path, StringComparer.Ordinal)
            .ToArray();
        var request = new AgentBuildRequest(tenantId, gameId, environmentId, buildId,
            reason, files, expiresAt, coreSdkVersion, engineAdapter, adapterVersion,
            1, 1, 1, 1);
        await WriteAtomic(destination, JsonSerializer.SerializeToUtf8Bytes(request,
            new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true
            }));
        await output.WriteLineAsync($"prepared {files.Length} protected files for {buildId}");
        return 0;
    }

    private static async Task<int> Doctor(TextWriter output)
    {
        await output.WriteLineAsync($"dotnet {Environment.Version}");
        await output.WriteLineAsync($"os {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
        await output.WriteLineAsync("status local SDK prerequisites available");
        return 0;
    }

    private static async Task<int> GenerateDevelopmentAgentKey(string keyId,
        string privateKeyPath, string trustStorePath, TextWriter output,
        string purpose = "Agent")
    {
        if (string.IsNullOrWhiteSpace(keyId) || keyId.Length > 128
            || keyId.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-'))
            throw new ArgumentException("Agent key ID is invalid.");
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] privateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var trustStore = new
        {
            keys = new[]
            {
                new
                {
                    key_id = keyId,
                    public_key_hex = Convert.ToHexString(publicKey).ToLowerInvariant(),
                    not_before_unix = now.AddMinutes(-5).ToUnixTimeSeconds(),
                    not_after_unix = now.AddDays(30).ToUnixTimeSeconds(),
                    revoked = false
                }
            }
        };
        try
        {
            await WriteExclusive(privateKeyPath, privateKey, privateMaterial: true);
            try
            {
                await WriteExclusive(trustStorePath, JsonSerializer.SerializeToUtf8Bytes(
                    trustStore, new JsonSerializerOptions { WriteIndented = true }),
                    privateMaterial: false);
            }
            catch
            {
                File.Delete(Path.GetFullPath(privateKeyPath));
                throw;
            }
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
        await output.WriteLineAsync($"generated development-only {purpose} keypair");
        await output.WriteLineAsync($"private key: {Path.GetFullPath(privateKeyPath)}");
        await output.WriteLineAsync($"public trust store: {Path.GetFullPath(trustStorePath)}");
        await output.WriteLineAsync("production must use an HSM/KMS signing provider");
        return 0;
    }

    private static async Task<int> SignCompatibility(string inputPath, string privateKeyPath,
        string keyId, string destination, TextWriter output)
    {
        CompatibilitySource source = JsonSerializer.Deserialize<CompatibilitySource>(
            await File.ReadAllBytesAsync(inputPath), JsonOptions())
            ?? throw new ArgumentException("Compatibility source is empty.");
        var claims = new CompatibilityManifestClaims(source.SchemaVersion, source.Revision,
            source.IssuedAt, source.ExpiresAt,
            source.Products.Select(product => new CompatibilityProductRule(
                ParseProduct(product.Product), product.MinimumSupportedVersion,
                product.RecommendedVersion, product.MinimumProtocolVersion,
                product.MaximumProtocolVersion)).ToArray(),
            source.Revocations.Select(revocation => new CompatibilityRevocation(
                ParseProduct(revocation.Product), revocation.Version,
                revocation.EffectiveAt, revocation.Reason)).ToArray());
        byte[] privateKey = await File.ReadAllBytesAsync(privateKeyPath);
        try
        {
            using Key key = Key.Import(SignatureAlgorithm.Ed25519, privateKey,
                KeyBlobFormat.RawPrivateKey);
            SignedCompatibilityManifest signed = new CompatibilityManifestSigner(key, keyId)
                .Sign(claims, DateTimeOffset.UtcNow);
            await WriteAtomic(destination, CompatibilityManifestCodec.EncodeSigned(signed));
            await output.WriteLineAsync($"signed compatibility revision {claims.Revision}");
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
        return 0;
    }

    private static async Task<int> CheckCompatibility(string signedPath, string trustStorePath,
        string productText, string version, string protocolText, TextWriter output)
    {
        SignedCompatibilityManifest signed = CompatibilityManifestCodec.DecodeSigned(
            await File.ReadAllBytesAsync(signedPath));
        CompatibilityTrustStore source = JsonSerializer.Deserialize<CompatibilityTrustStore>(
            await File.ReadAllBytesAsync(trustStorePath), JsonOptions())
            ?? throw new ArgumentException("Compatibility trust store is empty.");
        var ring = new CompatibilityVerificationKeyRing(source.Keys.Select(key =>
            new CompatibilityVerificationKey(key.KeyId,
                Convert.FromHexString(key.PublicKeyHex),
                DateTimeOffset.FromUnixTimeSeconds(key.NotBeforeUnix),
                DateTimeOffset.FromUnixTimeSeconds(key.NotAfterUnix), key.Revoked)));
        CompatibilityManifestClaims claims = CompatibilityManifestSigner.Verify(signed, ring,
            DateTimeOffset.UtcNow);
        if (!uint.TryParse(protocolText, out uint protocol))
            throw new ArgumentException("Protocol version is invalid.");
        CompatibilityDecision decision = CompatibilityEvaluator.Evaluate(claims,
            ParseProduct(productText), version, protocol, DateTimeOffset.UtcNow);
        await output.WriteLineAsync(JsonSerializer.Serialize(new
        {
            state = decision.State.ToString(),
            reason = decision.PublicReason,
            recommendedVersion = decision.RecommendedVersion,
            manifestRevision = decision.ManifestRevision,
            allowsNewProtectedSession = decision.AllowsNewProtectedSession
        }, new JsonSerializerOptions { WriteIndented = true }));
        return decision.AllowsNewProtectedSession ? 0 : 3;
    }

    private static CertaelProduct ParseProduct(string value) =>
        Enum.TryParse(value, true, out CertaelProduct product) && Enum.IsDefined(product)
            ? product : throw new ArgumentException("Certael product is invalid.");

    private static JsonSerializerOptions JsonOptions() => new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    private static async Task WriteExclusive(string path, byte[] content, bool privateMaterial)
    {
        string full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.WriteThrough
        };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = privateMaterial
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite
                : UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead
                    | UnixFileMode.OtherRead;
        await using var stream = new FileStream(full, options);
        await stream.WriteAsync(content);
        await stream.FlushAsync();
    }

    private static async Task WriteAtomic(string path, byte[] content)
    {
        string full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        string temporary = full + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllBytesAsync(temporary, content);
            File.Move(temporary, full, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static int Usage(TextWriter error)
    {
        error.WriteLine("usage: certaelctl rules validate <pack.yaml>");
        error.WriteLine("       certaelctl rules sign <pack.yaml> <private.pem> <key-id> <output.json>");
        error.WriteLine("       certaelctl manifest generate <root> <output.json>");
        error.WriteLine("       certaelctl agent-build request <root> <tenant> <game> <environment> <build> <godot|unity|unreal|native> <adapter-version> <core-sdk-version> <expires-at> <reason> <output.json>");
        error.WriteLine("       certaelctl agent-key generate-development <key-id> <private.key> <trust-store.json>");
        error.WriteLine("       certaelctl compatibility generate-development-key <key-id> <private.key> <trust-store.json>");
        error.WriteLine("       certaelctl compatibility sign <source.json> <private.key> <key-id> <output.pb>");
        error.WriteLine("       certaelctl compatibility check <signed.pb> <trust-store.json> <product> <version> <protocol>");
        error.WriteLine("       certaelctl doctor");
        return 1;
    }
}

internal sealed record SignedRulePackEnvelope(
    string PackId, string Version, string KeyId, string CanonicalDocumentBase64,
    string DigestSha256, string SignatureBase64);
internal sealed record BuildManifest(int Version, string Algorithm, IReadOnlyList<BuildFile> Files);
internal sealed record BuildFile(string Path, long Size, string Digest);
internal sealed record AgentBuildRequest(string TenantId, string GameId, string EnvironmentId,
    string BuildId, string Reason, IReadOnlyList<AgentBuildFile> Files,
    DateTimeOffset ExpiresAt, string CoreSdkVersion, string EngineAdapter,
    string EngineAdapterVersion, uint CoreCAbiVersion, uint ActionProtocolVersion,
    uint AgentProtocolVersion, uint AgentProbeAbiVersion);
internal sealed record AgentBuildFile(string Path, ulong Size, byte[] Sha256);
internal sealed record CompatibilitySource(uint SchemaVersion, ulong Revision,
    DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt,
    IReadOnlyList<CompatibilityProductSource> Products,
    IReadOnlyList<CompatibilityRevocationSource> Revocations);
internal sealed record CompatibilityProductSource(string Product,
    string MinimumSupportedVersion, string RecommendedVersion,
    uint MinimumProtocolVersion, uint MaximumProtocolVersion);
internal sealed record CompatibilityRevocationSource(string Product, string Version,
    DateTimeOffset EffectiveAt, string Reason);
internal sealed record CompatibilityTrustStore(
    [property: JsonPropertyName("keys")] IReadOnlyList<CompatibilityTrustKey> Keys);
internal sealed record CompatibilityTrustKey(
    [property: JsonPropertyName("key_id")] string KeyId,
    [property: JsonPropertyName("public_key_hex")] string PublicKeyHex,
    [property: JsonPropertyName("not_before_unix")] long NotBeforeUnix,
    [property: JsonPropertyName("not_after_unix")] long NotAfterUnix,
    [property: JsonPropertyName("revoked")] bool Revoked);
