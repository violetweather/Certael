using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Certael.Installer;
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
                ["project", "init", string root, string projectName, string engine,
                    string serverRuntime, string mode, string identityProvider] => await InitializeProject(
                        root, projectName, engine, serverRuntime, mode, identityProvider, output),
                ["console", "init-auth0", string root, string authority, string tokenEndpoint,
                    string clientId, string audience, string coreBaseUrl] => await InitializeAuth0Console(
                        root, authority, tokenEndpoint, clientId, audience, coreBaseUrl, output),
                ["deployment", "init", string root, string releaseTag, string tenantId] =>
                    await InitializeDeployment(root, releaseTag, tenantId, output),
                ["suite", "validate", string manifest] => await ValidateSuite(manifest, output),
                ["suite", "generate-development-key", string keyId, string privateKey,
                    string trustStore] => await GenerateDevelopmentAgentKey(keyId, privateKey,
                        trustStore, output, "suite manifest"),
                ["suite", "generate-release-key", string keyId, string privateKey,
                    string trustStore, string expiresAt] => await GenerateSuiteReleaseKey(
                        keyId, privateKey, trustStore, expiresAt, output),
                ["suite", "sign", string manifest, string privateKey, string keyId,
                    string destination] => await SignSuite(manifest, privateKey, keyId,
                        destination, output),
                ["suite", "assemble", string version, string issuedAt, string expiresAt,
                    string releaseBaseUri, string definition, string destination] =>
                    await AssembleSuite(version, issuedAt, expiresAt, releaseBaseUri,
                        definition, destination, output),
                ["suite", "verify", string envelope, string trustStore] => await VerifySuite(
                        envelope, trustStore, output),
                ["suite", "resolve", string manifest, string configuration,
                    string runtimeIdentifier] => await ResolveSuite(manifest, configuration,
                        runtimeIdentifier, output),
                ["suite", "install", string envelope, string trustStore, string configuration,
                    string runtimeIdentifier, string root, string cache] => await InstallSuite(
                        envelope, trustStore, configuration, runtimeIdentifier, root, cache, output),
                ["suite", "inspect", string root] => await InspectSuite(root, output),
                ["suite", "update", string envelope, string trustStore, string configuration,
                    string root, string cache] => await ChangeSuite("update", envelope, trustStore,
                        configuration, root, cache, false, output),
                ["suite", "update", string envelope, string trustStore, string configuration,
                    string root, string cache, "--force-modified"] => await ChangeSuite("update",
                        envelope, trustStore, configuration, root, cache, true, output),
                ["suite", "repair", string envelope, string trustStore, string configuration,
                    string root, string cache] => await ChangeSuite("repair", envelope, trustStore,
                        configuration, root, cache, false, output),
                ["suite", "repair", string envelope, string trustStore, string configuration,
                    string root, string cache, "--force-modified"] => await ChangeSuite("repair",
                        envelope, trustStore, configuration, root, cache, true, output),
                ["suite", "uninstall", string root] => await UninstallSuite(root, false, output),
                ["suite", "uninstall", string root, "--force-modified"] => await UninstallSuite(
                        root, true, output),
                ["suite", "recover", string root, string planId] => await RecoverSuite(
                        root, planId, output),
                ["doctor"] => await Doctor(output),
                _ => Usage(error)
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or CryptographicException or RulePackValidationException or ArgumentException
            or FormatException or JsonException or ConfigurationException)
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

    private static async Task<int> InitializeProject(string rootPath, string projectName,
        string engineText, string serverRuntimeText, string modeText, string identityProviderText,
        TextWriter output)
    {
        CertaelEngine engine = ParseEnum<CertaelEngine>(engineText, "Engine");
        CertaelServerRuntime serverRuntime = ParseEnum<CertaelServerRuntime>(serverRuntimeText,
            "Server runtime");
        CertaelDeploymentMode mode = ParseEnum<CertaelDeploymentMode>(modeText, "Deployment mode");
        CertaelIdentityProvider identityProvider = ParseEnum<CertaelIdentityProvider>(
            identityProviderText, "Identity provider");
        var configuration = new CertaelProjectConfiguration
        {
            ProjectName = projectName,
            Engine = engine,
            ServerRuntime = serverRuntime,
            DeploymentMode = mode,
            IdentityProvider = identityProvider,
            Components = ComponentsFor(engine, serverRuntime)
        };
        string yaml = CertaelProjectConfigurationCodec.Encode(configuration);
        var plan = new InstallationPlan(Guid.NewGuid(), Path.GetFullPath(rootPath),
        [
            new CreateDirectoryOperation("certael-state", "Create Certael project state", ".certael"),
            new WriteFileOperation("project-config", "Write project configuration", "certael.yaml",
                System.Text.Encoding.UTF8.GetBytes(yaml))
        ], DateTimeOffset.UtcNow);
        var observer = new TextInstallerObserver(output);
        InstallationResult result = await new CertaelInstallerEngine(TimeProvider.System)
            .ApplyAsync(plan, observer, CancellationToken.None);
        await output.WriteLineAsync($"initialized {configuration.ProjectName} at {Path.GetFullPath(rootPath)}");
        await output.WriteLineAsync($"journal {result.JournalPath}");
        return 0;
    }

    private static async Task<int> ValidateSuite(string path, TextWriter output)
    {
        CertaelSuiteManifest manifest = CertaelSuiteManifestCodec.Decode(
            await File.ReadAllBytesAsync(path), DateTimeOffset.UtcNow);
        await output.WriteLineAsync($"valid suite {manifest.SuiteVersion} ({manifest.Components.Count} components)");
        return 0;
    }

    private static async Task<int> InitializeAuth0Console(string root, string authority,
        string tokenEndpoint, string clientId, string audience, string coreBaseUrl,
        TextWriter output)
    {
        Auth0ConsoleBootstrapResult bootstrap = CertaelConsoleBootstrap.CreateDevelopmentPlan(
            new Auth0ConsoleBootstrapRequest(root, authority, tokenEndpoint, clientId,
                audience, coreBaseUrl), DateTimeOffset.UtcNow);
        var observer = new TextInstallerObserver(output);
        InstallationResult result = await new CertaelInstallerEngine(TimeProvider.System)
            .ApplyAsync(bootstrap.Plan, observer, CancellationToken.None);
        string thumbprint = CertaelConsoleBootstrap.CertificateThumbprintSha256(
            bootstrap.CertificatePath);
        await output.WriteLineAsync($"console configuration {bootstrap.ConfigurationPath}");
        await output.WriteLineAsync($"development certificate x5t#S256 {thumbprint}");
        await output.WriteLineAsync($"certificate expires {bootstrap.CertificateExpiresAt:O}");
        await output.WriteLineAsync("inject Authentication__ClientSecret and TokenExchange__ClientSecret from a secret store");
        await output.WriteLineAsync($"journal {result.JournalPath}");
        return 0;
    }

    private static async Task<int> InitializeDeployment(string root, string releaseTag,
        string tenantId, TextWriter output)
    {
        DeploymentBootstrapResult bootstrap = CertaelDeploymentBootstrap.CreatePlan(
            new DeploymentBootstrapRequest(root, releaseTag, tenantId), DateTimeOffset.UtcNow);
        InstallationResult result = await new CertaelInstallerEngine(TimeProvider.System)
            .ApplyAsync(bootstrap.Plan, new TextInstallerObserver(output), CancellationToken.None);
        await output.WriteLineAsync("generated private deployment configuration");
        await output.WriteLineAsync($"environment {bootstrap.EnvironmentPath}");
        await output.WriteLineAsync($"coordinator public key {bootstrap.PublicKeyPath}");
        await output.WriteLineAsync($"journal {result.JournalPath}");
        await output.WriteLineAsync("next: read .certael/DEPLOYMENT.md; no secret values were printed");
        return 0;
    }

    private static async Task<int> SignSuite(string manifestPath, string privateKeyPath,
        string keyId, string destination, TextWriter output)
    {
        CertaelSuiteManifest validated = CertaelSuiteManifestCodec.Decode(
            await File.ReadAllBytesAsync(manifestPath), DateTimeOffset.UtcNow);
        byte[] manifest = CertaelSuiteManifestCodec.Encode(validated);
        byte[] privateKey = await File.ReadAllBytesAsync(privateKeyPath);
        try
        {
            using Key key = Key.Import(SignatureAlgorithm.Ed25519, privateKey,
                KeyBlobFormat.RawPrivateKey);
            SignedSuiteManifest signed = SignedSuiteManifestCodec.Sign(manifest, key, keyId);
            await WriteAtomic(destination, SignedSuiteManifestCodec.Encode(signed));
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
        await output.WriteLineAsync($"signed suite {validated.SuiteVersion} with {keyId}");
        return 0;
    }

    private static async Task<int> AssembleSuite(string version, string issuedAtText,
        string expiresAtText, string releaseBaseUriText, string definitionPath,
        string destination, TextWriter output)
    {
        if (!DateTimeOffset.TryParse(issuedAtText, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out DateTimeOffset issuedAt)
            || !DateTimeOffset.TryParse(expiresAtText, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out DateTimeOffset expiresAt)
            || !Uri.TryCreate(releaseBaseUriText, UriKind.Absolute, out Uri? releaseBaseUri))
            throw new ArgumentException("Suite assembly timestamps or release base URI are invalid.");
        var json = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };
        SuiteAssemblyDefinition definition = JsonSerializer.Deserialize<SuiteAssemblyDefinition>(
            await File.ReadAllBytesAsync(definitionPath), json)
            ?? throw new ArgumentException("Suite assembly definition is empty.");
        CertaelSuiteManifest manifest = await CertaelSuiteManifestAssembler.AssembleAsync(
            version, issuedAt, expiresAt, releaseBaseUri, definition, CancellationToken.None);
        await WriteAtomic(destination, CertaelSuiteManifestCodec.Encode(manifest, issuedAt));
        await output.WriteLineAsync($"assembled suite {manifest.SuiteVersion} "
            + $"({manifest.Components.Count} components)");
        return 0;
    }

    private static async Task<int> VerifySuite(string envelopePath, string trustStorePath,
        TextWriter output)
    {
        CompatibilityTrustStore source = JsonSerializer.Deserialize<CompatibilityTrustStore>(
            await File.ReadAllBytesAsync(trustStorePath), JsonOptions())
            ?? throw new ArgumentException("Suite trust store is empty.");
        var ring = new SuiteVerificationKeyRing(source.Keys.Select(key => new SuiteVerificationKey(
            key.KeyId, Convert.FromHexString(key.PublicKeyHex),
            DateTimeOffset.FromUnixTimeSeconds(key.NotBeforeUnix),
            DateTimeOffset.FromUnixTimeSeconds(key.NotAfterUnix), key.Revoked)));
        CertaelSuiteManifest manifest = SignedSuiteManifestCodec.Verify(
            await File.ReadAllBytesAsync(envelopePath), ring, DateTimeOffset.UtcNow);
        await output.WriteLineAsync($"verified suite {manifest.SuiteVersion} ({manifest.Components.Count} components)");
        return 0;
    }

    private static async Task<int> ResolveSuite(string manifestPath, string configurationPath,
        string runtimeIdentifier, TextWriter output)
    {
        CertaelSuiteManifest manifest = CertaelSuiteManifestCodec.Decode(
            await File.ReadAllBytesAsync(manifestPath), DateTimeOffset.UtcNow);
        CertaelProjectConfiguration configuration = CertaelProjectConfigurationCodec.Decode(
            await File.ReadAllTextAsync(configurationPath));
        IReadOnlyList<CertaelResolvedComponent> resolved = CertaelSuiteResolver.Resolve(
            manifest, configuration.Components, runtimeIdentifier);
        await output.WriteLineAsync(JsonSerializer.Serialize(resolved.Select(value => new
        {
            id = value.Id,
            version = value.Version,
            runtimeIdentifier = value.Artifact.RuntimeIdentifier,
            uri = value.Artifact.Uri,
            size = value.Artifact.Size,
            sha256 = value.Artifact.Sha256
        }), new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }

    private static async Task<int> InstallSuite(string envelopePath, string trustStorePath,
        string configurationPath, string runtimeIdentifier, string rootPath, string cachePath,
        TextWriter output)
    {
        SuiteVerificationKeyRing keyRing = await LoadSuiteTrustStore(trustStorePath);
        CertaelProjectConfiguration configuration = CertaelProjectConfigurationCodec.Decode(
            await File.ReadAllTextAsync(configurationPath));
        using var client = new HttpClient { Timeout = TimeSpan.FromHours(2) };
        var observer = new TextInstallerObserver(output);
        SuiteInstallResult result = await new CertaelSuiteInstaller(client, TimeProvider.System)
            .InstallAsync(await File.ReadAllBytesAsync(envelopePath), keyRing, configuration,
                runtimeIdentifier, rootPath, cachePath, observer, CancellationToken.None);
        await output.WriteLineAsync($"installed suite {result.Manifest.SuiteVersion} "
            + $"({result.State.Components.Count} components, {result.State.Files.Count} files)");
        await output.WriteLineAsync($"plan {result.Installation.PlanId}");
        await output.WriteLineAsync($"journal {result.Installation.JournalPath}");
        return 0;
    }

    private static async Task<int> InspectSuite(string rootPath, TextWriter output)
    {
        InstalledSuiteState state = await LoadInstalledState(rootPath);
        SuiteInstallationInspection inspection = await CertaelInstallationLifecycle.InspectAsync(
            rootPath, state, CancellationToken.None);
        await output.WriteLineAsync(JsonSerializer.Serialize(new
        {
            suiteVersion = state.SuiteVersion,
            runtimeIdentifier = state.RuntimeIdentifier,
            healthy = inspection.Healthy,
            totalFiles = inspection.Files.Count,
            healthyFiles = inspection.Files.Count(value => value.Health == InstalledFileHealth.Healthy),
            drift = inspection.Files.Where(value => value.Health != InstalledFileHealth.Healthy)
                .Select(value => new
                {
                    path = value.File.Path,
                    component = value.File.ComponentId,
                    health = value.Health.ToString(),
                    expectedSha256 = value.File.Sha256,
                    actualSha256 = value.ActualSha256
                })
        }, new JsonSerializerOptions { WriteIndented = true }));
        return inspection.Healthy ? 0 : 4;
    }

    private static async Task<int> ChangeSuite(string action, string envelopePath,
        string trustStorePath, string configurationPath, string rootPath, string cachePath,
        bool forceModified, TextWriter output)
    {
        SuiteVerificationKeyRing keyRing = await LoadSuiteTrustStore(trustStorePath);
        CertaelProjectConfiguration configuration = CertaelProjectConfigurationCodec.Decode(
            await File.ReadAllTextAsync(configurationPath));
        using var client = new HttpClient { Timeout = TimeSpan.FromHours(2) };
        var installer = new CertaelSuiteInstaller(client, TimeProvider.System);
        byte[] envelope = await File.ReadAllBytesAsync(envelopePath);
        var observer = new TextInstallerObserver(output);
        SuiteInstallResult result = action == "update"
            ? await installer.UpdateAsync(envelope, keyRing, configuration, rootPath, cachePath,
                forceModified, observer, CancellationToken.None)
            : await installer.RepairAsync(envelope, keyRing, configuration, rootPath, cachePath,
                forceModified, observer, CancellationToken.None);
        string completedAction = action == "update" ? "updated" : "repaired";
        await output.WriteLineAsync($"{completedAction} suite {result.Manifest.SuiteVersion} "
            + $"({result.State.Components.Count} components, {result.State.Files.Count} files)");
        await output.WriteLineAsync($"plan {result.Installation.PlanId}");
        await output.WriteLineAsync($"journal {result.Installation.JournalPath}");
        return 0;
    }

    private static async Task<int> UninstallSuite(string rootPath, bool forceModified,
        TextWriter output)
    {
        InstalledSuiteState state = await LoadInstalledState(rootPath);
        var observer = new TextInstallerObserver(output);
        InstallationPlan plan = CertaelInstallationLifecycle.CreateUninstallPlan(
            rootPath, state, forceModified, DateTimeOffset.UtcNow);
        InstallationResult result = await new CertaelInstallerEngine(TimeProvider.System)
            .ApplyAsync(plan, observer, CancellationToken.None);
        await output.WriteLineAsync($"uninstalled {state.SuiteVersion}; preserved "
            + $"{state.Files.Count(value => value.PreserveOnUninstall)} operator files");
        await output.WriteLineAsync($"plan {result.PlanId}");
        await output.WriteLineAsync($"journal {result.JournalPath}");
        return 0;
    }

    private static async Task<int> RecoverSuite(string rootPath, string planIdText,
        TextWriter output)
    {
        if (!Guid.TryParse(planIdText, out Guid planId) || planId == Guid.Empty)
            throw new ArgumentException("Recovery plan ID is invalid.");
        InstallationResult result = await new CertaelInstallerEngine(TimeProvider.System)
            .RecoverAsync(rootPath, planId, new TextInstallerObserver(output), CancellationToken.None);
        await output.WriteLineAsync($"recovered plan {result.PlanId}");
        await output.WriteLineAsync($"journal {result.JournalPath}");
        return 0;
    }

    private static async Task<InstalledSuiteState> LoadInstalledState(string rootPath)
    {
        string root = Path.GetFullPath(rootPath);
        string path = InstallationPlan.ResolveInside(root,
            CertaelSuiteInstaller.InstalledStatePath.Replace('/', Path.DirectorySeparatorChar));
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > 16 * 1024 * 1024)
            throw new ConfigurationException("Installed suite inventory is missing or invalid.");
        return InstalledSuiteStateCodec.Decode(await File.ReadAllBytesAsync(path), root);
    }

    private static async Task<SuiteVerificationKeyRing> LoadSuiteTrustStore(string trustStorePath)
    {
        CompatibilityTrustStore source = JsonSerializer.Deserialize<CompatibilityTrustStore>(
            await File.ReadAllBytesAsync(trustStorePath), JsonOptions())
            ?? throw new ArgumentException("Suite trust store is empty.");
        return new SuiteVerificationKeyRing(source.Keys.Select(key => new SuiteVerificationKey(
            key.KeyId, Convert.FromHexString(key.PublicKeyHex),
            DateTimeOffset.FromUnixTimeSeconds(key.NotBeforeUnix),
            DateTimeOffset.FromUnixTimeSeconds(key.NotAfterUnix), key.Revoked)));
    }

    private static List<string> ComponentsFor(CertaelEngine engine,
        CertaelServerRuntime serverRuntime)
    {
        List<string> components = ["core-api", "event-worker", "analytics-worker", "console",
            "deployment", "certaelctl"];
        components.Add(engine switch
        {
            CertaelEngine.Godot => "godot-adapter",
            CertaelEngine.Unity => "unity-adapter",
            CertaelEngine.Unreal => "unreal-adapter",
            CertaelEngine.Native => "native-runtime",
            _ => "native-runtime"
        });
        components.Add(serverRuntime switch
        {
            CertaelServerRuntime.DotNet => "server-sdk-dotnet",
            CertaelServerRuntime.Node => "server-sdk-typescript",
            CertaelServerRuntime.Native => "server-sdk-native",
            _ => "server-sdk-dotnet"
        });
        return components;
    }

    private static T ParseEnum<T>(string value, string label) where T : struct, Enum =>
        Enum.TryParse(value, ignoreCase: true, out T parsed) && Enum.IsDefined(parsed)
            ? parsed : throw new ArgumentException($"{label} is invalid.");

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

    private static async Task<int> GenerateSuiteReleaseKey(string keyId,
        string privateKeyPath, string trustStorePath, string expiresAtText,
        TextWriter output)
    {
        if (string.IsNullOrWhiteSpace(keyId) || keyId.Length > 128
            || keyId.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-'))
            throw new ArgumentException("Suite release key ID is invalid.");
        if (!DateTimeOffset.TryParse(expiresAtText, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out DateTimeOffset expiresAt))
            throw new ArgumentException("Suite release key expiry must be an ISO-8601 timestamp.");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (expiresAt < now.AddDays(30) || expiresAt > now.AddDays(825))
            throw new ArgumentException("Suite release key expiry must be 30 to 825 days in the future.");
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] privateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var trustStore = new
        {
            keys = new[]
            {
                new
                {
                    key_id = keyId,
                    public_key_hex = Convert.ToHexString(publicKey).ToLowerInvariant(),
                    not_before_unix = now.AddMinutes(-5).ToUnixTimeSeconds(),
                    not_after_unix = expiresAt.ToUnixTimeSeconds(),
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
        string fingerprint = Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
        await output.WriteLineAsync($"generated suite release key {keyId}");
        await output.WriteLineAsync($"public key sha256 {fingerprint}");
        await output.WriteLineAsync($"private key {Path.GetFullPath(privateKeyPath)}");
        await output.WriteLineAsync($"public trust store {Path.GetFullPath(trustStorePath)}");
        await output.WriteLineAsync("import the private key into the release secret, then remove the local copy");
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
        error.WriteLine("       certaelctl project init <root> <name> <engine> <server-runtime> <mode> <identity-provider>");
        error.WriteLine("       certaelctl console init-auth0 <root> <authority> <token-endpoint> <client-id> <audience> <core-base-url>");
        error.WriteLine("       certaelctl deployment init <root> <release-tag> <tenant-id>");
        error.WriteLine("       certaelctl suite validate <suite.json>");
        error.WriteLine("       certaelctl suite generate-development-key <key-id> <private.key> <trust-store.json>");
        error.WriteLine("       certaelctl suite generate-release-key <key-id> <private.key> <trust-store.json> <expires-at>");
        error.WriteLine("       certaelctl suite sign <suite.json> <private.key> <key-id> <signed.json>");
        error.WriteLine("       certaelctl suite assemble <version> <issued-at> <expires-at> <release-base-uri> <definition.json> <suite.json>");
        error.WriteLine("       certaelctl suite verify <signed.json> <trust-store.json>");
        error.WriteLine("       certaelctl suite resolve <suite.json> <certael.yaml> <runtime-identifier>");
        error.WriteLine("       certaelctl suite install <signed.json> <trust-store.json> <certael.yaml> <runtime-identifier> <install-root> <cache-root>");
        error.WriteLine("       certaelctl suite inspect <install-root>");
        error.WriteLine("       certaelctl suite update <signed.json> <trust-store.json> <certael.yaml> <install-root> <cache-root> [--force-modified]");
        error.WriteLine("       certaelctl suite repair <signed.json> <trust-store.json> <certael.yaml> <install-root> <cache-root> [--force-modified]");
        error.WriteLine("       certaelctl suite uninstall <install-root> [--force-modified]");
        error.WriteLine("       certaelctl suite recover <install-root> <plan-id>");
        error.WriteLine("       certaelctl doctor");
        return 1;
    }
}

internal sealed class TextInstallerObserver(TextWriter output) : IInstallerObserver
{
    public async ValueTask ReportAsync(InstallerEvent value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string details = value.Details.Count == 0 ? string.Empty : " " + string.Join(" ",
            value.Details.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{pair.Key}={pair.Value}"));
        await output.WriteLineAsync($"[{value.Level}] {value.OperationId}: {value.Message}{details}");
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
