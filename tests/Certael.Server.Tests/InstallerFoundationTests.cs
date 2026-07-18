extern alias certaelcli;

using System.Text;
using System.Text.Json;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.IO.Compression;
using Certael.Installer;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class InstallerFoundationTests
{
    [Fact]
    public async Task CliInitializesAProjectThroughTheSharedInstallerEngine()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-cli-init", Guid.NewGuid().ToString("N"));
        try
        {
            using var stdout = new StringWriter();
            using var stderr = new StringWriter();
            int result = await certaelcli::CertaelCli.RunAsync(
                ["project", "init", root, "Blueprint Game", "unreal", "dotnet", "development", "development"],
                stdout, stderr);
            Assert.Equal(0, result);
            Assert.Empty(stderr.ToString());
            CertaelProjectConfiguration configuration = CertaelProjectConfigurationCodec.Decode(
                await File.ReadAllTextAsync(Path.Combine(root, "certael.yaml"),
                    TestContext.Current.CancellationToken));
            Assert.Equal(CertaelEngine.Unreal, configuration.Engine);
            Assert.Contains("unreal-adapter", configuration.Components);
            Assert.Contains("server-sdk-dotnet", configuration.Components);
            Assert.Contains("journal", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task Auth0ConsoleBootstrapCreatesSecretFreeConfigAndBoundedCertificate()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-console-init", Guid.NewGuid().ToString("N"));
        try
        {
            using var stdout = new StringWriter();
            using var stderr = new StringWriter();
            int result = await certaelcli::CertaelCli.RunAsync(
                ["console", "init-auth0", root, "https://tenant.example.auth0.com",
                    "https://tenant.example.mtls.auth0.com/oauth/token", "client-id",
                    "https://core.example/api", "https://core.example"], stdout, stderr);
            Assert.Equal(0, result);
            Assert.Empty(stderr.ToString());
            string configPath = Path.Combine(root, "console", "appsettings.Certael.json");
            string certificatePath = Path.Combine(root, "console", "workload-development.pfx");
            Assert.True(File.Exists(configPath));
            Assert.True(File.Exists(certificatePath));
            using JsonDocument config = JsonDocument.Parse(await File.ReadAllBytesAsync(configPath,
                TestContext.Current.CancellationToken));
            Assert.Equal(string.Empty, config.RootElement.GetProperty("authentication")
                .GetProperty("clientSecret").GetString());
            Assert.Equal(string.Empty, config.RootElement.GetProperty("tokenExchange")
                .GetProperty("clientSecret").GetString());
            string thumbprint = CertaelConsoleBootstrap.CertificateThumbprintSha256(certificatePath);
            Assert.Contains(thumbprint, stdout.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("hunter2", await File.ReadAllTextAsync(configPath,
                TestContext.Current.CancellationToken));

            Assert.Throws<ConfigurationException>(() => CertaelConsoleBootstrap.CreateDevelopmentPlan(
                new Auth0ConsoleBootstrapRequest(root, "http://tenant.example",
                    "https://tenant.example/oauth/token", "client", "audience",
                    "https://core.example"), DateTimeOffset.UtcNow));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task DeploymentBootstrapGeneratesPrivateSecretsWithoutLoggingThem()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-deployment-init",
            Guid.NewGuid().ToString("N"));
        try
        {
            using var stdout = new StringWriter();
            using var stderr = new StringWriter();
            int result = await certaelcli::CertaelCli.RunAsync(
                ["deployment", "init", root, "v0.4.0-alpha.2", "tenant-a"], stdout, stderr);
            Assert.Equal(0, result);
            Assert.Empty(stderr.ToString());
            string environmentPath = Path.Combine(root, ".certael", "deployment.env");
            string environment = await File.ReadAllTextAsync(environmentPath,
                TestContext.Current.CancellationToken);
            Dictionary<string, string> values = environment.Split('\n',
                    StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.TrimEnd('\r').Split('=', 2))
                .ToDictionary(parts => parts[0], parts => parts[1], StringComparer.Ordinal);
            Assert.Equal("v0.4.0-alpha.2", values["CERTAEL_VERSION"]);
            Assert.Equal("tenant-a", values["CERTAEL_TENANT_ID"]);
            string postgresPassword = await File.ReadAllTextAsync(Path.Combine(root,
                ".certael", "secrets", "postgres-password"),
                TestContext.Current.CancellationToken);
            string coordinatorPassword = await File.ReadAllTextAsync(Path.Combine(root,
                ".certael", "secrets", "coordinator-postgres-password"),
                TestContext.Current.CancellationToken);
            Assert.Equal(64, postgresPassword.Length);
            Assert.NotEqual(postgresPassword, coordinatorPassword);
            Assert.DoesNotContain("CERTAEL_POSTGRES_PASSWORD=", environment,
                StringComparison.Ordinal);
            Assert.Contains(postgresPassword, values["CERTAEL_POSTGRES_CONNECTION_STRING"],
                StringComparison.Ordinal);
            using ECDsa key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(Convert.FromBase64String(
                values["CERTAEL_COORDINATOR_SIGNING_KEY_PKCS8"]), out _);
            Assert.DoesNotContain(postgresPassword, stdout.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(values["CERTAEL_COORDINATOR_SIGNING_KEY_PKCS8"],
                stdout.ToString(), StringComparison.Ordinal);
            Assert.True(File.Exists(Path.Combine(root, ".certael", "DEPLOYMENT.md")));
            if (!OperatingSystem.IsWindows())
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(environmentPath));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData(CertaelEngine.Godot, CertaelServerRuntime.DotNet,
        "godot-adapter", "server-sdk-dotnet")]
    [InlineData(CertaelEngine.Unity, CertaelServerRuntime.Node,
        "unity-adapter", "server-sdk-typescript")]
    [InlineData(CertaelEngine.Unreal, CertaelServerRuntime.Native,
        "unreal-adapter", "server-sdk-native")]
    [InlineData(CertaelEngine.Native, CertaelServerRuntime.Custom,
        "native-runtime", null)]
    public void ProjectSelectionsAlwaysInferRequiredInstallComponents(
        CertaelEngine engine, CertaelServerRuntime serverRuntime,
        string engineComponent, string? serverComponent)
    {
        var configuration = new CertaelProjectConfiguration
        {
            ProjectName = "Inference",
            Engine = engine,
            ServerRuntime = serverRuntime,
            DeploymentMode = CertaelDeploymentMode.Development,
            IdentityProvider = CertaelIdentityProvider.Development,
            Components = ["core-api"]
        };

        IReadOnlyList<string> components = configuration.RequiredComponents();
        Assert.Contains(engineComponent, components);
        if (serverComponent is not null) Assert.Contains(serverComponent, components);
    }

    [Fact]
    public void ProjectConfigurationRoundTripsAndRejectsDevelopmentIdentityInProduction()
    {
        var source = new CertaelProjectConfiguration
        {
            ProjectName = "Reference Game",
            Engine = CertaelEngine.Unreal,
            ServerRuntime = CertaelServerRuntime.DotNet,
            DeploymentMode = CertaelDeploymentMode.Development,
            IdentityProvider = CertaelIdentityProvider.Development,
            Providers = [CertaelProvider.Steam],
            TenantId = "tenant-a",
            EnvironmentId = "dev"
        };
        string yaml = CertaelProjectConfigurationCodec.Encode(source);
        CertaelProjectConfiguration decoded = CertaelProjectConfigurationCodec.Decode(yaml);
        Assert.Equal(source.ProjectName, decoded.ProjectName);
        Assert.Equal(CertaelEngine.Unreal, decoded.Engine);
        Assert.Contains(CertaelProvider.Steam, decoded.Providers);

        Assert.Throws<ConfigurationException>(() => new CertaelProjectConfiguration
        {
            ProjectName = "Unsafe",
            Engine = CertaelEngine.Unity,
            ServerRuntime = CertaelServerRuntime.Node,
            DeploymentMode = CertaelDeploymentMode.Production,
            IdentityProvider = CertaelIdentityProvider.Development
        }.Validate());
    }

    [Fact]
    public void SuiteManifestValidatesAndResolvesExactDependencies()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var manifest = new CertaelSuiteManifest(1, "1.0.0", now.AddMinutes(-1), now.AddDays(1),
        [
            Component("runtime", "1.0.0"),
            Component("unity", "1.0.0", new Dictionary<string, string> { ["runtime"] = "1.0.0" })
        ]);
        CertaelSuiteManifestCodec.Validate(manifest, now);
        IReadOnlyList<CertaelResolvedComponent> resolved = CertaelSuiteResolver.Resolve(
            manifest, ["unity"], "win-x64");
        Assert.Equal(["runtime", "unity"], resolved.Select(value => value.Id));

        CertaelSuiteComponent portable = Component("portable", "1.0.0") with
        {
            Artifacts = [new CertaelSuiteArtifact("any", "https://example.invalid/portable.zip",
                42, new string('b', 64))]
        };
        CertaelSuiteManifest portableManifest = Manifest(now, [portable]);
        Assert.Equal("any", CertaelSuiteResolver.Resolve(portableManifest, ["portable"],
            "linux-x64").Single().Artifact.RuntimeIdentifier);

        CertaelSuiteManifest invalid = manifest with
        {
            Components = [Component("unity", "1.0.0",
                new Dictionary<string, string> { ["runtime"] = "2.0.0" })]
        };
        Assert.Throws<ConfigurationException>(() => CertaelSuiteManifestCodec.Validate(invalid, now));
    }

    [Fact]
    public async Task InstallerRollsBackCompletedWritesWhenLaterOperationFails()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-installer-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "existing.txt"), "original",
                TestContext.Current.CancellationToken);
            var plan = new InstallationPlan(Guid.NewGuid(), root,
            [
                new WriteFileOperation("replace", "Replace existing file", "existing.txt",
                    Encoding.UTF8.GetBytes("updated"), Overwrite: true),
                new WriteFileOperation("conflict", "Create conflicting file", "existing.txt",
                    Encoding.UTF8.GetBytes("failure"), Overwrite: false)
            ], DateTimeOffset.UtcNow);
            var observer = new InstallerEventBuffer();
            await Assert.ThrowsAsync<IOException>(() => new CertaelInstallerEngine(TimeProvider.System)
                .ApplyAsync(plan, observer, TestContext.Current.CancellationToken));
            Assert.Equal("original", await File.ReadAllTextAsync(Path.Combine(root, "existing.txt"),
                TestContext.Current.CancellationToken));
            Assert.Contains(observer.Events, value => value.Kind == InstallerEventKind.Rollback);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void InstallationPlanRejectsEscapingPathsAndLogsRedactSecrets()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-installer-tests", Guid.NewGuid().ToString("N"));
        var plan = new InstallationPlan(Guid.NewGuid(), root,
            [new WriteFileOperation("escape", "Escape", "../outside", new byte[] { 1 })], DateTimeOffset.UtcNow);
        Assert.Throws<ConfigurationException>(plan.Validate);

        string redacted = InstallerSecretRedactor.Redact(
            "client_secret=hunter2 Authorization: Bearer abc.def.ghi");
        Assert.DoesNotContain("hunter2", redacted);
        Assert.DoesNotContain("abc.def.ghi", redacted);
        IReadOnlyDictionary<string, string> details = InstallerSecretRedactor.Redact(
            new Dictionary<string, string> { ["certificate_password"] = "secret-value" });
        Assert.Equal("[REDACTED]", details["certificate_password"]);
    }

    [Fact]
    public void DesktopSetupTrustStoreCodecUsesStrictBoundedPublicKeys()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] encoded = JsonSerializer.SerializeToUtf8Bytes(new
        {
            keys = new[]
            {
                new
                {
                    key_id = "release-desktop",
                    public_key_hex = Convert.ToHexString(publicKey).ToLowerInvariant(),
                    not_before_unix = now.AddMinutes(-1).ToUnixTimeSeconds(),
                    not_after_unix = now.AddDays(1).ToUnixTimeSeconds(),
                    revoked = false
                }
            }
        });

        SuiteVerificationKeyRing ring = SuiteTrustStoreCodec.Decode(encoded);
        Assert.Equal(publicKey, ring.Active("release-desktop", now).PublicKey);
        Assert.Throws<ConfigurationException>(() => SuiteTrustStoreCodec.Decode(
            "{\"keys\":[{\"key_id\":\"bad\",\"public_key_hex\":\"00\",\"not_before_unix\":1,\"not_after_unix\":2,\"revoked\":false}]}"u8));
    }

    [Fact]
    public void SignedSuiteManifestRejectsTamperingAndRevokedKeys()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        CertaelSuiteManifest manifest = Manifest(now, [Component("runtime", "1.0.0")]);
        byte[] canonical = CertaelSuiteManifestCodec.Encode(manifest, now);
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        SignedSuiteManifest signed = SignedSuiteManifestCodec.Sign(canonical, key, "release-1");
        byte[] envelope = SignedSuiteManifestCodec.Encode(signed);
        var ring = new SuiteVerificationKeyRing([
            new SuiteVerificationKey("release-1", publicKey, now.AddDays(-1), now.AddDays(1))
        ]);
        Assert.Equal("1.0.0", SignedSuiteManifestCodec.Verify(envelope, ring, now).SuiteVersion);

        SignedSuiteManifest tampered = signed with { ManifestSha256 = new string('0', 64) };
        Assert.Throws<CryptographicException>(() => SignedSuiteManifestCodec.Verify(
            SignedSuiteManifestCodec.Encode(tampered), ring, now));
        var revoked = new SuiteVerificationKeyRing([
            new SuiteVerificationKey("release-1", publicKey, now.AddDays(-1), now.AddDays(1), true)
        ]);
        Assert.Throws<CryptographicException>(() => SignedSuiteManifestCodec.Verify(envelope, revoked, now));

        byte[] formatted = JsonSerializer.SerializeToUtf8Bytes(manifest,
            new JsonSerializerOptions { WriteIndented = true });
        SignedSuiteManifest noncanonical = SignedSuiteManifestCodec.Sign(formatted, key, "release-1");
        Assert.Throws<CryptographicException>(() => SignedSuiteManifestCodec.Verify(
            SignedSuiteManifestCodec.Encode(noncanonical), ring, now));
    }

    [Fact]
    public async Task SuiteAssemblerHashesRealFilesAndEmitsCanonicalReleaseUris()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-suite-assembly",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string artifactPath = Path.Combine(root, "component.zip");
            byte[] content = Encoding.UTF8.GetBytes("release artifact");
            await File.WriteAllBytesAsync(artifactPath, content,
                TestContext.Current.CancellationToken);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var definition = new SuiteAssemblyDefinition([
                new SuiteAssemblyComponent("runtime", "1.2.3",
                    new Dictionary<string, string>(), [new SuiteAssemblyArtifact(
                        "win-x64", artifactPath, "certael-runtime-v1.2.3.zip")])
            ]);
            CertaelSuiteManifest manifest = await CertaelSuiteManifestAssembler.AssembleAsync(
                "1.2.3", now, now.AddDays(7),
                new Uri("https://github.com/violetweather/Certael/releases/download/v1.2.3"),
                definition, TestContext.Current.CancellationToken);
            CertaelSuiteArtifact artifact = Assert.Single(Assert.Single(manifest.Components).Artifacts);
            Assert.Equal(content.Length, artifact.Size);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(),
                artifact.Sha256);
            Assert.Equal("https://github.com/violetweather/Certael/releases/download/v1.2.3/certael-runtime-v1.2.3.zip",
                artifact.Uri);
            byte[] encoded = CertaelSuiteManifestCodec.Encode(manifest, now);
            CertaelSuiteManifest decoded = CertaelSuiteManifestCodec.Decode(encoded, now);
            Assert.Equal(encoded, CertaelSuiteManifestCodec.Encode(decoded, now));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task DownloaderStreamsAndVerifiesSignedSizeAndDigest()
    {
        byte[] content = Encoding.UTF8.GetBytes("signed artifact content");
        string digest = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        var artifact = new CertaelSuiteArtifact("win-x64", "https://downloads.example/artifact.zip",
            content.Length, digest);
        using var client = new HttpClient(new StaticResponseHandler(content));
        string cache = Path.Combine(Path.GetTempPath(), "certael-download-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var observer = new InstallerEventBuffer();
            DownloadedArtifact downloaded = await new CertaelArtifactDownloader(client, TimeProvider.System)
                .DownloadAsync(artifact, cache, observer, TestContext.Current.CancellationToken);
            Assert.Equal(content.Length, downloaded.Size);
            Assert.Equal(digest, downloaded.Sha256);
            Assert.True(File.Exists(downloaded.Path));
            Assert.Contains(observer.Events, value => value.Kind == InstallerEventKind.OperationCompleted);
        }
        finally { if (Directory.Exists(cache)) Directory.Delete(cache, recursive: true); }
    }

    [Fact]
    public async Task ZipInstallationRejectsTraversalAndRollsBackPartialExtraction()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-zip-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string traversal = Path.Combine(root, "traversal.zip");
            CreateZip(traversal, [("../escape.txt", "escape")]);
            var traversalPlan = new InstallationPlan(Guid.NewGuid(), Path.Combine(root, "target-a"),
                [new ExtractZipOperation("extract", "Extract", "package", traversal)], DateTimeOffset.UtcNow);
            await Assert.ThrowsAsync<ConfigurationException>(() => new CertaelInstallerEngine(TimeProvider.System)
                .ApplyAsync(traversalPlan, new InstallerEventBuffer(),
                    TestContext.Current.CancellationToken));
            Assert.False(File.Exists(Path.Combine(root, "target-a", "escape.txt")));

            string rollbackTarget = Path.Combine(root, "target-b");
            Directory.CreateDirectory(Path.Combine(rollbackTarget, "package"));
            await File.WriteAllTextAsync(Path.Combine(rollbackTarget, "package", "existing.txt"),
                "existing", TestContext.Current.CancellationToken);
            string conflict = Path.Combine(root, "conflict.zip");
            CreateZip(conflict, [("created.txt", "created"), ("existing.txt", "replace")]);
            var conflictPlan = new InstallationPlan(Guid.NewGuid(), rollbackTarget,
                [new ExtractZipOperation("extract", "Extract", "package", conflict)], DateTimeOffset.UtcNow);
            await Assert.ThrowsAsync<IOException>(() => new CertaelInstallerEngine(TimeProvider.System)
                .ApplyAsync(conflictPlan, new InstallerEventBuffer(),
                    TestContext.Current.CancellationToken));
            Assert.False(File.Exists(Path.Combine(rollbackTarget, "package", "created.txt")));
            Assert.Equal("existing", await File.ReadAllTextAsync(
                Path.Combine(rollbackTarget, "package", "existing.txt"),
                TestContext.Current.CancellationToken));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task ManagedDeleteRefusesModifiedFilesAndCanRecoverFromJournal()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-delete-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string managed = Path.Combine(root, "managed.bin");
            byte[] original = Encoding.UTF8.GetBytes("managed-content");
            await File.WriteAllBytesAsync(managed, original, TestContext.Current.CancellationToken);
            string digest = Convert.ToHexString(SHA256.HashData(original)).ToLowerInvariant();
            var engine = new CertaelInstallerEngine(TimeProvider.System);
            var plan = new InstallationPlan(Guid.NewGuid(), root,
                [new DeleteFileOperation("remove-managed", "Remove managed file", "managed.bin", digest)],
                DateTimeOffset.UtcNow);
            InstallationResult removed = await engine.ApplyAsync(plan, new InstallerEventBuffer(),
                TestContext.Current.CancellationToken);
            Assert.True(removed.Succeeded);
            Assert.False(File.Exists(managed));

            InstallationResult recovered = await engine.RecoverAsync(root, plan.PlanId,
                new InstallerEventBuffer(), TestContext.Current.CancellationToken);
            Assert.True(recovered.RolledBack);
            Assert.Equal(original, await File.ReadAllBytesAsync(managed,
                TestContext.Current.CancellationToken));

            await File.WriteAllTextAsync(managed, "operator-modified",
                TestContext.Current.CancellationToken);
            var guarded = new InstallationPlan(Guid.NewGuid(), root,
                [new DeleteFileOperation("guard-modified", "Guard modified file", "managed.bin", digest)],
                DateTimeOffset.UtcNow);
            await Assert.ThrowsAsync<IOException>(() => engine.ApplyAsync(guarded,
                new InstallerEventBuffer(), TestContext.Current.CancellationToken));
            Assert.Equal("operator-modified", await File.ReadAllTextAsync(managed,
                TestContext.Current.CancellationToken));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task InstalledStateDetectsDriftAndBuildsAConservativeUninstallPlan()
    {
        string root = Path.Combine(Path.GetTempPath(), "certael-state-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "bin"));
        Directory.CreateDirectory(Path.Combine(root, "config"));
        try
        {
            byte[] binary = Encoding.UTF8.GetBytes("binary");
            byte[] config = Encoding.UTF8.GetBytes("operator-config");
            await File.WriteAllBytesAsync(Path.Combine(root, "bin", "core.bin"), binary,
                TestContext.Current.CancellationToken);
            await File.WriteAllBytesAsync(Path.Combine(root, "config", "certael.json"), config,
                TestContext.Current.CancellationToken);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var state = new InstalledSuiteState(1, "1.0.0", "win-x64",
                [new InstalledSuiteComponent("core", "1.0.0", new string('a', 64))],
                [
                    new InstalledSuiteFile("bin/core.bin", "core", binary.Length,
                        Convert.ToHexString(SHA256.HashData(binary)).ToLowerInvariant()),
                    new InstalledSuiteFile("config/certael.json", "core", config.Length,
                        Convert.ToHexString(SHA256.HashData(config)).ToLowerInvariant(), true),
                    new InstalledSuiteFile("bin/missing.bin", "core", 10, new string('b', 64))
                ], Guid.NewGuid(), now, now);
            byte[] encoded = InstalledSuiteStateCodec.Encode(state, root);
            InstalledSuiteState decoded = InstalledSuiteStateCodec.Decode(encoded, root);
            SuiteInstallationInspection inspection = await CertaelInstallationLifecycle.InspectAsync(
                root, decoded, TestContext.Current.CancellationToken);
            Assert.False(inspection.Healthy);
            Assert.Contains(inspection.Files, value => value.File.Path == "bin/core.bin"
                && value.Health == InstalledFileHealth.Healthy);
            Assert.Contains(inspection.Files, value => value.File.Path == "bin/missing.bin"
                && value.Health == InstalledFileHealth.Missing);

            InstallationPlan uninstall = CertaelInstallationLifecycle.CreateUninstallPlan(
                root, decoded, false, now);
            Assert.DoesNotContain(uninstall.Operations,
                value => value.RelativePath == "config/certael.json");
            await new CertaelInstallerEngine(TimeProvider.System).ApplyAsync(uninstall,
                new InstallerEventBuffer(), TestContext.Current.CancellationToken);
            Assert.False(File.Exists(Path.Combine(root, "bin", "core.bin")));
            Assert.True(File.Exists(Path.Combine(root, "config", "certael.json")));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task SignedSuiteInstallPreflightsArtifactsAndRecordsAHealthyInventory()
    {
        string basePath = Path.Combine(Path.GetTempPath(), "certael-suite-install",
            Guid.NewGuid().ToString("N"));
        string root = Path.Combine(basePath, "install");
        string cache = Path.Combine(basePath, "cache");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        byte[] runtimeArchive = CreateZipBytes([("bin/runtime.txt", "runtime")]);
        byte[] consoleArchive = CreateZipBytes([("console/index.html", "console")]);
        try
        {
            CertaelSuiteComponent runtime = ArchiveComponent("runtime", runtimeArchive);
            CertaelSuiteComponent console = ArchiveComponent("console", consoleArchive,
                new Dictionary<string, string> { ["runtime"] = "1.0.0" });
            var manifest = new CertaelSuiteManifest(1, "1.0.0", now.AddMinutes(-1),
                now.AddDays(1), [runtime, console]);
            using Key key = Key.Create(SignatureAlgorithm.Ed25519,
                new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            byte[] envelope = SignedSuiteManifestCodec.Encode(SignedSuiteManifestCodec.Sign(
                CertaelSuiteManifestCodec.Encode(manifest, now), key, "release-1"));
            var ring = new SuiteVerificationKeyRing([new SuiteVerificationKey("release-1",
                key.PublicKey.Export(KeyBlobFormat.RawPublicKey), now.AddDays(-1), now.AddDays(1))]);
            var configuration = new CertaelProjectConfiguration
            {
                ProjectName = "Installed Game",
                Engine = CertaelEngine.None,
                ServerRuntime = CertaelServerRuntime.Custom,
                DeploymentMode = CertaelDeploymentMode.Production,
                IdentityProvider = CertaelIdentityProvider.Auth0,
                Components = ["console"]
            };
            var responses = new Dictionary<string, byte[]>
            {
                [runtime.Artifacts[0].Uri] = runtimeArchive,
                [console.Artifacts[0].Uri] = consoleArchive
            };
            using var client = new HttpClient(new MapResponseHandler(responses));
            var installer = new CertaelSuiteInstaller(client, TimeProvider.System);
            SuiteInstallResult result = await installer
                .InstallAsync(envelope, ring, configuration, "win-x64", root, cache,
                    new InstallerEventBuffer(), TestContext.Current.CancellationToken);

            Assert.True(result.Installation.Succeeded);
            Assert.Equal(["console", "runtime"], result.State.Components.Select(value => value.Id));
            Assert.Equal("runtime", await File.ReadAllTextAsync(Path.Combine(root,
                "bin", "runtime.txt"), TestContext.Current.CancellationToken));
            byte[] stateBytes = await File.ReadAllBytesAsync(Path.Combine(root, ".certael",
                "installed-state.json"), TestContext.Current.CancellationToken);
            InstalledSuiteState state = InstalledSuiteStateCodec.Decode(stateBytes, root);
            SuiteInstallationInspection inspection = await CertaelInstallationLifecycle.InspectAsync(
                root, state, TestContext.Current.CancellationToken);
            Assert.True(inspection.Healthy);
            Assert.Equal(2, inspection.Files.Count);

            string runtimePath = Path.Combine(root, "bin", "runtime.txt");
            File.Delete(runtimePath);
            SuiteInstallResult repaired = await installer.RepairAsync(envelope, ring,
                configuration, root, cache, false, new InstallerEventBuffer(),
                TestContext.Current.CancellationToken);
            Assert.Equal("runtime", await File.ReadAllTextAsync(runtimePath,
                TestContext.Current.CancellationToken));
            Assert.NotEqual(result.State.PlanId, repaired.State.PlanId);

            await File.WriteAllTextAsync(runtimePath, "operator-change",
                TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<IOException>(() => installer.RepairAsync(envelope, ring,
                configuration, root, cache, false, new InstallerEventBuffer(),
                TestContext.Current.CancellationToken));
            await installer.RepairAsync(envelope, ring, configuration, root, cache, true,
                new InstallerEventBuffer(), TestContext.Current.CancellationToken);
            Assert.Equal("runtime", await File.ReadAllTextAsync(runtimePath,
                TestContext.Current.CancellationToken));

            byte[] nextRuntimeArchive = CreateZipBytes([("bin/runtime.txt", "runtime-v2")]);
            byte[] nextConsoleArchive = CreateZipBytes([("console/app.html", "console-v2")]);
            CertaelSuiteComponent nextRuntime = ArchiveComponent("runtime", nextRuntimeArchive,
                version: "1.1.0");
            CertaelSuiteComponent nextConsole = ArchiveComponent("console", nextConsoleArchive,
                new Dictionary<string, string> { ["runtime"] = "1.1.0" }, "1.1.0");
            var nextManifest = new CertaelSuiteManifest(1, "1.1.0", now.AddMinutes(-1),
                now.AddDays(1), [nextRuntime, nextConsole]);
            byte[] nextEnvelope = SignedSuiteManifestCodec.Encode(SignedSuiteManifestCodec.Sign(
                CertaelSuiteManifestCodec.Encode(nextManifest, now), key, "release-1"));
            responses[nextRuntime.Artifacts[0].Uri] = nextRuntimeArchive;
            responses[nextConsole.Artifacts[0].Uri] = nextConsoleArchive;
            SuiteInstallResult updated = await installer.UpdateAsync(nextEnvelope, ring,
                configuration, root, cache, false, new InstallerEventBuffer(),
                TestContext.Current.CancellationToken);
            Assert.Equal("1.1.0", updated.State.SuiteVersion);
            Assert.Equal("runtime-v2", await File.ReadAllTextAsync(runtimePath,
                TestContext.Current.CancellationToken));
            Assert.False(File.Exists(Path.Combine(root, "console", "index.html")));
            Assert.Equal("console-v2", await File.ReadAllTextAsync(Path.Combine(root,
                "console", "app.html"), TestContext.Current.CancellationToken));
        }
        finally { if (Directory.Exists(basePath)) Directory.Delete(basePath, recursive: true); }
    }

    [Fact]
    public async Task SuiteInstallRejectsCrossComponentAndReservedPathsBeforeMutation()
    {
        foreach ((string firstPath, string secondPath) in new[]
        {
            ("shared/file.txt", "shared/file.txt"),
            ("safe/file.txt", ".certael/installed-state.json")
        })
        {
            string basePath = Path.Combine(Path.GetTempPath(), "certael-suite-preflight",
                Guid.NewGuid().ToString("N"));
            string root = Path.Combine(basePath, "install");
            DateTimeOffset now = DateTimeOffset.UtcNow;
            byte[] first = CreateZipBytes([(firstPath, "first")]);
            byte[] second = CreateZipBytes([(secondPath, "second")]);
            try
            {
                CertaelSuiteComponent one = ArchiveComponent("one", first);
                CertaelSuiteComponent two = ArchiveComponent("two", second);
                var manifest = new CertaelSuiteManifest(1, "1.0.0", now.AddMinutes(-1),
                    now.AddDays(1), [one, two]);
                using Key key = Key.Create(SignatureAlgorithm.Ed25519,
                    new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
                byte[] envelope = SignedSuiteManifestCodec.Encode(SignedSuiteManifestCodec.Sign(
                    CertaelSuiteManifestCodec.Encode(manifest, now), key, "release-1"));
                var ring = new SuiteVerificationKeyRing([new SuiteVerificationKey("release-1",
                    key.PublicKey.Export(KeyBlobFormat.RawPublicKey), now.AddDays(-1), now.AddDays(1))]);
                var configuration = new CertaelProjectConfiguration
                {
                    ProjectName = "Rejected Game",
                    Engine = CertaelEngine.None,
                    ServerRuntime = CertaelServerRuntime.Custom,
                    DeploymentMode = CertaelDeploymentMode.Production,
                    IdentityProvider = CertaelIdentityProvider.Auth0,
                    Components = ["one", "two"]
                };
                using var client = new HttpClient(new MapResponseHandler(new Dictionary<string, byte[]>
                {
                    [one.Artifacts[0].Uri] = first,
                    [two.Artifacts[0].Uri] = second
                }));
                await Assert.ThrowsAsync<IOException>(() => new CertaelSuiteInstaller(
                    client, TimeProvider.System).InstallAsync(envelope, ring, configuration,
                        "win-x64", root, Path.Combine(basePath, "cache"),
                        new InstallerEventBuffer(), TestContext.Current.CancellationToken));
                Assert.False(Directory.Exists(root));
            }
            finally { if (Directory.Exists(basePath)) Directory.Delete(basePath, recursive: true); }
        }
    }

    private static CertaelSuiteComponent Component(string id, string version,
        IReadOnlyDictionary<string, string>? dependencies = null) => new(id, version,
        dependencies ?? new Dictionary<string, string>(),
        [new CertaelSuiteArtifact("win-x64", $"https://example.invalid/{id}.zip", 42,
            new string('a', 64))]);

    private static CertaelSuiteManifest Manifest(DateTimeOffset now,
        IReadOnlyList<CertaelSuiteComponent> components) =>
        new(1, "1.0.0", now.AddMinutes(-1), now.AddDays(1), components);

    private static CertaelSuiteComponent ArchiveComponent(string id, byte[] archive,
        IReadOnlyDictionary<string, string>? dependencies = null, string version = "1.0.0")
    {
        string digest = Convert.ToHexString(SHA256.HashData(archive)).ToLowerInvariant();
        return new CertaelSuiteComponent(id, version,
            dependencies ?? new Dictionary<string, string>(),
            [new CertaelSuiteArtifact("win-x64", $"https://downloads.example/{id}.zip",
                archive.Length, digest)]);
    }

    private sealed class StaticResponseHandler(byte[] content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(content)
            });
        }
    }

    private sealed class MapResponseHandler(IReadOnlyDictionary<string, byte[]> content)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.RequestUri is null
                || !content.TryGetValue(request.RequestUri.AbsoluteUri, out byte[]? body))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(body)
            });
        }
    }

    private static void CreateZip(string path, IReadOnlyList<(string Path, string Content)> entries)
    {
        using ZipArchive archive = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach ((string name, string content) in entries)
        {
            ZipArchiveEntry entry = archive.CreateEntry(name);
            using StreamWriter writer = new(entry.Open());
            writer.Write(content);
        }
    }

    private static byte[] CreateZipBytes(IReadOnlyList<(string Path, string Content)> entries)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, string content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name);
                using StreamWriter writer = new(entry.Open());
                writer.Write(content);
            }
        }
        return output.ToArray();
    }
}
