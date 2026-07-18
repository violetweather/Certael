using System.Security.Cryptography;
using Certael.Server.Rules;
using Certael.Server.Configuration;
using Certael.Server.Integrations;
using Certael.Server.Protections;
using NSec.Cryptography;

namespace Certael.Server.Tests;

public sealed class WasmRuleTests
{
    [Fact]
    public void CanonicalInputAndDecisionCodecsRoundTripStrictly()
    {
        var input = new WasmRuleInputV1("tenant", "game", "prod", "inventory.rule",
            "1.0.0", [1, 2, 3], [4, 5]);
        byte[] encodedInput = WasmRuleV1Codec.EncodeInput(input);
        WasmRuleInputV1 decodedInput = WasmRuleV1Codec.DecodeInput(encodedInput);
        Assert.Equal(input.TenantId, decodedInput.TenantId);
        Assert.Equal(input.RuleId, decodedInput.RuleId);
        Assert.Equal(input.CanonicalAction, decodedInput.CanonicalAction);
        Assert.Equal(input.CanonicalState, decodedInput.CanonicalState);
        Assert.Throws<WasmRuleException>(() => WasmRuleV1Codec.DecodeInput(
            encodedInput.Concat(new byte[] { 0x48, 0x01 }).ToArray()));

        var decision = new WasmRuleDecisionV1(WasmRuleOutcome.Reject,
            "RULE_REJECTED", 70, new Dictionary<string, string>
            { ["asset"] = "gold", ["quantity"] = "5" });
        byte[] encodedDecision = WasmRuleV1Codec.EncodeDecision(decision);
        WasmRuleDecisionV1 decoded = WasmRuleV1Codec.DecodeDecision(encodedDecision);
        Assert.Equal(decision.Outcome, decoded.Outcome);
        Assert.Equal(decision.BoundedRisk, decoded.BoundedRisk);
        Assert.Equal(decision.BoundedEvidence, decoded.BoundedEvidence);
        Assert.Equal(encodedDecision, WasmRuleV1Codec.EncodeDecision(decoded));
    }

    [Fact]
    public async Task RegistryBindsSignatureDigestRuleAndVersion()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] moduleBytes = [0, 97, 115, 109, 1, 0, 0, 0];
        byte[] digest = SHA256.HashData(moduleBytes);
        byte[] signature = SignatureAlgorithm.Ed25519.Sign(key,
            SignedWasmRuleRegistry.SignaturePayload("inventory.rule", "1.0.0", digest));
        var module = new SignedWasmModule("inventory.rule", "1.0.0", moduleBytes,
            digest, "wasm-key", signature);
        var runtime = new RecordingWasmRuntime(new WasmRuleDecisionV1(WasmRuleOutcome.Pass,
            "RULE_PASSED", 0, new Dictionary<string, string>()));
        var registry = new SignedWasmRuleRegistry(
            new Dictionary<string, PublicKey> { ["wasm-key"] = key.PublicKey }, runtime);
        registry.Register(module, new WasmRuntimeLimits());
        var input = new WasmRuleInputV1("tenant", "game", "prod", "inventory.rule",
            "1.0.0", [1], []);
        WasmRuleDecisionV1 decision = await registry.EvaluateAsync(digest, input,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(WasmRuleOutcome.Pass, decision.Outcome);
        Assert.True(runtime.Called);

        WasmRuleDecisionV1 mismatch = await registry.EvaluateAsync(digest,
            input with { RuleVersion = "2.0.0" }, cancellationToken:
                TestContext.Current.CancellationToken);
        Assert.Equal("WASM_PROFILE_BINDING_MISMATCH", mismatch.PublicReason);
        Assert.Throws<InvalidOperationException>(() => registry.Register(module with
        {
            RuleId = "another.rule"
        }, new WasmRuntimeLimits()));
    }

    [Fact]
    public async Task TrapsAndMalformedRuntimeOutputBecomeBoundedIndeterminate()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] moduleBytes = [0, 97, 115, 109, 1, 0, 0, 0];
        byte[] digest = SHA256.HashData(moduleBytes);
        var signed = new SignedWasmModule("rule", "1", moduleBytes, digest, "key",
            SignatureAlgorithm.Ed25519.Sign(key,
                SignedWasmRuleRegistry.SignaturePayload("rule", "1", digest)));
        var registry = new SignedWasmRuleRegistry(
            new Dictionary<string, PublicKey> { ["key"] = key.PublicKey },
            new ThrowingWasmRuntime());
        registry.Register(signed, new WasmRuntimeLimits());
        WasmRuleDecisionV1 decision = await registry.EvaluateAsync(digest,
            new WasmRuleInputV1("tenant", "game", "prod", "rule", "1", [1], []),
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(WasmRuleOutcome.Indeterminate, decision.Outcome);
        Assert.Equal("WASM_INDETERMINATE", decision.PublicReason);
        Assert.Throws<WasmRuleException>(() => new WasmRuntimeLimits(Fuel: 10_000_001)
            .Validate());
    }

    [Fact]
    public async Task NativeRuntimeExecutesThePublishedReferenceModule()
    {
        if (Environment.GetEnvironmentVariable("CERTAEL_RUN_WASM_NATIVE_TESTS") != "1")
            return;
        string libraryName = OperatingSystem.IsWindows() ? "certael_wasm.dll"
            : OperatingSystem.IsMacOS() ? "libcertael_wasm.dylib" : "libcertael_wasm.so";
        string root = RepositoryRoot();
        string library = Path.Combine(root, "target", "release", libraryName);
        string module = Path.Combine(root, "target", "wasm32-unknown-unknown",
            "release", "certael_reference_repeated_reward_rule.wasm");
        Assert.True(File.Exists(library), $"Missing native WASM runtime: {library}");
        Assert.True(File.Exists(module), $"Missing reference WASM rule: {module}");
        using var runtime = new NativeWasmRuleRuntime(library);
        WasmRuleDecisionV1 decision = await runtime.EvaluateAsync(
            await File.ReadAllBytesAsync(module, TestContext.Current.CancellationToken),
            new WasmRuleInputV1("tenant", "game", "prod", "reward.repeated", "1",
                [4], []), new WasmRuntimeLimits(), TestContext.Current.CancellationToken);
        Assert.Equal(WasmRuleOutcome.Reject, decision.Outcome);
        Assert.Equal("REPEATED_REWARD", decision.PublicReason);
        Assert.Equal(80, decision.BoundedRisk);
        Assert.Equal("3", decision.BoundedEvidence["threshold"]);
    }

    [Fact]
    public void WasmAndPlatformProfilesUseSharedSignedStagedConfigurationLifecycle()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        DateTimeOffset now = DateTimeOffset.Parse("2030-01-01T00:00:00Z");
        var keys = new Dictionary<string, ECDsa> { ["key-1"] = key };
        var clock = new FixedTimeProvider(now);
        var verifier = new SignedConfigurationVerifier(new RulePackVerifier(keys),
            new ProtectionProfileVerifier(keys), new WasmRuleProfileVerifier(keys, clock),
            new PlatformProofPolicyVerifier(keys, clock));
        SignedWasmRuleProfile wasm = new WasmRuleProfileSigner(key, "key-1").Sign(
            new WasmRuleProfile("wasm-profile", "1", "tenant", "game", "prod",
                "rule", "1", new byte[32], now.AddHours(1)));
        SignedConfigurationArtifact wasmArtifact = SignedConfigurationArtifact.From(wasm);
        Assert.True(verifier.Verify(wasmArtifact));
        Assert.False(verifier.Verify(wasmArtifact with { TenantId = "other" }));

        SignedPlatformProofPolicy platform = new PlatformProofPolicySigner(key, "key-1").Sign(
            new PlatformProofPolicyProfile("proof-policy", "1", "tenant", "game", "prod",
                "vendor", PlatformProofKind.Attestation, PlatformProofRequirement.Optional,
                "application", 300, now.AddHours(1)));
        SignedConfigurationArtifact platformArtifact = SignedConfigurationArtifact.From(platform);
        Assert.True(verifier.Verify(platformArtifact));
        Assert.False(verifier.Verify(platformArtifact with { GameId = "other" }));
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Cargo.toml"))
                && Directory.Exists(Path.Combine(directory.FullName, "runtime", "certael-wasm")))
                return directory.FullName;
            directory = directory.Parent;
        }
        throw new InvalidOperationException("Could not locate the Certael repository root.");
    }

    private sealed class RecordingWasmRuntime(WasmRuleDecisionV1 decision) : IWasmRuleRuntime
    {
        public bool Called { get; private set; }
        public ValueTask<WasmRuleDecisionV1> EvaluateAsync(ReadOnlyMemory<byte> module,
            WasmRuleInputV1 input, WasmRuntimeLimits limits,
            CancellationToken cancellationToken = default)
        { Called = true; return ValueTask.FromResult(decision); }
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed class ThrowingWasmRuntime : IWasmRuleRuntime
    {
        public ValueTask<WasmRuleDecisionV1> EvaluateAsync(ReadOnlyMemory<byte> module,
            WasmRuleInputV1 input, WasmRuntimeLimits limits,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<WasmRuleDecisionV1>(new InvalidOperationException("trap"));
    }
}
