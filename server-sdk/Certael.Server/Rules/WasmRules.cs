using System.Security.Cryptography;
using NSec.Cryptography;

namespace Certael.Server.Rules;

public enum WasmRuleOutcome : byte { Pass = 1, Reject = 2, Indeterminate = 3 }
public sealed record WasmRuleInputV1(string TenantId, string GameId, string EnvironmentId,
    string RuleId, string RuleVersion, byte[] CanonicalAction, byte[] CanonicalState);
public sealed record WasmRuleDecisionV1(WasmRuleOutcome Outcome, string PublicReason,
    int BoundedRisk, IReadOnlyDictionary<string, string> BoundedEvidence);
public sealed record SignedWasmModule(string RuleId, string Version, byte[] Module, byte[] Digest,
    string KeyId, byte[] Signature);
public sealed record WasmRuntimeLimits(int MaximumModuleBytes = 4 * 1024 * 1024,
    int MaximumMemoryBytes = 16 * 1024 * 1024, int MaximumInputBytes = 1024 * 1024,
    int MaximumOutputBytes = 64 * 1024, ulong Fuel = 10_000_000, TimeSpan? Deadline = null)
{
    public TimeSpan EffectiveDeadline => Deadline ?? TimeSpan.FromMilliseconds(10);
}

public interface IWasmRuleRuntime
{
    ValueTask<WasmRuleDecisionV1> EvaluateAsync(ReadOnlyMemory<byte> module,
        WasmRuleInputV1 input, WasmRuntimeLimits limits, CancellationToken cancellationToken = default);
}

public sealed class SignedWasmRuleRegistry(IReadOnlyDictionary<string, PublicKey> keys,
    IWasmRuleRuntime runtime)
{
    private readonly Dictionary<string, SignedWasmModule> _modules = new(StringComparer.Ordinal);
    private static readonly SignatureAlgorithm Signature = SignatureAlgorithm.Ed25519;

    public void Register(SignedWasmModule module, WasmRuntimeLimits limits)
    {
        if (module.Module.Length is < 8 || module.Module.Length > limits.MaximumModuleBytes
            || module.Digest.Length != 32
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(module.Module), module.Digest))
            throw new InvalidOperationException("WASM module digest or size is invalid.");
        if (!keys.TryGetValue(module.KeyId, out PublicKey? key)
            || !Signature.Verify(key, module.Digest, module.Signature))
            throw new InvalidOperationException("WASM module signature is invalid.");
        _modules[Convert.ToHexString(module.Digest)] = module;
    }

    public async ValueTask<WasmRuleDecisionV1> EvaluateAsync(byte[] digest, WasmRuleInputV1 input,
        WasmRuntimeLimits? limits = null, CancellationToken cancellationToken = default)
    {
        if (!_modules.TryGetValue(Convert.ToHexString(digest), out SignedWasmModule? module))
            return Indeterminate("WASM_MODULE_UNAVAILABLE");
        try
        {
            WasmRuleDecisionV1 decision = await runtime.EvaluateAsync(module.Module, input,
                limits ?? new WasmRuntimeLimits(), cancellationToken);
            if (decision.BoundedRisk is < 0 or > 100 || decision.BoundedEvidence.Count > 64
                || decision.PublicReason.Length is < 1 or > 64
                || decision.BoundedEvidence.Any(e => e.Key.Length is < 1 or > 64 || e.Value.Length > 4096))
                return Indeterminate("WASM_MALFORMED_OUTPUT");
            return decision;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        { return Indeterminate("WASM_INDETERMINATE"); }
    }

    private static WasmRuleDecisionV1 Indeterminate(string reason) =>
        new(WasmRuleOutcome.Indeterminate, reason, 0, new Dictionary<string, string>());
}
