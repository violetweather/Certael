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

    public void Validate()
    {
        if (MaximumModuleBytes is < 8 or > 4 * 1024 * 1024
            || MaximumMemoryBytes is < 64 * 1024 or > 16 * 1024 * 1024
            || MaximumInputBytes is < 1 or > 1024 * 1024
            || MaximumOutputBytes is < 1 or > 64 * 1024
            || Fuel is < 1 or > 10_000_000
            || EffectiveDeadline <= TimeSpan.Zero
            || EffectiveDeadline > TimeSpan.FromMilliseconds(10))
            throw new WasmRuleException("WASM runtime limits are invalid.");
    }
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
        limits.Validate();
        if (module.Module.Length is < 8 || module.Module.Length > limits.MaximumModuleBytes
            || module.Digest.Length != 32
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(module.Module), module.Digest))
            throw new InvalidOperationException("WASM module digest or size is invalid.");
        if (!Identifier(module.RuleId) || !Identifier(module.Version) || !Identifier(module.KeyId)
            || !keys.TryGetValue(module.KeyId, out PublicKey? key)
            || !Signature.Verify(key, SignaturePayload(module.RuleId, module.Version,
                module.Digest), module.Signature))
            throw new InvalidOperationException("WASM module signature is invalid.");
        string digest = Convert.ToHexString(module.Digest);
        if (_modules.TryGetValue(digest, out SignedWasmModule? existing)
            && (existing.RuleId != module.RuleId || existing.Version != module.Version
                || !CryptographicOperations.FixedTimeEquals(existing.Module, module.Module)))
            throw new InvalidOperationException("WASM module digest is already registered differently.");
        _modules[digest] = module;
    }

    public async ValueTask<WasmRuleDecisionV1> EvaluateAsync(byte[] digest, WasmRuleInputV1 input,
        WasmRuntimeLimits? limits = null, CancellationToken cancellationToken = default)
    {
        if (!_modules.TryGetValue(Convert.ToHexString(digest), out SignedWasmModule? module))
            return Indeterminate("WASM_MODULE_UNAVAILABLE");
        if (input.RuleId != module.RuleId || input.RuleVersion != module.Version)
            return Indeterminate("WASM_PROFILE_BINDING_MISMATCH");
        try
        {
            (limits ??= new WasmRuntimeLimits()).Validate();
            WasmRuleDecisionV1 decision = await runtime.EvaluateAsync(module.Module, input,
                limits, cancellationToken);
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

    public static byte[] SignaturePayload(string ruleId, string version,
        ReadOnlySpan<byte> digest)
    {
        if (!Identifier(ruleId) || !Identifier(version) || digest.Length != 32)
            throw new WasmRuleException("WASM signature binding is invalid.");
        using var output = new MemoryStream();
        output.Write("certael.wasm.module.v1\0"u8);
        Write(output, ruleId); Write(output, version); output.Write(digest);
        return output.ToArray();
    }

    private static void Write(Stream output, string value)
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        output.Write(length); output.Write(bytes);
    }

    private static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
}
