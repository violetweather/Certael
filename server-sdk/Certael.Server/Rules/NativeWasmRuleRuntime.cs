using System.Runtime.InteropServices;
using System.Collections.Concurrent;

namespace Certael.Server.Rules;

public sealed class NativeWasmRuleRuntime : IWasmRuleRuntime, IDisposable
{
    private static readonly ConcurrentDictionary<string, Lazy<NativeEntry>> Libraries =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly EvaluateDelegate _evaluate;
    private bool _disposed;

    public NativeWasmRuleRuntime(string absoluteLibraryPath)
    {
        if (!Path.IsPathFullyQualified(absoluteLibraryPath))
            throw new ArgumentException("WASM runtime path must be absolute.",
                nameof(absoluteLibraryPath));
        var file = new FileInfo(absoluteLibraryPath);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > 128 * 1024 * 1024)
            throw new ArgumentException("WASM runtime must be a bounded regular file.",
                nameof(absoluteLibraryPath));
        // The Rust host owns a process-wide Wasmtime engine and epoch thread. Keep
        // the validated library loaded for the process lifetime so that thread can
        // never execute code from an unloaded module.
        _evaluate = Libraries.GetOrAdd(file.FullName, path => new Lazy<NativeEntry>(
            () => Load(path), LazyThreadSafetyMode.ExecutionAndPublication)).Value.Evaluate;
    }

    public ValueTask<WasmRuleDecisionV1> EvaluateAsync(ReadOnlyMemory<byte> module,
        WasmRuleInputV1 input, WasmRuntimeLimits limits,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        limits.Validate();
        byte[] moduleBytes = module.ToArray();
        byte[] inputBytes = WasmRuleV1Codec.EncodeInput(input);
        if (moduleBytes.Length is < 8 || moduleBytes.Length > limits.MaximumModuleBytes
            || inputBytes.Length > limits.MaximumInputBytes)
            return ValueTask.FromResult(Indeterminate("WASM_RESOURCE_LIMIT"));
        byte[] output = new byte[limits.MaximumOutputBytes];
        GCHandle moduleHandle = default, inputHandle = default, outputHandle = default;
        try
        {
            moduleHandle = GCHandle.Alloc(moduleBytes, GCHandleType.Pinned);
            inputHandle = GCHandle.Alloc(inputBytes, GCHandleType.Pinned);
            outputHandle = GCHandle.Alloc(output, GCHandleType.Pinned);
            int status = _evaluate(moduleHandle.AddrOfPinnedObject(), (nuint)moduleBytes.Length,
                inputHandle.AddrOfPinnedObject(), (nuint)inputBytes.Length, limits.Fuel,
                checked((uint)Math.Ceiling(limits.EffectiveDeadline.TotalMilliseconds)),
                (nuint)limits.MaximumMemoryBytes, (nuint)limits.MaximumOutputBytes,
                outputHandle.AddrOfPinnedObject(), (nuint)output.Length, out nuint outputLength);
            cancellationToken.ThrowIfCancellationRequested();
            if (status != 0 || outputLength > (nuint)output.Length)
                return ValueTask.FromResult(Indeterminate(status switch
                {
                    1 => "WASM_INVALID_MODULE", 2 or 5 => "WASM_RESOURCE_LIMIT",
                    3 => "WASM_TRAP", 4 => "WASM_MALFORMED_OUTPUT",
                    _ => "WASM_INDETERMINATE"
                }));
            try
            {
                return ValueTask.FromResult(WasmRuleV1Codec.DecodeDecision(
                    output.AsSpan(0, checked((int)outputLength))));
            }
            catch (WasmRuleException)
            { return ValueTask.FromResult(Indeterminate("WASM_MALFORMED_OUTPUT")); }
        }
        finally
        {
            if (outputHandle.IsAllocated) outputHandle.Free();
            if (inputHandle.IsAllocated) inputHandle.Free();
            if (moduleHandle.IsAllocated) moduleHandle.Free();
        }
    }

    private static WasmRuleDecisionV1 Indeterminate(string reason) =>
        new(WasmRuleOutcome.Indeterminate, reason, 0,
            new Dictionary<string, string>());

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
    }

    private static NativeEntry Load(string path)
    {
        IntPtr library = NativeLibrary.Load(path);
        try
        {
            IntPtr export = NativeLibrary.GetExport(library, "certael_wasm_evaluate_v1");
            return new NativeEntry(library,
                Marshal.GetDelegateForFunctionPointer<EvaluateDelegate>(export));
        }
        catch
        {
            NativeLibrary.Free(library);
            throw;
        }
    }

    private sealed record NativeEntry(IntPtr Library, EvaluateDelegate Evaluate);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int EvaluateDelegate(IntPtr module, nuint moduleLength,
        IntPtr input, nuint inputLength, ulong fuel, uint deadlineMilliseconds,
        nuint maximumMemoryBytes, nuint maximumOutputBytes,
        IntPtr output, nuint outputCapacity, out nuint outputLength);
}
