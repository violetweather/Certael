using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Certael.Unity
{
public sealed class CertaelSessionBinding
{
    public string SessionId = "", GameId = "", EnvironmentId = "", MatchId = "", BuildId = "";
    public long ExpiresAtUnix;
    public byte[] BindingDigest = Array.Empty<byte>();
    public ulong InitialSequence;
}

/// <summary>Protects request transport; authoritative game servers still decide outcomes.</summary>
public sealed class CertaelClient : IDisposable
{
    private IntPtr _client;

    public CertaelClient() => ThrowIfFailed(CertaelNative.certael_client_create(out _client));

    public byte[] CreateSessionPublicKey()
    {
        byte[] key = new byte[32];
        ThrowIfFailed(CertaelNative.certael_client_public_key(_client, key, (nuint)key.Length));
        return key;
    }

    public byte[] SignRedemption(Guid ticketId, byte[] challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        byte[] signature = new byte[64];
        ThrowIfFailed(CertaelNative.certael_client_sign_redemption(_client,
            UuidNetworkBytes(ticketId), 16, challenge, (nuint)challenge.Length, signature, 64));
        return signature;
    }

    public void ActivateSession(CertaelSessionBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (binding.BindingDigest.Length != 32) throw new ArgumentException("Binding digest must be 32 bytes.");
        using var memory = new NativeMemory();
        var native = new CertaelNative.SessionBinding
        {
            StructSize = (nuint)Marshal.SizeOf<CertaelNative.SessionBinding>(), AbiVersion = CertaelNative.AbiVersion,
            SessionId = memory.String(binding.SessionId), GameId = memory.String(binding.GameId),
            EnvironmentId = memory.String(binding.EnvironmentId), MatchId = memory.String(binding.MatchId),
            BuildId = memory.String(binding.BuildId), NowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ExpiresAtUnix = binding.ExpiresAtUnix,
            BindingDigest = memory.Bytes(binding.BindingDigest), InitialSequence = binding.InitialSequence
        };
        ThrowIfFailed(CertaelNative.certael_client_activate_session(_client, ref native));
    }

    public byte[] AuthorizeAction(string actionType, string requestSchema,
        uint schemaVersion, byte[] requestPayload)
    {
        ArgumentNullException.ThrowIfNull(requestPayload);
        using var memory = new NativeMemory();
        var request = new CertaelNative.ActionRequest
        {
            StructSize = (nuint)Marshal.SizeOf<CertaelNative.ActionRequest>(), AbiVersion = CertaelNative.AbiVersion,
            ActionType = memory.String(actionType), RequestSchema = memory.String(requestSchema),
            SchemaVersion = schemaVersion, NowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ClientMonotonicMicros = Environment.TickCount64 * 1000, Payload = memory.Bytes(requestPayload)
        };
        byte[] output = new byte[requestPayload.Length + 2048];
        ThrowIfFailed(CertaelNative.certael_client_authorize_action_v1(
            _client, ref request, output, (nuint)output.Length, out nuint written));
        Array.Resize(ref output, checked((int)written)); return output;
    }

    private static byte[] UuidNetworkBytes(Guid value)
    {
        string text = value.ToString("N"); var bytes = new byte[16];
        for (int index = 0; index < bytes.Length; index++) bytes[index] = Convert.ToByte(text.Substring(index * 2, 2), 16);
        return bytes;
    }

    private static void ThrowIfFailed(CertaelNative.Result result)
    { if (result != CertaelNative.Result.Ok) throw new InvalidOperationException($"Certael operation failed: {result}"); }

    public void Dispose()
    {
        if (_client != IntPtr.Zero) { CertaelNative.certael_client_destroy(_client); _client = IntPtr.Zero; }
        GC.SuppressFinalize(this);
    }

    private sealed class NativeMemory : IDisposable
    {
        private readonly List<IntPtr> _allocations = new();
        internal CertaelNative.StringView String(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value ?? ""); IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
            if (bytes.Length > 0) Marshal.Copy(bytes, 0, pointer, bytes.Length); _allocations.Add(pointer);
            return new() { Data = pointer, Length = (nuint)bytes.Length };
        }
        internal CertaelNative.BytesView Bytes(byte[] value)
        {
            IntPtr pointer = Marshal.AllocHGlobal(value.Length);
            if (value.Length > 0) Marshal.Copy(value, 0, pointer, value.Length); _allocations.Add(pointer);
            return new() { Data = pointer, Length = (nuint)value.Length };
        }
        public void Dispose() { foreach (IntPtr pointer in _allocations) Marshal.FreeHGlobal(pointer); }
    }
}
}
