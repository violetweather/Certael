using System;
using System.Text;

namespace Certael.Unity
{
/// <summary>Protects request transport; it does not authorize game state.</summary>
public sealed class CertaelClient : IDisposable
{
    private IntPtr _runtime;

    public CertaelClient()
    {
        ThrowIfFailed(CertaelNative.certael_runtime_create(out _runtime));
    }

    public byte[] CreateSessionPublicKey()
    {
        byte[] key = new byte[32];
        ThrowIfFailed(CertaelNative.certael_runtime_public_key(_runtime, key, (nuint)key.Length));
        return key;
    }

    public byte[] SignRedemption(Guid ticketId, byte[] challenge)
    {
        byte[] id = UuidNetworkBytes(ticketId);
        byte[] signature = new byte[64];
        ThrowIfFailed(CertaelNative.certael_runtime_sign_redemption(
            _runtime, id, 16, challenge, (nuint)challenge.Length, signature, 64));
        return signature;
    }

    private static byte[] UuidNetworkBytes(Guid value)
    {
        string text = value.ToString("N");
        var bytes = new byte[16];
        for (int index = 0; index < bytes.Length; index++)
            bytes[index] = Convert.ToByte(text.Substring(index * 2, 2), 16);
        return bytes;
    }

    public void ActivateSession(string verifiedBindingJson, ulong initialSequence)
    {
        byte[] binding = Encoding.UTF8.GetBytes(verifiedBindingJson);
        ThrowIfFailed(CertaelNative.certael_runtime_activate(
            _runtime, binding, (nuint)binding.Length, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), initialSequence));
    }

    /// <summary>Wraps untrusted intent for transport to an authoritative game server.</summary>
    public byte[] AuthorizeAction(string actionType, uint schemaVersion, byte[] requestPayload)
    {
        byte[] output = new byte[requestPayload.Length + 2048];
        CertaelNative.Result result = CertaelNative.certael_runtime_authorize_action(
            _runtime, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), actionType, schemaVersion,
            Environment.TickCount64 * 1000, requestPayload, (nuint)requestPayload.Length,
            output, (nuint)output.Length, out nuint written);
        ThrowIfFailed(result);
        Array.Resize(ref output, checked((int)written));
        return output;
    }

    private static void ThrowIfFailed(CertaelNative.Result result)
    {
        if (result != CertaelNative.Result.Ok)
            throw new InvalidOperationException($"Certael operation failed: {result}");
    }

    public void Dispose()
    {
        if (_runtime != IntPtr.Zero) { CertaelNative.certael_runtime_destroy(_runtime); _runtime = IntPtr.Zero; }
        GC.SuppressFinalize(this);
    }
}
}
