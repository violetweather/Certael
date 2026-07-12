using System;
using System.Runtime.InteropServices;

namespace Certael.Unity
{
internal static class CertaelNative
{
    internal const uint AbiVersion = 1;
    private const string Library = "certael_c_api";

    [StructLayout(LayoutKind.Sequential)] internal struct BytesView { internal IntPtr Data; internal nuint Length; }
    [StructLayout(LayoutKind.Sequential)] internal struct StringView { internal IntPtr Data; internal nuint Length; }
    [StructLayout(LayoutKind.Sequential)] internal struct SessionBinding
    {
        internal nuint StructSize; internal uint AbiVersion;
        internal StringView SessionId, GameId, EnvironmentId, MatchId, BuildId;
        internal long NowUnix, ExpiresAtUnix; internal BytesView BindingDigest; internal ulong InitialSequence;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct ActionRequest
    {
        internal nuint StructSize; internal uint AbiVersion;
        internal StringView ActionType, RequestSchema; internal uint SchemaVersion;
        internal long NowUnix, ClientMonotonicMicros; internal BytesView Payload;
    }

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_client_create(out IntPtr client);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_client_public_key(IntPtr client, byte[] output, nuint length);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_client_sign_redemption(IntPtr client, byte[] ticketId,
        nuint ticketIdLength, byte[] challenge, nuint challengeLength, byte[] signature, nuint signatureLength);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_client_activate_session(IntPtr client, ref SessionBinding binding);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_client_authorize_action_v1(IntPtr client, ref ActionRequest request,
        byte[] output, nuint outputCapacity, out nuint outputLength);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void certael_client_destroy(IntPtr client);

    internal enum Result
    {
        Ok, InvalidArgument, SessionInactive, SessionExpired, PayloadTooLarge,
        BufferTooSmall, InvalidEnvelope, InvalidProof, InternalError = 255
    }
}
}
