using System;
using System.Runtime.InteropServices;

namespace Certael.Unity
{
internal static class CertaelNative
{
    private const string Library = "certael_c_api";

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_runtime_create(out IntPtr runtime);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_runtime_public_key(IntPtr runtime, byte[] output, nuint length);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_runtime_sign_redemption(
        IntPtr runtime, byte[] ticketId, nuint ticketIdLength,
        byte[] challenge, nuint challengeLength, byte[] signature, nuint signatureLength);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_runtime_activate(
        IntPtr runtime, byte[] bindingJson, nuint bindingLength, long nowUnix, ulong initialSequence);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_runtime_authorize_action(
        IntPtr runtime, long nowUnix, [MarshalAs(UnmanagedType.LPUTF8Str)] string actionType,
        uint schemaVersion, long monotonicMicros, byte[] payload, nuint payloadLength,
        byte[] output, nuint outputCapacity, out nuint outputLength);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void certael_runtime_destroy(IntPtr runtime);

    internal enum Result { Ok, InvalidArgument, SessionInactive, SessionExpired, PayloadTooLarge, InternalError = 255 }
}
}
