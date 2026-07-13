using System;
using System.Runtime.InteropServices;

namespace Certael.Unity
{
internal static class CertaelAgentNative
{
    private const string Library = "certael_agent_probe";

    internal enum Result : int
    {
        Ok = 0,
        InvalidArgument = 1,
        BufferTooSmall = 2,
        NotConnected = 3,
        InvalidFrame = 4,
        UnsupportedPlatform = 5,
        InternalError = 255
    }

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_agent_channel_open(out IntPtr channel);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_agent_channel_read(IntPtr channel,
        out byte messageType, byte[]? output, nuint capacity, out nuint written);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern Result certael_agent_channel_write(IntPtr channel,
        byte messageType, byte[] payload, nuint payloadLength);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void certael_agent_channel_destroy(IntPtr channel);
}
}

