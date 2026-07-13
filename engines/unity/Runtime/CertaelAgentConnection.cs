using System;

namespace Certael.Unity
{
public enum CertaelAgentState { Disconnected, Ready, Degraded, Lost, UpdateRequired }

public sealed class CertaelAgentHealth
{
    public CertaelAgentState State { get; }
    public string PublicReason { get; }
    public CertaelAgentHealth(CertaelAgentState state, string publicReason)
    { State = state; PublicReason = publicReason; }
}

/// <summary>Private inherited connection to the optional Certael Agent.</summary>
public sealed class CertaelAgentConnection : IDisposable
{
    private const byte AgentHello = 1, LaunchGrant = 2;
    private IntPtr _channel;
    private byte[] _agentPublicKey = Array.Empty<byte>();
    private CertaelAgentHealth _health = new(CertaelAgentState.Disconnected, "AGENT_NOT_CONNECTED");

    public void ConnectToInheritedAgent()
    {
        if (_channel != IntPtr.Zero) throw new InvalidOperationException("Agent is already connected.");
        Throw(CertaelAgentNative.certael_agent_channel_open(out _channel));
        try
        {
            (byte type, byte[] hello) = ReadMessage();
            if (type != AgentHello) throw new InvalidOperationException("Agent did not send a canonical hello.");
            _agentPublicKey = AgentHelloCodec.ReadPublicKey(hello);
            _health = new(CertaelAgentState.Ready, "AGENT_READY");
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public byte[] GetAgentSessionPublicKey()
    {
        if (_agentPublicKey.Length != 32) throw new InvalidOperationException("Agent is not connected.");
        return _agentPublicKey.ToArray();
    }

    public void BindAgentLaunchBundle(byte[] signedPolicy, byte[] signedGrant)
    {
        ArgumentNullException.ThrowIfNull(signedPolicy);
        ArgumentNullException.ThrowIfNull(signedGrant);
        if (_channel == IntPtr.Zero)
            throw new InvalidOperationException("Agent connection or launch grant is invalid.");
        byte[] grantBytes = AgentLaunchBundleCodec.Encode(signedPolicy, signedGrant);
        Throw(CertaelAgentNative.certael_agent_channel_write(_channel, LaunchGrant,
            grantBytes, (nuint)grantBytes.Length));
        Array.Clear(grantBytes, 0, grantBytes.Length);
    }

    public CertaelAgentHealth GetAgentHealth() => _health;

    public void DisposeAgentConnection() => Dispose();

    private (byte Type, byte[] Payload) ReadMessage()
    {
        CertaelAgentNative.Result first = CertaelAgentNative.certael_agent_channel_read(
            _channel, out byte type, null, 0, out nuint required);
        if (first != CertaelAgentNative.Result.BufferTooSmall || required is 0 or > 64 * 1024)
            Throw(first);
        byte[] payload = new byte[checked((int)required)];
        Throw(CertaelAgentNative.certael_agent_channel_read(
            _channel, out byte confirmedType, payload, (nuint)payload.Length, out nuint written));
        if (confirmedType != type || written != (nuint)payload.Length)
            throw new InvalidOperationException("Agent frame changed during buffered read.");
        return (type, payload);
    }

    private static void Throw(CertaelAgentNative.Result result)
    {
        if (result != CertaelAgentNative.Result.Ok)
            throw new InvalidOperationException($"Certael Agent operation failed: {result}");
    }

    public void Dispose()
    {
        if (_channel != IntPtr.Zero)
        {
            CertaelAgentNative.certael_agent_channel_destroy(_channel);
            _channel = IntPtr.Zero;
        }
        Array.Clear(_agentPublicKey, 0, _agentPublicKey.Length);
        _agentPublicKey = Array.Empty<byte>();
        _health = new(CertaelAgentState.Disconnected, "AGENT_NOT_CONNECTED");
        GC.SuppressFinalize(this);
    }
}

internal static class AgentLaunchBundleCodec
{
    internal static byte[] Encode(ReadOnlySpan<byte> signedPolicy, ReadOnlySpan<byte> signedGrant)
    {
        if (signedPolicy.Length is < 1 or > 32 * 1024 || signedGrant.Length is < 1 or > 32 * 1024)
            throw new InvalidOperationException("Signed Agent launch material is invalid.");
        using var stream = new System.IO.MemoryStream();
        Bytes(stream, 1, signedPolicy); Bytes(stream, 2, signedGrant);
        if (stream.Length > 64 * 1024)
            throw new InvalidOperationException("Agent launch bundle exceeds 64 KiB.");
        return stream.ToArray();
    }

    private static void Bytes(System.IO.Stream stream, uint field, ReadOnlySpan<byte> value)
    { Varint(stream, (ulong)field << 3 | 2); Varint(stream, (ulong)value.Length); stream.Write(value); }

    private static void Varint(System.IO.Stream stream, ulong value)
    {
        while (value >= 0x80) { stream.WriteByte((byte)(value | 0x80)); value >>= 7; }
        stream.WriteByte((byte)value);
    }
}

internal static class AgentHelloCodec
{
    internal static byte[] ReadPublicKey(ReadOnlySpan<byte> input)
    {
        int offset = 0;
        RequireVarintField(input, ref offset, 1);
        _ = ReadVarint(input, ref offset);
        SkipBytesField(input, ref offset, 2, 64);
        byte[] key = ReadBytesField(input, ref offset, 3, 32);
        SkipBytesField(input, ref offset, 4, 128);
        _ = ReadBytesField(input, ref offset, 5, 32);
        if (offset != input.Length || key.Length != 32)
            throw new InvalidOperationException("Agent hello is not canonical.");
        return key;
    }

    private static void SkipBytesField(ReadOnlySpan<byte> input, ref int offset, uint field, int maximum) =>
        _ = ReadBytesField(input, ref offset, field, maximum);

    private static byte[] ReadBytesField(ReadOnlySpan<byte> input, ref int offset, uint field, int maximum)
    {
        ulong key = ReadVarint(input, ref offset);
        if (key != ((ulong)field << 3 | 2)) throw new InvalidOperationException("Agent hello field is invalid.");
        ulong rawLength = ReadVarint(input, ref offset);
        if (rawLength > (ulong)maximum || rawLength > (ulong)(input.Length - offset))
            throw new InvalidOperationException("Agent hello length is invalid.");
        int length = (int)rawLength;
        byte[] value = input.Slice(offset, length).ToArray();
        offset += length;
        return value;
    }

    private static void RequireVarintField(ReadOnlySpan<byte> input, ref int offset, uint field)
    {
        if (ReadVarint(input, ref offset) != (ulong)field << 3)
            throw new InvalidOperationException("Agent hello field is invalid.");
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> input, ref int offset)
    {
        int start = offset;
        ulong value = 0;
        for (int shift = 0; shift <= 63; shift += 7)
        {
            if (offset >= input.Length) throw new InvalidOperationException("Agent hello is truncated.");
            byte current = input[offset++];
            if (shift == 63 && current > 1) throw new InvalidOperationException("Agent hello varint overflows.");
            value |= (ulong)(current & 0x7f) << shift;
            if ((current & 0x80) == 0)
            {
                int expected = 1;
                for (ulong copy = value; copy >= 0x80; copy >>= 7) expected++;
                if (offset - start != expected)
                    throw new InvalidOperationException("Agent hello varint is not canonical.");
                return value;
            }
        }
        throw new InvalidOperationException("Agent hello varint overflows.");
    }
}
}
