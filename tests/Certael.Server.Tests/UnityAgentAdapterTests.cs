using Certael.Unity;

namespace Certael.Server.Tests;

public sealed class UnityAgentAdapterTests
{
    [Fact]
    public void HelloCodecExtractsBoundPublicKeyAndRejectsTrailingData()
    {
        byte[] publicKey = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        using var stream = new MemoryStream();
        Varint(stream, 8); Varint(stream, 1);
        Bytes(stream, 2, "0.1.0"u8);
        Bytes(stream, 3, publicKey);
        Bytes(stream, 4, "build"u8);
        Bytes(stream, 5, new byte[32]);
        byte[] hello = stream.ToArray();
        CertaelAgentHello decoded = AgentHelloCodec.Decode(hello);
        Assert.Equal((uint)1, decoded.ProtocolVersion);
        Assert.Equal("0.1.0", decoded.AgentVersion);
        Assert.Equal("build", decoded.BuildId);
        Assert.Equal(publicKey, decoded.AgentPublicKey);
        Assert.Equal(new byte[32], decoded.ExecutableSha256);
        Assert.Throws<InvalidOperationException>(() =>
            AgentHelloCodec.ReadPublicKey(hello.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void LaunchBundleUsesCanonicalTypedEnvelope()
    {
        Assert.Equal("0a03010203120204051a0106", Convert.ToHexString(
            AgentLaunchBundleCodec.Encode([1, 2, 3], [4, 5], [6])).ToLowerInvariant());
        Assert.Throws<InvalidOperationException>(() =>
            AgentLaunchBundleCodec.Encode([], [1], [2]));
    }

    [Fact]
    public void HealthCodecExtractsCanonicalState()
    {
        Assert.Equal("ready", AgentHealthCodec.DecodeState([
            0x0a, 0x07, (byte)'s', (byte)'e', (byte)'s', (byte)'s', (byte)'i', (byte)'o', (byte)'n',
            0x12, 0x05, (byte)'r', (byte)'e', (byte)'a', (byte)'d', (byte)'y']));
        Assert.Throws<InvalidOperationException>(() => AgentHealthCodec.DecodeState([
            0x0a, 0x07, (byte)'s', (byte)'e', (byte)'s', (byte)'s', (byte)'i', (byte)'o', (byte)'n',
            0x12, 0x05, (byte)'r', (byte)'e', (byte)'a', (byte)'d', (byte)'y', 0x18, 0x00]));
    }

    private static void Bytes(Stream stream, uint field, ReadOnlySpan<byte> value)
    { Varint(stream, (ulong)field << 3 | 2); Varint(stream, (ulong)value.Length); stream.Write(value); }

    private static void Varint(Stream stream, ulong value)
    {
        while (value >= 0x80) { stream.WriteByte((byte)(value | 0x80)); value >>= 7; }
        stream.WriteByte((byte)value);
    }
}
