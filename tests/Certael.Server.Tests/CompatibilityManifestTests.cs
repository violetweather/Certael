using System.Text.Json;

namespace Certael.Server.Tests;

public sealed class CompatibilityManifestTests
{
    [Fact]
    public void ReleaseCompatibilityManifestMatchesFrozenBoundaries()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(AppContext.BaseDirectory, "fixtures", "core-agent-v1.json")));
        JsonElement root = document.RootElement;
        Assert.Equal(1, root.GetProperty("schema_version").GetInt32());
        Assert.Equal("certael-core", root.GetProperty("product").GetString());
        Assert.Equal(1, root.GetProperty("core_c_abi_version").GetInt32());
        Assert.Equal(1, root.GetProperty("action_protocol_version").GetInt32());
        Assert.Equal(1, root.GetProperty("agent_protocol_version").GetInt32());
        Assert.Equal(1, root.GetProperty("agent_probe_abi_version").GetInt32());
        Assert.Equal("4.7", root.GetProperty("certified_engines").GetProperty("godot").GetString());
        Assert.Equal("6000.3.16f1",
            root.GetProperty("certified_engines").GetProperty("unity").GetString());
        Assert.Equal("5.8", root.GetProperty("certified_engines").GetProperty("unreal").GetString());
        Assert.Equal(4, root.GetProperty("certified_player_targets").GetArrayLength());
    }
}
