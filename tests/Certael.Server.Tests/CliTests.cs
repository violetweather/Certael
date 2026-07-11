extern alias certaelcli;

namespace Certael.Server.Tests;

public sealed class CliTests
{
    [Fact]
    public async Task ValidatesShippedRulesAndProducesDeterministicManifest()
    {
        CancellationToken _ = TestContext.Current.CancellationToken;
        string fixture = Path.Combine(AppContext.BaseDirectory, "fixtures", "inventory.yaml");
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        int valid = await certaelcli::CertaelCli.RunAsync(["rules", "validate", fixture], stdout, stderr);
        Assert.Equal(0, valid);
        Assert.Contains("valid example.inventory@1.0.0", stdout.ToString());

        string root = Path.Combine(Path.GetTempPath(), "certael-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "b.txt"), "b", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root, "a.txt"), "a", TestContext.Current.CancellationToken);
            string first = Path.Combine(root, "first.json");
            string second = Path.Combine(root, "second.json");
            Assert.Equal(0, await certaelcli::CertaelCli.RunAsync(["manifest", "generate", root, first], stdout, stderr));
            File.Delete(first);
            Assert.Equal(0, await certaelcli::CertaelCli.RunAsync(["manifest", "generate", root, second], stdout, stderr));
            string content = await File.ReadAllTextAsync(second, TestContext.Current.CancellationToken);
            Assert.True(content.IndexOf("a.txt", StringComparison.Ordinal) < content.IndexOf("b.txt", StringComparison.Ordinal));
        }
        finally { Directory.Delete(root, true); }
    }
}
