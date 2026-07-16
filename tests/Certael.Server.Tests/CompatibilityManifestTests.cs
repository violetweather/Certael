using System.Text.Json;
using System.Security.Cryptography;
using Certael.Server.Compatibility;
using NSec.Cryptography;

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

    [Fact]
    public void SignedManifestProducesEveryOperationalDecision()
    {
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(2_000_000_000);
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var claims = new CompatibilityManifestClaims(1, 42, now.AddMinutes(-1), now.AddDays(7),
            [
                new(CertaelProduct.Agent, "0.2.0", "0.3.0", 1, 1),
                new(CertaelProduct.Core, "0.2.0", "0.3.0", 1, 2)
            ],
            [new(CertaelProduct.Agent, "0.2.1", now.AddMinutes(-1), "security-withdrawal")]);
        SignedCompatibilityManifest signed = new CompatibilityManifestSigner(key, "release-1")
            .Sign(claims, now);
        var keys = new CompatibilityVerificationKeyRing([
            new("release-1", key.PublicKey.Export(KeyBlobFormat.RawPublicKey),
                now.AddDays(-1), now.AddDays(30))
        ]);
        CompatibilityManifestClaims verified = CompatibilityManifestSigner.Verify(
            CompatibilityManifestCodec.DecodeSigned(
                CompatibilityManifestCodec.EncodeSigned(signed)), keys, now);

        Assert.Equal(CompatibilityState.UpdateRequired, Decide("0.1.9", 1).State);
        Assert.Equal(CompatibilityState.Deprecated, Decide("0.2.0", 1).State);
        Assert.Equal(CompatibilityState.Revoked, Decide("0.2.1", 1).State);
        Assert.Equal(CompatibilityState.Supported, Decide("0.3.0", 1).State);
        Assert.Equal(CompatibilityState.Unknown, Decide("0.3.0", 2).State);
        Assert.Equal(CompatibilityState.Unknown,
            CompatibilityEvaluator.Evaluate(verified, CertaelProduct.UnityAdapter,
                "0.3.0", 1, now).State);

        CompatibilityDecision Decide(string version, uint protocol) =>
            CompatibilityEvaluator.Evaluate(verified, CertaelProduct.Agent,
                version, protocol, now);
    }

    [Fact]
    public void ExpiredOrTamperedManifestFailsClosed()
    {
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(2_000_000_000);
        var expired = new CompatibilityManifestClaims(1, 1, now.AddDays(-2), now.AddDays(-1),
            [new(CertaelProduct.Agent, "0.1.0", "0.1.0", 1, 1)], []);
        Assert.Equal(CompatibilityState.Indeterminate,
            CompatibilityEvaluator.Evaluate(expired, CertaelProduct.Agent, "0.1.0", 1, now).State);

        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var current = expired with { IssuedAt = now.AddMinutes(-1), ExpiresAt = now.AddDays(1) };
        SignedCompatibilityManifest signed = new CompatibilityManifestSigner(key, "release-1")
            .Sign(current, now);
        signed.Claims[^1] ^= 1;
        var keys = new CompatibilityVerificationKeyRing([
            new("release-1", key.PublicKey.Export(KeyBlobFormat.RawPublicKey),
                now.AddDays(-1), now.AddDays(2))
        ]);
        Assert.Throws<CryptographicException>(() =>
            CompatibilityManifestSigner.Verify(signed, keys, now));
    }
}
