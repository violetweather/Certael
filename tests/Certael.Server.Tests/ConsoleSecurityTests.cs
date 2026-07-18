extern alias consolebff;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DelegatedCoreTokenCache = consolebff::DelegatedCoreTokenCache;
using DelegatedToken = consolebff::DelegatedToken;
using DelegatedTokenBinding = consolebff::DelegatedTokenBinding;

namespace Certael.Server.Tests;

public sealed class ConsoleSecurityTests
{
    [Fact]
    public async Task DelegatedTokenCacheCoalescesAndRefreshesNearExpiry()
    {
        var cache = new DelegatedCoreTokenCache();
        DateTimeOffset now = new(2026, 7, 17, 16, 0, 0, TimeSpan.Zero);
        int exchanges = 0;
        async Task<DelegatedToken> Exchange()
        {
            Interlocked.Increment(ref exchanges);
            await Task.Yield();
            return new DelegatedToken("bound-token", now.AddMinutes(10));
        }

        Task<string>[] requests = Enumerable.Range(0, 20).Select(_ => cache.GetAsync(
            "operator", now, Exchange, TestContext.Current.CancellationToken)).ToArray();
        Assert.All(await Task.WhenAll(requests), value => Assert.Equal("bound-token", value));
        Assert.Equal(1, exchanges);

        string refreshed = await cache.GetAsync("operator", now.AddMinutes(9).AddSeconds(30),
            () => Task.FromResult(new DelegatedToken("refreshed", now.AddMinutes(20))),
            TestContext.Current.CancellationToken);
        Assert.Equal("refreshed", refreshed);
    }

    [Fact]
    public void DelegatedTokenMustCarryTheExactCertificateThumbprint()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=certael-console-test", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        string thumbprint = Base64Url(SHA256.HashData(certificate.RawData));
        string valid = Jwt(new { cnf = new Dictionary<string, string> { ["x5t#S256"] = thumbprint } });
        string wrong = Jwt(new { cnf = new Dictionary<string, string> { ["x5t#S256"] = Base64Url(new byte[32]) } });

        Assert.True(DelegatedTokenBinding.IsBoundToCertificate(valid, certificate));
        Assert.False(DelegatedTokenBinding.IsBoundToCertificate(wrong, certificate));
        Assert.False(DelegatedTokenBinding.IsBoundToCertificate("opaque-token", certificate));
    }

    private static string Jwt(object payload) => $"e30.{Base64Url(
        JsonSerializer.SerializeToUtf8Bytes(payload))}.signature";

    private static string Base64Url(ReadOnlySpan<byte> value) => Convert.ToBase64String(value)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
