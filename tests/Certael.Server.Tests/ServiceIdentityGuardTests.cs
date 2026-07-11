using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certael.Api.Security;

namespace Certael.Server.Tests;

public sealed class ServiceIdentityGuardTests
{
    [Fact]
    public void RequiresAuthenticationCertificateScopeAndExactBoundaryClaims()
    {
        using X509Certificate2 certificate = Certificate();
        ClaimsPrincipal allowed = Principal("tenant", "prod", "sessions:issue builds:read");
        Assert.Equal(ServiceIdentityDecision.Allowed,
            ServiceIdentityGuard.Authorize(allowed, certificate, "sessions:issue", "tenant", "prod"));
        Assert.Equal(ServiceIdentityDecision.Unauthenticated,
            ServiceIdentityGuard.Authorize(allowed, null, "sessions:issue", "tenant", "prod"));
        Assert.Equal(ServiceIdentityDecision.Forbidden,
            ServiceIdentityGuard.Authorize(Principal("other", "prod", "sessions:issue"), certificate,
                "sessions:issue", "tenant", "prod"));
        Assert.Equal(ServiceIdentityDecision.Forbidden,
            ServiceIdentityGuard.Authorize(Principal("tenant", "prod", "builds:read"), certificate,
                "sessions:issue", "tenant", "prod"));
    }

    private static ClaimsPrincipal Principal(string tenant, string environment, string scopes)
    {
        var identity = new ClaimsIdentity([
            new Claim("sub", "server"), new Claim("tenant_id", tenant),
            new Claim("environment_id", environment), new Claim("scope", scopes)
        ], "test");
        return new ClaimsPrincipal(identity);
    }

    private static X509Certificate2 Certificate()
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=certael-test", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
    }
}
