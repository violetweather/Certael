using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace Certael.Api.Security;

public enum ServiceIdentityDecision { Allowed, Unauthenticated, Forbidden }

public static class ServiceIdentityGuard
{
    public static ServiceIdentityDecision Authorize(
        ClaimsPrincipal principal,
        X509Certificate2? clientCertificate,
        string requiredScope,
        string requestedTenant,
        string requestedEnvironment)
    {
        if (principal.Identity?.IsAuthenticated != true || clientCertificate is null)
            return ServiceIdentityDecision.Unauthenticated;
        if (!Scopes(principal).Contains(requiredScope, StringComparer.Ordinal))
            return ServiceIdentityDecision.Forbidden;
        if (!string.Equals(principal.FindFirstValue("tenant_id"), requestedTenant, StringComparison.Ordinal)
            || !string.Equals(principal.FindFirstValue("environment_id"), requestedEnvironment, StringComparison.Ordinal))
            return ServiceIdentityDecision.Forbidden;
        return ServiceIdentityDecision.Allowed;
    }

    private static IEnumerable<string> Scopes(ClaimsPrincipal principal) =>
        principal.FindAll("scope").SelectMany(claim =>
            claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
}
