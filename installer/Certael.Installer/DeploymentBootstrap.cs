using System.Security.Cryptography;
using System.Text;

namespace Certael.Installer;

public sealed record DeploymentBootstrapRequest(
    string RootPath, string ReleaseTag, string TenantId);

public sealed record DeploymentBootstrapResult(
    InstallationPlan Plan, string EnvironmentPath, string PublicKeyPath);

public static class CertaelDeploymentBootstrap
{
    public static DeploymentBootstrapResult CreatePlan(DeploymentBootstrapRequest request,
        DateTimeOffset now)
    {
        string root = Path.GetFullPath(request.RootPath);
        if (Path.GetPathRoot(root) == root)
            throw new ConfigurationException("Deployment root cannot be a filesystem root.");
        if (request.ReleaseTag.Length is < 2 or > 80 || request.ReleaseTag[0] != 'v'
            || request.ReleaseTag[1..].Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '-')))
            throw new ConfigurationException("Certael release tag is invalid.");
        ValidateToken(request.TenantId, "Tenant ID");

        string postgresPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(32))
            .ToLowerInvariant();
        string coordinatorPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(32))
            .ToLowerInvariant();
        using ECDsa coordinatorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string coordinatorPrivateKey = Convert.ToBase64String(
            coordinatorKey.ExportPkcs8PrivateKey());
        string publicKey = coordinatorKey.ExportSubjectPublicKeyInfoPem();
        string keyId = "coordinator-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8))
            .ToLowerInvariant();
        string environment = $"""
            CERTAEL_VERSION={request.ReleaseTag}
            CERTAEL_TENANT_ID={request.TenantId}
            CERTAEL_POSTGRES_CONNECTION_STRING=Host=postgres;Port=5432;Database=certael;Username=certael;Password={postgresPassword}
            CERTAEL_COORDINATOR_POSTGRES_CONNECTION_STRING=Host=control-postgres;Port=5432;Database=certael_control;Username=certael_coordinator;Password={coordinatorPassword}
            CERTAEL_COORDINATOR_SIGNING_KEY_ID={keyId}
            CERTAEL_COORDINATOR_SIGNING_KEY_PKCS8={coordinatorPrivateKey}
            """;
        string instructions = $"""
            Certael deployment bootstrap

            Generated at {now:O} for {request.ReleaseTag}.

            Start the core platform from the installation root:

              docker compose --env-file .certael/deployment.env -f deployment/compose/docker-compose.release.yml up -d

            Verify the API:

              docker compose --env-file .certael/deployment.env -f deployment/compose/docker-compose.release.yml ps
              curl --fail http://127.0.0.1:8080/healthz

            The environment file contains database connection strings and the coordinator private
            key. PostgreSQL passwords are separate Docker secret files under `.certael/secrets`.
            Keep all of them out of source control, backups without encryption, tickets, logs, and
            screenshots. Rotate the generated development credentials before a production
            deployment and move secrets to the platform's secret manager.

            The console profile remains disabled until OIDC and mTLS are configured. Run
            `certaelctl console init-auth0`, register its certificate, inject both Auth0 client
            secrets through the environment or a secret store, then start with `--profile console`.

            Multi-region coordination remains disabled until its control database, routing,
            fencing, and failover procedures are reviewed. Start it with `--profile multi-region`.
            """;
        var plan = new InstallationPlan(Guid.NewGuid(), root,
        [
            new CreateDirectoryOperation("deployment-state", "Create private deployment state",
                ".certael"),
            new WriteFileOperation("deployment-environment", "Write private deployment environment",
                ".certael/deployment.env", Encoding.UTF8.GetBytes(environment), Private: true),
            new WriteFileOperation("postgres-password", "Write private PostgreSQL secret",
                ".certael/secrets/postgres-password", Encoding.UTF8.GetBytes(postgresPassword),
                Private: true),
            new WriteFileOperation("coordinator-postgres-password",
                "Write private coordinator PostgreSQL secret",
                ".certael/secrets/coordinator-postgres-password",
                Encoding.UTF8.GetBytes(coordinatorPassword), Private: true),
            new WriteFileOperation("coordinator-public-key", "Write coordinator verification key",
                ".certael/coordinator-public-key.pem", Encoding.UTF8.GetBytes(publicKey)),
            new WriteFileOperation("deployment-instructions", "Write deployment startup instructions",
                ".certael/DEPLOYMENT.md", Encoding.UTF8.GetBytes(instructions))
        ], now);
        return new DeploymentBootstrapResult(plan,
            Path.Combine(root, ".certael", "deployment.env"),
            Path.Combine(root, ".certael", "coordinator-public-key.pem"));
    }

    private static void ValidateToken(string value, string label)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-')))
            throw new ConfigurationException($"{label} is invalid.");
    }
}
