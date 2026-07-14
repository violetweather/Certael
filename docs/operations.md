# Production operations

The Compose file is a development convenience, not a deployment blueprint.
Production requires a real identity provider, TLS termination with client
certificates, durable data services, private networking, secret management,
observability, and tested recovery.

## Workload identity

Ticket issuance, session renewal/revocation, audit reads, and administrative
operations require both:

- a valid OAuth/JWT workload identity with audience `certael-api`; and
- a presented client certificate.

Tokens must carry the operation's exact scope and matching `tenant_id` and
`environment_id` claims. Supported scopes currently include `sessions:issue`,
`sessions:renew`, `sessions:revoke`, `sessions:revoke:bulk`, and `audit:read`.
The OAuth token must be certificate-bound through `cnf.x5t#S256`. Issue one
short-lived identity per game/environment/workload. Do not reuse credentials
between development and production or place them in clients.

Agent workloads additionally use `agents:launch`, `agents:challenge`,
`agents:report`, `agents:health`, and `agents:revoke`. Agent-policy operators use
the separate `agent-policies:create`, `agent-policies:approve`,
`agent-policies:promote`, `agent-policies:retire`, and read-only
`agent-policies:read` scopes. Do not grant an
authoritative game server the policy-administration scopes.
Build-release operators use `agent-builds:register` and `agent-builds:revoke`;
these scopes must remain separate from ordinary game-server identities.

Rule-pack and protection-profile administration additionally uses:

- `configurations:write`
- `configurations:approve`
- `configurations:promote`
- `configurations:rollback`
- `configurations:retire`

Configure verification-only keys; never mount the configuration signing private
key into the API:

```json
{
  "ConfigurationSigning": {
    "TrustedKeys": [
      {
        "KeyId": "rules-2026-q3",
        "PublicKeyPemPath": "/run/secrets/certael-rules-public.pem"
      }
    ]
  }
}
```

Every configuration mutation also requires a reason, tenant/environment-bound
OIDC claims, and a validated client certificate. Enforced promotion requires two
distinct approver subjects over the exact stored digest.

Set these configuration values outside source control:

```text
Authentication__Authority=https://identity.example.com/
Authentication__Audience=certael-api
Signing__PrivateKeyPemPath=/run/secrets/certael-ticket-signing.pem
Signing__ActiveKeyId=production-ticket-2026-07
Signing__Issuer=https://certael.example.com
Signing__Audience=certael-session
ConnectionStrings__Postgres=<secret reference>
ConnectionStrings__Redis=<secret reference>
OTEL_EXPORTER_OTLP_ENDPOINT=https://telemetry-collector.example.com
Agent__SigningPrivateKeyPath=/run/secrets/certael-agent-ed25519.key
Agent__SigningKeyId=agent-policy-2026-07
Privacy__RawAgentReportRetentionMinutes=1440
Privacy__DerivedEvidenceRetentionDays=30

Player privacy requests use `POST /v1/admin/privacy/delete-player` with the
`privacy:delete` scope. The operation is restricted to the caller's tenant and
environment, atomically removes raw Agent reports before their parent sessions,
removes derived evidence, and writes an audit event containing only a one-way
resource digest rather than the player subject.
```

`Agent:Policies` must contain at least one immutable tenant/game/environment
policy outside Development. The first startup signs and stores it in PostgreSQL;
subsequent startups compare configuration to the durable record and fail if it
was changed in place. Promote new behavior with a new policy ID through the
authenticated approval endpoints instead of editing an existing policy.
Production also requires at least one `Agent:ApprovedBuilds` entry. Unknown and
revoked build IDs fail closed before Core signs an Agent launch grant.

For an overlapping rotation, configure `Signing:Keys` entries with `KeyId`,
`PemPath`, `NotBefore`, `NotAfter`, `Usage=ticket-signing`, optional tenant and
environment scope, and revocation status; then move `Signing:ActiveKeyId` only
after all verifiers have the new key. A retired verification entry may contain
public-only PEM material. Rehearse activation, overlap, rollback, and emergency
revocation before production use.

Example overlapping configuration:

```json
{
  "Signing": {
    "ActiveKeyId": "ticket-2026-08",
    "Issuer": "https://certael.example.com",
    "Audience": "certael-session",
    "Keys": [
      {
        "KeyId": "ticket-2026-07",
        "PemPath": "/run/secrets/ticket-2026-07-public.pem",
        "NotBefore": "2026-07-01T00:00:00Z",
        "NotAfter": "2026-08-15T00:00:00Z",
        "Revoked": false,
        "Usage": "ticket-signing",
        "TenantId": "studio",
        "EnvironmentId": "production"
      },
      {
        "KeyId": "ticket-2026-08",
        "PemPath": "/run/secrets/ticket-2026-08-private.pem",
        "NotBefore": "2026-08-01T00:00:00Z",
        "NotAfter": "2026-09-15T00:00:00Z",
        "Revoked": false,
        "Usage": "ticket-signing",
        "TenantId": "studio",
        "EnvironmentId": "production"
      }
    ]
  }
}
```

Only the active entry needs private signing capability. For a managed KMS/HSM,
replace PEM signing with `IBootstrapSigningProvider` while keeping the same key
ID, validity, usage, tenant, environment, overlap, and revocation controls.

The production executable contains no insecure service-identity bypass. Local
integration tests must use a test identity provider and a client certificate
whose SHA-256 thumbprint is bound to the OAuth token through the standard `cnf`
`x5t#S256` confirmation claim. The application refuses missing persistence and
signing configuration outside the Development environment.

## Network controls

- Terminate TLS 1.2+ or newer at Kestrel for the reference deployment. The
  current guard reads `HttpContext.Connection.ClientCertificate`. If an operator
  terminates mTLS at a proxy, it must add and audit explicit ASP.NET certificate
  forwarding with a fixed trusted-proxy allowlist; never trust a public client-
  certificate header directly.
- Keep PostgreSQL, Redis, NATS, and ClickHouse on private networks.
- Restrict issuance/renewal to game-server workload networks.
- Apply per-identity and per-tenant limits in addition to the redemption
  endpoint's IP fixed-window limit.
- Do not log tickets, possession signatures, access tokens, connection strings,
  or raw sensitive evidence.

## Keys and certificates

- Store ticket and rule-pack signing keys in a KMS/HSM or managed secret store.
- Implement `IBootstrapSigningProvider` for the selected KMS/HSM so stable
  production deployments do not import private key bytes into the API process;
  the PEM-file provider is intended for development and controlled migration.
- Separate ticket, rule, artifact, and environment signing keys.
- Publish key IDs and overlapping verification keys before rotation.
- Rotate client certificates and OAuth credentials automatically.
- Revoke compromised keys, stop issuance, expire affected sessions, and preserve
  audit evidence through a documented incident runbook.
- Sign engine native libraries and publish checksums, SBOMs, and provenance for
  every release. These supply-chain acceptance items are not yet verified by the
  repository.

## Data and availability

PostgreSQL is the durable source for sessions, ticket redemption, results,
evidence, and atomic action state. Redis provides high-rate action sequencing. Configure HA,
backups, point-in-time recovery, encryption, and alerts for both. Never fail open
when either system cannot safely establish idempotency or replay state.

Test these failures regularly:

- PostgreSQL unavailable before and during commit;
- Redis unavailable or losing a primary;
- delayed/out-of-order game traffic;
- exhausted connection pools;
- rule callback timeout;
- expired signing certificate or unknown key ID;
- regional failover with existing sessions;
- restoration from backup without re-granting an action.

## Observability

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable OTLP export. Without it, Certael
creates standard `ActivitySource` and `Meter` instruments but sends nothing to
an external collector. The API exports ASP.NET Core traces and metrics, runtime
metrics, structured logs, Certael action outcome/latency counters, and session
operation counters. Health probes are excluded from request traces.

At minimum, measure by tenant, game, environment, build, action type, and public
reason:

- ticket issue/redeem success, rejection, and latency;
- active sessions, renewals, and expiry;
- action accept/reject/indeterminate totals and latency percentiles;
- replay, reorder, binding, and proof failures;
- transaction conflicts and duplicate-result hits;
- callback timeout/failure;
- rule-pack version, stage, canary population, and rollback;
- evidence pipeline lag and storage errors.

Alert on changes from established baselines, not only absolute thresholds. Avoid
high-cardinality player IDs in metric labels.

## Administrative session revocation

Revoke one bound session with:

```text
POST /v1/sessions/{sessionId}/revoke
scope: sessions:revoke
```

Emergency bulk revocation uses:

```text
POST /v1/admin/sessions/revoke
scope: sessions:revoke:bulk
```

The body requires `tenantId`, `environmentId`, and a human-readable `reason`.
Optional `gameId`, `buildId`, `signingKeyId`, and `authoritativeServerId` fields
narrow the selector. Omitting all optional selectors revokes every active
session in that tenant/environment, so reserve this scope for emergency
operators. The mutation is rate-limited and records operator, selector digest,
reason, request ID, source network, workload identity, timestamp, outcome, and
result digest in the tenant-isolated audit log. The authenticated response
returns the affected count.

## Privacy and enforcement

Collect only evidence needed for a documented security purpose. Mark sensitive
fields, pseudonymize player identifiers, restrict access by role and tenant, audit
reads, define regional storage requirements, and automatically enforce retention.
Provide deletion/export handling consistent with the game's legal obligations.

Roll out enforcement in this order: observe, shadow, canary, action rejection,
temporary restriction, then broader account action. Maintain appeal and manual
review paths. Client integrity evidence by itself must never cause a permanent
ban.

## Production readiness gate

- [ ] Game-specific threat model reviewed and owned
- [ ] All protected mutations occur only on authoritative servers
- [ ] Replay, binding, duplicate, concurrency, and failure tests pass
- [ ] Every supported engine/platform build passes conformance tests
- [ ] Rule packs are signed, approved, shadowed, canaried, and rollback-tested
- [ ] mTLS, scoped OAuth, secret storage, rotation, and revocation are exercised
- [ ] HA, backup restoration, regional failure, and capacity are tested
- [ ] Privacy retention and enforcement appeal processes are approved
- [ ] Release artifacts are signed with SBOM and provenance
- [ ] Load targets are verified for the intended game traffic
- [ ] Independent security review findings are resolved

Track repository-wide gaps in [Acceptance status](acceptance-status.md).
