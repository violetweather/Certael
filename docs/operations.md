# Production operations

The Compose file is a development convenience, not a deployment blueprint.
Production requires a real identity provider, TLS termination with client
certificates, durable data services, private networking, secret management,
observability, and tested recovery.

## Workload identity

Ticket issuance and session renewal require both:

- a valid OAuth/JWT workload identity with audience `certael-api`; and
- a presented client certificate.

Tokens must carry the required `sessions:issue` or `sessions:renew` scope and
exact `tenant_id` and `environment_id` claims. Issue one short-lived identity per
game/environment/workload. Do not reuse credentials between development and
production or place them in clients.

Set these configuration values outside source control:

```text
Authentication__Authority=https://identity.example.com/
Authentication__Audience=certael-api
Signing__PrivateKeyPemPath=/run/secrets/certael-ticket-signing.pem
ConnectionStrings__Postgres=<secret reference>
ConnectionStrings__Redis=<secret reference>
```

`Development__AllowInsecureServiceIdentity` must remain `false` outside isolated
local testing. The application already refuses missing persistence and signing
configuration outside the Development environment.

## Network controls

- Terminate TLS 1.2+ or newer at a trusted proxy or Kestrel and forward client
  certificates only across an authenticated hop.
- Keep PostgreSQL, Redis, NATS, and ClickHouse on private networks.
- Restrict issuance/renewal to game-server workload networks.
- Apply per-identity and per-tenant limits in addition to the redemption
  endpoint's IP fixed-window limit.
- Do not log tickets, possession signatures, access tokens, connection strings,
  or raw sensitive evidence.

## Keys and certificates

- Store ticket and rule-pack signing keys in a KMS/HSM or managed secret store.
- Separate ticket, rule, artifact, and environment signing keys.
- Publish key IDs and overlapping verification keys before rotation.
- Rotate client certificates and OAuth credentials automatically.
- Revoke compromised keys, stop issuance, expire affected sessions, and preserve
  audit evidence through a documented incident runbook.
- Sign engine native libraries and publish checksums, SBOMs, and provenance for
  every release. These supply-chain acceptance items are not yet verified by the
  repository.

## Data and availability

PostgreSQL is the durable source for sessions, results, evidence, and atomic
action state. Redis provides sequencing and ticket redemption. Configure HA,
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
