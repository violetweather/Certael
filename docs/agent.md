# Certael Agent integration

Certael Agent is an optional, separately released user-mode companion application. Its source and release lifecycle live in `violetweather/Certael-Agent`; implementation files must not be copied into this Core repository.

Core owns the authoritative side of the contract:

- the canonical schema under `protocol/protobuf/certael/agent/v1`;
- launch-grant, challenge, report, health, and revocation semantics;
- strict report proof, session, sequence, digest-chain, and build verification;
- conversion of accepted observations into client-only evidence;
- signed policies deciding whether Agent health is required, optional, or disabled.

Agent report acceptance is transport admission, not gameplay authorization and not proof that a client is honest. The game server must continue using `ValidateAndExecuteAsync` or the native authoritative pipeline for gameplay actions.

Offline play does not require the Agent. Ranked or protected-economy modes may deny admission when the Agent is missing or cryptographically invalid. Debugger and unexpected-module observations remain advisory and cannot independently trigger account punishment.

See the Agent repository's `SECURITY-CONTRACT.md`, `PROTOCOL.md`, and `ENGINE-INTEGRATION.md` before integrating an engine package.

## Trust and launch flow

The game client must never mint an Agent policy or grant. A trusted game server performs the following flow over Certael's authenticated workload API:

1. Launch the game through the Agent and receive `AgentHelloV1` from the inherited local channel.
2. Send the hello's public key and build ID to `POST /v1/agent/sessions` using mTLS plus a certificate-bound, short-lived workload JWT with `agents:launch` scope.
3. Receive `AgentLaunchResponseV1`. Relay its `signed_policy`,
   `signed_launch_grant`, and `signed_build_manifest` fields unchanged to the
   local Agent as canonical `AgentLaunchBundleV1` bytes.
4. Request a fresh challenge with `agents:challenge`, relay it to the Agent, then submit the returned signed report with `agents:report`.
5. Query health at the policy cadence. At match exit, account switch, server
   migration, or logout, relay the canonical signed revocation returned by
   Core before closing the local channel.

The signed policy binds tenant, game, environment, requirement mode, cadence,
grace window, version floor, and expiry. The signed launch grant binds that exact
policy digest and exact signed build-manifest digest to tenant, game, environment, player, match, build, Agent ephemeral
public key, and authoritative server. Both signed objects must agree on tenant,
game, and environment. A server migration therefore creates a new Agent session
and grant; an existing binding is never edited.

The workload JWT must contain matching `tenant_id`, `environment_id`, `server_id`, and scope claims. Possessing a JWT without the matching validated client certificate is insufficient. Production endpoints reject missing TLS, untrusted certificates, wrong claim bindings, JSON bodies, noncanonical Protobuf, oversized bodies, and unknown fields.

## Agent trust store

Each signed game registration pins Core's Agent verification keys in a
per-game trust store. There is no mutable global game trust store:

```json
{
  "keys": [
    {
      "key_id": "agent-policy-2026-01",
      "public_key_hex": "<64 lowercase hexadecimal characters>",
      "not_before_unix": 1780000000,
      "not_after_unix": 1810000000,
      "revoked": false
    }
  ]
}
```

The trust store is public configuration, not a private key. Its digest is bound
by the signed registration alongside the TUF root and executable path. Unknown
keys, revoked keys, invalid registrations, mismatched digests, symlinks,
oversized files, malformed JSON, and unsafe Unix permissions fail closed.

Core's Agent signing private key must be supplied through a production KMS/HSM-backed signing deployment and must never be placed in an engine project, repository, container layer, or ordinary configuration value. Development uses a separate ephemeral key and is not production-compatible.

For local development only, generate a matching raw signing key and public
trust store without manually converting key formats:

```bash
dotnet run --project cli/Certael.Cli -- agent-key generate-development \
  development-agent-key ./local-secrets/agent-signing.key \
  ./local-secrets/trust-store.json
```

Point `Agent:SigningPrivateKeyPath` at the private `.key` file and install only
the generated `trust-store.json` on the test machine. The command refuses to
overwrite either file and creates the Unix private key with mode `0600`. Never
use this development command for production; production signing goes through
the `IAgentGrantSigningProvider` KMS/HSM boundary.

## Production policy administration

Production deployments persist immutable Agent policies and approvals in
PostgreSQL. Both tables are protected by forced tenant row-level security. A
workload can select an approved policy ID when launching a session, but cannot
override its requirement mode, timing, minimum Agent version, tenant, game, or
environment.

The launch build must exist in the tenant/game/environment Agent build registry
with a signed whole-build manifest. Generate the bounded registration request:

```bash
dotnet run --project cli/Certael.Cli -- agent-build request \
  ./export tenant game production BUILD_ID godot 0.3.0-alpha.2 \
  0.3.0-alpha.2 2027-01-01T00:00:00Z release \
  agent-build-request.json
```

POST that JSON to `/v1/admin/agent-builds` using the scoped administrative
identity. Core validates every relative path, size, SHA-256 digest, lifetime,
and duplicate; signs the canonical binary manifest through the configured
KMS/HSM boundary; and stores the exact signed bytes immutably. Game-server
launch requests select only the build ID—they cannot supply or replace its
manifest. Core returns the stored manifest and binds its digest into the launch
grant. The Agent hashes every listed file before protected admission and fails
closed if a file is missing, added to the manifest incorrectly, resized, or
changed. Use `/v1/admin/agent-builds/revoke` to stop new admissions.

Starting with `v0.3.0-alpha.1`, that signed manifest also binds the Core SDK,
engine adapter and adapter version, C ABI, action protocol, Agent protocol, and
probe ABI. Core refuses to register an unsupported combination. Regenerate
manifests produced by earlier alphas; the new Agent intentionally rejects them.

Build approvals created before manifest support cannot authorize protected
launch. Re-register each pre-1.0 build with the generated file list after
applying database migration 016.

Administrative policy creation, approval, promotion, and retirement use the
`/v1/admin/agent-policies` endpoints. They require a trusted client certificate,
a short-lived workload token bound to that certificate, the exact tenant and
environment, and the matching `agent-policies:create`, `:approve`, `:promote`,
or `:retire` scope. Enforced promotion requires two distinct approving subjects
over the exact immutable policy digest. Every mutation writes an audit event.
Shadow and canary policies cannot silently become enforced.
A shadow policy is resolvable only when its signed requirement mode is optional
or disabled; Core refuses a required shadow policy. Canary assignment is
deterministic from the pseudonymous player/match key. Sessions outside a canary
must explicitly use the currently enforced baseline policy ID.

For bootstrapped self-hosted deployments, `Agent:Policies` may seed the same
immutable records. A later startup fails if configuration disagrees with the
stored policy. Production must provide at least one policy; the automatically
generated `development-default` policy exists only without production stores.

Raw canonical Agent reports default to a maximum 24-hour retention window and
are tenant-purged during report admission. Configure a shorter interval with
`Privacy:RawAgentReportRetentionMinutes` (1–1440); keep longer-lived findings
subject to `Privacy:DerivedEvidenceRetentionDays` (30 or less for advisory
findings). Operators can execute an audited, tenant/environment-scoped player
deletion through `/v1/admin/privacy/delete-player`; this removes raw reports,
Agent sessions, and derived evidence without putting the player subject in the
audit resource field. Retain findings only as minimized, pseudonymous evidence.
Evidence bundles containing any
client-only or environmental finding are capped at 30 days even if the general
evidence retention setting is longer.

## Engine responsibility

Godot, Unity, and Unreal adapters are local binary relays. They:

- read the inherited channel handle established by the Agent launcher;
- decode the bounded `AgentHelloV1`;
- give the hello to trusted server bootstrap code;
- relay canonical launch bundles, health, challenges, reports, revocations, and shutdown frames;
- expose health loss so protected online modes can fail according to policy.

They do not sign policies, decide whether reports are honest, call account-ban APIs, or replace authoritative gameplay validation. Do not expose security-sensitive JSON or a Blueprint/GDScript method that lets an untrusted client invent a grant.

## Failure behavior

- `required`: protected-mode admission fails when launch verification fails; loss after admission enters the configured grace period and then restricts the session.
- `optional`: health loss records advisory evidence but does not independently reject gameplay.
- `disabled`: the game does not require Agent evidence; offline play remains available.

Core `v0.3.0-alpha.1` adapters incorrectly required the protobuf
`last_report_at_unix` field in the initial Agent health message. Canonical
protobuf omits that scalar when its value is zero, so a valid initial `ready`
message could surface as `AGENT_HEALTH_INVALID`. Upgrade the complete engine
package to Core `v0.3.0-alpha.2` or newer; do not replace only one native
library. Agent `v0.4.0-alpha.1` also sends a bounded rejection health response
before closing admission, allowing current adapters to distinguish update,
registration, manifest, build, and local-channel failures.

Godot projects should keep one `CertaelClient` autoload for the process lifetime.
Its `initialize()` method is idempotent in `v0.3.0-alpha.2`; repeatedly creating
native clients or mixing adapter/probe binaries from different archives is not
a supported connection model.

An accepted report only proves that the admitted Agent key signed the expected bounded report chain. User-mode evidence can be bypassed on a fully controlled machine and cannot independently punish an account.
