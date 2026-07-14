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
3. Receive `AgentLaunchResponseV1`. Relay only its `signed_policy` and `signed_launch_grant` fields to the local Agent as canonical `AgentLaunchBundleV1` bytes.
4. Request a fresh challenge with `agents:challenge`, relay it to the Agent, then submit the returned signed report with `agents:report`.
5. Query health at the policy cadence. Revoke the Agent session at match exit, account switch, server migration, or logout.

The signed policy binds tenant, game, environment, requirement mode, cadence,
grace window, version floor, and expiry. The signed launch grant binds that exact
policy digest to tenant, game, environment, player, match, build, Agent ephemeral
public key, and authoritative server. Both signed objects must agree on tenant,
game, and environment. A server migration therefore creates a new Agent session
and grant; an existing binding is never edited.

The workload JWT must contain matching `tenant_id`, `environment_id`, `server_id`, and scope claims. Possessing a JWT without the matching validated client certificate is insufficient. Production endpoints reject missing TLS, untrusted certificates, wrong claim bindings, JSON bodies, noncanonical Protobuf, oversized bodies, and unknown fields.

## Agent trust store

The separately installed Agent pins Core's Agent-policy verification keys in its local trust store:

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

The trust store is configuration, not a private key. It must ship through a signed Agent package or signed update and must not be writable by ordinary users. Unknown keys, revoked keys, keys outside their validity interval, symlinks, oversized files, malformed JSON, and group/world-writable Unix files fail closed.

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

The launch build ID must also exist in the tenant/game/environment Agent build
registry. Register and revoke these IDs with the separately scoped
`/v1/admin/agent-builds` endpoints. Core rejects an otherwise valid launch
before signing a grant when the build is unknown or revoked. A build ID is
normally the lowercase SHA-256 digest of the approved exported executable; an
integration may instead use a canonical manifest digest after independently
verifying that complete manifest.

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
- relay canonical launch bundles, challenges, reports, and shutdown frames;
- expose health loss so protected online modes can fail according to policy.

They do not sign policies, decide whether reports are honest, call account-ban APIs, or replace authoritative gameplay validation. Do not expose security-sensitive JSON or a Blueprint/GDScript method that lets an untrusted client invent a grant.

## Failure behavior

- `required`: protected-mode admission fails when launch verification fails; loss after admission enters the configured grace period and then restricts the session.
- `optional`: health loss records advisory evidence but does not independently reject gameplay.
- `disabled`: the game does not require Agent evidence; offline play remains available.

An accepted report only proves that the admitted Agent key signed the expected bounded report chain. User-mode evidence can be bypassed on a fully controlled machine and cannot independently punish an account.
