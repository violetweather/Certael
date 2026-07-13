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

The signed launch grant binds tenant, game, environment, player, match, build, Agent ephemeral public key, policy digest, and authoritative server. A server migration therefore creates a new Agent session and grant; an existing binding is never edited.

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
