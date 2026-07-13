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

