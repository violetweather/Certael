# Certael

Certael is an open-source, cross-engine anti-cheat foundation for authoritative
online games. It gives Godot, Unity, and Unreal projects one secure action
protocol, a memory-safe native client runtime, a .NET server SDK, portable game
rules, and a self-hosted control plane.

> The client requests. The authoritative server decides and commits.

Certael is designed for inventories, economies, movement, progression, social
systems, racing, card games, strategy games, and shooters. It does not depend on
genre-specific heuristics.

## Why Certael

- **Server-owned outcomes:** clients send typed intent, never authoritative state.
- **Replay-resistant sessions:** 60-second, single-use bootstrap tickets are bound
  to player, game, environment, match, server, build, and an ephemeral client key.
- **Atomic actions:** validation, mutation, result, and outbox event share an
  authoritative transaction; duplicates return the original result.
- **Portable rules:** signed declarative packs and bounded trusted callbacks let
  each game define its own invariants.
- **Cross-engine runtime:** a Rust core and stable C ABI back Godot, Unity, and
  Unreal adapters with the same envelope semantics.
- **Explainable evidence:** every signal carries provenance; untrusted client
  integrity evidence cannot independently justify a permanent ban.

## Security boundary

Assume the player can read and patch the client, suppress SDK calls, forge
telemetry, extract in-memory keys, and replace the engine adapter. A valid Certael
signature proves possession of a session key—not that a requested action is fair.
Only a trusted game server may validate and commit gameplay state.

```text
Game client                  Authoritative game server          Certael backend
-----------                  -------------------------          ---------------
ephemeral key  ----------->  issue bound, short-lived ticket
prove possession ----------> redeem / create session  -------> session storage
signed action intent ------> authorize + evaluate rules
                              atomic state commit       -------> evidence/outbox
authoritative result <------
```

Read [Security model](docs/security-model.md) before integrating.

## Start locally

Prerequisites: .NET 10, Rust stable, Docker Compose, and a supported engine when
building an adapter.

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
curl --fail http://localhost:8080/healthz
dotnet test Certael.slnx
cargo test --workspace
```

The Compose profile uses development-only credentials and plain HTTP on the
loopback interface. It is not a production configuration.

## Documentation

- [Documentation home](docs/README.md)
- [Secure quickstart](docs/getting-started.md)
- [Session and action authorization](docs/authorization.md)
- [Godot, Unity, and Unreal integration](docs/engine-support.md)
- [Custom game rules](docs/rules.md)
- [Protection modules](docs/protections.md)
- [Production operations](docs/operations.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Acceptance status](docs/acceptance-status.md)

## Repository layout

| Path | Purpose |
|---|---|
| `runtime/` | Rust session/action core and stable C ABI |
| `engines/` | Godot, Unity, and Unreal adapters |
| `server-sdk/` | Authoritative .NET action and rule SDK |
| `backend/` | ASP.NET Core API and persistence adapters |
| `protocol/` | Canonical Protobuf contracts |
| `rules/` | Rule-pack examples |
| `cli/` | Rule and build-manifest tooling |
| `deploy/` | Local deployment profile |
| `tests/` | Security, persistence, adapter, and conformance tests |

## Project status

Certael is a pre-1.0 security engineering release. Interfaces and packaging may
change. Do not use it as the sole control for a production economy or competitive
game until your integration has passed adversarial tests and an independent
security review. See [Acceptance status](docs/acceptance-status.md) for what is
implemented and what remains unverified.

Security issues should be reported using [SECURITY.md](SECURITY.md), not a public
issue. Certael is licensed under the terms in [LICENSE](LICENSE).
