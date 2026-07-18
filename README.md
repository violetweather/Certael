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
- **Cross-engine runtime:** a Rust core and versioned C ABI back Godot, Unity, and
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

Repository-development prerequisites: .NET 10, the pinned Rust 1.97.0
toolchain, Docker Compose, and a supported engine when building its adapter.
Consumers of a published prebuilt engine package do not install Rust or a native
compiler.

```bash
export CERTAEL_DEV_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
docker compose -f deploy/compose/docker-compose.yml up -d
curl --fail http://localhost:8080/healthz
dotnet test Certael.slnx
cargo test --workspace
```

The Compose profile uses development-only credentials and plain HTTP on the
loopback interface. It is not a production configuration.

## Godot: install in minutes

Godot developers use a prebuilt package; Rust, SCons, `godot-cpp`, MSVC, and
MinGW are not required.

1. Download `certael-godot-4.7-vX.Y.Z.zip` and `checksums-sha256.txt` from the
   same [Certael release](https://github.com/violetweather/Certael/releases).
2. Verify the archive against the checksum, close Godot, and extract the zip
   into the project root. You should now have `res://addons/certael/plugin.cfg`.
3. Reopen Godot and enable **Certael** under **Project Settings → Plugins**. This
   installs the `Certael` autoload.
4. Initialize once and give the 32-byte session key to your authenticated game
   server:

```gdscript
func _ready() -> void:
    if not Certael.initialize():
        push_error("Certael is missing for this platform")
        return
    game_network.request_certael_ticket(Certael.create_session_public_key())

func on_ticket_challenge(ticket_id: PackedByteArray, challenge: PackedByteArray) -> void:
    var proof := Certael.sign_redemption(ticket_id, challenge)
    game_network.redeem_certael_ticket(ticket_id, challenge, proof)

func on_verified_session(binding: Dictionary) -> void:
    if not Certael.activate_session(binding):
        push_error("Certael rejected the server binding")

func request_craft(craft_request: PackedByteArray) -> void:
    var envelope := Certael.authorize_action(
        "inventory.craft", "mygame.Craft.v1", 1, craft_request)
    game_network.send_authoritative_action(envelope)
```

`game_network` is your existing authenticated multiplayer transport. The server
must redeem the session, validate the envelope against server-owned state, and
commit the result; installing a client plugin alone cannot make gameplay
authoritative. Follow the complete [Godot session walkthrough](docs/engine-support.md#godot-47).

### Optional Certael Agent in Godot

The same Godot zip includes the small platform probe. Install the separately
released [Certael Agent](https://github.com/violetweather/Certael-Agent/releases)
on the player's machine, register the game with its publisher-signed public
trust material, and have the Agent launch the exported game. Then:

```gdscript
if Certael.connect_agent():
    game_network.begin_agent_session(Certael.agent_hello())

func on_agent_launch(signed_policy: PackedByteArray, signed_grant: PackedByteArray,
        signed_build_manifest: PackedByteArray) -> void:
    if not Certael.bind_agent_launch(signed_policy, signed_grant, signed_build_manifest):
        push_error(Certael.agent_last_error())

## Run this blocking call in WorkerThreadPool, then forward the bytes unchanged.
func exchange_agent_challenge(challenge: PackedByteArray) -> PackedByteArray:
    return Certael.exchange_agent_challenge(challenge)
```

The authoritative server—not GDScript—creates policies, launch grants, and
challenges and verifies reports. Competitive modes can set
`certael/agent/required` to `true`; offline play should leave it disabled. See
[Agent trust and server flow](docs/agent.md) before enabling protected queues.

## Documentation

- [Documentation home](docs/README.md)
- [Secure quickstart](docs/getting-started.md)
- [Install a prebuilt engine package](docs/installing-prebuilt.md)
- [Session and action authorization](docs/authorization.md)
- [TypeScript authoritative server SDK](docs/typescript-server-sdk.md)
- [Native C and C++ API](docs/native-api.md)
- [Godot, Unity, and Unreal integration](docs/engine-support.md)
- [Cross-session economy protection](docs/economy-protection.md)
- [Custom game rules](docs/rules.md)
- [Protection modules](docs/protections.md)
- [Optional Certael Agent integration](docs/agent.md)
- [Version support, required updates, and withdrawals](docs/compatibility.md)
- [Production operations](docs/operations.md)
- [Secure operator console setup](docs/console-setup.md)
- [Signed full-suite installer](docs/suite-installer.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Acceptance status](docs/acceptance-status.md)
- [Normative security contract](docs/security-contract.md)
- [Release and verification](docs/releasing.md)

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
