# Secure quickstart

This guide brings up the development backend and identifies the minimum work for
one end-to-end protected action. It intentionally stops short of calling the
development profile production-ready.

## Prerequisites

- .NET 10 SDK
- Rust stable toolchain
- Docker with Compose support
- Git and a C/C++ compiler for native smoke tests
- Godot 4.3+, Unity 2022 LTS+, or Unreal 5.3+ only when building that adapter
- An authoritative game server; listen servers and peer hosts are lower assurance

Confirm the repository builds before integration:

```bash
dotnet test Certael.slnx
cargo test --workspace
```

## 1. Run the development backend

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
curl --fail http://localhost:8080/healthz
```

The profile starts PostgreSQL, Redis, NATS, ClickHouse, and the API. PostgreSQL
stores sessions and atomic results; Redis enforces one-time ticket redemption and
action sequencing. NATS and ClickHouse are present for the wider event/evidence
architecture but are not fully wired by the current API.

The local API is HTTP and uses development credentials. Keep it on loopback or an
isolated development network.

## 2. Build the client runtime

```bash
cargo build --release -p certael-c-api
```

The native library is emitted under `target/release`. Copy the platform library
to the location required by your engine adapter. Release packages are not yet
published, so a production adopter must build, sign, and distribute its own
artifacts. See [Engine support](engine-support.md).

## 3. Reference the authoritative SDK

Until a signed NuGet package is published, reference the SDK project from the
game-server solution:

```xml
<ItemGroup>
  <ProjectReference Include="path/to/certael/server-sdk/Certael.Server/Certael.Server.csproj" />
</ItemGroup>
```

Never place the server SDK, ticket-signing key, OAuth credential, or service
certificate in an engine project.

## 4. Protect one action

Choose a mutation with a simple invariant, such as `inventory.craft`:

1. Define a versioned request payload: recipe ID, quantity, and expected revision.
2. Move recipe lookup, ingredient checks, spending, and item creation to the game
   server.
3. Bootstrap the Certael session using the flow in [Authorization](authorization.md).
4. Have the client call the adapter's `AuthorizeAction`/`authorize_action` and
   send the returned envelope over the game's authenticated network connection.
5. On the game server, decode the envelope into `AuthorizedAction<TRequest>` and
   pass it to `AuthoritativeActionHandler` with an exact `ActionBinding`.
6. In `validateAndApply`, evaluate the request against the transaction's current
   authoritative state and stage only an accepted mutation.
7. Return `ActionResult<TResponse>` and the new authoritative snapshot to the
   client.

Transport decoding and game-state transaction implementations are integration
points: Certael does not know the game's RPC framework or state database.

## 5. Exercise hostile cases

Before protecting more actions, automate these cases:

- forged quantity, recipe, or target ID;
- stale authoritative revision;
- duplicate action ID and repeated sequence;
- reordered sequence and cross-session envelope;
- wrong game, environment, match, server, or build binding;
- expired or twice-redeemed bootstrap ticket;
- concurrent double spend;
- rule callback timeout or exception;
- database failure during commit.

The invariant is simple: failure must reject or return `Indeterminate`; it must
never grant the mutation twice. A client receiving `Indeterminate` should query
authoritative state instead of blindly retrying with a new action ID.

## 6. Add an engine

Follow [Engine support](engine-support.md) for Godot, Unity, or Unreal. All three
adapters expose the same four operations:

1. create an ephemeral session public key;
2. sign a server challenge to prove possession;
3. activate a server-verified session binding;
4. create a signed, sequenced action envelope.

## 7. Add and validate rules

```bash
dotnet run --project cli/Certael.Cli -- rules validate rules/examples/inventory.yaml
dotnet run --project cli/Certael.Cli -- doctor
```

Continue with [Custom game rules](rules.md), including signing, shadow evaluation,
canary rollout, approvals, and rollback.

## Ready for production?

Not after this quickstart alone. Complete [Production operations](operations.md),
the game's threat model, load tests, false-positive analysis, platform builds,
artifact signing, rollback exercises, and an independent review.
