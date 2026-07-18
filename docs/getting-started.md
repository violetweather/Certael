# Secure quickstart

This guide brings up the development backend and identifies the minimum work for
one end-to-end protected action. It intentionally stops short of calling the
development profile production-ready.

## Prerequisites

- .NET 10 SDK
- Rust 1.97.0 only when building native code from source
- Docker with Compose support
- Git and a C/C++ compiler only for source builds and native smoke tests
- Godot 4.7, Unity 6000.3.16f1, or Unreal 5.8 only when building that adapter
- An authoritative game server; listen servers and peer hosts are lower assurance

Confirm the repository builds before integration:

```bash
dotnet test Certael.slnx
cargo test --workspace
```

## 1. Run the development backend

```bash
export CERTAEL_DEV_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export CERTAEL_DEV_POSTGRES_CONNECTION_STRING="$(printf 'Host=postgres;Port=5432;Database=certael;Username=certael;%s=%s' 'Password' "$CERTAEL_DEV_POSTGRES_PASSWORD")"
docker compose -f deploy/compose/docker-compose.yml up -d
curl --fail http://localhost:8080/healthz
```

The profile starts PostgreSQL, Redis, NATS JetStream, ClickHouse, the API, the
transactional event worker, and the analytics projection worker. PostgreSQL
stores authoritative sessions, mutations, outbox records, evidence, and cases;
Redis enforces real-time admission; JetStream carries durable canonical events;
and ClickHouse is a rebuildable analytical projection.

The local API is HTTP and uses development credentials. Keep it on loopback or an
isolated development network.

There is no insecure ticket-issuance bypass, even in Development. The HTTP
Compose profile is suitable for health checks, persistence work, and the public
cryptographic redemption path; its workload-authenticated endpoints are
unavailable without TLS client-certificate termination. The automated endpoint
tests provide in-process development coverage. For manual end-to-end testing,
run Kestrel or a trusted local proxy with HTTPS, a dedicated test OIDC issuer,
and a client certificate bound through `cnf.x5t#S256`. Never reuse those
credentials in production.

## 2. Install or build the client runtime

Normal game developers should install a verified prebuilt engine package and do
not need Rust, C++, SCons, `godot-cpp`, MinGW, or MSVC. Follow the
[prebuilt installation guide](installing-prebuilt.md). Maintainers can build the
native runtime from source with:

```bash
./scripts/build.sh native --configuration Release
```

```powershell
.\scripts\build.ps1 native -Configuration Release
```

Use `all` instead of `native` to build the host Godot adapter too. The scripts
pin Rust, select `x86_64-pc-windows-msvc` on Windows, fetch the locked
`godot-cpp` revision, link the actual native library, and fail rather than emit a
dummy library. See [Engine support](engine-support.md) for prebuilt layouts.

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
5. On the game server, call `CertaelServerEngine.ValidateAndExecuteAsync` with
   the raw envelope, exact `ActionBinding`, verified signed protection profile,
   generated request decoder, and authoritative transaction factory.
6. In the bounded trusted callback, evaluate the request against the transaction's current
   authoritative state and stage only an accepted mutation.
7. Return `ActionResult<TResponse>` and the new authoritative snapshot to the
   client.

The high-level API strictly decodes the envelope, verifies the protection-profile
signature and profile/session binding, applies that action's schema and rate
policy, authorizes proof/sequence/chain state, bounds the callback, and commits
through the authoritative handler. It deliberately does not expose a
signature-valid shortcut. Transport and game-state transaction implementations
remain integration points because Certael does not know the game's RPC framework
or simulation database.

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
