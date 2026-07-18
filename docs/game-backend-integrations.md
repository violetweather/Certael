# Game-backend integrations

Certael verifies opaque vendor assertions on an authoritative server before it
binds a Core session. A client never sends normalized identity claims and no
vendor login is treated as device attestation.

## Packages and roles

| Package | Verified role | Transport boundary |
|---|---|---|
| `Certael.Integrations.Steam` | Steam player identity | Concrete bounded `SteamWebApiClient` for Steamworks `AuthenticateUserTicket` |
| `Certael.Integrations.Eos` | Epic Online Services Product User identity | `IEosConnectClient` adapter implemented against the integrating game's official EOS SDK version |
| `Certael.Integrations.PlayFab` | PlayFab authoritative server/title context | `IPlayFabServerApiClient` adapter implemented with the game's server credential flow |
| `Certael.Integrations.Agones` | Allocated Agones GameServer context | `IAgonesSdkClient` adapter implemented against the sidecar/Allocator topology used by the cluster |

Steam and EOS assertions are `PlatformProofKind.Identity`. They prove a vendor
account/application binding but are deliberately normalized with an empty nonce digest: the
login assertion does not prove nonce-bound device integrity. Only an official attestation
provider may emit `PlatformProofKind.Attestation` with a verified nonce digest.
PlayFab and Agones establish server context and are not player or device proofs.

Vendor SDK adapters remain deliberately small because EOS, PlayFab, and Agones
SDK/client versions are selected by the integrating game or cluster. Their
interfaces return the original authoritative response fields Certael needs to
validate, rather than accepting normalized claims supplied by a game client.

## Bound lifecycle

Compose one player verifier, one server verifier, the Core ticket/session binder,
and the Agent lifecycle implementation:

```csharp
IGameBackendSessionIntegration integration = new GameBackendSessionIntegration(
    playerVerifier, serverVerifier, coreSessionBinder, agentLifecycle,
    TimeProvider.System);

GameBackendSession session = await integration.StartAsync(new(
    PlayerAssertion: opaqueVendorAssertion,
    ServerApplicationId: serverApplicationId,
    ServerCredential: serverCredential,
    TenantId: tenantId,
    GameId: gameId,
    EnvironmentId: environmentId,
    MatchId: authoritativeMatchId,
    ProofKey: clientEphemeralPublicKey), cancellationToken);
```

The lifecycle validates provider freshness and boundaries, verifies player and
server context, binds the exact player/server/match/proof key through Core, and
starts Agent. If Core returns a mismatched binding or Agent launch fails, the
newly bound Core session is revoked. Shutdown attempts Agent stop and always
revokes Core, even when Agent stop fails.

`Certael.Integrations` emits bounded operation counters and duration histograms
tagged by operation, player provider, server provider, and public outcome. Raw
credentials, assertions, tickets, platform IDs, and vendor error text are never
metric labels.

## Steamworks configuration

Construct `SteamWebApiClient` with an `HttpClient` and a publisher Web API key,
then pass it to `SteamIdentityVerifier`. Keep the key in a server-side secret
store. Do not ship it in an engine client. The client uses HTTPS, a ten-second
default timeout, a 1 MiB response limit, strict JSON parsing, numeric App IDs,
and bounded ticket sizes. Configure the underlying handler with redirects
disabled so credentials cannot follow a redirect to another origin.

## Provider conformance checklist

Before enabling a provider in production, verify:

- expired assertions and credentials are rejected before use;
- replay is rejected by the vendor or the Core one-time ticket/session flow;
- wrong application, title, product, server, allocation, and player subjects fail;
- cancellation and vendor outages return bounded public errors;
- the returned Core session exactly matches player, server, match, and proof key;
- Agent launch failure revokes the newly bound Core session;
- logout, migration, and shutdown stop Agent and revoke Core; and
- secrets and raw vendor responses never appear in logs, metrics, evidence, or
  client-visible errors.

Run these checks against each vendor sandbox in protected CI. Unit conformance
tests validate the common failure contract without contacting vendor services.
