# TypeScript server SDK

`@certael/server` is the Node.js 22+ ESM SDK for an authoritative game server.
It verifies a canonical action envelope, reserves replay admission, executes a
trusted game callback against server-owned state, and stages the result and event
before one authoritative commit.

This SDK belongs on the trusted game server. Never bundle it, its native verifier,
database credentials, workload certificate, or Core credential into a game
client or engine project.

## Status and boundaries

The current package version is `0.4.0-alpha.2`.

It provides:

- `handleAction()` for the authoritative action lifecycle;
- `SessionStore`, `AdmissionStore`, and transaction interfaces;
- tenant-RLS-scoped `PostgresSessionStore`, atomic `RedisAdmissionStore`, and a
  one-commit `PostgresAuthoritativeTransactionFactory`;
- deterministic, length-framed SHA-256 replay digests;
- a bounded, typed `CertaelApiClient` for session, binary Agent, evidence, case,
  and administrative requests;
- `createNativeVerifier()` and four ABI-checked Rust Node-API packages.

The alpha does not provide:

- a complete canonical envelope/request codec for each game schema;
- declarative-rule parity with the .NET SDK;
- automatic retries or duplicate-result lookup;
- game-state transactions, networking, or authentication policy.

The integrating game owns those boundaries because Certael cannot safely infer
the game's database transaction, request schemas, or authoritative invariants.

## Requirements

- Node.js 22 or newer
- ESM (`"type": "module"`)
- TypeScript configured for modern Node ESM
- PostgreSQL for authoritative session, result, event/outbox, and game-state data
- Redis or an equivalent atomic admission store for real-time replay windows
- the native package matching the server OS and architecture
- an authenticated, mTLS-protected Core connection when using Core APIs

## Install from a Certael release

Download these files from the same Certael GitHub release:

- `certael-typescript-vX.Y.Z.tar.gz`;
- the matching `certael-server-<platform>-X.Y.Z.tgz` native npm package;
- `checksums-sha256.txt` and its Sigstore bundle.

Verify both packages before installation. Install the main package and the exact
native package together when using GitHub release files:

```bash
pnpm add ./vendor/certael-server-0.4.0-alpha.2.tgz \
  ./vendor/certael-server-linux-x64-0.4.0-alpha.2.tgz
```

The main package declares all four native packages as exact optional
dependencies; the package manager selects the current OS and CPU. Certael never
downloads a binary at application startup. A deployment may instead pass an
absolute, verified `.node` path to `createNativeVerifier()`.

For development directly from the repository:

```bash
cd server-sdk/typescript
corepack enable
pnpm install --frozen-lockfile
pnpm run build
pnpm run test
```

## Core lifecycle

`handleAction()` runs these operations in order:

1. Find the server-trusted session binding.
2. Verify the envelope and possession proof through `NativeVerifier`.
3. Confirm that the verifier accepted the exact canonical input bytes.
4. Atomically reserve `(sessionId, actionId, sequence)` admission.
5. Begin an authoritative transaction and load its state snapshot.
6. Run the trusted game callback.
7. Stage one or more durable events and the accepted result.
8. Commit once and verify the expected revision.

A missing session, invalid proof, noncanonical envelope, replay, or duplicate is
rejected. An exception after transaction start rolls back and returns the bounded
`Indeterminate` outcome. The client should reconcile authoritative state after an
indeterminate result rather than blindly retrying under a new action ID.

## Implement the stores

### SessionStore

`SessionStore.find()` must return a session binding created from a verified Core
session, never identifiers copied from the client request.

```ts
interface SessionStore {
  find(sessionId: string, signal?: AbortSignal):
    Promise<SessionBinding | undefined>
}
```

Validate expiry, revocation, tenant, game, environment, server, match, and player
binding before returning a session. `PostgresSessionStore` performs a
tenant-local RLS transaction, rejects expired/revoked rows, loads the verified
ephemeral key and protocol/sequence ranges, and recomputes Core's binding digest.

### AdmissionStore

`reserve()` must be one atomic operation:

```ts
interface AdmissionStore {
  reserve(
    sessionId: string,
    actionId: string,
    sequence: bigint,
    signal?: AbortSignal,
  ): Promise<'reserved' | 'duplicate' | 'replay'>
}
```

Return:

- `reserved` only when this action ID and sequence are newly accepted;
- `duplicate` when the action ID was already reserved;
- `replay` for a consumed, stale, or invalid sequence.

`RedisAdmissionStore` uses one Lua operation, compares decimal unsigned-64-bit
sequences without floating-point conversion, bounds per-session action fields,
and applies a session TTL. A read followed by a separate write is unsafe. The
current alpha maps duplicates to
`DUPLICATE_ACTION`; applications needing idempotent duplicate responses must add
an authoritative result lookup before or around `handleAction()`.

### AuthoritativeTransactionFactory

`begin()` must join the same database transaction used for the game mutation,
accepted result, and durable outbox event.

```ts
interface AuthoritativeTransaction<TState, TResponse> {
  readonly state: TState
  readonly revision: bigint
  stageResult(actionId: string, result: ActionOutcome<TResponse>, signal?: AbortSignal): Promise<void>
  stageEvent(eventId: string, eventType: string, schemaVersion: number,
    payload: Uint8Array, signal?: AbortSignal): Promise<void>
  commit(signal?: AbortSignal): Promise<bigint>
  rollback(): Promise<void>
}
```

Required properties:

- `state` is an authoritative snapshot read inside the transaction;
- `revision` is locked or protected by optimistic concurrency;
- `stageEvent()` writes up to 256 unique, UUID-identified events to the
  transactional outbox, not directly to NATS;
- `stageResult()` and the game mutation share the transaction;
- `commit()` returns exactly the committed revision;
- `rollback()` is safe after any failure and never grants a mutation.

The included PostgreSQL transaction factory keeps a checked-out connection from
`BEGIN` through game mutation, result, outbox event, and `COMMIT`:

```ts
import {
  PostgresAuthoritativeTransactionFactory,
  PostgresSessionStore,
  RedisAdmissionStore,
} from '@certael/server'

const sessions = new PostgresSessionStore(pgPool, 'tenant-a', 'production')
const admission = new RedisAdmissionStore(redisClient, 'tenant-a')

const transactions = new PostgresAuthoritativeTransactionFactory({
  pool: pgPool,
  tenantId: 'tenant-a',
  responseType: 'game.craft-result.v1',
  loadState: async (client, binding) => loadLockedInventory(client, binding),
  commitGameMutation: async (client, binding, state, previousRevision) =>
    stageAndAdvanceInventory(client, binding, state, previousRevision),
  serializeResult: result => encodeJsonSafeResult(result),
})
```

The injected state loader and mutation function must use the supplied client.
Opening another connection or committing inside either hook breaks atomicity.
The factory refuses a revision that does not advance exactly once, buffers the
result and all events until both exist, inserts them in the same transaction, and
rolls back before releasing the connection on failure. Convert `bigint` and
binary values deliberately in `serializeResult`; ordinary `JSON.stringify()`
cannot encode `bigint`.

## Connect the native verifier

Supply a strict game request decoder. Rust first performs canonical envelope
decoding, session-binding validation, protocol validation, and possession-proof
verification; only its verified payload reaches this decoder:

```ts
import { createNativeVerifier } from '@certael/server'

const verifier = createNativeVerifier({
  decodeRequest(payload, context) {
    if (context.requestSchema !== 'game.Craft.v1' || context.schemaVersion !== 1) {
      throw new Error('unsupported request schema')
    }
    return decodeCanonicalCraftRequest(payload)
  },
})
```

`createNativeVerifier()`:

1. loads only the current signed platform package, or an explicit absolute
   regular `.node` file no larger than 64 MiB;
2. requires Node ABI contract v1;
3. passes the trusted ephemeral key, binding digest, and protocol range to Rust;
4. checks the returned identifiers, protocol, payload bound, and digest;
5. returns the exact verified envelope with the bounded decoded request.

Reject unknown fields, duplicate fields, unsupported schema versions, oversized
payloads, and trailing bytes. Do not use an ordinary JSON parse as a substitute
for the canonical protocol decoder.

The game-specific request decoder remains an integration point because only the
game defines that schema and its authoritative meaning.

## Execute one authoritative action

The following example shows the application wiring. The store, verifier, codec,
and transaction implementations are deliberately injected rather than hidden:

```ts
import {
  handleAction,
  type AdmissionStore,
  type AuthoritativeTransactionFactory,
  type NativeVerifier,
  type SessionStore,
  type VerifiedAction,
} from '@certael/server'

interface CraftRequest {
  recipeId: string
  quantity: number
  expectedRevision: bigint
}

interface InventoryState {
  revision: bigint
  ingredients: ReadonlyMap<string, number>
}

interface CraftResponse {
  itemId: string
  revision: bigint
}

declare const sessions: SessionStore
declare const admission: AdmissionStore
declare const verifier: NativeVerifier
declare const transactions:
  AuthoritativeTransactionFactory<InventoryState, CraftResponse>
declare function encodeCraftEvent(value: unknown): Uint8Array
declare function createEventId(): string

export async function authorizeCraft(
  sessionId: string,
  envelope: Uint8Array,
  signal?: AbortSignal,
) {
  return handleAction<CraftRequest, CraftResponse, InventoryState>({
    sessionId,
    envelope,
    sessions,
    admission,
    verifier,
    transactions,
    signal,
    execute: async (
      action: VerifiedAction<CraftRequest>,
      state: InventoryState,
    ) => {
      if (action.actionType !== 'inventory.craft') {
        throw new Error('wrong action type')
      }
      if (action.request.quantity < 1 || action.request.quantity > 10) {
        throw new Error('quantity outside policy')
      }
      if (action.request.expectedRevision !== state.revision) {
        throw new Error('stale inventory revision')
      }

      // The transaction implementation performs the authoritative ingredient
      // checks and stages the actual spend/create mutation. Never trust client
      // inventory values or calculate the granted item from client state.
      const nextRevision = state.revision + 1n
      const response = { itemId: 'server-generated-item-id', revision: nextRevision }
      return {
        response,
        eventId: createEventId(),
        eventType: 'economy.inventory-crafted.v1',
        schemaVersion: 1,
        payload: encodeCraftEvent({ sessionId, actionId: action.actionId, response }),
      }
    },
  })
}
```

In a real implementation, the transaction object should expose application
methods that stage the game mutation; do not mutate an in-memory `state` object
and assume that it is authoritative.

## Interpret outcomes

```ts
const result = await authorizeCraft(sessionId, envelope, signal)

switch (result.outcome) {
  case 'accepted':
    // Return only the authoritative response and revision.
    return result.response
  case 'rejected':
    // Return the bounded public reason; keep sensitive detail in server logs.
    throw new ClientActionError(result.publicReason)
  case 'indeterminate':
    // Query authoritative state before deciding whether the action committed.
    throw new ReconciliationRequiredError()
}
```

Do not turn `Indeterminate` into success, automatically issue a new action ID,
or rerun the trusted callback outside the original transaction.

## Replay digests

`replayDigest()` hashes each canonical component with a four-byte big-endian
length prefix:

```ts
import { replayDigest } from '@certael/server'

const digest = replayDigest(canonicalEnvelope, canonicalEventPayload)
```

Persist the digest with the accepted result and evidence. The same canonical
inputs must produce the same digest across replay; do not include clocks,
randomness, database row order, or noncanonical JSON.

## Core API client

`CertaelApiClient` accepts a base URL and an optional injected `fetch` function:

```ts
import { CertaelApiClient } from '@certael/server'

const core = new CertaelApiClient(new URL('https://certael-api.internal/'),
  authenticatedMtlsFetch, () => ({ authorization: `Bearer ${currentToken()}` }))
```

The injected fetcher is responsible for mTLS, timeouts, bounded retries, and
certificate rotation. Static headers or a per-request header callback supplies
the short-lived OAuth token. The client rejects cross-origin redirects, buffers
at most 1 MiB of response data, and limits Agent request bodies to Core's 64 KiB
canonical binary bound. Never use an unauthenticated global `fetch` against
administrative endpoints.

Session requests and responses use typed JSON wire contracts with binary fields
represented as Base64 strings. Agent launch, challenge, report, health, and
revocation helpers use `application/x-protobuf`; do not JSON-encode those bodies.
Evidence/case search and detail helpers are typed and include assignment, note,
transition, and bounded-action operations. Confirm package compatibility against
the deployed Core manifest before enabling a new SDK version.

## Game-backend providers

`SteamIdentityVerifier` performs the bounded authoritative Steamworks ticket
exchange. `EosIdentityVerifier`, `PlayFabServerVerifier`, and
`AgonesServerVerifier` wrap the official SDK/client selected by the integrating
game and validate returned application, title, allocation, subject, and server
context. Provider failures expose stable public reasons without including vendor
responses or credentials.

## Sandboxed WASM rules

`SignedWasmRuleRegistry` verifies the Ed25519 signature over the rule ID,
version, and SHA-256 module digest before invoking the platform native package.
It uses the same canonical protobuf ABI and limits as .NET. Traps, timeouts,
resource exhaustion, invalid modules, and malformed output return bounded
`WASM_INDETERMINATE`; rules cannot mutate state. See
[sandboxed WASM rules](wasm-rules.md).

## Deployment checklist

- Pin Node, the TypeScript package, Core, and native artifact versions.
- Verify release checksums and Sigstore provenance before deployment.
- Match the native package to the exact OS and architecture.
- Run as a non-root workload with a read-only application filesystem.
- Keep PostgreSQL, Redis, Core, and NATS on private networks.
- Store OAuth credentials and mTLS keys in the platform secret manager.
- Bound envelope size before buffering and propagate `AbortSignal` deadlines.
- Log correlation IDs and bounded reason codes, never raw proofs or secrets.
- Monitor duplicate/replay rates, indeterminate outcomes, transaction rollbacks,
  outbox lag, native load failures, and Core authorization failures.
- Exercise rollback to the previous compatible package/native pair.

## Verification checklist

Before protecting a production action, test:

- valid acceptance and one atomic commit;
- invalid signature, wrong session binding, and noncanonical input;
- duplicate action ID, stale sequence, and reordered sequence;
- stale authoritative revision and concurrent double spend;
- callback exception, timeout, database failure, and commit revision mismatch;
- outbox broker outage without loss of the staged event;
- process restart after commit but before the response reaches the client;
- native package mismatch or load failure;
- replay digest equality against Core golden vectors;
- tenant, game, environment, match, server, and player isolation.

Continue with [Authorization](authorization.md), [Security model](security-model.md),
[Production operations](operations.md), and [Testing](testing.md).
