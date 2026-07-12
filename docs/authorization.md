# Session and action authorization

Certael does not use a shared client secret or trust an initialization call. It
establishes a narrowly bound session using a server-issued ticket and proof of
possession, then signs every action with an ephemeral key.

## Roles

- **Game client:** creates an ephemeral key and signs requests; always untrusted.
- **Authoritative game server:** authenticates the player, requests tickets,
  validates actions, reads trusted state, and commits outcomes.
- **Certael API:** signs/redeems bootstrap tickets and persists authorization.
- **Identity provider:** authenticates game-server workloads for the Certael API.

## Bootstrap sequence

1. The client creates one `CertaelClient`/runtime for the active game session.
2. It calls `CreateSessionPublicKey` and sends the 32-byte Ed25519 public key to
   its authenticated authoritative game server.
3. The game server calls `POST /v1/sessions/tickets` using both mTLS and an OAuth
   access token. The identity requires `sessions:issue`, plus matching
   `tenant_id` and `environment_id` claims. Its standard `cnf.x5t#S256` claim
   must bind the token to the presented certificate.
4. The request binds the ticket to tenant, game, environment, player subject,
   match, authoritative server, build, protection profile, and ephemeral key.
5. Certael deterministically encodes the ticket claims as strict Protobuf-wire
   bytes and signs `certael.ticket.v1\0 || claims` with the active scoped ECDSA
   key. The ticket is valid for at most 60 seconds.
6. The server generates a cryptographically random 16–256 byte, single-use
   challenge and sends the ticket ID and challenge to the client.
7. The client signs it using `SignRedemption`/`sign_redemption`.
8. The ticket, public key, challenge, and signature are sent to
   `POST /v1/sessions/redeem`. Redemption is rate-limited and one-time.
9. The returned binding is relayed through the authenticated game connection.
   The client activates only that verified binding and initial sequence.

The current redeem endpoint is public by design because the ticket and possession
proof are its credentials. Deploy it behind TLS, rate limiting, and abuse
monitoring. Ticket issuance and renewal are workload-authenticated operations.

## Ticket request

```json
{
  "tenantId": "studio",
  "gameId": "my-game",
  "environmentId": "production",
  "playerSubject": "opaque-player-4f9...",
  "matchId": "match-128",
  "serverId": "game-server-us-17",
  "buildId": "2026.07.11.1",
  "protectionProfile": "standard",
  "ephemeralPublicKey": "<base64-encoded 32 bytes>"
}
```

Do not use an email address or display name as `playerSubject`; use a stable,
pseudonymous identifier. Do not let the client choose any binding field without
server verification.

## Activated binding

The engine runtime accepts a typed binding built from the redeemed session:

```text
session ID, game ID, environment ID, match ID, build ID, protection profile,
permitted protocol range, expiry, initial sequence, and the opaque 32-byte
session-binding digest
```

Construct it from the successful Certael response in trusted networking code.
Never activate a binding received from an unauthenticated peer. The binding
digest covers server-only identity fields without exposing them to the client.

## Action sequence

The client serializes a typed request payload and calls the adapter. The runtime
adds protocol version, session ID, monotonically increasing sequence, random
action ID, action type, request-schema ID/version, session-binding digest,
monotonic timestamp, previous-action digest, and Ed25519 proof. Production uses
strict canonical Protobuf-wire bytes. Payloads are limited to 64 KiB.

The authoritative server then:

1. decodes the envelope using the canonical protocol mapping;
2. supplies the expected action/game/environment/match/server/build binding;
3. checks session lifetime, exact binding, sequence range, signature, replay, and
   reorder through `ActionAuthorizer`;
4. opens an authoritative transaction and reserves the action ID;
5. evaluates rules against `transaction.Current`;
6. stages the mutation, result, and authoritative outbox event;
7. commits once and returns the result.

Admission requires the exact next sequence, not merely a larger sequence.
Skipping a value returns `SEQUENCE_GAP`. A valid contiguous action rejected only
for rate excess consumes its sequence and digest so later client actions remain
synchronized; replay, chain, proof, binding, and gap failures do not.

An accepted action must produce an `AuthoritativeEvent`. Any unexpected exception
returns `INDETERMINATE`; the client must reconcile from authoritative state.

Use `CertaelServerEngine.ValidateAndExecuteAsync` as the production entry point.
It accepts canonical envelope bytes, the expected binding, a signed protection
profile, a generated request decoder, the authoritative transaction factory,
and the trusted game callback. The engine verifies the profile signature,
game/environment/profile/session binding, action registration, request schema,
per-action rate policy, possession proof, sequence, and digest chain before the
callback can stage a mutation. There is intentionally no public “signature is
valid, therefore allow” API.

```csharp
var certael = new CertaelServerEngine(
    actionAuthorizer,
    actionResultStore,
    TimeProvider.System,
    trustedProtectionProfileVerifier);

ActionResult<CraftResponse> result =
    await certael.ValidateAndExecuteAsync<CraftRequest, CraftResponse, InventoryState>(
        envelope,
        new ActionBinding(
            ActionType: "inventory.craft",
            GameId: "my-game",
            EnvironmentId: "production",
            MatchId: matchId,
            ServerId: serverId,
            BuildId: buildId,
            TenantId: tenantId),
        signedProtectionProfile,
        payload => craftCodec.Decode(payload),
        transactionFactory.BeginInventoryAsync,
        async (action, transaction, cancellationToken) =>
        {
            // Read only transaction.Current and other trusted server state.
            return await craftRules.ValidateAndStageAsync(
                action, transaction, cancellationToken);
        },
        callbackTimeout: TimeSpan.FromMilliseconds(250),
        cancellationToken: cancellationToken);
```

The signed profile supplies the action's schema/version and admission rate; do
not duplicate those values from client input. A callback timeout, exception,
invalid public reason/evidence shape, transaction uncertainty, or unexpected
revision returns `Indeterminate` and does not justify an account punishment.

## What proofs do—and do not—prove

Proofs stop simple ticket substitution, network replay, cross-binding reuse, and
accidental request corruption. They do not prove the client binary is original,
the input came from a human, telemetry is truthful, or the action obeys game
rules. Those questions require server invariants and corroborated evidence.

## Session renewal and logout

`POST /v1/sessions/{sessionId}/renew` requires mTLS, OAuth, the
`sessions:renew` scope, matching tenant/environment claims, and the bound server
ID. Renew before expiry through the authoritative server. Dispose the client
runtime on logout, match exit, account switch, or server migration; create a new
ephemeral identity for the next session.
