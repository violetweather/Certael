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
   `tenant_id` and `environment_id` claims.
4. The request binds the ticket to tenant, game, environment, player subject,
   match, authoritative server, build, protection profile, and ephemeral key.
5. Certael returns an ECDSA-signed ticket valid for at most 60 seconds.
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

The engine runtime accepts JSON matching the native `SessionBinding` fields:

```json
{
  "session_id": "7a9c...",
  "game_id": "my-game",
  "environment_id": "production",
  "match_id": "match-128",
  "build_id": "2026.07.11.1",
  "expires_at_unix": 1783814400
}
```

Construct this JSON from the successful Certael response on trusted networking
code. Never activate arbitrary JSON received from an unauthenticated peer.

## Action sequence

The client serializes a typed request payload and calls the adapter. The runtime
adds a session ID, monotonically increasing sequence, random action ID, action
type, schema version, monotonic timestamp, previous-action digest, and Ed25519
possession proof. Payloads are limited to 64 KiB and action types to 128 safe
ASCII identifier characters.

The authoritative server then:

1. decodes the envelope using the canonical protocol mapping;
2. supplies the expected action/game/environment/match/server/build binding;
3. checks session lifetime, exact binding, sequence range, signature, replay, and
   reorder through `ActionAuthorizer`;
4. opens an authoritative transaction and reserves the action ID;
5. evaluates rules against `transaction.Current`;
6. stages the mutation, result, and authoritative outbox event;
7. commits once and returns the result.

An accepted action must produce an `AuthoritativeEvent`. Any unexpected exception
returns `INDETERMINATE`; the client must reconcile from authoritative state.

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
