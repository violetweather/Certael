# Troubleshooting

Start with the exact public reason or native result. Do not work around a security
failure by disabling binding, sequence, proof, or authoritative-state checks.

## Local API is unhealthy

```bash
docker compose -f deploy/compose/docker-compose.yml ps
docker compose -f deploy/compose/docker-compose.yml logs api postgres redis
curl --fail http://localhost:8080/healthz
```

Check that ports 8080, 5432, and 6379 are free and that PostgreSQL passed its
health check. The development API listens on HTTP; HTTPS redirection behavior may
depend on the local container environment.

## Native runtime is missing

- Prefer a verified prebuilt engine package. For a source build, run
  `./scripts/build.sh native --configuration Release` or
  `.\scripts\build.ps1 native -Configuration Release`.
- Confirm library architecture matches the editor/player architecture.
- Verify engine import/build rules include the library in packaged output.
- Check platform code signing and dependent runtime libraries.
- Test a packaged build, not only the editor.

Godot returns `false` from `initialize` if `CertaelNative` is unavailable. Unity
usually raises a native-library loading exception. Unreal may compile but fail to
stage the runtime dependency if `Certael.Build.cs` paths are wrong.

## Session activation fails

Verify that the typed binding has a future expiry, a 32-byte binding digest, the
returned initial sequence/protocol range/protection profile, and non-empty
session/game/environment/match/build IDs. Activate only after successful
redemption.

## Ticket redemption is rejected

| Reason | Likely cause |
|---|---|
| `UNKNOWN_SIGNING_KEY` | ticket key ID differs from the configured verifier |
| `INVALID_SIGNATURE` | ticket changed, wrong key, or corrupt encoding |
| `INVALID_CLAIMS` | malformed ticket claims |
| `SIGNING_KEY_SCOPE_MISMATCH` | key metadata is not valid for this tenant/environment |
| `ISSUER_OR_AUDIENCE_MISMATCH` | API environments or configuration mixed |
| `TICKET_EXPIRED_OR_NOT_YET_VALID` | 60-second window elapsed or severe clock skew |
| `PROOF_KEY_MISMATCH` | different runtime/key answered the challenge |
| `INVALID_POSSESSION_PROOF` | ticket ID/challenge encoding mismatch or invalid proof |
| `TICKET_ALREADY_REDEEMED` | duplicate redemption or stolen/replayed ticket |

Generate ticket ID bytes in network/RFC order. Challenges must be 16–256 bytes
and should be cryptographically random and single-use.

## Action is rejected

| Reason | What to inspect |
|---|---|
| `INVALID_ACTION` | empty action ID or wrong action type |
| `INVALID_SESSION` | session not persisted or wrong environment |
| `SESSION_EXPIRED` | renewal timing and server clocks |
| `SESSION_BINDING_MISMATCH` | game/environment/match/server/build mismatch |
| `PROTOCOL_NOT_PERMITTED` | envelope protocol is outside the ticket/session range |
| `SEQUENCE_OUT_OF_RANGE` | wrong initial sequence or exhausted policy range |
| `INVALID_POSSESSION_PROOF` | canonical encoding or wrong ephemeral key |
| `REPLAY_OR_REORDER` | duplicate, concurrent client runtime, or reordered transport |
| `SEQUENCE_GAP` | a sequence was skipped; rebootstrap rather than guessing state |
| `ACTION_CHAIN_MISMATCH` | previous digest does not match the last consumed action |
| `ACTION_RATE_LIMITED` | action exceeded its signed protection-profile rate policy |
| `SCHEMA_MISMATCH` | action payload schema/version differs from its registered policy |
| `ACTION_NOT_REGISTERED` | signed protection profile does not register this action type |
| game-specific reason | rule inputs and authoritative state |

Do not share one runtime across multiple active sessions or create multiple
runtimes for the same session. If the game's transport can reorder messages,
serialize protected actions or implement an explicitly reviewed buffering policy
before authorization consumes the sequence.

## Result is `INDETERMINATE`

The handler encountered cancellation, callback failure, or transaction/commit
failure and cannot safely claim success. Do not mint a new action ID and repeat
the purchase or reward. Query the authoritative snapshot and/or original action
result, then reconcile through game-specific idempotency policy.

## Rule pack does not validate

```bash
dotnet run --project cli/Certael.Cli -- rules validate path/to/pack.yaml
```

Check canonical numeric versions, identifier characters, unique rule IDs,
protocol range, public reason format, supported expression nodes, and risk caps.
Versions are immutable after registration.

## Getting useful diagnostics safely

Record correlation/action IDs, public reasons, tenant/game/environment/build,
rule-pack version, and timing. Redact tokens, tickets, signatures, client
certificates, signing keys, connection strings, raw player identifiers, and
sensitive evidence before sharing logs. Report suspected vulnerabilities through
[the security policy](../SECURITY.md).
