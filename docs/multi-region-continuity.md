# Multi-region controlled continuity

Certael coordinates exclusive match ownership across regions. It does not copy
game state and it does not create active-active gameplay writers. The game moves
authoritative match state; Certael proves which regional server may accept the
next protected action.

## Safety model

- One match has one owner lease identified by tenant, game, environment, and
  match.
- Every acquisition or forced failover receives a monotonically increasing
  fencing epoch.
- The owner renews every 10 seconds. Leases expire after 30 seconds.
- A regional server closes its local protected-action gate when renewal fails
  through expiry or the coordinator reports a stale epoch.
- Every protected mutation must validate the current region, server, and fencing
  epoch before its authoritative transaction commits.
- Forced failover requires a separately authorized mTLS operator certificate and
  leaves an immutable coordinator audit record.

These constraints prevent a recovered or partitioned source from committing
after ownership moved. They do not make the game database multi-primary.

## Production coordinator

`Certael.Coordinator` uses a highly available PostgreSQL control database. The
release Compose profile exposes HTTPS on port `8443` and requires:

- `ConnectionStrings__ControlPostgres`
- `Coordinator__SigningKeyId`
- `Coordinator__SigningPrivateKeyPkcs8Base64` containing a P-256 PKCS#8 key
- `Coordinator__ClientCaCertificatePath`
- a Kestrel server PFX and password
- `Coordinator__FailoverCertificateThumbprints` for emergency operators

Client certificates must chain to the configured private CA and include the
client-authentication EKU. The certificate simple name is the coordinator
identity. Regional server certificates therefore use their exact signed
`serverId` as the subject name. The development identity header works only in
the Development environment when `Coordinator:AllowInsecureDevelopment=true`.

## Owning a match

Create an mTLS `HttpClient` whose base address is the coordinator HTTPS endpoint,
then construct `CoordinatorLeaseClient`.

1. Call `AcquireAsync` with the tenant, game, environment, match, region, and
   local server ID.
2. Start `RegionalLeaseSupervisor` with the returned lease.
3. Keep the local admission and action gate open only while
   `supervisor.AcceptingProtectedActions` is true.
4. Bind `lease.FencingEpoch` into the match writer or use
   `CoordinatorRegionalActionFence` immediately before commit.
5. On the loss callback, stop new protected actions, cancel queued work for the
   stale epoch, and let in-flight authoritative transactions fail their fence.
6. Dispose the supervisor during an orderly shutdown; it makes a best-effort
   lease release.

The SDK retries transient coordinator outages every two seconds while the
existing lease is still fresh. An outage never extends the signed expiry.

## Transferring a player and match

1. The source asks the coordinator for a `RegionTransferGrantV1` while it still
   owns the current lease.
2. The grant is signed, single-use, nonce-bound, tied to source and destination,
   and expires after 60 seconds.
3. The game transfers authoritative state through its own authenticated channel.
4. The source releases ownership, or the destination waits for lease expiry.
5. The destination redeems the signed grant using its mTLS server identity.
6. Successful redemption creates a fresh lease and fencing epoch. The
   destination must issue fresh Core and Agent sessions before admitting the
   player.

Repeated redemption, wrong destinations, stale epochs, destination failure, and
late source recovery return bounded conflicts; they never create a second owner.

## Emergency failover

Use `AcquireAsync(... Force: true)` only from an operator identity whose
certificate thumbprint is allow-listed. Forced acquisition increments the
fencing epoch. Before forcing, confirm the game can reconstruct or restore the
authoritative match state. Certael records who forced the action but cannot make
lost game state reappear.

## Operations and verification

- Alert on lease-renewal latency, stale-epoch conflicts, forced failovers,
  transfer redemption conflicts, and coordinator PostgreSQL health.
- Keep gameplay processing region-local. Project analytics asynchronously.
- Back up the coordinator control database and signing key using the same
  recovery class as other security control-plane material.
- Exercise split-brain, 30-second expiry, region loss, stale source recovery,
  repeated grant redemption, failed destination, and forced failover before
  enabling the feature flag.
- Ship continuity disabled, then shadow the fencing checks, canary selected
  matches, and only then enforce them.

The coordinator is intentionally the final roadmap layer because it depends on
stable session, Agent, event, audit, and operational foundations.
