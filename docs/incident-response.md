# Incident response runbooks

Every incident follows: detect, contain, preserve evidence, eradicate, recover,
communicate, and review. Never destroy logs needed to determine affected tenants
or releases.

## Signing-key compromise

Stop issuance, mark the key revoked, activate a pre-staged replacement, reject
new tickets under the key, revoke affected sessions, notify operators, preserve
key-use audit records, and publish a scoped advisory.

## Malicious rule or protection profile

Disable promotion, roll back to the recorded prior digest, identify approving
identities, compare affected decisions, reverse game enforcement through the
operator's appeal process, and rotate compromised control-plane identities.

## Compromised release

Remove the artifact from supported channels, revoke its signing identity where
possible, publish affected hashes, rebuild only from a reviewed clean revision,
issue new provenance, and require operators to verify the replacement.

## Tenant-isolation failure

Disable affected endpoints, preserve database/audit evidence, identify accessed
rows and identities, rotate service credentials, patch and retest RLS and
application predicates, and follow applicable notification requirements.

## Redis replay-state loss

Fail closed, stop protected matchmaking or rebootstrap sessions into a clean
namespace, do not reconstruct accepted state from client reports, and reconcile
valuable outcomes from PostgreSQL.

## PostgreSQL corruption or failover anomaly

Fail protected writes closed, retain the affected primary and write-ahead logs,
promote only a consistency-checked replica, compare action-result/outbox/game
transaction invariants, and never replay a client request under a new action ID.
Restore into an isolated environment first and reconcile by immutable action ID
before reopening protected matchmaking.

## Evidence pipeline outage

Keep authoritative action decisions independent of asynchronous evidence
delivery, apply backpressure before queues become unbounded, retain the durable
outbox, and disable advisory enforcement recommendations while evidence is
incomplete. Reprocess idempotently and record the observation gap.

## Stolen game-server identity

Revoke the workload certificate and token subject, bulk-revoke sessions bound
to the server ID, block ticket issuance, preserve certificate/token/audit
records, rotate the workload identity, and verify that tenant/environment and
certificate-binding checks reject the stolen credential before recovery.

## Vulnerable engine adapter or dependency

Stop distributing affected packages, identify exact source and artifact
digests, publish supported mitigations, patch and run the full engine/protocol
conformance suite, issue new signed artifacts and SBOMs, and revoke affected
build manifests when exploitation could alter trusted admission behavior.

## Regional failure

Stop new protected admissions in the failed region, use newly bound sessions
for migration rather than editing existing bindings, verify replay stores and
database recovery points in the destination, and reconcile match outcomes by
action ID before resuming rewards.

## Excessive false positives

Move the responsible rule to shadow or roll back, stop automated session
recommendations, preserve versioned findings, measure affected cohorts, notify
game operators, and correct prior enforcement through their appeal process.

## Privacy incident

Stop collection/access, preserve access audit logs, determine data categories,
players, regions, and retention exposure, revoke identities, notify the operator
and required authorities, and delete data only after evidence-preservation needs
are satisfied.
