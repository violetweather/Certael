# Version support and withdrawals

Certael uses a short-lived, Ed25519-signed compatibility manifest to decide
whether a Core, Agent, engine adapter, or server SDK may start a new protected
session. A repository tag, package filename, or client-supplied version does not
make a component supported.

## Decision states

| State | New protected session | Operator meaning |
|---|---:|---|
| `Supported` | allowed | Current supported and recommended version |
| `Deprecated` | allowed | Still supported; schedule the recommended update |
| `UpdateRequired` | denied | Below the minimum version or protocol |
| `Revoked` | denied | Exact version withdrawn for a security or integrity issue |
| `Unknown` | denied | Product or protocol is newer or unknown |
| `Indeterminate` | denied | Policy is missing, expired, malformed, or unverifiable |

An admitted match is not disconnected only because the compatibility manifest
expires. This is the bounded degraded mode for a control-plane outage. New
protected sessions fail closed. Explicit session, build, or signing-key
revocation remains effective through its normal channel.

## Production configuration

Generate a compatibility-only offline Ed25519 keypair. It must not be the
bootstrap-ticket, Agent-policy, rule-pack, or TUF key. Keep the private key
offline and install only the 32-byte public key on API hosts.

Create a source JSON document with a validity period no longer than 32 days:

```json
{
  "schema_version": 1,
  "revision": 42,
  "issued_at": "2026-07-15T00:00:00Z",
  "expires_at": "2026-08-14T00:00:00Z",
  "products": [
    {
      "product": "Core",
      "minimum_supported_version": "0.3.0-alpha.2",
      "recommended_version": "0.3.0-alpha.2",
      "minimum_protocol_version": 1,
      "maximum_protocol_version": 1
    },
    {
      "product": "Agent",
      "minimum_supported_version": "0.3.0-alpha.2",
      "recommended_version": "0.3.0-alpha.3",
      "minimum_protocol_version": 1,
      "maximum_protocol_version": 1
    }
  ],
  "revocations": []
}
```

Include every deployed product: `Core`, `Agent`, `GodotAdapter`,
`UnityAdapter`, `UnrealAdapter`, `DotNetServerSdk`, and `NativeServerSdk`.
Then sign and inspect it:

```bash
dotnet run --project cli/Certael.Cli -- compatibility generate-development-key \
  compatibility-development compatibility-offline.key compatibility-trust-store.json

dotnet run --project cli/Certael.Cli -- compatibility sign \
  compatibility-source.json compatibility-offline.key compatibility-2026-01 \
  compatibility.pb

dotnet run --project cli/Certael.Cli -- compatibility check \
  compatibility.pb compatibility-trust-store.json Agent 0.3.0-alpha.3 1
```

The generated private key command is for local/staging exercises only. Use a
witnessed offline release-key ceremony for production.

Configure `Compatibility:SignedManifestPath` and
`Compatibility:TrustStorePath` with the generated public trust-store JSON.
Alternatively configure overlapping `Compatibility:TrustedKeys` entries with
`KeyId`, `PublicKeyPath`, `NotBefore`, `NotAfter`, and `Revoked`. Outside
Development, startup fails if this policy is absent. Rotate before expiry.
Replacing the file currently takes a normal API deployment or restart.
Set `Compatibility:MinimumRevision` to the highest deployed revision so a
validly signed older manifest cannot be restored as a rollback.

## Build binding

Every newly registered signed whole-build manifest binds the Core SDK version,
engine adapter and version, Core C ABI, action protocol, Agent protocol, and
Agent probe ABI. Core evaluates these declarations before registration, and the
Agent verifies the same signed fields before protected admission. Alpha build
manifests made before `v0.3.0-alpha.1` must be regenerated.

## Operations

`GET /v1/status/compatibility` reports Core's current decision. Authorized
operators can call `POST /v1/admin/compatibility/check` with the
`compatibility:read` scope. OpenTelemetry exports
`certael.compatibility.decisions` by product, version, state, public reason,
and manifest revision.

To withdraw a bad component, add an exact-version revocation, increment the
revision, sign it offline, and deploy it. Use the existing build/session
revocation endpoints too when active exposure must be contained.
