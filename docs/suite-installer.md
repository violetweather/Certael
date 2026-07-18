# Install and manage the Certael suite

`certaelctl` installs Core services, workers, the console, deployment files,
server SDKs, provider integrations, and the selected engine adapter from one
signed release manifest. The command-line workflow and the native setup
application use the same transactional installer library and installed-state
format.

## Desktop setup application

For a guided operating-system UI, download the `certael-setup-<runtime>` archive
for your platform from the same GitHub release as the signed suite manifest and
trust store. Extract it, then run `Certael.Setup.exe` on Windows or
`Certael.Setup` on Linux/macOS.

The app supports install, update, repair, inventory inspection, uninstall, and
interrupted-plan recovery. Each operation follows three explicit phases:

1. choose the signed inputs, project configuration, destination, and runtime;
2. verify the signature and review the exact resolved components before any
   mutation;
3. apply the recoverable transaction while showing a redacted live transcript.

The technical-details panel is intentionally verbose. It records downloads,
digest checks, operations, rollback, plan IDs, and journal paths, while redacting
secret-shaped values before display or export. The UI never runs source code or
unsigned release scripts and never substitutes weaker behavior after a failure.
For automation, air-gapped procedures, and exact command transcripts, use the
equivalent `certaelctl` commands below.

The installer does not download source code or run arbitrary release scripts.
It accepts only a canonical manifest signed by a trusted Certael release key,
downloads artifacts over HTTPS, verifies their signed size and SHA-256 digest,
preflights every ZIP, and then applies one recoverable transaction.

## Prerequisites

- A supported 64-bit platform: Windows x64, Linux x64, macOS x64, or macOS arm64.
- The `certaelctl` package, signed suite manifest, and release-key trust store
  from the same official GitHub release.
- .NET 10 for framework-dependent service and command packages.
- Docker with Compose when using the bundled self-hosted deployment profile.
- An empty installation directory, or a directory without paths owned by the
  selected Certael components.

Use one of these runtime identifiers:

| Platform | Runtime identifier |
|---|---|
| Windows x64 | `win-x64` |
| Linux x64 | `linux-x64` |
| macOS Apple silicon | `osx-arm64` |
| macOS Intel | `osx-x64` |

## 1. Create the project selection

The project file records the engine, authoritative-server runtime, deployment
mode, identity provider, and components. This example selects Unreal, .NET, and
Auth0 for a development environment:

```powershell
certaelctl project init C:\Games\Example "Example Game" unreal dotnet development auth0
```

```bash
certaelctl project init ./example "Example Game" unreal dotnet development auth0
```

Edit `certael.yaml` only before installation. Provider selections such as Steam,
EOS, PlayFab, and Agones add their isolated integration package automatically.
Production configurations reject the development identity provider.

## 2. Verify and install the signed release

Keep the signed envelope and trust store separate from the installation root.
Replace the example version and paths with exact files from the release:

```powershell
certaelctl suite verify .\certael-suite-vX.Y.Z.signed.json .\certael-release-keys.json
certaelctl suite install .\certael-suite-vX.Y.Z.signed.json .\certael-release-keys.json `
  C:\Games\Example\certael.yaml win-x64 C:\Games\Example C:\CertaelCache
```

```bash
certaelctl suite verify ./certael-suite-vX.Y.Z.signed.json ./certael-release-keys.json
certaelctl suite install ./certael-suite-vX.Y.Z.signed.json ./certael-release-keys.json \
  ./example/certael.yaml linux-x64 ./example ~/.cache/certael
```

The command reports every download, verification, operation, rollback, and
journal path. Secret-shaped values are redacted. A successful installation
writes `.certael/installed-state.json` with the exact component version,
artifact digest, file size, and file digest for every managed file.

The installer rejects, before mutation:

- unsigned, expired, revoked, noncanonical, or tampered manifests;
- the wrong runtime, missing dependencies, or component version mismatches;
- path traversal, absolute paths, Windows device names, links, special files,
  case collisions, file/directory collisions, and reserved `.certael` paths;
- cross-component file ownership conflicts, oversized archives, and corrupt or
  digest-mismatched content.

## 3. Inspect, repair, update, or uninstall

Inspect compares every installed file with the signed inventory and returns a
nonzero status when anything is missing, modified, or replaced by a link:

```bash
certaelctl suite inspect ./example
```

Repair requires the manifest for the installed version. Missing files are
restored. Modified files are refused unless an operator explicitly chooses the
force option:

```bash
certaelctl suite repair ./certael-suite-vX.Y.Z.signed.json \
  ./certael-release-keys.json ./example/certael.yaml ./example ~/.cache/certael
```

Update accepts a newer signed manifest, removes retired managed files, installs
the new inventory, and replaces the state file in one transaction:

```bash
certaelctl suite update ./certael-suite-vNEXT.signed.json \
  ./certael-release-keys.json ./example/certael.yaml ./example ~/.cache/certael
```

`--force-modified` is intentionally verbose and explicit on repair, update, and
uninstall. Without it, Certael will not overwrite or remove a managed file whose
digest differs from the installed inventory. Declared operator-owned files are
preserved on uninstall.

```bash
certaelctl suite uninstall ./example
```

Every mutation writes a journal under
`.certael/transactions/<plan-id>/journal.json`. If a process or machine stops
mid-operation, use the plan ID printed by the command:

```bash
certaelctl suite recover ./example 00000000-0000-0000-0000-000000000000
```

Recovery validates every journal and backup path before restoring files. Keep
the transaction directory until installation, update, repair, or uninstall has
been verified.

## 4. Generate local deployment secrets

After installation, generate local database credentials and the coordinator
signing key without printing them:

```bash
certaelctl deployment init ./example vX.Y.Z tenant-a
```

This writes a private `.certael/deployment.env`, the coordinator public key, and
`.certael/DEPLOYMENT.md`. Start the default stack with:

```bash
docker compose --env-file .certael/deployment.env \
  -f deployment/compose/docker-compose.release.yml up -d
```

The generated secrets are suitable for an isolated development deployment, not
as a substitute for a production secret manager, certificate authority, key
rotation policy, backups, network policy, or database operations plan.

## 5. Configure the console separately

The console profile remains off until an actual identity provider and mTLS
workload identity exist. For Auth0, continue with [Operator console
setup](console-setup.md) and run `certaelctl console init-auth0`. Certael never
stores or invents the Auth0 client secrets; inject them from a secret manager or
the local environment when starting the `console` Compose profile.

## CI and unattended use

All commands are noninteractive and return nonzero on verification, drift,
configuration, download, or transaction failure. Preserve their verbose output
as a build artifact after applying the same secret-redaction policy used for
other deployment logs. Do not pass private keys, access tokens, client secrets,
or connection strings as positional command arguments.
