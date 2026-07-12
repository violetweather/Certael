# Install a prebuilt Certael package

This is the shortest path for game developers. A normal installation does not
require Rust, SCons, `godot-cpp`, Visual Studio Build Tools, or MinGW.

> Certael releases are currently pre-1.0 development previews. Use the package
> that exactly matches the engine and platform versions shown below, and test it
> in a non-production environment before protecting real players.

## 1. Download from the official release

Open the [Certael Releases page](https://github.com/violetweather/Certael/releases)
and select the newest successful pre-release. Do not use files copied to an
unofficial mirror.

Choose one engine package:

| Game engine | Download |
|---|---|
| Godot 4.7 | `certael-godot-4.7-vX.Y.Z.zip` |
| Unity 6000.3 | `certael-unity-6000.3-vX.Y.Z.tgz` |
| Unreal Engine 5.8 | `certael-unreal-5.8-vX.Y.Z.zip` |

Server and native integrators can instead use the `certael-managed-*` or
`certael-native-<platform>-*` archives attached to the same release. The backend
container is published at `ghcr.io/violetweather/certael-api` and should be
deployed by immutable digest, not a floating tag.

If the release workflow is red or the expected archive is absent, stop. A
partially successful workflow is not a published Certael release.

## 2. Verify the download

Download `checksums-sha256.txt` from the same release. From the directory that
contains both files, compare the package with the published checksum.

On Windows PowerShell:

```powershell
Get-FileHash .\certael-godot-4.7-vX.Y.Z.zip -Algorithm SHA256
Select-String -Path .\checksums-sha256.txt -Pattern "certael-godot-4.7-vX.Y.Z.zip"
```

On Linux:

```bash
sha256sum --check checksums-sha256.txt --ignore-missing
```

On macOS:

```bash
shasum -a 256 certael-godot-4.7-vX.Y.Z.zip
grep 'certael-godot-4.7-vX.Y.Z.zip' checksums-sha256.txt
```

The two hashes must be identical. Advanced users can also verify the attached
Sigstore bundle and GitHub artifact attestation; see [Release process](releasing.md).

## 3. Install the engine package

### Godot 4.7

1. Close the Godot editor.
2. Extract the archive into the project root. The result must contain
   `res://addons/certael/plugin.cfg` and `res://addons/certael/bin/`.
3. Reopen the project and enable **Certael** under
   **Project Settings → Plugins**.
4. Run the project and export a development build for the target platform.

Do not move individual files out of `addons/certael`; the `.gdextension` file
uses that package layout to find each platform library.

### Unity 6000.3

1. Open **Window → Package Management → Package Manager**.
2. Select **+ → Add package from tarball**.
3. Choose `certael-unity-6000.3-vX.Y.Z.tgz` without extracting it.
4. Open Certael's editor diagnostics and confirm the native library is available.
5. Test both an Editor session and an IL2CPP development player.

### Unreal Engine 5.8

1. Close the Unreal editor.
2. Extract the archive as `<Project>/Plugins/Certael/`.
3. Regenerate project files, build the normal game target, and enable the
   Certael plugin.
4. Package a development build and confirm its staged runtime dependencies.

Unreal packages include the C++/Blueprint adapter and prebuilt Certael native
runtime. Building the game or plugin with Unreal's normal toolchain may still be
required; building Rust is not.

## 4. Connect it safely

Installing the client package alone does not protect gameplay. Complete these
steps before treating an action as protected:

1. Run Certael beside a trusted, authoritative game server.
2. Bootstrap a bound session using the flow in [Authorization](authorization.md).
3. Have the client create a signed action envelope.
4. Send that envelope through the game's authenticated network connection.
5. Validate and execute it against server-owned state using the server SDK.
6. Apply only the authoritative server response on the client.

Start with one low-risk action and follow [Protect one action](getting-started.md#4-protect-one-action).
Never put a server credential, ticket-signing key, or database password in a
Godot, Unity, or Unreal project.

## 5. Confirm the installation

Before adding more rules, verify all of the following:

- the adapter creates a 32-byte ephemeral public key;
- a server challenge can be signed and redeemed once;
- a verified session binding activates successfully;
- a normal action is accepted by the authoritative server;
- changing one payload byte causes rejection;
- replaying the envelope does not repeat the mutation;
- a packaged game contains and loads the correct platform library.

If a native library is missing, do not add a dummy replacement or copy a library
from another platform. See [Troubleshooting](troubleshooting.md).

## Updating

Treat every pre-1.0 package as an explicit upgrade. Read the release notes,
download and verify the complete new archive, replace the package as a unit, and
rerun session, tamper, replay, and packaged-player tests. Do not mix binaries
from different Certael versions.
