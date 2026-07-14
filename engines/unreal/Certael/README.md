# Certael for Unreal Engine 5.8

Copy the extracted `Certael` directory into the project's `Plugins` directory,
enable the plugin, and restart the editor. Release packages contain the Core
native libraries, optional Agent probe, headers, source commit, licenses, and
compatibility manifest for Windows 11 x64, Ubuntu 24.04 x64, and macOS 15.

Use `UCertaelSubsystem` from the game instance to create the ephemeral session
key, answer the server redemption challenge, activate the returned binding, and
authorize typed player intent. Send the returned envelope to the authoritative
server; never apply the requested gameplay mutation merely because the client
signed it.

## Optional Agent flow

When Certael Agent launched the game:

1. Call `ConnectToInheritedAgent` and send the returned hello bytes/fields to the
   trusted dedicated server.
2. The server calls Certael's authenticated Agent launch API with its workload
   identity and the hello's public key/build.
3. Relay only the returned signed policy and signed grant to
   `BindAgentLaunchBundle`.
4. For each server-issued canonical challenge, call `ExchangeAgentChallenge` on
   a worker thread and forward the returned signed report unchanged.
5. Call `ShutdownAgent` on logout, account switch, match exit, or server migration,
   and revoke the old Agent session on the server.

The exchange call blocks while evidence is collected. Never call it on Unreal's
game or render thread. Blueprint code must not create policies, grants, signatures,
or security-sensitive JSON. Agent observations are advisory and cannot independently
punish an account.
