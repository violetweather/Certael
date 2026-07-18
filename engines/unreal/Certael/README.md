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

## Blueprint-first flow

Every existing subsystem call remains available, and the `Try ...` nodes add
separate success/failure execution pins plus an `FCertaelOperationResult` with a
stable error category and public reason. A typical Blueprint flow is:

1. Use **Get Certael Subsystem**. Treat a null result as protected play being
   unavailable; never silently bypass protection.
2. Call `Try Create Session Public Key` and send the 32-byte output through the
   game's existing authenticated networking layer.
3. Pass the server ticket and challenge to `Try Sign Redemption`.
4. Populate `FCertaelSessionBinding` only from the server response, then call
   `Try Activate Session`.
5. Serialize the game-specific request with the game's canonical codec and call
   `Try Authorize Action`. Send the envelope to the authoritative server.

Blueprints may bind to `OnSessionActivated`, `OnActionAuthorized`,
`OnAgentConnected`, and `OnAgentConnectionChanged`. These events report client
lifecycle only; they do not confirm that the server accepted or committed a
gameplay mutation.

## Optional Agent flow

When Certael Agent launched the game:

1. Call `ConnectToInheritedAgent` and send the returned hello bytes/fields to the
   trusted dedicated server.
2. The server calls Certael's authenticated Agent launch API with its workload
   identity and the hello's public key/build.
3. Relay only the returned signed policy, signed grant, and signed build
   manifest to `BindAgentLaunchBundle`.
4. For each server-issued canonical challenge, use `Exchange Certael Agent
   Challenge (Async)` and forward the Success report unchanged. The node runs
   evidence collection on a worker thread and completes on the game thread with
   typed Success and Failure pins.
5. Call `ShutdownAgent` on logout, account switch, match exit, or server migration,
   and revoke the old Agent session on the server.

The C++ `ExchangeAgentChallenge` call still blocks while evidence is collected
and is intentionally not exposed as a Blueprint node. Blueprint code must
not create policies, grants, signatures, or security-sensitive JSON. Agent
observations are advisory and cannot independently punish an account.
