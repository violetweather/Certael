# Godot 4.7, Unity 6000.3.16f1, and Unreal 5.8 integration

All adapters wrap the same Rust runtime through its stable C ABI. They create
signed request envelopes; they never authorize gameplay state. Keep the envelope
on the game's authenticated client-to-server channel rather than sending it
directly to a gameplay database or trusting it locally.

> **Current release status:** verified `v0.*` packages are development previews,
> not certified 1.0 artifacts. Follow the [prebuilt installation guide](installing-prebuilt.md)
> and never download native libraries from an unofficial mirror.

## Common lifecycle

Regardless of engine:

1. create one runtime per active player session;
2. send its 32-byte public key to the authenticated game server;
3. sign the server's random redemption challenge;
4. activate the binding returned after successful redemption;
5. serialize a typed, versioned request and authorize it;
6. send the envelope to the authoritative game server;
7. apply only the authoritative response;
8. destroy the runtime when the session ends.

Do not serialize engine objects, arbitrary dictionaries, or user-authored JSON as
game requests. Generate a stable binary payload from a schema and validate it on
the server.

## Godot 4.7

### Install

1. Download `certael-godot-4.7-vX.Y.Z.zip` from a verified Certael pre-release,
   validate its checksum/attestation, and extract it into the project root.
2. Confirm `res://addons/certael` contains the platform binaries; do not compile
   Rust, C++, SCons, or `godot-cpp` for a normal installation.
3. Enable Certael under **Project Settings → Plugins**.
4. Export every supported target and confirm the extension loads outside the
   editor. Missing platform binaries must fail the export preflight.

Maintainers and contributors may build from source with
`./scripts/build.sh all --configuration Release` or
`.\scripts\build.ps1 all -Configuration Release`. The scripts pin and fetch
`godot-cpp`, select MSVC on Windows, and fail if the real native library is absent.

### Use

```gdscript
var certael := preload("res://addons/certael/certael_client.gd").new()

func _ready() -> void:
    add_child(certael)
    if not certael.initialize():
        push_error("Certael runtime unavailable")
        return
    var public_key: PackedByteArray = certael.create_session_public_key()
    game_network.request_certael_ticket(public_key)

func on_redemption_challenge(ticket_id: PackedByteArray, challenge: PackedByteArray) -> void:
    var proof := certael.sign_redemption(ticket_id, challenge)
    game_network.redeem_certael_ticket(ticket_id, challenge, proof)

func on_certael_session(binding: Dictionary) -> void:
    if not certael.activate_session(binding):
        push_error("Certael session activation failed")

func request_craft(payload: PackedByteArray) -> void:
    var envelope := certael.authorize_action(
        "inventory.craft", "example.Craft.v1", 1, payload)
    game_network.send_authoritative_action(envelope)
```

The named `game_network` methods are integration placeholders for the project's
existing authenticated multiplayer transport, not methods supplied by Certael.

### Optional Agent lifecycle

The prebuilt Godot archive contains the matching Agent probe. The companion
Agent application is installed separately, and the game is added with a signed
per-game registration plus public trust and update roots; private signing keys
never belong in the project. Set `certael/agent/required` to `true`
only for exports that must refuse protected play when the probe is absent.
The export plugin stages the probe as a native shared object rather than packing
it into the PCK; test the exported player, not only the editor.

The Agent must launch the game so the probe inherits a private channel. Connect
once after `Certael.initialize()`, then send the validated hello to trusted
server bootstrap code:

```gdscript
func begin_protected_mode() -> void:
    if not Certael.connect_agent():
        push_error(Certael.agent_last_error())
        return
    var hello := Certael.agent_hello()
    assert(hello.agent_public_key.size() == 32)
    assert(hello.executable_sha256.size() == 32)
    game_network.begin_agent_session(hello)

func on_agent_launch_material(policy: PackedByteArray, grant: PackedByteArray) -> void:
    if not Certael.bind_agent_launch(policy, grant, signed_build_manifest):
        protected_mode_failed(Certael.agent_last_error())
```

For each canonical challenge returned by the server, use a worker task because
the local challenge/report exchange blocks while the Agent gathers its bounded
observations:

```gdscript
func relay_agent_challenge(challenge: PackedByteArray) -> void:
    WorkerThreadPool.add_task(func() -> void:
        var report := Certael.exchange_agent_challenge(challenge)
        call_deferred("_submit_agent_report", report))

func _submit_agent_report(report: PackedByteArray) -> void:
    if report.is_empty():
        protected_mode_failed(Certael.agent_last_error())
    else:
        game_network.submit_agent_report(report)
```

Call `Certael.shutdown_agent()` at logout or final game exit. On a server
migration, revoke the old Agent session, disconnect, and bootstrap a newly bound
grant. The adapter exposes `agent_state()` (`disconnected`, `ready`, `lost`, or
`update_required`) plus `agent_last_error()` and the `agent_health_changed`
signal. Local health is diagnostic; the signed server policy decides required,
optional, grace, and restriction behavior.

## Unity 6000.3.16f1

### Install

1. Download and verify `certael-unity-6000.3-vX.Y.Z.tgz`.
2. In Package Manager, choose **Add package from tarball**. Native libraries and
   import layout are included; a normal install needs no native compiler.
3. Test Editor/Mono and player/IL2CPP builds. Include AOT and stripping checks.

### Use

```csharp
using Certael.Unity;

public sealed class SecureGameSession : IDisposable
{
    private readonly CertaelClient certael = new();
    private readonly IGameNetwork network;

    public SecureGameSession(IGameNetwork network) => this.network = network;

    public void Begin() => network.RequestCertaelTicket(certael.CreateSessionPublicKey());

    public void AnswerChallenge(Guid ticketId, byte[] challenge) =>
        network.RedeemCertaelTicket(ticketId, challenge, certael.SignRedemption(ticketId, challenge));

    public void Activate(CertaelSessionBinding verifiedBinding) =>
        certael.ActivateSession(verifiedBinding);

    public void RequestCraft(byte[] typedPayload) =>
        network.SendAuthoritativeAction(
            certael.AuthorizeAction(
                "inventory.craft", "example.Craft.v1", 1, typedPayload));

    public void Dispose() => certael.Dispose();
}
```

`IGameNetwork` is illustrative. Keep the `CertaelClient` out of prefabs that can
be duplicated and dispose it on logout or match transition.

For protected modes launched by Certael Agent, create one
`CertaelAgentConnection` on a worker thread. `ConnectToInheritedAgent()` reads
and strictly validates the canonical hello. Send `GetAgentHello()` to trusted
server bootstrap code; its build ID and copied ephemeral public key are inputs
to the authenticated Agent launch API. Relay the returned signed components
with `BindAgentLaunchBundle(signedPolicy, signedGrant, signedBuildManifest)`,
then call `ExchangeChallenge` for each canonical
server challenge and forward the returned signed report unchanged. The exchange
blocks, so it must not run on Unity's render thread. Call `ShutdownAgent` at
ordinary process exit. At logout, match exit, or server migration, first call
`RevokeSession` with the signed revocation returned by Core.

The Unity adapter does not mint policies or grants and does not interpret a
report as gameplay authorization. A channel error moves local health to `Lost`;
the server applies the signed required/optional grace policy.

## Unreal Engine 5.8

### Install

1. Download and verify `certael-unreal-5.8-vX.Y.Z.zip` and extract `Certael` into
   the project's `Plugins` directory. The archive includes native headers and
   runtime libraries; Blueprint users do not compile Rust. Stable 1.0 artifacts
   additionally require platform code signing.
2. Regenerate project files, compile the normal Unreal game target, and enable
   the plugin.
3. Package every target configuration; editor success alone does not validate
   staged runtime dependencies.

### Use from C++

```cpp
UCertaelSubsystem* Certael = GetGameInstance()->GetSubsystem<UCertaelSubsystem>();
TArray<uint8> PublicKey = Certael->CreateSessionPublicKey();
GameNetwork->RequestCertaelTicket(PublicKey);

TArray<uint8> Proof = Certael->SignRedemption(TicketIdBytes, Challenge);
GameNetwork->RedeemCertaelTicket(TicketIdBytes, Challenge, Proof);

if (!Certael->ActivateSession(VerifiedBinding))
{
    // Abort protected play and surface a safe reconnect path.
}

FCertaelAuthorizedAction Action =
    Certael->AuthorizeAction(
        TEXT("inventory.craft"), TEXT("example.Craft.v1"), 1, TypedPayload);
GameNetwork->SendAuthoritativeAction(Action.Envelope);
```

### Use from Blueprints

Use **Get Certael Subsystem** and use the `Try` nodes for the
same lifecycle. They expose separate success/failure execution pins and return
an `FCertaelOperationResult` containing a stable `ECertaelBlueprintError` plus a
safe public reason. Bind to the subsystem's session, action, and Agent delegates
when an event-driven graph is clearer than a direct chain.

For Agent evidence collection, use **Exchange Certael Agent Challenge (Async)**.
It performs the blocking native exchange on a worker thread and returns to the
game thread through typed success/failure pins. The blocking C++ method is
deliberately not Blueprint-callable, so a graph cannot accidentally freeze the
game thread while Agent evidence is collected.

Build payload bytes from typed C++ or generated schema structures; session
activation is typed and Blueprint users do not hand-author security-critical
JSON. A successful action node means only that an envelope was created. The
authoritative game server still decides and commits the gameplay result.

## Platform and release checklist

- Build the Rust runtime and adapter for every OS/architecture/configuration.
- Sign libraries with the platform's normal code-signing mechanism.
- Generate a build manifest with `certaelctl manifest generate`.
- Confirm native dependencies are present in packaged builds.
- Run session and action test vectors through every adapter.
- Test suspend/resume, clock changes, reconnect, server migration, and logout.
- Treat missing or failed Certael initialization according to an explicit policy;
  competitive queues should fail closed, while offline play may disable protected
  features with a visible degraded mode.
