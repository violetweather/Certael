# Godot, Unity, and Unreal integration

All adapters wrap the same Rust runtime through its stable C ABI. They create
signed request envelopes; they never authorize gameplay state. Keep the envelope
on the game's authenticated client-to-server channel rather than sending it
directly to a gameplay database or trusting it locally.

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

## Godot 4.3+

### Install

1. Copy `engines/godot/addons/certael` to `res://addons/certael`.
2. Build the Rust `certael-c-api` library and the GDExtension wrapper in
   `engines/godot` using the platform toolchain and `godot-cpp` dependency.
3. Put each signed native binary at the path declared in
   `certael.gdextension`; update that file when using a different layout.
4. Enable Certael under **Project Settings → Plugins**.
5. Export every supported target and confirm the extension loads outside the
   editor. Missing platform binaries must fail the export preflight.

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

func on_certael_session(binding_json: String, initial_sequence: int) -> void:
    if not certael.activate_session(binding_json, initial_sequence):
        push_error("Certael session activation failed")

func request_craft(payload: PackedByteArray) -> void:
    var envelope := certael.authorize_action("inventory.craft", 1, payload)
    game_network.send_authoritative_action(envelope)
```

The named `game_network` methods are integration placeholders for the project's
existing authenticated multiplayer transport, not methods supplied by Certael.

## Unity 2022 LTS+

### Install

1. Add `engines/unity` as a local package with Unity Package Manager.
2. Place the signed native library in appropriate package runtime directories
   and set import targets for each OS/architecture.
3. Preserve the native library name expected by `CertaelNative.cs`.
4. Test Editor/Mono and player/IL2CPP builds. Include AOT and stripping checks.

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

    public void Activate(string verifiedBindingJson, ulong initialSequence) =>
        certael.ActivateSession(verifiedBindingJson, initialSequence);

    public void RequestCraft(byte[] typedPayload) =>
        network.SendAuthoritativeAction(
            certael.AuthorizeAction("inventory.craft", 1, typedPayload));

    public void Dispose() => certael.Dispose();
}
```

`IGameNetwork` is illustrative. Keep the `CertaelClient` out of prefabs that can
be duplicated and dispose it on logout or match transition.

## Unreal Engine 5.3+

### Install

1. Copy `engines/unreal/Certael` to the project's `Plugins` directory.
2. Place signed platform libraries where `Certael.Build.cs` expects them, or
   adjust the build rules to the project's third-party layout.
3. Regenerate project files, compile, and enable the plugin.
4. Package every target configuration; editor success alone does not validate
   staged runtime dependencies.

### Use from C++

```cpp
UCertaelSubsystem* Certael = GetGameInstance()->GetSubsystem<UCertaelSubsystem>();
TArray<uint8> PublicKey = Certael->CreateSessionPublicKey();
GameNetwork->RequestCertaelTicket(PublicKey);

TArray<uint8> Proof = Certael->SignRedemption(TicketIdBytes, Challenge);
GameNetwork->RedeemCertaelTicket(TicketIdBytes, Challenge, Proof);

if (!Certael->ActivateSession(VerifiedBindingJson, InitialSequence))
{
    // Abort protected play and surface a safe reconnect path.
}

FCertaelAuthorizedAction Action =
    Certael->AuthorizeAction(TEXT("inventory.craft"), 1, TypedPayload);
GameNetwork->SendAuthoritativeAction(Action.Envelope);
```

The subsystem is also Blueprint-callable. Build payload bytes from typed C++ or
generated schema structures; do not ask Blueprint users to hand-author security-
critical JSON.

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
