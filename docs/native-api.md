# Native C and C++ API

The native API is a versioned C ABI backed by the Rust runtime. Engine adapters
use the same functions; the C++ header adds ownership-safe RAII without changing
the ABI. The native client creates authenticated request envelopes. It never
authorizes or commits gameplay state.

## ABI rules

- Every input structure begins with `struct_size` and `abi_version`.
- Set `abi_version` to `CERTAEL_ABI_VERSION_1` and `struct_size` to `sizeof` the
  exact structure used by the caller.
- String and byte views are borrowed only for the duration of a call.
- The caller owns every output buffer. Certael returns no borrowed output memory.
- Functions return `certael_result`; no Rust panic or C++ exception crosses the
  ABI boundary.
- Pointer validity and declared buffer lengths remain the caller's
  responsibility. Certael validates null pointers, sizes, UTF-8, identifier
  limits, protocol limits, and payload limits before use where the ABI permits.
- A client pointer must be destroyed exactly once with
  `certael_client_destroy`. Passing an already-destroyed pointer is invalid.

Include [certael.h](../runtime/certael-c-api/include/certael.h) from C or
[certael.hpp](../runtime/certael-c-api/include/certael.hpp) from C++.

## Client lifecycle

1. `certael_client_create` creates an ephemeral Ed25519 identity.
2. `certael_client_public_key` copies its 32-byte public key.
3. `certael_client_sign_redemption` signs a 16–256 byte server challenge under
   `certael.redeem.v1\0` and the canonical 16-byte ticket ID.
4. After the server redeems the ticket, populate
   `certael_session_binding_v1` exclusively from the authenticated server
   response and call `certael_client_activate_session`.
5. For each typed request, populate `certael_action_request_v1` and call
   `certael_client_authorize_action_v1`.
6. Destroy the client on logout, match exit, account switch, server migration,
   or rebootstrap.

Session activation requires the session/game/environment/match/build fields,
current and expiry times, the opaque 32-byte server binding digest, and initial
sequence. An expired or malformed binding fails closed.

## Output-buffer contract

`certael_client_authorize_action_v1` supports a size query. Pass a null output or
insufficient capacity and it returns `CERTAEL_BUFFER_TOO_SMALL` while writing a
safe required capacity to `output_length`. This does **not** consume a sequence
number. Allocate that capacity and call again; success replaces
`output_length` with the exact encoded length.

The payload limit is 64 KiB. Godot, Unity, and Unreal adapters allocate payload
length plus the required envelope overhead, so normal adapter callers do not
perform this negotiation themselves.

## Native server verification

`certael_server_verify_action_v1` strictly decodes canonical protocol-v1 bytes,
checks the permitted protocol range, exact session ID and binding digest, and
verifies the Ed25519 possession proof. On success it fills
`certael_verified_action_v1` and copies the request payload into caller-owned
storage.

This function performs cryptographic and protocol admission only. A successful
result does **not** authorize the action. The authoritative server must still:

1. load the tenant-owned active session;
2. atomically enforce contiguous sequence, digest chain, replay, and rate state;
3. validate the registered request schema;
4. evaluate signed rules and trusted game callbacks against authoritative state;
5. atomically commit the mutation, result, and authoritative event.

The .NET safe-path equivalent is
`CertaelServerEngine.ValidateAndExecuteAsync`. Native dedicated servers supply
their own authoritative simulation and persistence around the verifier.

## Result handling

Treat these categories distinctly:

- `CERTAEL_INVALID_ARGUMENT`: caller ABI, structure, pointer, identifier, or
  request problem;
- `CERTAEL_SESSION_INACTIVE` / `CERTAEL_SESSION_EXPIRED`: rebootstrap through the
  authoritative server;
- `CERTAEL_PAYLOAD_TOO_LARGE`: reject before sending;
- `CERTAEL_BUFFER_TOO_SMALL`: resize without consuming an action sequence;
- `CERTAEL_INVALID_ENVELOPE` / `CERTAEL_INVALID_PROOF`: reject and record only
  minimized evidence;
- `CERTAEL_INTERNAL_ERROR`: fail closed and reconcile authoritative state.

Never translate an error into an unsigned or permissive fallback envelope.
