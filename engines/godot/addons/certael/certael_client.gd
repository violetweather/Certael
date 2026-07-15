extends Node

signal session_ready(session_id: String)
signal session_failed(public_reason: String)
signal agent_health_changed(state: String, public_reason: String)

var _native: Object

func initialize() -> bool:
	if not ClassDB.class_exists("CertaelNative"):
		push_error("Certael native GDExtension is missing for this export platform")
		return false
	_native = ClassDB.instantiate("CertaelNative")
	return _native.initialize()

func create_session_public_key() -> PackedByteArray:
	assert(_native != null, "Call initialize first")
	return _native.create_session_public_key()

func sign_redemption(ticket_id: PackedByteArray, challenge: PackedByteArray) -> PackedByteArray:
	assert(_native != null, "Call initialize first")
	return _native.sign_redemption(ticket_id, challenge)

func activate_session(verified_binding: Dictionary) -> bool:
	assert(_native != null, "Call initialize first")
	return _native.activate_session(verified_binding)

## Returns a replay-resistant envelope containing untrusted player intent.
## The authoritative game server must validate and perform the action.
func authorize_action(action_type: String, request_schema: String, schema_version: int, payload: PackedByteArray) -> PackedByteArray:
	assert(_native != null, "Call initialize first")
	return _native.authorize_action(action_type, request_schema, schema_version, payload)

## Connects to the private channel inherited from Certael Agent and validates its
## canonical hello. The game must have been started by the Agent.
func connect_agent(probe_path: String = "") -> bool:
	assert(_native != null, "Call initialize first")
	var connected: bool = _native.agent_connect(probe_path)
	agent_health_changed.emit(agent_state(), agent_last_error())
	return connected

## Returns protocol_version, agent_version, agent_public_key, build_id, and
## executable_sha256. Returns an empty Dictionary while disconnected.
func agent_hello() -> Dictionary:
	assert(_native != null, "Call initialize first")
	return _native.agent_get_hello()

## Sends the exact signed policy, server-bound launch grant, and whole-build
## manifest returned by the authoritative server. Never construct them here.
func bind_agent_launch(signed_policy: PackedByteArray, signed_grant: PackedByteArray,
		signed_build_manifest: PackedByteArray) -> bool:
	assert(_native != null, "Call initialize first")
	var bound: bool = _native.agent_bind_launch_bundle(signed_policy, signed_grant,
		signed_build_manifest)
	agent_health_changed.emit(agent_state(), agent_last_error())
	return bound

## Sends one canonical server challenge and blocks until the Agent returns its
## signed integrity report. Call from a WorkerThreadPool task, not the main thread.
func exchange_agent_challenge(canonical_challenge: PackedByteArray) -> PackedByteArray:
	assert(_native != null, "Call initialize first")
	var report: PackedByteArray = _native.agent_exchange_challenge(canonical_challenge)
	call_deferred("_emit_agent_health")
	return report

## Relays the exact signed revocation returned by the authoritative server.
func revoke_agent_session(signed_revocation: PackedByteArray) -> bool:
	return _native != null and _native.agent_send_revocation(signed_revocation)

func _emit_agent_health() -> void:
	agent_health_changed.emit(agent_state(), agent_last_error())

## Requests an orderly Agent shutdown and closes the inherited channel.
func shutdown_agent() -> void:
	if _native == null:
		return
	_native.agent_shutdown()
	agent_health_changed.emit(agent_state(), agent_last_error())

## Closes only the game-side channel; it does not request Agent shutdown.
func disconnect_agent() -> void:
	if _native == null:
		return
	_native.agent_disconnect()
	agent_health_changed.emit(agent_state(), agent_last_error())

func agent_state() -> String:
	return "disconnected" if _native == null else _native.agent_get_state()

func agent_last_error() -> String:
	return "AGENT_NOT_CONNECTED" if _native == null else _native.agent_get_last_error()
