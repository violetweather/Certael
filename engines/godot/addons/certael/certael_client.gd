extends Node

signal session_ready(session_id: String)
signal session_failed(public_reason: String)

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

func activate_session(verified_binding_json: String, initial_sequence: int) -> bool:
	assert(_native != null, "Call initialize first")
	return _native.activate_session(verified_binding_json, initial_sequence)

## Returns a replay-resistant envelope containing untrusted player intent.
## The authoritative game server must validate and perform the action.
func authorize_action(action_type: String, schema_version: int, payload: PackedByteArray) -> PackedByteArray:
	assert(_native != null, "Call initialize first")
	return _native.authorize_action(action_type, schema_version, payload)
