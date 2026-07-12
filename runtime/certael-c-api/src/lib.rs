use std::{panic::AssertUnwindSafe, ptr, slice, str};

use certael_core::{
    verify_action, ActionSequencer, CertaelError, SessionBinding, SessionState, VerifiedSession,
};
use uuid::Uuid;

const ABI_V1: u32 = 1;

pub struct CertaelClient {
    session: SessionState,
    sequencer: Option<ActionSequencer>,
}

#[repr(C)]
pub enum CertaelResult {
    Ok = 0,
    InvalidArgument = 1,
    SessionInactive = 2,
    SessionExpired = 3,
    PayloadTooLarge = 4,
    BufferTooSmall = 5,
    InvalidEnvelope = 6,
    InvalidProof = 7,
    InternalError = 255,
}

#[repr(C)]
pub struct BytesView {
    data: *const u8,
    length: usize,
}
#[repr(C)]
pub struct StringView {
    data: *const u8,
    length: usize,
}

#[repr(C)]
pub struct SessionBindingV1 {
    struct_size: usize,
    abi_version: u32,
    session_id: StringView,
    game_id: StringView,
    environment_id: StringView,
    match_id: StringView,
    build_id: StringView,
    now_unix: i64,
    expires_at_unix: i64,
    binding_digest: BytesView,
    initial_sequence: u64,
}

#[repr(C)]
pub struct ActionRequestV1 {
    struct_size: usize,
    abi_version: u32,
    action_type: StringView,
    request_schema: StringView,
    schema_version: u32,
    now_unix: i64,
    client_monotonic_micros: i64,
    payload: BytesView,
}

#[repr(C)]
pub struct VerifiedSessionV1 {
    struct_size: usize,
    abi_version: u32,
    expected_session_id: StringView,
    expected_binding_digest: BytesView,
    ephemeral_public_key: BytesView,
    protocol_minimum: u32,
    protocol_maximum: u32,
}

#[repr(C)]
pub struct VerifiedActionV1 {
    struct_size: usize,
    abi_version: u32,
    sequence: u64,
    action_id: [u8; 16],
    action_digest: [u8; 32],
    schema_version: u32,
    client_monotonic_micros: i64,
    payload_length: usize,
    action_type: [u8; 129],
    action_type_length: usize,
    request_schema: [u8; 129],
    request_schema_length: usize,
    previous_action_digest: [u8; 32],
}

fn map_error(error: CertaelError) -> CertaelResult {
    match error {
        CertaelError::InvalidArgument | CertaelError::InvalidActionType => {
            CertaelResult::InvalidArgument
        }
        CertaelError::SessionInactive => CertaelResult::SessionInactive,
        CertaelError::SessionExpired => CertaelResult::SessionExpired,
        CertaelError::PayloadTooLarge => CertaelResult::PayloadTooLarge,
        CertaelError::InvalidEnvelope | CertaelError::NonCanonicalEnvelope => {
            CertaelResult::InvalidEnvelope
        }
        _ => CertaelResult::InternalError,
    }
}

unsafe fn bytes<'a>(view: &BytesView, maximum: usize) -> Option<&'a [u8]> {
    if view.length > maximum || (view.length > 0 && view.data.is_null()) {
        return None;
    }
    Some(if view.length == 0 {
        &[]
    } else {
        slice::from_raw_parts(view.data, view.length)
    })
}

unsafe fn string(view: &StringView) -> Option<String> {
    let value = bytes(
        &BytesView {
            data: view.data,
            length: view.length,
        },
        128,
    )?;
    str::from_utf8(value).ok().map(ToOwned::to_owned)
}

/// Creates a client runtime.
/// # Safety
/// `output` must point to writable storage for one pointer.
unsafe fn client_create_impl(output: *mut *mut CertaelClient) -> CertaelResult {
    if output.is_null() {
        return CertaelResult::InvalidArgument;
    }
    *output = Box::into_raw(Box::new(CertaelClient {
        session: SessionState::new(),
        sequencer: None,
    }));
    CertaelResult::Ok
}

/// Copies the client's public key.
/// # Safety
/// `client` must be live and `output` must reference at least `length` writable bytes.
unsafe fn client_public_key_impl(
    client: *const CertaelClient,
    output: *mut u8,
    length: usize,
) -> CertaelResult {
    if client.is_null() || output.is_null() || length < 32 {
        return CertaelResult::InvalidArgument;
    }
    ptr::copy_nonoverlapping((*client).session.public_key().as_ptr(), output, 32);
    CertaelResult::Ok
}

/// Signs a redemption challenge.
/// # Safety
/// All non-null pointers must reference the declared readable or writable lengths.
unsafe fn client_sign_redemption_impl(
    client: *const CertaelClient,
    ticket_id: *const u8,
    ticket_id_length: usize,
    challenge: *const u8,
    challenge_length: usize,
    signature: *mut u8,
    signature_length: usize,
) -> CertaelResult {
    if client.is_null()
        || ticket_id.is_null()
        || ticket_id_length != 16
        || challenge.is_null()
        || !(16..=256).contains(&challenge_length)
        || signature.is_null()
        || signature_length < 64
    {
        return CertaelResult::InvalidArgument;
    }
    let id = match Uuid::from_slice(slice::from_raw_parts(ticket_id, 16)) {
        Ok(v) => v,
        Err(_) => return CertaelResult::InvalidArgument,
    };
    match (*client)
        .session
        .sign_redemption(id, slice::from_raw_parts(challenge, challenge_length))
    {
        Ok(value) => {
            ptr::copy_nonoverlapping(value.as_ptr(), signature, 64);
            CertaelResult::Ok
        }
        Err(error) => map_error(error),
    }
}

/// Activates a server-verified session binding.
/// # Safety
/// `client` and `value` must be live; every view in `value` must remain readable for the call.
unsafe fn client_activate_session_impl(
    client: *mut CertaelClient,
    value: *const SessionBindingV1,
) -> CertaelResult {
    if client.is_null() || value.is_null() {
        return CertaelResult::InvalidArgument;
    }
    let value = &*value;
    if value.struct_size != std::mem::size_of::<SessionBindingV1>() || value.abi_version != ABI_V1 {
        return CertaelResult::InvalidArgument;
    }
    let digest = match bytes(&value.binding_digest, 32).and_then(|v| <[u8; 32]>::try_from(v).ok()) {
        Some(v) => v,
        None => return CertaelResult::InvalidArgument,
    };
    let binding = SessionBinding {
        session_id: match string(&value.session_id) {
            Some(v) => v,
            None => return CertaelResult::InvalidArgument,
        },
        game_id: match string(&value.game_id) {
            Some(v) => v,
            None => return CertaelResult::InvalidArgument,
        },
        environment_id: match string(&value.environment_id) {
            Some(v) => v,
            None => return CertaelResult::InvalidArgument,
        },
        match_id: match string(&value.match_id) {
            Some(v) => v,
            None => return CertaelResult::InvalidArgument,
        },
        build_id: match string(&value.build_id) {
            Some(v) => v,
            None => return CertaelResult::InvalidArgument,
        },
        expires_at_unix: value.expires_at_unix,
        binding_digest: digest,
    };
    match (*client).session.activate(binding, value.now_unix) {
        Ok(()) => {
            (*client).sequencer = Some(ActionSequencer::new(value.initial_sequence));
            CertaelResult::Ok
        }
        Err(error) => map_error(error),
    }
}

/// Creates a canonical signed action envelope.
/// # Safety
/// The client must be exclusively borrowed and all request/output pointers must cover their declared lengths.
unsafe fn client_authorize_action_v1_impl(
    client: *mut CertaelClient,
    request: *const ActionRequestV1,
    output: *mut u8,
    output_capacity: usize,
    output_length: *mut usize,
) -> CertaelResult {
    if client.is_null() || request.is_null() || output_length.is_null() {
        return CertaelResult::InvalidArgument;
    }
    let request = &*request;
    if request.struct_size != std::mem::size_of::<ActionRequestV1>()
        || request.abi_version != ABI_V1
    {
        return CertaelResult::InvalidArgument;
    }
    let action_type = match string(&request.action_type) {
        Some(v) => v,
        None => return CertaelResult::InvalidArgument,
    };
    let schema = match string(&request.request_schema) {
        Some(v) => v,
        None => return CertaelResult::InvalidArgument,
    };
    let payload = match bytes(&request.payload, 64 * 1024) {
        Some(v) => v.to_vec(),
        None => return CertaelResult::PayloadTooLarge,
    };
    let required_capacity = match payload.len().checked_add(2048) {
        Some(value) => value,
        None => return CertaelResult::InvalidArgument,
    };
    *output_length = required_capacity;
    if output.is_null() || output_capacity < required_capacity {
        return CertaelResult::BufferTooSmall;
    }
    let sequencer = match (*client).sequencer.as_mut() {
        Some(v) => v,
        None => return CertaelResult::SessionInactive,
    };
    let envelope = match sequencer.authorize(
        &(*client).session,
        request.now_unix,
        &action_type,
        &schema,
        request.schema_version,
        request.client_monotonic_micros,
        payload,
    ) {
        Ok(v) => v,
        Err(e) => return map_error(e),
    };
    let encoded = match envelope.encode() {
        Ok(v) => v,
        Err(e) => return map_error(e),
    };
    *output_length = encoded.len();
    ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
    CertaelResult::Ok
}

/// Strictly decodes and verifies an action proof against a trusted session.
/// # Safety
/// All structures and buffers must be valid for the declared lengths for the duration of the call.
unsafe fn server_verify_action_v1_impl(
    session: *const VerifiedSessionV1,
    input: *const u8,
    input_length: usize,
    payload_output: *mut u8,
    payload_capacity: usize,
    result: *mut VerifiedActionV1,
) -> CertaelResult {
    if session.is_null() || input.is_null() || result.is_null() {
        return CertaelResult::InvalidArgument;
    }
    if input_length == 0 || input_length > 64 * 1024 + 2048 {
        return CertaelResult::InvalidEnvelope;
    }
    let session = &*session;
    let result_ref = &mut *result;
    if session.struct_size != std::mem::size_of::<VerifiedSessionV1>()
        || session.abi_version != ABI_V1
        || result_ref.struct_size != std::mem::size_of::<VerifiedActionV1>()
        || result_ref.abi_version != ABI_V1
        || session.protocol_minimum == 0
        || session.protocol_maximum < session.protocol_minimum
    {
        return CertaelResult::InvalidArgument;
    }
    let expected_id = match string(&session.expected_session_id) {
        Some(v) => v,
        None => return CertaelResult::InvalidArgument,
    };
    let expected_digest = match bytes(&session.expected_binding_digest, 32) {
        Some(v) if v.len() == 32 => v,
        _ => return CertaelResult::InvalidArgument,
    };
    let public = match bytes(&session.ephemeral_public_key, 32) {
        Some(v) if v.len() == 32 => v,
        _ => return CertaelResult::InvalidArgument,
    };
    let public: &[u8; 32] = match public.try_into() {
        Ok(v) => v,
        Err(_) => return CertaelResult::InvalidArgument,
    };
    let digest: &[u8; 32] = match expected_digest.try_into() {
        Ok(v) => v,
        Err(_) => return CertaelResult::InvalidArgument,
    };
    let verified = match verify_action(
        slice::from_raw_parts(input, input_length),
        &VerifiedSession {
            session_id: &expected_id,
            binding_digest: digest,
            ephemeral_public_key: public,
            protocol_minimum: session.protocol_minimum,
            protocol_maximum: session.protocol_maximum,
        },
    ) {
        Ok(v) => v,
        Err(CertaelError::Cryptography) => return CertaelResult::InvalidProof,
        Err(e) => return map_error(e),
    };
    let envelope = verified.envelope;
    if envelope.payload.len() > payload_capacity
        || (payload_capacity > 0 && payload_output.is_null())
    {
        return CertaelResult::BufferTooSmall;
    }
    if !envelope.payload.is_empty() {
        ptr::copy_nonoverlapping(
            envelope.payload.as_ptr(),
            payload_output,
            envelope.payload.len(),
        );
    }
    result_ref.sequence = envelope.sequence;
    result_ref.action_id = *envelope.action_id.as_bytes();
    result_ref.action_digest = verified.signed_digest;
    result_ref.schema_version = envelope.schema_version;
    result_ref.client_monotonic_micros = envelope.client_monotonic_micros;
    result_ref.payload_length = envelope.payload.len();
    result_ref.action_type.fill(0);
    result_ref.action_type[..envelope.action_type.len()]
        .copy_from_slice(envelope.action_type.as_bytes());
    result_ref.action_type_length = envelope.action_type.len();
    result_ref.request_schema.fill(0);
    result_ref.request_schema[..envelope.request_schema.len()]
        .copy_from_slice(envelope.request_schema.as_bytes());
    result_ref.request_schema_length = envelope.request_schema.len();
    result_ref.previous_action_digest = envelope.previous_action_digest;
    CertaelResult::Ok
}

/// Destroys a client once.
/// # Safety
/// `client` must be null or a pointer returned by `certael_client_create` that has not been destroyed.
unsafe fn client_destroy_impl(client: *mut CertaelClient) {
    if !client.is_null() {
        drop(Box::from_raw(client));
    }
}

fn ffi_result(operation: impl FnOnce() -> CertaelResult) -> CertaelResult {
    std::panic::catch_unwind(AssertUnwindSafe(operation)).unwrap_or(CertaelResult::InternalError)
}

#[no_mangle]
/// Creates a client runtime.
/// # Safety
/// `output` must point to writable storage for one pointer.
pub unsafe extern "C" fn certael_client_create(output: *mut *mut CertaelClient) -> CertaelResult {
    ffi_result(|| client_create_impl(output))
}

#[no_mangle]
/// Copies the client's public key.
/// # Safety
/// `client` must be live and `output` must reference at least `length` writable bytes.
pub unsafe extern "C" fn certael_client_public_key(
    client: *const CertaelClient,
    output: *mut u8,
    length: usize,
) -> CertaelResult {
    ffi_result(|| client_public_key_impl(client, output, length))
}

#[no_mangle]
/// Signs a ticket redemption challenge.
/// # Safety
/// Every pointer must remain valid for its declared length for the duration of the call.
pub unsafe extern "C" fn certael_client_sign_redemption(
    client: *const CertaelClient,
    ticket_id: *const u8,
    ticket_id_length: usize,
    challenge: *const u8,
    challenge_length: usize,
    signature: *mut u8,
    signature_length: usize,
) -> CertaelResult {
    ffi_result(|| {
        client_sign_redemption_impl(
            client,
            ticket_id,
            ticket_id_length,
            challenge,
            challenge_length,
            signature,
            signature_length,
        )
    })
}

#[no_mangle]
/// Activates a server-verified session binding.
/// # Safety
/// `client`, `value`, and every view contained in `value` must be valid for the call.
pub unsafe extern "C" fn certael_client_activate_session(
    client: *mut CertaelClient,
    value: *const SessionBindingV1,
) -> CertaelResult {
    ffi_result(|| client_activate_session_impl(client, value))
}

#[no_mangle]
/// Produces a canonical, signed protocol-v1 action envelope.
/// # Safety
/// The client must be exclusively borrowed and all buffers must be valid for their declared lengths.
pub unsafe extern "C" fn certael_client_authorize_action_v1(
    client: *mut CertaelClient,
    request: *const ActionRequestV1,
    output: *mut u8,
    output_capacity: usize,
    output_length: *mut usize,
) -> CertaelResult {
    ffi_result(|| {
        client_authorize_action_v1_impl(client, request, output, output_capacity, output_length)
    })
}

#[no_mangle]
/// Verifies a canonical protocol-v1 action envelope against a trusted session.
/// # Safety
/// All structures and buffers must be valid for their declared lengths for the duration of the call.
pub unsafe extern "C" fn certael_server_verify_action_v1(
    session: *const VerifiedSessionV1,
    input: *const u8,
    input_length: usize,
    payload_output: *mut u8,
    payload_capacity: usize,
    result: *mut VerifiedActionV1,
) -> CertaelResult {
    ffi_result(|| {
        server_verify_action_v1_impl(
            session,
            input,
            input_length,
            payload_output,
            payload_capacity,
            result,
        )
    })
}

#[no_mangle]
/// Destroys a client exactly once.
/// # Safety
/// `client` must be null or a pointer returned by `certael_client_create` that has not been destroyed.
pub unsafe extern "C" fn certael_client_destroy(client: *mut CertaelClient) {
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| client_destroy_impl(client)));
}
