use std::{
    ffi::{c_char, CStr},
    ptr, slice,
};

use certael_core::{ActionSequencer, CertaelError, SessionBinding, SessionState};
use uuid::Uuid;

pub struct Runtime {
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
    InternalError = 255,
}

fn map_error(error: CertaelError) -> CertaelResult {
    match error {
        CertaelError::InvalidArgument | CertaelError::InvalidActionType => {
            CertaelResult::InvalidArgument
        }
        CertaelError::SessionInactive => CertaelResult::SessionInactive,
        CertaelError::SessionExpired => CertaelResult::SessionExpired,
        CertaelError::PayloadTooLarge => CertaelResult::PayloadTooLarge,
        _ => CertaelResult::InternalError,
    }
}

#[no_mangle]
/// Allocates a runtime.
/// # Safety
/// `output` must be writable and remain valid for one pointer-sized write.
pub unsafe extern "C" fn certael_runtime_create(output: *mut *mut Runtime) -> CertaelResult {
    if output.is_null() {
        return CertaelResult::InvalidArgument;
    }
    *output = Box::into_raw(Box::new(Runtime {
        session: SessionState::new(),
        sequencer: None,
    }));
    CertaelResult::Ok
}

#[no_mangle]
/// Copies the session public key.
/// # Safety
/// `runtime` must come from `certael_runtime_create`; `output` must reference at least 32 writable bytes.
pub unsafe extern "C" fn certael_runtime_public_key(
    runtime: *const Runtime,
    output: *mut u8,
    output_length: usize,
) -> CertaelResult {
    if runtime.is_null() || output.is_null() || output_length < 32 {
        return CertaelResult::InvalidArgument;
    }
    ptr::copy_nonoverlapping((*runtime).session.public_key().as_ptr(), output, 32);
    CertaelResult::Ok
}

#[no_mangle]
/// Signs a one-time ticket redemption challenge.
/// # Safety
/// `runtime` must be valid; input and output pointers must reference the declared ranges.
pub unsafe extern "C" fn certael_runtime_sign_redemption(
    runtime: *const Runtime,
    ticket_id: *const u8,
    ticket_id_length: usize,
    challenge: *const u8,
    challenge_length: usize,
    signature: *mut u8,
    signature_length: usize,
) -> CertaelResult {
    if runtime.is_null()
        || ticket_id.is_null()
        || ticket_id_length != 16
        || challenge.is_null()
        || signature.is_null()
        || signature_length < 64
    {
        return CertaelResult::InvalidArgument;
    }
    let id = match Uuid::from_slice(slice::from_raw_parts(ticket_id, ticket_id_length)) {
        Ok(value) => value,
        Err(_) => return CertaelResult::InvalidArgument,
    };
    match (*runtime)
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

#[no_mangle]
/// Activates a verified session binding.
/// # Safety
/// `runtime` must be valid and `json` must reference `len` readable bytes for the duration of the call.
pub unsafe extern "C" fn certael_runtime_activate(
    runtime: *mut Runtime,
    json: *const u8,
    len: usize,
    now: i64,
    initial: u64,
) -> CertaelResult {
    if runtime.is_null() || json.is_null() || len == 0 {
        return CertaelResult::InvalidArgument;
    }
    let binding: SessionBinding = match serde_json::from_slice(slice::from_raw_parts(json, len)) {
        Ok(value) => value,
        Err(_) => return CertaelResult::InvalidArgument,
    };
    match (*runtime).session.activate(binding, now) {
        Ok(()) => {
            (*runtime).sequencer = Some(ActionSequencer::new(initial));
            CertaelResult::Ok
        }
        Err(error) => map_error(error),
    }
}

#[no_mangle]
/// Creates an untrusted action envelope.
/// # Safety
/// All pointers must reference the declared readable or writable ranges. `runtime` must be exclusively accessible.
pub unsafe extern "C" fn certael_runtime_authorize_action(
    runtime: *mut Runtime,
    now: i64,
    action_type: *const c_char,
    schema_version: u32,
    monotonic: i64,
    payload: *const u8,
    payload_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> CertaelResult {
    if runtime.is_null()
        || action_type.is_null()
        || output_len.is_null()
        || (payload_len > 0 && payload.is_null())
    {
        return CertaelResult::InvalidArgument;
    }
    let action_type = match CStr::from_ptr(action_type).to_str() {
        Ok(v) => v,
        Err(_) => return CertaelResult::InvalidArgument,
    };
    let payload = if payload_len == 0 {
        vec![]
    } else {
        slice::from_raw_parts(payload, payload_len).to_vec()
    };
    let sequencer = match (*runtime).sequencer.as_mut() {
        Some(v) => v,
        None => return CertaelResult::SessionInactive,
    };
    let envelope = match sequencer.authorize(
        &(*runtime).session,
        now,
        action_type,
        schema_version,
        monotonic,
        payload,
    ) {
        Ok(v) => v,
        Err(error) => return map_error(error),
    };
    let encoded = match serde_json::to_vec(&envelope) {
        Ok(v) => v,
        Err(_) => return CertaelResult::InternalError,
    };
    *output_len = encoded.len();
    if output.is_null() || output_capacity < encoded.len() {
        return CertaelResult::InvalidArgument;
    }
    ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
    CertaelResult::Ok
}

#[no_mangle]
/// Releases a runtime exactly once.
/// # Safety
/// `runtime` must be null or a pointer returned by `certael_runtime_create` that has not already been released.
pub unsafe extern "C" fn certael_runtime_destroy(runtime: *mut Runtime) {
    if !runtime.is_null() {
        drop(Box::from_raw(runtime));
    }
}
