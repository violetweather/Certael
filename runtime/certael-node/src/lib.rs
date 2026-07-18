use certael_core::{verify_action, VerifiedSession};
use certael_wasm::{evaluate, DEFAULT_FUEL, MAX_DEADLINE};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::time::Duration;

#[napi(object)]
pub struct NodeVerifiedAction {
    pub action_id: String,
    pub session_id: String,
    pub sequence: BigInt,
    pub action_type: String,
    pub request_schema: String,
    pub schema_version: u32,
    pub protocol_major: u32,
    pub protocol_minor: u32,
    pub payload: Buffer,
    pub signed_digest: Buffer,
}

#[napi]
pub fn certael_node_abi_version() -> u32 {
    2
}

#[napi]
pub fn evaluate_wasm_rule(
    module: Buffer,
    canonical_input: Buffer,
    fuel: Option<BigInt>,
    deadline_milliseconds: Option<u32>,
) -> Result<Buffer> {
    let fuel = match fuel {
        Some(value) => {
            let (signed, value, lossless) = value.get_u64();
            if signed || !lossless || value == 0 || value > DEFAULT_FUEL {
                return Err(Error::from_reason("WASM fuel limit is invalid"));
            }
            value
        }
        None => DEFAULT_FUEL,
    };
    let deadline = deadline_milliseconds.unwrap_or(MAX_DEADLINE.as_millis() as u32);
    if deadline == 0 || deadline > MAX_DEADLINE.as_millis() as u32 {
        return Err(Error::from_reason("WASM deadline is invalid"));
    }
    evaluate(
        module.as_ref(),
        canonical_input.as_ref(),
        fuel,
        Duration::from_millis(deadline as u64),
    )
    .map(Buffer::from)
    .map_err(|_| Error::from_reason("WASM rule evaluation was indeterminate"))
}

#[napi]
pub fn verify_action_envelope(
    input: Buffer,
    session_id: String,
    binding_digest: Buffer,
    ephemeral_public_key: Buffer,
    protocol_minimum: u32,
    protocol_maximum: u32,
) -> Result<NodeVerifiedAction> {
    let binding: [u8; 32] = binding_digest
        .as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("binding digest must be 32 bytes"))?;
    let key: [u8; 32] = ephemeral_public_key
        .as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("public key must be 32 bytes"))?;
    let verified = verify_action(
        &input,
        &VerifiedSession {
            session_id: &session_id,
            binding_digest: &binding,
            ephemeral_public_key: &key,
            protocol_minimum,
            protocol_maximum,
        },
    )
    .map_err(|_| Error::from_reason("action verification failed"))?;
    Ok(NodeVerifiedAction {
        action_id: verified.envelope.action_id.to_string(),
        session_id: verified.envelope.session_id,
        sequence: BigInt {
            sign_bit: false,
            words: vec![verified.envelope.sequence],
        },
        action_type: verified.envelope.action_type,
        request_schema: verified.envelope.request_schema,
        schema_version: verified.envelope.schema_version,
        protocol_major: verified.envelope.protocol_major,
        protocol_minor: verified.envelope.protocol_minor,
        payload: verified.envelope.payload.into(),
        signed_digest: verified.signed_digest.to_vec().into(),
    })
}
