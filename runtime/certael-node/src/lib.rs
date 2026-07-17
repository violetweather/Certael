use certael_core::{verify_action, VerifiedSession};
use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object)]
pub struct NodeVerifiedAction {
    pub action_id: String,
    pub session_id: String,
    pub sequence: BigInt,
    pub action_type: String,
    pub signed_digest: Buffer,
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
        signed_digest: verified.signed_digest.to_vec().into(),
    })
}
