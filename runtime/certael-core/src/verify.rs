use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{ActionEnvelope, CertaelError, Result};

pub struct VerifiedSession<'a> {
    pub session_id: &'a str,
    pub binding_digest: &'a [u8; 32],
    pub ephemeral_public_key: &'a [u8; 32],
    pub protocol_minimum: u32,
    pub protocol_maximum: u32,
}

pub struct VerifiedAction {
    pub envelope: ActionEnvelope,
    pub signed_digest: [u8; 32],
}

/// Strictly decodes a canonical envelope and verifies its session binding and proof.
/// Replay, rate, trusted-state rules, and mutation remain server responsibilities.
pub fn verify_action(input: &[u8], session: &VerifiedSession<'_>) -> Result<VerifiedAction> {
    let envelope = ActionEnvelope::decode(input)?;
    if envelope.session_id != session.session_id
        || &envelope.session_binding_digest != session.binding_digest
        || envelope.protocol_major < session.protocol_minimum
        || envelope.protocol_major > session.protocol_maximum
    {
        return Err(CertaelError::InvalidEnvelope);
    }
    let key = VerifyingKey::from_bytes(session.ephemeral_public_key)
        .map_err(|_| CertaelError::Cryptography)?;
    let signature = Signature::from_slice(&envelope.possession_proof)
        .map_err(|_| CertaelError::Cryptography)?;
    let signed = envelope.signed_bytes()?;
    let mut message = b"certael.action.v1\0".to_vec();
    message.extend_from_slice(&signed);
    key.verify(&message, &signature)
        .map_err(|_| CertaelError::Cryptography)?;
    Ok(VerifiedAction {
        envelope,
        signed_digest: Sha256::digest(&signed).into(),
    })
}
