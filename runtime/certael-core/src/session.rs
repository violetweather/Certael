use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{CertaelError, Result};

pub struct EphemeralIdentity {
    signing_key: SigningKey,
}

impl EphemeralIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        VerifyingKey::from(&self.signing_key).to_bytes()
    }

    pub fn sign(&self, domain: &[u8], message: &[u8]) -> [u8; 64] {
        let mut input = Vec::with_capacity(domain.len() + message.len());
        input.extend_from_slice(domain);
        input.extend_from_slice(message);
        self.signing_key.sign(&input).to_bytes()
    }
}

impl Drop for EphemeralIdentity {
    fn drop(&mut self) {
        // ed25519-dalek zeroizes key material with its zeroize feature paths;
        // overwrite an additional temporary representation defensively.
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionBinding {
    pub session_id: String,
    pub game_id: String,
    pub environment_id: String,
    pub match_id: String,
    pub build_id: String,
    pub expires_at_unix: i64,
}

pub struct SessionState {
    identity: EphemeralIdentity,
    binding: Option<SessionBinding>,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            identity: EphemeralIdentity::generate(),
            binding: None,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    pub fn activate(&mut self, binding: SessionBinding, now_unix: i64) -> Result<()> {
        if binding.session_id.is_empty()
            || binding.game_id.is_empty()
            || binding.environment_id.is_empty()
            || binding.match_id.is_empty()
            || binding.build_id.is_empty()
        {
            return Err(CertaelError::InvalidArgument);
        }
        if binding.expires_at_unix <= now_unix {
            return Err(CertaelError::SessionExpired);
        }
        self.binding = Some(binding);
        Ok(())
    }

    pub fn binding(&self, now_unix: i64) -> Result<&SessionBinding> {
        let binding = self.binding.as_ref().ok_or(CertaelError::SessionInactive)?;
        if binding.expires_at_unix <= now_unix {
            return Err(CertaelError::SessionExpired);
        }
        Ok(binding)
    }

    /// Signs a server-provided, single-use redemption challenge before session activation.
    pub fn sign_redemption(&self, ticket_id: Uuid, challenge: &[u8]) -> Result<[u8; 64]> {
        if challenge.len() < 16 || challenge.len() > 256 {
            return Err(CertaelError::InvalidArgument);
        }
        let mut message = Vec::with_capacity(16 + 8 + challenge.len());
        message.extend_from_slice(ticket_id.as_bytes());
        message.extend_from_slice(&(challenge.len() as u64).to_be_bytes());
        message.extend_from_slice(challenge);
        Ok(self.identity.sign(b"certael.redeem.v1\0", &message))
    }

    pub(crate) fn sign_action(&self, canonical: &[u8]) -> [u8; 64] {
        self.identity.sign(b"certael.action.v1\0", canonical)
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}
