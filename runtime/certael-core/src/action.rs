use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CertaelError, Result, SessionState};

pub const DEFAULT_MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionEnvelope {
    pub session_id: String,
    pub sequence: u64,
    pub action_id: Uuid,
    pub action_type: String,
    pub schema_version: u32,
    pub client_monotonic_micros: i64,
    pub payload: Vec<u8>,
    pub previous_action_digest: [u8; 32],
    pub possession_proof: Vec<u8>,
}

pub struct ActionSequencer {
    next_sequence: u64,
    previous_digest: [u8; 32],
    max_payload: usize,
}

impl ActionSequencer {
    pub fn new(initial_sequence: u64) -> Self {
        Self {
            next_sequence: initial_sequence,
            previous_digest: [0; 32],
            max_payload: DEFAULT_MAX_PAYLOAD,
        }
    }

    pub fn authorize(
        &mut self,
        session: &SessionState,
        now_unix: i64,
        action_type: &str,
        schema_version: u32,
        client_monotonic_micros: i64,
        payload: Vec<u8>,
    ) -> Result<ActionEnvelope> {
        let binding = session.binding(now_unix)?;
        if action_type.is_empty()
            || action_type.len() > 128
            || !action_type
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(CertaelError::InvalidActionType);
        }
        if payload.len() > self.max_payload {
            return Err(CertaelError::PayloadTooLarge);
        }

        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(CertaelError::SequenceExhausted)?;
        let action_id = Uuid::new_v4();
        let canonical = canonical_bytes(
            &binding.session_id,
            sequence,
            action_id,
            action_type,
            schema_version,
            client_monotonic_micros,
            &payload,
            &self.previous_digest,
        );
        let possession_proof = session.sign_action(&canonical);
        let digest: [u8; 32] = Sha256::digest(&canonical).into();

        let envelope = ActionEnvelope {
            session_id: binding.session_id.clone(),
            sequence,
            action_id,
            action_type: action_type.to_owned(),
            schema_version,
            client_monotonic_micros,
            payload,
            previous_action_digest: self.previous_digest,
            possession_proof: possession_proof.to_vec(),
        };
        self.previous_digest = digest;
        Ok(envelope)
    }
}

#[allow(clippy::too_many_arguments)]
fn canonical_bytes(
    session_id: &str,
    sequence: u64,
    action_id: Uuid,
    action_type: &str,
    schema_version: u32,
    client_monotonic_micros: i64,
    payload: &[u8],
    previous_digest: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + payload.len());
    push_len_bytes(&mut out, session_id.as_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(action_id.as_bytes());
    push_len_bytes(&mut out, action_type.as_bytes());
    out.extend_from_slice(&schema_version.to_be_bytes());
    out.extend_from_slice(&client_monotonic_micros.to_be_bytes());
    push_len_bytes(&mut out, payload);
    out.extend_from_slice(previous_digest);
    out
}

fn push_len_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionBinding;

    fn session() -> SessionState {
        let mut session = SessionState::new();
        session
            .activate(
                SessionBinding {
                    session_id: "session-1".into(),
                    game_id: "game".into(),
                    environment_id: "test".into(),
                    match_id: "match".into(),
                    build_id: "build".into(),
                    expires_at_unix: 1000,
                },
                1,
            )
            .unwrap();
        session
    }

    #[test]
    fn chains_and_sequences_actions() {
        let session = session();
        let mut seq = ActionSequencer::new(7);
        let first = seq
            .authorize(&session, 2, "inventory.craft", 1, 10, vec![1])
            .unwrap();
        let second = seq
            .authorize(&session, 2, "inventory.craft", 1, 11, vec![2])
            .unwrap();
        assert_eq!(first.sequence, 7);
        assert_eq!(second.sequence, 8);
        assert_eq!(first.previous_action_digest, [0; 32]);
        assert_ne!(second.previous_action_digest, [0; 32]);
        assert_ne!(first.possession_proof, second.possession_proof);
    }

    #[test]
    fn rejects_oversized_and_invalid_actions() {
        let session = session();
        let mut seq = ActionSequencer::new(0);
        assert_eq!(
            seq.authorize(&session, 2, "bad/type", 1, 0, vec![]),
            Err(CertaelError::InvalidActionType)
        );
        assert_eq!(
            seq.authorize(&session, 2, "ok", 1, 0, vec![0; DEFAULT_MAX_PAYLOAD + 1]),
            Err(CertaelError::PayloadTooLarge)
        );
    }
}
