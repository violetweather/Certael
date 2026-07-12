use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CertaelError, Result, SessionState};

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;
pub const DEFAULT_MAX_PAYLOAD: usize = 64 * 1024;
const MAX_IDENTIFIER: usize = 128;
const MAX_ENVELOPE: usize = DEFAULT_MAX_PAYLOAD + 2048;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionEnvelope {
    pub protocol_major: u32,
    pub protocol_minor: u32,
    pub session_id: String,
    pub sequence: u64,
    pub action_id: Uuid,
    pub action_type: String,
    pub request_schema: String,
    pub schema_version: u32,
    pub session_binding_digest: [u8; 32],
    pub client_monotonic_micros: i64,
    pub payload: Vec<u8>,
    pub previous_action_digest: [u8; 32],
    pub possession_proof: Vec<u8>,
}

impl ActionEnvelope {
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        validate_envelope(self, false)?;
        let mut out = Vec::with_capacity(192 + self.payload.len());
        field_varint(&mut out, 1, self.protocol_major as u64);
        field_varint(&mut out, 2, self.protocol_minor as u64);
        field_bytes(&mut out, 3, self.session_id.as_bytes());
        field_varint(&mut out, 4, self.sequence);
        field_bytes(&mut out, 5, self.action_id.as_bytes());
        field_bytes(&mut out, 6, self.action_type.as_bytes());
        field_bytes(&mut out, 7, self.request_schema.as_bytes());
        field_varint(&mut out, 8, self.schema_version as u64);
        field_bytes(&mut out, 9, &self.session_binding_digest);
        field_varint(&mut out, 10, self.client_monotonic_micros as u64);
        field_bytes(&mut out, 11, &self.payload);
        field_bytes(&mut out, 12, &self.previous_action_digest);
        Ok(out)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_envelope(self, true)?;
        let mut out = self.signed_bytes()?;
        field_bytes(&mut out, 13, &self.possession_proof);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.is_empty() || input.len() > MAX_ENVELOPE {
            return Err(CertaelError::InvalidEnvelope);
        }
        let mut decoder = Decoder::new(input);
        let protocol_major = decoder.varint_field(1)? as u32;
        let protocol_minor = decoder.varint_field(2)? as u32;
        let session_id = decoder.string_field(3, MAX_IDENTIFIER)?;
        let sequence = decoder.varint_field(4)?;
        let action_id = Uuid::from_slice(decoder.bytes_field(5, 16)?)
            .map_err(|_| CertaelError::InvalidEnvelope)?;
        let action_type = decoder.string_field(6, MAX_IDENTIFIER)?;
        let request_schema = decoder.string_field(7, MAX_IDENTIFIER)?;
        let schema_version = decoder.varint_field(8)? as u32;
        let session_binding_digest = array32(decoder.bytes_field(9, 32)?)?;
        let monotonic = decoder.varint_field(10)?;
        if monotonic > i64::MAX as u64 {
            return Err(CertaelError::InvalidEnvelope);
        }
        let payload = decoder.bytes_field(11, DEFAULT_MAX_PAYLOAD)?.to_vec();
        let previous_action_digest = array32(decoder.bytes_field(12, 32)?)?;
        let possession_proof = decoder.bytes_field(13, 64)?.to_vec();
        if !decoder.finished() {
            return Err(CertaelError::InvalidEnvelope);
        }
        let envelope = Self {
            protocol_major,
            protocol_minor,
            session_id,
            sequence,
            action_id,
            action_type,
            request_schema,
            schema_version,
            session_binding_digest,
            client_monotonic_micros: monotonic as i64,
            payload,
            previous_action_digest,
            possession_proof,
        };
        validate_envelope(&envelope, true)?;
        if envelope.encode()?.as_slice() != input {
            return Err(CertaelError::NonCanonicalEnvelope);
        }
        Ok(envelope)
    }
}

pub struct ActionSequencer {
    next_sequence: u64,
    previous_digest: [u8; 32],
}

impl ActionSequencer {
    pub fn new(initial_sequence: u64) -> Self {
        Self {
            next_sequence: initial_sequence,
            previous_digest: [0; 32],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &mut self,
        session: &SessionState,
        now_unix: i64,
        action_type: &str,
        request_schema: &str,
        schema_version: u32,
        client_monotonic_micros: i64,
        payload: Vec<u8>,
    ) -> Result<ActionEnvelope> {
        let binding = session.binding(now_unix)?;
        if !valid_identifier(action_type)
            || !valid_identifier(request_schema)
            || schema_version == 0
            || client_monotonic_micros < 0
        {
            return Err(CertaelError::InvalidArgument);
        }
        if payload.len() > DEFAULT_MAX_PAYLOAD {
            return Err(CertaelError::PayloadTooLarge);
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(CertaelError::SequenceExhausted)?;
        let mut envelope = ActionEnvelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            session_id: binding.session_id.clone(),
            sequence,
            action_id: Uuid::new_v4(),
            action_type: action_type.to_owned(),
            request_schema: request_schema.to_owned(),
            schema_version,
            session_binding_digest: binding.binding_digest,
            client_monotonic_micros,
            payload,
            previous_action_digest: self.previous_digest,
            possession_proof: Vec::new(),
        };
        let signed = envelope.signed_bytes()?;
        envelope.possession_proof = session.sign_action(&signed).to_vec();
        self.previous_digest = Sha256::digest(&signed).into();
        Ok(envelope)
    }
}

fn validate_envelope(value: &ActionEnvelope, require_proof: bool) -> Result<()> {
    if value.protocol_major != PROTOCOL_MAJOR
        || value.protocol_minor > PROTOCOL_MINOR
        || !valid_identifier(&value.session_id)
        || !valid_identifier(&value.action_type)
        || !valid_identifier(&value.request_schema)
        || value.schema_version == 0
        || value.client_monotonic_micros < 0
        || value.payload.len() > DEFAULT_MAX_PAYLOAD
        || (require_proof && value.possession_proof.len() != 64)
    {
        return Err(CertaelError::InvalidEnvelope);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn array32(value: &[u8]) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| CertaelError::InvalidEnvelope)
}

fn field_varint(out: &mut Vec<u8>, field: u32, value: u64) {
    varint(out, (field as u64) << 3);
    varint(out, value);
}

fn field_bytes(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    varint(out, ((field as u64) << 3) | 2);
    varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    last_field: u32,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            last_field: 0,
        }
    }
    fn finished(&self) -> bool {
        self.offset == self.input.len()
    }
    fn key(&mut self, expected: u32, wire: u64) -> Result<()> {
        let key = self.read_varint()?;
        let field = (key >> 3) as u32;
        if field != expected || field <= self.last_field || key & 7 != wire {
            return Err(CertaelError::NonCanonicalEnvelope);
        }
        self.last_field = field;
        Ok(())
    }
    fn varint_field(&mut self, expected: u32) -> Result<u64> {
        self.key(expected, 0)?;
        self.read_varint()
    }
    fn bytes_field(&mut self, expected: u32, maximum: usize) -> Result<&'a [u8]> {
        self.key(expected, 2)?;
        let length =
            usize::try_from(self.read_varint()?).map_err(|_| CertaelError::InvalidEnvelope)?;
        if length > maximum
            || self
                .offset
                .checked_add(length)
                .filter(|end| *end <= self.input.len())
                .is_none()
        {
            return Err(CertaelError::InvalidEnvelope);
        }
        let start = self.offset;
        self.offset += length;
        Ok(&self.input[start..self.offset])
    }
    fn string_field(&mut self, expected: u32, maximum: usize) -> Result<String> {
        let bytes = self.bytes_field(expected, maximum)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CertaelError::InvalidEnvelope)
    }
    fn read_varint(&mut self) -> Result<u64> {
        let start = self.offset;
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = *self
                .input
                .get(self.offset)
                .ok_or(CertaelError::InvalidEnvelope)?;
            self.offset += 1;
            if shift == 63 && byte > 1 {
                return Err(CertaelError::InvalidEnvelope);
            }
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                let mut canonical = Vec::new();
                varint(&mut canonical, value);
                if canonical.as_slice() != &self.input[start..self.offset] {
                    return Err(CertaelError::NonCanonicalEnvelope);
                }
                return Ok(value);
            }
        }
        Err(CertaelError::InvalidEnvelope)
    }
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
                    binding_digest: [7; 32],
                },
                1,
            )
            .unwrap();
        session
    }

    #[test]
    fn binary_round_trip_chains_and_sequences() {
        let session = session();
        let mut seq = ActionSequencer::new(7);
        let first = seq
            .authorize(
                &session,
                2,
                "inventory.craft",
                "example.Craft.v1",
                1,
                10,
                vec![1],
            )
            .unwrap();
        let encoded = first.encode().unwrap();
        assert_eq!(ActionEnvelope::decode(&encoded).unwrap(), first);
        let second = seq
            .authorize(
                &session,
                2,
                "inventory.craft",
                "example.Craft.v1",
                1,
                11,
                vec![2],
            )
            .unwrap();
        assert_eq!(first.sequence, 7);
        assert_eq!(second.sequence, 8);
        assert_eq!(first.previous_action_digest, [0; 32]);
        assert_ne!(second.previous_action_digest, [0; 32]);
    }

    #[test]
    fn rejects_noncanonical_unknown_and_oversized_input() {
        let session = session();
        let mut seq = ActionSequencer::new(1);
        let envelope = seq
            .authorize(&session, 2, "ok", "ok.v1", 1, 0, vec![])
            .unwrap();
        let mut encoded = envelope.encode().unwrap();
        encoded.extend_from_slice(&[0x70, 0x01]);
        assert!(ActionEnvelope::decode(&encoded).is_err());
        assert!(seq
            .authorize(&session, 2, "bad/type", "ok.v1", 1, 0, vec![])
            .is_err());
        assert_eq!(
            seq.authorize(
                &session,
                2,
                "ok",
                "ok.v1",
                1,
                0,
                vec![0; DEFAULT_MAX_PAYLOAD + 1]
            ),
            Err(CertaelError::PayloadTooLarge)
        );
    }
}
