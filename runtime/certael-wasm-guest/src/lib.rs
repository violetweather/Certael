#![no_std]

use core::cell::UnsafeCell;
use core::str;

pub const ABI_VERSION: u32 = 1;
pub const MAX_EVIDENCE_ENTRIES: usize = 64;
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Outcome {
    Pass = 1,
    Reject = 2,
    Indeterminate = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evidence<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision<'a> {
    pub outcome: Outcome,
    pub public_reason: &'a str,
    pub bounded_risk: u32,
    /// Entries must already be sorted by key and have unique keys.
    pub evidence: &'a [Evidence<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input<'a> {
    pub tenant_id: &'a str,
    pub game_id: &'a str,
    pub environment_id: &'a str,
    pub rule_id: &'a str,
    pub rule_version: &'a str,
    pub canonical_action: &'a [u8],
    pub canonical_state: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    Invalid,
    OutputTooSmall,
}

pub fn decode_input(encoded: &[u8]) -> Result<Input<'_>, CodecError> {
    let mut reader = Reader::new(encoded);
    if reader.unsigned(1)? != ABI_VERSION as u64 {
        return Err(CodecError::Invalid);
    }
    let tenant_id = reader.text(2, 128)?;
    let game_id = reader.text(3, 128)?;
    let environment_id = reader.text(4, 128)?;
    let rule_id = reader.text(5, 128)?;
    let rule_version = reader.text(6, 128)?;
    let canonical_action = reader.bytes(7, 1024 * 1024, false)?;
    let canonical_state = reader.bytes(8, 1024 * 1024, false)?;
    if !reader.end()
        || canonical_action.is_empty()
        || canonical_action.len().saturating_add(canonical_state.len()) > 1024 * 1024
        || !identifier(tenant_id, 128)
        || !identifier(game_id, 128)
        || !identifier(environment_id, 128)
        || !identifier(rule_id, 128)
        || !identifier(rule_version, 128)
    {
        return Err(CodecError::Invalid);
    }
    Ok(Input {
        tenant_id,
        game_id,
        environment_id,
        rule_id,
        rule_version,
        canonical_action,
        canonical_state,
    })
}

pub fn encode_decision(decision: Decision<'_>, output: &mut [u8]) -> Result<usize, CodecError> {
    if output.len() > MAX_OUTPUT_BYTES
        || decision.bounded_risk > 100
        || !identifier(decision.public_reason, 64)
        || decision.evidence.len() > MAX_EVIDENCE_ENTRIES
    {
        return Err(CodecError::Invalid);
    }
    let mut previous = None;
    let mut writer = Writer::new(output);
    writer.unsigned(1, ABI_VERSION as u64)?;
    writer.unsigned(2, decision.outcome as u64)?;
    writer.bytes(3, decision.public_reason.as_bytes())?;
    writer.unsigned(4, decision.bounded_risk as u64)?;
    for evidence in decision.evidence {
        if !identifier(evidence.key, 64)
            || evidence.value.len() > 4096
            || evidence
                .value
                .bytes()
                .any(|value| value < 0x20 || value == 0x7f)
            || previous.is_some_and(|value: &str| value >= evidence.key)
        {
            return Err(CodecError::Invalid);
        }
        previous = Some(evidence.key);
        let entry_length = field_size(1, evidence.key.len()) + field_size(2, evidence.value.len());
        writer.key(5, 2)?;
        writer.varint(entry_length as u64)?;
        writer.bytes(1, evidence.key.as_bytes())?;
        writer.bytes(2, evidence.value.as_bytes())?;
    }
    Ok(writer.offset)
}

pub const fn pack_output(offset: u32, length: u32) -> i64 {
    (((offset as u64) << 32) | length as u64) as i64
}

/// Single-threaded output storage for an exported guest function.
/// The host rejects WASM threads and invokes an instance serially.
pub struct OutputBuffer<const N: usize>(UnsafeCell<[u8; N]>);
impl<const N: usize> OutputBuffer<N> {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }

    pub fn pointer(&self) -> *mut u8 {
        self.0.get().cast::<u8>()
    }
}
impl<const N: usize> Default for OutputBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}
// SAFETY: ABI-v1 modules cannot enable threads or shared memory.
unsafe impl<const N: usize> Sync for OutputBuffer<N> {}

#[macro_export]
macro_rules! export_rule {
    ($evaluator:path, $capacity:expr) => {
        static CERTAEL_RULE_OUTPUT: $crate::OutputBuffer<$capacity> = $crate::OutputBuffer::new();

        #[no_mangle]
        pub unsafe extern "C" fn certael_evaluate_v1(pointer: i32, length: i32) -> i64 {
            if pointer < 0 || length < 0 {
                return 0;
            }
            let input = unsafe {
                core::slice::from_raw_parts(pointer as usize as *const u8, length as usize)
            };
            let decision = $evaluator(input);
            let output = unsafe {
                core::slice::from_raw_parts_mut(CERTAEL_RULE_OUTPUT.pointer(), $capacity)
            };
            match $crate::encode_decision(decision, output) {
                Ok(length) => $crate::pack_output(output.as_ptr() as usize as u32, length as u32),
                Err(_) => 0,
            }
        }
    };
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

const fn varint_size(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}
const fn field_size(field: u32, length: usize) -> usize {
    varint_size(((field as u64) << 3) | 2) + varint_size(length as u64) + length
}

struct Writer<'a> {
    output: &'a mut [u8],
    offset: usize,
}
impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, offset: 0 }
    }
    fn unsigned(&mut self, field: u32, value: u64) -> Result<(), CodecError> {
        self.key(field, 0)?;
        self.varint(value)
    }
    fn bytes(&mut self, field: u32, value: &[u8]) -> Result<(), CodecError> {
        self.key(field, 2)?;
        self.varint(value.len() as u64)?;
        self.write(value)
    }
    fn key(&mut self, field: u32, wire: u8) -> Result<(), CodecError> {
        self.varint(((field as u64) << 3) | wire as u64)
    }
    fn varint(&mut self, mut value: u64) -> Result<(), CodecError> {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.write(&[byte])?;
            if value == 0 {
                return Ok(());
            }
        }
    }
    fn write(&mut self, value: &[u8]) -> Result<(), CodecError> {
        let end = self
            .offset
            .checked_add(value.len())
            .ok_or(CodecError::OutputTooSmall)?;
        let destination = self
            .output
            .get_mut(self.offset..end)
            .ok_or(CodecError::OutputTooSmall)?;
        destination.copy_from_slice(value);
        self.offset = end;
        Ok(())
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
    last_field: u32,
}
impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            last_field: 0,
        }
    }
    fn end(&self) -> bool {
        self.offset == self.input.len()
    }
    fn unsigned(&mut self, field: u32) -> Result<u64, CodecError> {
        self.key(field, 0, false)?;
        self.varint()
    }
    fn text(&mut self, field: u32, maximum: usize) -> Result<&'a str, CodecError> {
        str::from_utf8(self.bytes(field, maximum, false)?).map_err(|_| CodecError::Invalid)
    }
    fn bytes(
        &mut self,
        field: u32,
        maximum: usize,
        repeated: bool,
    ) -> Result<&'a [u8], CodecError> {
        self.key(field, 2, repeated)?;
        let length = usize::try_from(self.varint()?).map_err(|_| CodecError::Invalid)?;
        if length > maximum {
            return Err(CodecError::Invalid);
        }
        let end = self.offset.checked_add(length).ok_or(CodecError::Invalid)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(CodecError::Invalid)?;
        self.offset = end;
        Ok(value)
    }
    fn key(&mut self, expected: u32, wire: u8, repeated: bool) -> Result<(), CodecError> {
        let key = self.varint()?;
        let field = u32::try_from(key >> 3).map_err(|_| CodecError::Invalid)?;
        if field != expected
            || field < self.last_field
            || (field == self.last_field && !repeated)
            || key as u8 & 7 != wire
        {
            return Err(CodecError::Invalid);
        }
        self.last_field = field;
        Ok(())
    }
    fn varint(&mut self) -> Result<u64, CodecError> {
        let start = self.offset;
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let current = *self.input.get(self.offset).ok_or(CodecError::Invalid)?;
            self.offset += 1;
            if shift == 63 && current > 1 {
                return Err(CodecError::Invalid);
            }
            value |= u64::from(current & 0x7f) << shift;
            if current & 0x80 == 0 {
                if self.offset - start != varint_size(value) {
                    return Err(CodecError::Invalid);
                }
                return Ok(value);
            }
        }
        Err(CodecError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_canonical_decision() {
        let evidence = [Evidence {
            key: "count",
            value: "4",
        }];
        let decision = Decision {
            outcome: Outcome::Reject,
            public_reason: "REPEATED_REWARD",
            bounded_risk: 80,
            evidence: &evidence,
        };
        let mut output = [0u8; 256];
        let length = encode_decision(decision, &mut output).unwrap();
        assert_eq!(&output[..4], &[8, 1, 16, 2]);
        assert!(length > 4);
    }

    #[test]
    fn rejects_unsorted_or_control_evidence() {
        let evidence = [
            Evidence {
                key: "z",
                value: "1",
            },
            Evidence {
                key: "a",
                value: "2",
            },
        ];
        let decision = Decision {
            outcome: Outcome::Pass,
            public_reason: "PASS",
            bounded_risk: 0,
            evidence: &evidence,
        };
        assert_eq!(
            encode_decision(decision, &mut [0; 256]),
            Err(CodecError::Invalid)
        );
    }
}
