use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn main() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let session = "session";
    let sequence = 9u64;
    let id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let action_type = "inventory.craft";
    let schema = 1u32;
    let monotonic = 123456i64;
    let payload = [1u8, 2, 3];
    let previous = [0u8; 32];
    let mut canonical = Vec::new();
    push(&mut canonical, session.as_bytes());
    canonical.extend_from_slice(&sequence.to_be_bytes());
    canonical.extend_from_slice(id.as_bytes());
    push(&mut canonical, action_type.as_bytes());
    canonical.extend_from_slice(&schema.to_be_bytes());
    canonical.extend_from_slice(&monotonic.to_be_bytes());
    push(&mut canonical, &payload);
    canonical.extend_from_slice(&previous);
    let mut signed = b"certael.action.v1\0".to_vec();
    signed.extend_from_slice(&canonical);
    let signature = key.sign(&signed).to_bytes();
    println!("public={}", hex(&key.verifying_key().to_bytes()));
    println!("canonical={}", hex(&canonical));
    println!("signature={}", hex(&signature));
    println!("digest={}", hex(&Sha256::digest(&canonical)));
}

fn push(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}
