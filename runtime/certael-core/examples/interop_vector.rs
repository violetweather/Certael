use certael_core::ActionEnvelope;
use uuid::Uuid;

fn main() {
    let envelope = ActionEnvelope {
        protocol_major: 1,
        protocol_minor: 0,
        session_id: "session".into(),
        sequence: 9,
        action_id: Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
        action_type: "inventory.craft".into(),
        request_schema: "example.Craft.v1".into(),
        schema_version: 1,
        session_binding_digest: [7; 32],
        client_monotonic_micros: 123456,
        payload: vec![1, 2, 3],
        previous_action_digest: [0; 32],
        possession_proof: vec![0; 64],
    };
    println!("signed={}", hex(&envelope.signed_bytes().unwrap()));
    println!("envelope={}", hex(&envelope.encode().unwrap()));
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
