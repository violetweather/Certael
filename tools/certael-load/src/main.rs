use std::{env, process, time::Instant};

use certael_core::{ActionEnvelope, ActionSequencer, SessionBinding, SessionState};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

fn main() {
    let sessions = argument("--sessions", 10_000);
    let actions = argument("--actions-per-session", 10);
    if sessions == 0 || sessions > 1_000_000 || actions == 0 || actions > 10_000 {
        eprintln!("load dimensions are outside safe harness bounds");
        process::exit(2);
    }
    let started = Instant::now();
    let mut accepted = 0u64;
    let mut bytes = 0u64;
    for index in 0..sessions {
        let mut session = SessionState::new();
        let public = session.public_key();
        session
            .activate(
                SessionBinding {
                    session_id: format!("load-{index}"),
                    game_id: "load".into(),
                    environment_id: "benchmark".into(),
                    match_id: format!("match-{index}"),
                    build_id: "benchmark-build".into(),
                    expires_at_unix: i64::MAX,
                    binding_digest: [1; 32],
                },
                0,
            )
            .expect("valid benchmark binding");
        let mut sequence = ActionSequencer::new(1);
        for action_index in 0..actions {
            let envelope = sequence
                .authorize(
                    &session,
                    1,
                    "benchmark.action",
                    "benchmark.Action.v1",
                    1,
                    action_index as i64,
                    vec![0; 32],
                )
                .expect("authorize");
            let encoded = envelope.encode().expect("encode");
            verify(&encoded, &public).expect("verify");
            bytes += encoded.len() as u64;
            accepted += 1;
        }
    }
    let elapsed = started.elapsed();
    println!("{{\"sessions\":{sessions},\"actions\":{accepted},\"bytes\":{bytes},\"elapsed_seconds\":{:.6},\"actions_per_second\":{:.2}}}",
        elapsed.as_secs_f64(), accepted as f64 / elapsed.as_secs_f64());
}

fn verify(encoded: &[u8], public: &[u8; 32]) -> Result<(), &'static str> {
    let envelope = ActionEnvelope::decode(encoded).map_err(|_| "decode")?;
    let signed = envelope.signed_bytes().map_err(|_| "canonical")?;
    let key = VerifyingKey::from_bytes(public).map_err(|_| "key")?;
    let signature = Signature::from_slice(&envelope.possession_proof).map_err(|_| "signature")?;
    let mut message = b"certael.action.v1\0".to_vec();
    message.extend_from_slice(&signed);
    key.verify(&message, &signature).map_err(|_| "proof")
}

fn argument(name: &str, default: usize) -> usize {
    let values: Vec<String> = env::args().collect();
    values
        .iter()
        .position(|value| value == name)
        .and_then(|index| values.get(index + 1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
