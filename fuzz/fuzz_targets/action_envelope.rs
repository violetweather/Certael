#![no_main]
use certael_core::ActionEnvelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = ActionEnvelope::decode(data) {
        let encoded = envelope.encode().expect("a decoded envelope must re-encode");
        assert_eq!(encoded, data, "accepted envelopes must be canonical");
    }
});
