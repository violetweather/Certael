#![cfg_attr(target_arch = "wasm32", no_std)]

use certael_wasm_guest::{decode_input, Decision, Evidence, Outcome};

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

pub fn evaluate(encoded: &[u8]) -> Decision<'static> {
    let Ok(input) = decode_input(encoded) else {
        return Decision {
            outcome: Outcome::Indeterminate,
            public_reason: "INVALID_INPUT",
            bounded_risk: 0,
            evidence: &[],
        };
    };
    // The reference game's canonical reward action stores the bounded reward count
    // in its first byte. Real games should decode their own canonical action schema.
    if input.canonical_action.first().copied().unwrap_or_default() > 3 {
        static EVIDENCE: [Evidence<'static>; 1] = [Evidence {
            key: "threshold",
            value: "3",
        }];
        Decision {
            outcome: Outcome::Reject,
            public_reason: "REPEATED_REWARD",
            bounded_risk: 80,
            evidence: &EVIDENCE,
        }
    } else {
        Decision {
            outcome: Outcome::Pass,
            public_reason: "PASS",
            bounded_risk: 0,
            evidence: &[],
        }
    }
}

#[cfg(target_arch = "wasm32")]
certael_wasm_guest::export_rule!(evaluate, 1024);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_input_is_indeterminate() {
        assert_eq!(evaluate(&[]).outcome, Outcome::Indeterminate);
    }
}
