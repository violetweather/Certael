use certael_wasm::{evaluate, DEFAULT_FUEL, MAX_DEADLINE};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("usage: certael-wasm-check <module.wasm>");
        return ExitCode::from(2);
    };
    let module = match fs::read(path) {
        Ok(module) => module,
        Err(_) => {
            eprintln!("unable to read WASM module");
            return ExitCode::from(2);
        }
    };
    let input = canonical_input(4);
    let output = match evaluate(&module, &input, DEFAULT_FUEL, MAX_DEADLINE) {
        Ok(output) => output,
        Err(_) => {
            eprintln!("reference WASM rule evaluation was indeterminate");
            return ExitCode::FAILURE;
        }
    };
    if output != canonical_rejection() {
        eprintln!("reference WASM rule returned a noncanonical or unexpected decision");
        return ExitCode::FAILURE;
    }
    println!("Certael reference WASM ABI v1 verified");
    ExitCode::SUCCESS
}

fn canonical_input(reward_count: u8) -> Vec<u8> {
    let mut output = vec![8, 1];
    string(&mut output, 2, "tenant");
    string(&mut output, 3, "game");
    string(&mut output, 4, "prod");
    string(&mut output, 5, "reward.repeated");
    string(&mut output, 6, "1");
    bytes(&mut output, 7, &[reward_count]);
    bytes(&mut output, 8, &[]);
    output
}

fn canonical_rejection() -> Vec<u8> {
    let mut output = vec![8, 1, 16, 2];
    string(&mut output, 3, "REPEATED_REWARD");
    output.extend_from_slice(&[32, 80]);
    let mut evidence = Vec::new();
    string(&mut evidence, 1, "threshold");
    string(&mut evidence, 2, "3");
    bytes(&mut output, 5, &evidence);
    output
}

fn string(output: &mut Vec<u8>, field: u8, value: &str) {
    bytes(output, field, value.as_bytes());
}

fn bytes(output: &mut Vec<u8>, field: u8, value: &[u8]) {
    output.push((field << 3) | 2);
    assert!(value.len() < 128);
    output.push(value.len() as u8);
    output.extend_from_slice(value);
}
