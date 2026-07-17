use std::time::Duration;
use thiserror::Error;
use wasmparser::{Operator, Parser, Payload};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

pub const MAX_MODULE: usize = 4 * 1024 * 1024;
pub const MAX_MEMORY: usize = 16 * 1024 * 1024;
pub const MAX_INPUT: usize = 1024 * 1024;
pub const MAX_OUTPUT: usize = 64 * 1024;
pub const DEFAULT_FUEL: u64 = 10_000_000;

#[derive(Debug, Error)]
pub enum WasmRuleError {
    #[error("invalid module")]
    Invalid,
    #[error("resource limit")]
    Limit,
    #[error("trap")]
    Trap,
    #[error("malformed output")]
    Output,
}
pub struct RuntimeState {
    limits: StoreLimits,
}

pub fn evaluate(
    module_bytes: &[u8],
    canonical_input: &[u8],
    fuel: u64,
    deadline: Duration,
) -> Result<Vec<u8>, WasmRuleError> {
    if module_bytes.len() > MAX_MODULE || canonical_input.len() > MAX_INPUT {
        return Err(WasmRuleError::Limit);
    }
    reject_nondeterminism(module_bytes)?;
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    let engine = Engine::new(&config).map_err(|_| WasmRuleError::Invalid)?;
    let module = Module::new(&engine, module_bytes).map_err(|_| WasmRuleError::Invalid)?;
    if module.imports().next().is_some() {
        return Err(WasmRuleError::Invalid);
    }
    let limits = StoreLimitsBuilder::new().memory_size(MAX_MEMORY).build();
    let mut store = Store::new(&engine, RuntimeState { limits });
    store.limiter(|state| &mut state.limits);
    store.set_fuel(fuel).map_err(|_| WasmRuleError::Limit)?;
    store.set_epoch_deadline(1);
    let timeout_engine = engine.clone();
    std::thread::spawn(move || {
        std::thread::sleep(deadline);
        timeout_engine.increment_epoch();
    });
    let instance = Linker::new(&engine)
        .instantiate(&mut store, &module)
        .map_err(|_| WasmRuleError::Trap)?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or(WasmRuleError::Invalid)?;
    memory
        .write(&mut store, 0, canonical_input)
        .map_err(|_| WasmRuleError::Limit)?;
    let evaluate = instance
        .get_typed_func::<(i32, i32), i64>(&mut store, "certael_evaluate_v1")
        .map_err(|_| WasmRuleError::Invalid)?;
    let packed = evaluate
        .call(&mut store, (0, canonical_input.len() as i32))
        .map_err(|_| WasmRuleError::Trap)? as u64;
    let offset = (packed >> 32) as usize;
    let length = (packed & 0xffff_ffff) as usize;
    if length > MAX_OUTPUT {
        return Err(WasmRuleError::Output);
    }
    let mut output = vec![0; length];
    memory
        .read(&store, offset, &mut output)
        .map_err(|_| WasmRuleError::Output)?;
    Ok(output)
}

fn reject_nondeterminism(bytes: &[u8]) -> Result<(), WasmRuleError> {
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.map_err(|_| WasmRuleError::Invalid)? {
            let mut reader = body
                .get_operators_reader()
                .map_err(|_| WasmRuleError::Invalid)?;
            while !reader.eof() {
                let op = reader.read().map_err(|_| WasmRuleError::Invalid)?;
                let name = format!("{op:?}");
                if matches!(op, Operator::F32Const { .. } | Operator::F64Const { .. })
                    || name.starts_with("F32")
                    || name.starts_with("F64")
                    || name.contains("Atomic")
                    || name.starts_with("V128")
                    || name.contains("x8")
                    || name.contains("x16")
                    || name.contains("x32")
                    || name.contains("x64")
                {
                    return Err(WasmRuleError::Invalid);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_integer_only_module_without_host_access() {
        let module = wat::parse_str(
            r#"(module
          (memory (export "memory") 1)
          (func (export "certael_evaluate_v1") (param i32 i32) (result i64) i64.const 0))"#,
        )
        .unwrap();
        assert_eq!(
            evaluate(&module, b"input", DEFAULT_FUEL, Duration::from_millis(10)).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn rejects_imports_and_floating_point() {
        let imported = wat::parse_str(
            r#"(module (import "host" "clock" (func))
          (memory (export "memory") 1)
          (func (export "certael_evaluate_v1") (param i32 i32) (result i64) i64.const 0))"#,
        )
        .unwrap();
        assert!(matches!(
            evaluate(&imported, b"", DEFAULT_FUEL, Duration::from_millis(10)),
            Err(WasmRuleError::Invalid)
        ));
        let floating = wat::parse_str(
            r#"(module (memory (export "memory") 1)
          (func (export "certael_evaluate_v1") (param i32 i32) (result i64)
            f32.const 1 drop i64.const 0))"#,
        )
        .unwrap();
        assert!(matches!(
            evaluate(&floating, b"", DEFAULT_FUEL, Duration::from_millis(10)),
            Err(WasmRuleError::Invalid)
        ));
    }

    #[test]
    fn fuel_exhaustion_is_bounded() {
        let module = wat::parse_str(
            r#"(module (memory (export "memory") 1)
          (func (export "certael_evaluate_v1") (param i32 i32) (result i64)
            (loop br 0) i64.const 0))"#,
        )
        .unwrap();
        assert!(matches!(
            evaluate(&module, b"", 100, Duration::from_millis(10)),
            Err(WasmRuleError::Trap)
        ));
    }
}
