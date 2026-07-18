use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use thiserror::Error;
use wasmparser::{Operator, Parser, Payload, Validator, WasmFeatures};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

pub const MAX_MODULE: usize = 4 * 1024 * 1024;
pub const MAX_MEMORY: usize = 16 * 1024 * 1024;
pub const MAX_INPUT: usize = 1024 * 1024;
pub const MAX_OUTPUT: usize = 64 * 1024;
pub const DEFAULT_FUEL: u64 = 10_000_000;
pub const MAX_DEADLINE: Duration = Duration::from_millis(10);
const MAX_CACHED_MODULES: usize = 256;

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

struct Runtime {
    engine: Engine,
    modules: Mutex<BTreeMap<[u8; 32], Arc<Module>>>,
}

static RUNTIME: OnceLock<Result<Runtime, ()>> = OnceLock::new();

pub fn evaluate(
    module_bytes: &[u8],
    canonical_input: &[u8],
    fuel: u64,
    deadline: Duration,
) -> Result<Vec<u8>, WasmRuleError> {
    evaluate_with_limits(
        module_bytes,
        canonical_input,
        fuel,
        deadline,
        MAX_MEMORY,
        MAX_OUTPUT,
    )
}

fn evaluate_with_limits(
    module_bytes: &[u8],
    canonical_input: &[u8],
    fuel: u64,
    deadline: Duration,
    maximum_memory: usize,
    maximum_output: usize,
) -> Result<Vec<u8>, WasmRuleError> {
    if module_bytes.len() < 8
        || module_bytes.len() > MAX_MODULE
        || canonical_input.len() > MAX_INPUT
        || fuel == 0
        || fuel > DEFAULT_FUEL
        || deadline.is_zero()
        || deadline > MAX_DEADLINE
        || maximum_memory == 0
        || maximum_memory > MAX_MEMORY
        || maximum_output == 0
        || maximum_output > MAX_OUTPUT
    {
        return Err(WasmRuleError::Limit);
    }
    reject_nondeterminism(module_bytes)?;
    let runtime = runtime()?;
    let module = cached_module(runtime, module_bytes)?;
    let engine = &runtime.engine;
    if module.imports().next().is_some() {
        return Err(WasmRuleError::Invalid);
    }
    let limits = StoreLimitsBuilder::new()
        .memory_size(maximum_memory)
        .build();
    let mut store = Store::new(engine, RuntimeState { limits });
    store.limiter(|state| &mut state.limits);
    store.set_fuel(fuel).map_err(|_| WasmRuleError::Limit)?;
    store.set_epoch_deadline(deadline.as_millis().max(1) as u64);
    let instance = Linker::new(engine)
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
    if length > maximum_output {
        return Err(WasmRuleError::Output);
    }
    let mut output = vec![0; length];
    memory
        .read(&store, offset, &mut output)
        .map_err(|_| WasmRuleError::Output)?;
    Ok(output)
}

fn runtime() -> Result<&'static Runtime, WasmRuleError> {
    RUNTIME
        .get_or_init(|| {
            let mut config = Config::new();
            config.consume_fuel(true);
            config.epoch_interruption(true);
            config.wasm_simd(false);
            config.wasm_relaxed_simd(false);
            config.wasm_tail_call(false);
            config.wasm_memory64(false);
            config.wasm_multi_memory(false);
            let engine = Engine::new(&config).map_err(|_| ())?;
            let ticker = engine.clone();
            std::thread::Builder::new()
                .name("certael-wasm-epoch".to_owned())
                .spawn(move || loop {
                    std::thread::sleep(Duration::from_millis(1));
                    ticker.increment_epoch();
                })
                .map_err(|_| ())?;
            Ok(Runtime {
                engine,
                modules: Mutex::new(BTreeMap::new()),
            })
        })
        .as_ref()
        .map_err(|_| WasmRuleError::Invalid)
}

fn cached_module(runtime: &Runtime, bytes: &[u8]) -> Result<Arc<Module>, WasmRuleError> {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut modules = runtime.modules.lock().map_err(|_| WasmRuleError::Invalid)?;
    if let Some(module) = modules.get(&digest) {
        return Ok(module.clone());
    }
    let module = Arc::new(Module::new(&runtime.engine, bytes).map_err(|_| WasmRuleError::Invalid)?);
    if modules.len() == MAX_CACHED_MODULES {
        if let Some(first) = modules.keys().next().copied() {
            modules.remove(&first);
        }
    }
    modules.insert(digest, module.clone());
    Ok(module)
}

fn reject_nondeterminism(bytes: &[u8]) -> Result<(), WasmRuleError> {
    let features = WasmFeatures::MUTABLE_GLOBAL
        | WasmFeatures::SIGN_EXTENSION
        | WasmFeatures::MULTI_VALUE
        | WasmFeatures::BULK_MEMORY;
    Validator::new_with_features(features)
        .validate_all(bytes)
        .map_err(|_| WasmRuleError::Invalid)?;
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

#[repr(i32)]
pub enum WasmRuleStatus {
    Success = 0,
    Invalid = 1,
    Limit = 2,
    Trap = 3,
    Output = 4,
    BufferTooSmall = 5,
    InvalidArgument = 6,
}

/// Evaluates one canonical ABI-v1 input into a caller-owned output buffer.
///
/// # Safety
/// Every non-empty input/output pointer must reference the declared number of
/// readable/writable bytes for the duration of this call. `output_length` must
/// point to a writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn certael_wasm_evaluate_v1(
    module_pointer: *const u8,
    module_length: usize,
    input_pointer: *const u8,
    input_length: usize,
    fuel: u64,
    deadline_milliseconds: u32,
    maximum_memory_bytes: usize,
    maximum_output_bytes: usize,
    output_pointer: *mut u8,
    output_capacity: usize,
    output_length: *mut usize,
) -> i32 {
    if module_pointer.is_null()
        || (input_length > 0 && input_pointer.is_null())
        || output_pointer.is_null()
        || output_length.is_null()
        || output_capacity == 0
        || output_capacity > MAX_OUTPUT
        || maximum_memory_bytes == 0
        || maximum_memory_bytes > MAX_MEMORY
        || maximum_output_bytes == 0
        || maximum_output_bytes > MAX_OUTPUT
        || output_capacity < maximum_output_bytes
    {
        return WasmRuleStatus::InvalidArgument as i32;
    }
    let result = std::panic::catch_unwind(|| {
        let module = unsafe { std::slice::from_raw_parts(module_pointer, module_length) };
        let input = if input_length == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(input_pointer, input_length) }
        };
        evaluate_with_limits(
            module,
            input,
            fuel,
            Duration::from_millis(deadline_milliseconds as u64),
            maximum_memory_bytes,
            maximum_output_bytes,
        )
    });
    let bytes = match result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(WasmRuleError::Invalid)) => return WasmRuleStatus::Invalid as i32,
        Ok(Err(WasmRuleError::Limit)) => return WasmRuleStatus::Limit as i32,
        Ok(Err(WasmRuleError::Trap)) => return WasmRuleStatus::Trap as i32,
        Ok(Err(WasmRuleError::Output)) => return WasmRuleStatus::Output as i32,
        Err(_) => return WasmRuleStatus::Trap as i32,
    };
    unsafe { output_length.write(bytes.len()) };
    if bytes.len() > output_capacity {
        return WasmRuleStatus::BufferTooSmall as i32;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output_pointer, bytes.len()) };
    WasmRuleStatus::Success as i32
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
