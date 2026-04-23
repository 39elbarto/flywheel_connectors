#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_raptorq::{DecodeAdmissionController, DecodeError, RaptorQConfig, RaptorQDecoder};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_SYMBOL_BYTES: usize = 1024;
const MAX_EXTRA_ATTEMPTS: u32 = 64;
const ADMISSION_BOUNDARY_SYMBOLS: u32 = 2001;

#[derive(Arbitrary, Debug, Deserialize)]
struct DecodeFloodInput {
    transfer_length: u16,
    symbol_size: u16,
    max_object_size: u16,
    exact_attempts: u16,
    malformed_every: u8,
    fill_byte: u8,
    exercise_admission_boundary: bool,
}

fn exercise_admission_boundary() {
    let config = RaptorQConfig {
        symbol_size: 1,
        repair_ratio_bps: 0,
        max_object_size: 1001,
        ..RaptorQConfig::default()
    };
    let controller = DecodeAdmissionController::new(&config);
    let mut permit = controller
        .try_acquire()
        .expect("fresh controller must provide a decode permit");

    for _ in 0..ADMISSION_BOUNDARY_SYMBOLS {
        permit
            .try_buffer_symbol(1)
            .expect("permit must admit symbols up to its exact boundary");
    }

    match permit.try_buffer_symbol(1) {
        Err(DecodeError::SymbolBufferExceeded { buffered, limit }) => {
            assert_eq!(buffered, ADMISSION_BOUNDARY_SYMBOLS);
            assert_eq!(limit, ADMISSION_BOUNDARY_SYMBOLS);
        }
        other => panic!("expected permit symbol cap at 2001 buffered symbols, got {other:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let input = if let Ok(seed) = serde_json::from_slice::<DecodeFloodInput>(data) {
        seed
    } else {
        let mut unstructured = Unstructured::new(data);
        let Ok(seed) = DecodeFloodInput::arbitrary(&mut unstructured) else {
            return;
        };
        seed
    };

    let symbol_size = input.symbol_size.clamp(1, 256);
    let max_object_size = input.max_object_size.max(symbol_size).clamp(1, 4096);
    let transfer_length = input.transfer_length.max(1).min(max_object_size);
    let config = RaptorQConfig {
        symbol_size,
        max_object_size: u32::from(max_object_size),
        ..RaptorQConfig::default()
    };

    let limit = config
        .total_symbols(usize::from(transfer_length))
        .saturating_add(1000);
    let attempts = u32::from(input.exact_attempts).min(limit.saturating_add(MAX_EXTRA_ATTEMPTS));
    let k = limit.saturating_add(1);
    let mut decoder =
        RaptorQDecoder::with_expected_symbols(k, u64::from(transfer_length), symbol_size, &config);
    let malformed_every = usize::from(input.malformed_every);
    let mut saw_symbol_cap = false;

    for esi in 0..attempts {
        let exact_size = malformed_every == 0 || ((esi as usize + 1) % malformed_every != 0);
        let data_len = if exact_size {
            usize::from(symbol_size)
        } else {
            usize::from(symbol_size)
                .saturating_add(1)
                .min(MAX_SYMBOL_BYTES)
        };
        let data = vec![input.fill_byte.wrapping_add(esi as u8); data_len];
        match decoder.add_symbol(esi, data) {
            Ok(_) => {}
            Err(DecodeError::SymbolBufferExceeded {
                buffered,
                limit: actual_limit,
            }) => {
                assert_eq!(buffered, actual_limit);
                assert_eq!(actual_limit, limit);
                saw_symbol_cap = true;
                break;
            }
            Err(
                DecodeError::InvalidSymbol { .. }
                | DecodeError::MemoryLimitExceeded { .. }
                | DecodeError::AdmissionDenied { .. }
                | DecodeError::Timeout
                | DecodeError::InsufficientSymbols { .. }
                | DecodeError::InvalidTransmissionInfo { .. }
                | DecodeError::Runtime { .. }
                | DecodeError::UnsupportedSourceBlockSize { .. }
                | DecodeError::Cancelled,
            ) => {}
        }
    }

    if malformed_every == 0 && attempts > limit {
        assert!(
            saw_symbol_cap,
            "adversarial exact-size symbol flood must hit the cap"
        );
    }

    if input.exercise_admission_boundary {
        exercise_admission_boundary();
    }
});
