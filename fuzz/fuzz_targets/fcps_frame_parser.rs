//! FCPS frame parser fuzz target for `flywheel_connectors-angoc.10.1`.
//!
//! Seed corpus: `crates/fcp-testkit/corpus/fcps_frame_parser/seeds.hex`.
//! The target accepts raw frame bytes and newline-delimited hex seed bundles.

#![no_main]

use fcp_protocol::{FCPS_HEADER_LEN, FcpsFrame, FcpsFrameHeader, SymbolRecord};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const FUZZ_MTU_BYTES: usize = 65536;

fuzz_target!(|data: &[u8]| {
    let result = catch_unwind(AssertUnwindSafe(|| {
        parse_hex_seed_bundle_or_raw(data, |bytes| {
            let _ = parse_fcps_frame(bytes);
        });
    }));
    assert!(result.is_ok(), "FCPS parser panicked on fuzz input");
});

fn parse_hex_seed_bundle_or_raw(data: &[u8], mut parse: impl FnMut(&[u8])) {
    let Ok(text) = std::str::from_utf8(data) else {
        parse(data);
        return;
    };
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if lines.is_empty()
        || !lines
            .iter()
            .all(|line| line.len() % 2 == 0 && line.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        parse(data);
        return;
    }

    for line in lines {
        if let Ok(bytes) = hex::decode(line) {
            parse(&bytes);
        }
    }
}

fn parse_fcps_frame(data: &[u8]) -> Result<(), String> {
    let header_result = FcpsFrameHeader::decode(data);

    for symbol_size in [1u16, 64, 128, 256, 512, 1024, 2048] {
        let _ = SymbolRecord::decode(data, symbol_size);
    }

    for max_datagram_bytes in [0usize, 64, FCPS_HEADER_LEN, 4096, FUZZ_MTU_BYTES] {
        let _ = FcpsFrame::decode(data, max_datagram_bytes);
    }

    match FcpsFrame::decode(data, FUZZ_MTU_BYTES) {
        Ok(frame) => {
            if frame.symbols.len() != frame.header.symbol_count as usize {
                return Err("decoded FCPS symbol count diverged from header".into());
            }
            let payload_len: usize = frame.symbols.iter().map(SymbolRecord::wire_size).sum();
            if payload_len != frame.header.total_payload_len as usize {
                return Err("decoded FCPS payload length diverged from header".into());
            }
            let encoded = frame.encode().map_err(|error| error.to_string())?;
            let reparsed =
                FcpsFrame::decode(&encoded, FUZZ_MTU_BYTES).map_err(|error| error.to_string())?;
            if reparsed != frame {
                return Err("FCPS decode/encode/decode roundtrip diverged".into());
            }
            Ok(())
        }
        Err(frame_error) => header_result
            .map(|_| ())
            .map_err(|header_error| format!("{header_error}; {frame_error}")),
    }
}
