//! FCPC frame parser fuzz target for `flywheel_connectors-angoc.10.1`.
//!
//! Seed corpus: `crates/fcp-testkit/corpus/fcpc_frame_parser/seeds.hex`.
//! The target accepts raw frame bytes and newline-delimited hex seed bundles.

#![no_main]

use fcp_protocol::{FCPC_TAG_LEN, FcpcFrame, FcpcFrameHeader};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

fuzz_target!(|data: &[u8]| {
    let result = catch_unwind(AssertUnwindSafe(|| {
        parse_hex_seed_bundle_or_raw(data, |bytes| {
            let _ = parse_fcpc_frame(bytes);
        });
    }));
    assert!(result.is_ok(), "FCPC parser panicked on fuzz input");
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

fn parse_fcpc_frame(data: &[u8]) -> Result<(), String> {
    let header_result = FcpcFrameHeader::decode(data);

    for max_payload_len in [0usize, 64, 256, 1024, 4096, 65536] {
        let _ = FcpcFrame::decode_with_limit(data, max_payload_len);
    }

    match FcpcFrame::decode(data) {
        Ok(frame) => {
            if frame.header.len as usize != frame.ciphertext.len() {
                return Err("decoded FCPC frame length fields diverged".into());
            }
            if frame.tag.len() != FCPC_TAG_LEN {
                return Err("decoded FCPC tag length diverged".into());
            }
            let encoded = frame.encode();
            let reparsed = FcpcFrame::decode(&encoded).map_err(|error| error.to_string())?;
            if reparsed != frame {
                return Err("FCPC decode/encode/decode roundtrip diverged".into());
            }
            Ok(())
        }
        Err(frame_error) => header_result
            .map(|_| ())
            .map_err(|header_error| format!("{header_error}; {frame_error}")),
    }
}
