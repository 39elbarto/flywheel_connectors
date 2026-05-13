//! COSE envelope parser fuzz target for `flywheel_connectors-angoc.10.1`.
//!
//! Seed corpus: `crates/fcp-testkit/corpus/cose_envelope_parser/seeds.hex`.
//! The target accepts raw COSE bytes and newline-delimited hex seed bundles.

#![no_main]

use fcp_crypto::cose::{CoseToken, MAX_COSE_TOKEN_BYTES};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

fuzz_target!(|data: &[u8]| {
    let result = catch_unwind(AssertUnwindSafe(|| {
        parse_hex_seed_bundle_or_raw(data, |bytes| {
            let _ = parse_cose_envelope(bytes);
        });
    }));
    assert!(
        result.is_ok(),
        "COSE envelope parser panicked on fuzz input"
    );
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

fn parse_cose_envelope(data: &[u8]) -> Result<(), String> {
    if data.len() > MAX_COSE_TOKEN_BYTES {
        return Err("COSE input exceeds parser cap".into());
    }

    let token = CoseToken::from_cbor(data).map_err(|error| error.to_string())?;
    let encoded = token.to_cbor().map_err(|error| error.to_string())?;
    let reparsed = CoseToken::from_cbor(&encoded).map_err(|error| error.to_string())?;
    let _ = reparsed.claims_unverified();
    Ok(())
}
