//! Capability claim parser fuzz target for `flywheel_connectors-angoc.10.1`.
//!
//! Seed corpus: `crates/fcp-testkit/corpus/capability_claim_parser/seeds.hex`.
//! The target accepts raw claim bytes and newline-delimited hex seed bundles.

#![no_main]

use fcp_auth_schema::AuthClaims;
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_INPUT_BYTES: usize = 1024;

fuzz_target!(|data: &[u8]| {
    let result = catch_unwind(AssertUnwindSafe(|| {
        parse_hex_seed_bundle_or_raw(data, |bytes| {
            let _ = parse_capability_claims(bytes);
        });
    }));
    assert!(
        result.is_ok(),
        "capability claim parser panicked on fuzz input"
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

fn parse_capability_claims(data: &[u8]) -> Result<(), String> {
    if data.len() > MAX_INPUT_BYTES {
        return Err("capability claims input exceeds parser cap".into());
    }

    let claims = AuthClaims::from_canonical_cbor(data).map_err(|error| error.to_string())?;
    let encoded = claims
        .to_canonical_cbor()
        .map_err(|error| error.to_string())?;
    let reparsed = AuthClaims::from_canonical_cbor(&encoded).map_err(|error| error.to_string())?;
    if reparsed != claims {
        return Err("capability claims canonical roundtrip diverged".into());
    }
    Ok(())
}
