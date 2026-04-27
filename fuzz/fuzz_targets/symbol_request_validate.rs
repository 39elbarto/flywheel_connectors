#![no_main]

//! Fuzz the fcp-protocol `SymbolRequest` CBOR decode + validate + verify path.
//!
//! `SymbolRequest` is the control-plane parser the mesh evaluates **before**
//! it commits any response symbols. A panic anywhere in decode →
//! `validate_hint_bounds` → `validate_bounds` → `transcript_bytes` → `verify`
//! is a remote DoS, because the request travels across FCPC and the receiver
//! has no opportunity to reject it earlier than the structural validators
//! exercised here.
//!
//! Property the fuzzer asserts on every decode-success: the validator chain
//! returns a `Result` (or a bool) without panicking, regardless of how
//! adversarial the decoded values are. Anti-amplification caps
//! `MAX_SYMBOLS_HARD_CAP` (= 2001) and `MAX_MISSING_HINT_ENTRIES` (= 100)
//! must be enforced by the validators, not by the decoder.
//!
//! No panic is the only oracle. We deliberately do **not** assert that
//! `verify` returns `Ok` — the fuzzer-supplied signatures will essentially
//! always be invalid; we just need to know that signature verification
//! itself never panics on a structurally-valid request.

use ciborium::de::from_reader;
use fcp_crypto::Ed25519SigningKey;
use fcp_protocol::SymbolRequest;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(request) = from_reader::<SymbolRequest, _>(Cursor::new(data)) else {
        return;
    };

    // Each of these must return without panicking, regardless of the field
    // values inside `request`. Errors are explicitly allowed and ignored —
    // the property under test is panic-freedom, not acceptance.
    let _ = request.validate_hint_bounds();
    let _ = request.validate_bounds(true);
    let _ = request.validate_bounds(false);
    let _ = request.has_proof_of_need();

    // `transcript_bytes` is infallible by signature but must not allocate
    // unboundedly or overflow on adversarial input. The hint loop is
    // bounded by the number of entries the CBOR decoder accepted; we cap
    // overall input above to keep iteration bounded.
    let _ = request.transcript_bytes();

    // `verify` runs the same defensive bounds checks before the Ed25519
    // call, so this exercises the full path. We construct a fixed key so
    // every fuzzer run is deterministic and shares cached cryptographic
    // setup.
    let signing_key = Ed25519SigningKey::from_bytes(&[0x42; 32])
        .expect("fixed Ed25519 key bytes are always valid");
    let verifying_key = signing_key.verifying_key();
    let _ = request.verify(&verifying_key);
});
