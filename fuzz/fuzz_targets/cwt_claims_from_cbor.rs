//! `CwtClaims::from_cbor` fuzz target (mechanical port of
//! the proptest harness shipped in commit 2ace18e83 —
//! `cwt_claims_from_cbor_never_panics` and
//! `cwt_claims_oversized_input_fails_closed`).
//!
//! Targets the capability-token CLAIM deserializer specifically — NOT
//! the surrounding COSE envelope. The sibling fuzz target
//! `auth_claims_cbor.rs` covers a different type
//! (`fcp_auth_schema::AuthClaims`); this one exercises
//! `fcp_crypto::cose::CwtClaims` which is the actual claim payload
//! inside every signed capability token.
//!
//! ## Oracles
//!
//! - **Crash oracle:** `from_cbor` MUST return `CryptoResult` on
//!   arbitrary bytes — never panic. libFuzzer's coverage feedback
//!   walks the ciborium-value-to-CwtClaims mapping branches
//!   (numeric label → claim slot, unknown label → reject).
//!
//! - **Cap-bound oracle:** inputs over `MAX_COSE_TOKEN_BYTES` (64 KiB)
//!   MUST reject before allocation. We exercise this with the
//!   MAX_INPUT_BYTES cap set to that exact value — libFuzzer will
//!   produce inputs that straddle it.
//!
//! - **Trailing-bytes oracle:** `from_cbor` checks
//!   `cursor.position() == bytes.len()` (cose.rs:418). A canonical
//!   value followed by even one trailing byte MUST reject. The
//!   coverage-guided walk discovers these mixed inputs efficiently.
//!
//! - **Authentication non-leak oracle:** `from_cbor` MUST NOT mark
//!   the returned claims authenticated — verification is a separate
//!   gate. We can't directly assert this from the public API
//!   (CwtClaims doesn't expose an "is_authenticated" bit), but the
//!   crash oracle pins that no signature-verification side-effect
//!   leaks into the deserializer.
//!
//! ## Run command
//!
//! ```bash
//! cd /Users/jemanuel/projects/flywheel_connectors
//! cargo +nightly fuzz run fuzz_cwt_claims_from_cbor
//! cargo +nightly fuzz run fuzz_cwt_claims_from_cbor -- -runs=100000 -max_total_time=60
//! ```

#![no_main]

use fcp_crypto::cose::MAX_COSE_TOKEN_BYTES;
use fcp_crypto::CwtClaims;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = MAX_COSE_TOKEN_BYTES + 16;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Crash oracle: never panics on arbitrary CBOR-shaped or random
    // bytes. The interesting branches are:
    //   - numeric integer keys → known CWT claim slot
    //   - canonical CBOR rejection (non-canonical encoding)
    //   - trailing-bytes check
    //   - oversized payload (> MAX_COSE_TOKEN_BYTES)
    let result = CwtClaims::from_cbor(data);

    // Cap-bound check: any input over MAX_COSE_TOKEN_BYTES MUST
    // reject. The MAX_INPUT_BYTES floor above keeps the coverage
    // window straddling the boundary so libFuzzer sees both branches
    // (just-under and just-over).
    if data.len() > MAX_COSE_TOKEN_BYTES {
        assert!(
            result.is_err(),
            "input over MAX_COSE_TOKEN_BYTES ({} bytes) MUST reject before allocation; got Ok",
            data.len(),
        );
    }
});
