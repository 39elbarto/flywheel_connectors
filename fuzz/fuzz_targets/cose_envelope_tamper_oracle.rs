//! COSE envelope verifier tamper-oracle fuzz target (mechanical port
//! of the proptest harness shipped in commit 2ace18e83 —
//! `cose_envelope_tampered_signature_byte_fails_with_typed_error`).
//!
//! The existing `cose_parse_adversarial.rs` and `cose_roundtrip.rs`
//! targets cover `CoseToken::from_cbor` parsing and the encode →
//! decode round-trip. Neither of them exercises the **verify gate**
//! against tampered envelopes — which is the load-bearing security
//! invariant of the entire capability-token surface.
//!
//! This target seeds with a real signed envelope (built once via
//! `LLVMFuzzerInitialize`-equivalent lazy init), then uses the
//! fuzz-supplied bytes as a TAMPER MASK xor'd into the signed
//! envelope. The verifier MUST reject every non-zero-mask result
//! with a typed `CryptoError`.
//!
//! ## Why this shape
//!
//! Naive byte-replacement fuzzing rarely hits the signature-region
//! bytes — most random bytes look like garbage CBOR and reject at
//! `from_cbor` long before reaching `verify`. By xor'ing the input
//! INTO a known-valid envelope, we guarantee that ~all inputs reach
//! the verifier; libFuzzer's coverage feedback then drives toward
//! masks that touch the signature region without breaking CBOR
//! framing.
//!
//! ## Oracle
//!
//! - Mask of all zeros → re-encoded envelope identical to original
//!   → `verify(...)` MUST succeed (proves the harness wires up).
//! - Any non-zero mask that survives `from_cbor` → `verify(...)`
//!   MUST return `Err(CryptoError::*)` — never silent Ok, never
//!   panic.
//!
//! ## Run command
//!
//! ```bash
//! cd /Users/jemanuel/projects/flywheel_connectors
//! cargo +nightly fuzz run fuzz_cose_envelope_tamper_oracle
//! cargo +nightly fuzz run fuzz_cose_envelope_tamper_oracle -- -runs=100000 -max_total_time=60
//! ```

#![no_main]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{CoseToken, CwtClaims, Ed25519SigningKey, Ed25519VerifyingKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Lazily-built valid COSE envelope + verifying key. Initialised once
/// per fuzz-process lifetime to keep exec/s high — every iteration
/// reuses the same baseline. Per the testing-fuzzing skill's Hard
/// Rule #13: "move all one-time initialization out of the fuzz
/// target body."
struct Baseline {
    envelope_bytes: Vec<u8>,
    verifying_key: Ed25519VerifyingKey,
}

static BASELINE: OnceLock<Baseline> = OnceLock::new();

fn baseline() -> &'static Baseline {
    BASELINE.get_or_init(|| {
        // Deterministic seed so the baseline is reproducible across
        // runs (helps with crash-replay if libFuzzer finds a
        // tamper input that bypasses verification).
        let signing_key = Ed25519SigningKey::from_bytes(&[0x42_u8; 32])
            .expect("32-byte seed produces valid Ed25519 key");
        let verifying_key = signing_key.verifying_key();
        let now = Utc::now();
        let claims = CwtClaims::new()
            .issuer("amberlark-fuzz-tamper-oracle")
            .subject("baseline")
            .issued_at(now)
            .expiration(now + ChronoDuration::hours(1));
        let token = CoseToken::sign(&signing_key, &claims).expect("sign baseline");
        let envelope_bytes = token.to_cbor().expect("encode baseline");
        Baseline {
            envelope_bytes,
            verifying_key,
        }
    })
}

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let base = baseline();

    // XOR the fuzz input INTO the baseline envelope (modulo-cycle
    // when the input is shorter, which is the common case). A mask
    // of all zeros leaves the envelope intact; any non-zero mask
    // produces a tampered envelope that — IF it still parses as
    // CBOR — MUST fail verification.
    let mut tampered = base.envelope_bytes.clone();
    if !data.is_empty() {
        for (i, byte) in tampered.iter_mut().enumerate() {
            *byte ^= data[i % data.len()];
        }
    }

    // Try to parse the tampered envelope. Most random masks will
    // break CBOR framing and short-circuit here.
    let Ok(token) = CoseToken::from_cbor(&tampered) else {
        return;
    };

    // The interesting case: mask survived CBOR framing, so we
    // reach the verifier. Verify against the baseline's verifying
    // key. EVERY non-trivially-zero mask MUST produce Err.
    let result = token.verify(&base.verifying_key);

    // Special case: if the mask is exactly the zero mask (or
    // cycles to zero modulo input length), we may have left the
    // envelope unchanged — Ok is the correct outcome there. Detect
    // by comparing tampered to baseline.
    if tampered == base.envelope_bytes {
        // No-op mask — verify SHOULD succeed.
        assert!(
            result.is_ok(),
            "zero-mask MUST verify the baseline envelope; got {result:?}",
        );
    } else {
        // Non-trivial tamper that survived CBOR framing — verify
        // MUST reject. A silent Ok here would be a critical
        // signature-bypass vulnerability.
        assert!(
            result.is_err(),
            "tampered envelope MUST NOT verify; got Ok — possible signature-bypass bug. \
             baseline_len={} tampered_len={} mask_len={}",
            base.envelope_bytes.len(),
            tampered.len(),
            data.len(),
        );
    }
});
