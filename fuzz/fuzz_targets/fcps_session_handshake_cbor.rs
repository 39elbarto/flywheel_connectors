//! FCPS session-handshake CBOR parser fuzz target (mechanical port of
//! the proptest harnesses shipped in commit 2ace18e83 —
//! `session_decode_hello_cbor_never_panics`,
//! `session_decode_ack_cbor_never_panics`, and
//! `session_decode_cookie_panic_safe_and_length_strict`).
//!
//! Targets the THREE byte-input boundaries on the FCPS handshake
//! parser that accept untrusted CBOR / opaque bytes from a
//! prospective peer:
//!
//! - `decode_hello_cbor` — peer-initiated session start
//! - `decode_ack_cbor`   — gateway-side acknowledgement
//! - `decode_cookie_bytes` — stateless retry cookie
//!
//! The proptest harness covers the same three entry points but at
//! 512 random shapes per run. libFuzzer's coverage-guided exploration
//! finds shapes that hit specific CBOR major-type / definite-vs-
//! indefinite-length branches the proptest random walk would only
//! hit with low probability (e.g., a CBOR map with claimed length
//! 2^32 followed by zero bytes — exercises the canonical-CBOR
//! length-vs-actual-bytes mismatch detector).
//!
//! ## Crash-only oracle
//!
//! Every rejection MUST surface as `SessionError`, never a panic.
//! The cookie length check is invariant: input.len() == 32 → Ok,
//! anything else → Err.
//!
//! ## Run command
//!
//! ```bash
//! cd /Users/jemanuel/projects/flywheel_connectors
//! cargo +nightly fuzz run fuzz_fcps_session_handshake_cbor
//! cargo +nightly fuzz run fuzz_fcps_session_handshake_cbor -- -runs=100000 -max_total_time=60
//! ```

#![no_main]

use fcp_protocol::{decode_ack_cbor, decode_cookie_bytes, decode_hello_cbor};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 32 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Crash oracle: each parser MUST return Result, not panic, for
    // any input. The corpus quickly converges on inputs that walk
    // each parser's full CBOR-major-type matrix.
    let _ = decode_hello_cbor(data);
    let _ = decode_ack_cbor(data);

    // Length-strict oracle for the cookie: 32 bytes ⇒ Ok, else Err.
    // This is a structural invariant that should never flip; an
    // off-by-one in the boundary check would be caught by the
    // assertion below. Pre-fix: a length-comparison bug that
    // accepted 31 or 33 bytes would silently widen the cookie
    // surface and let a peer forge handshake retries.
    let cookie_result = decode_cookie_bytes(data);
    if data.len() == 32 {
        assert!(
            cookie_result.is_ok(),
            "32-byte cookie MUST decode but rejected: {cookie_result:?}",
        );
    } else {
        assert!(
            cookie_result.is_err(),
            "non-32-byte cookie ({}b) MUST reject but accepted",
            data.len(),
        );
    }
});
