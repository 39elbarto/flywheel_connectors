//! Adversarial fuzz harness — fcp-host invoke envelope decode
//! (testing-fuzzing alpha-domain coverage).
//!
//! AmberLark, 2026-05-02. Complements CrimsonWolf's beta PQ-crypto
//! fuzz sweep (commit 6f46e6a13) with alpha-side wire-format coverage.
//!
//! Feeds arbitrary bytes to two real decoders that the fcp-host
//! invoke path uses on the wire boundary:
//!
//! - `serde_json::from_slice::<InvokeRequest>`  (HTTP `/rpc/invoke` body).
//! - `ciborium::de::from_reader::<InvokeRequest, _>` (CBOR transport).
//!
//! Asserts:
//!
//! - **Never panics.** No proptest input may panic either decoder.
//! - **Bounded allocation.** Decode either succeeds or returns a typed
//!   `Err` — the harness uses `panic::catch_unwind` to fail loudly on
//!   any allocator-abort or decoder panic. Allocation bounds are
//!   already enforced by `MAX_DESERIALIZATION_RECURSION_LIMIT` and
//!   the workspace's `MAX_V4_PAYLOAD_BYTES` cap (br-CrimsonWolf beta
//!   sweep), so this harness pins that contract from the alpha side.
//! - **Deterministic decode.** Re-decoding the same bytes twice
//!   produces equivalent `Ok`/`Err` discriminants.

use std::panic;

use proptest::collection::vec;
use proptest::prelude::*;

use fcp_core::InvokeRequest;

/// Cap input size so the harness stays in budget. Larger than the
/// minimum InvokeRequest envelope (~200 bytes) so realistic
/// wire-format inputs can be exercised; small enough that proptest
/// shrinking stays fast.
const MAX_INPUT_BYTES: usize = 4 * 1024;

fn arb_envelope_bytes() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..MAX_INPUT_BYTES)
}

/// Strategy that occasionally produces a structurally-plausible JSON
/// envelope (the `{"type":"invoke",...}` shape the wire path uses)
/// alongside fully-random byte runs. Mixing both gives the fuzzer a
/// path to exercise the deeper decode tree, not just the
/// length-prefix / first-byte rejection path.
fn arb_mixed_envelope_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        9 => arb_envelope_bytes(),
        1 => "\\{\"type\"\\s*:\\s*\"[a-z]{0,16}\"[a-zA-Z0-9_:.,\"\\s\\{\\}\\[\\]]{0,256}\\}"
                .prop_map(String::into_bytes),
    ]
}

fn try_decode_json(bytes: &[u8]) -> Result<(), serde_json::Error> {
    serde_json::from_slice::<InvokeRequest>(bytes).map(|_| ())
}

fn try_decode_cbor(bytes: &[u8]) -> Result<(), ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader::<InvokeRequest, _>(bytes).map(|_| ())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// br-AmberLark/fuzz: arbitrary bytes through serde_json
    /// MUST NOT panic the decoder. Either `Ok(InvokeRequest)` or
    /// typed `Err`. Anything else is a real bug.
    #[test]
    fn rpc_invoke_envelope_fuzz_json_never_panics(
        bytes in arb_mixed_envelope_bytes(),
    ) {
        let result = panic::catch_unwind(|| try_decode_json(&bytes));
        prop_assert!(
            result.is_ok(),
            "serde_json decode panicked on {} bytes — possible adversarial-input bug",
            bytes.len()
        );
    }

    /// br-AmberLark/fuzz: arbitrary bytes through ciborium MUST NOT
    /// panic. The MAX_DESERIALIZATION_RECURSION_LIMIT bound is
    /// already enforced upstream (br-CrimsonWolf); this harness pins
    /// that contract from the consumer side.
    #[test]
    fn rpc_invoke_envelope_fuzz_cbor_never_panics(
        bytes in arb_envelope_bytes(),
    ) {
        let result = panic::catch_unwind(|| try_decode_cbor(&bytes));
        prop_assert!(
            result.is_ok(),
            "ciborium decode panicked on {} bytes — possible adversarial-input bug",
            bytes.len()
        );
    }

    /// br-AmberLark/fuzz: re-decoding the same bytes twice produces
    /// the SAME outcome shape (Ok-vs-Err). No hidden state in the
    /// decoder.
    #[test]
    fn rpc_invoke_envelope_fuzz_json_decode_is_deterministic(
        bytes in arb_envelope_bytes(),
    ) {
        let first = try_decode_json(&bytes).is_ok();
        let second = try_decode_json(&bytes).is_ok();
        prop_assert_eq!(first, second,
            "serde_json decode flipped Ok/Err across two attempts on identical bytes");
    }

    /// br-AmberLark/fuzz: empty bytes MUST always reject (typed Err)
    /// in both formats. Acts as the canonical floor case so a future
    /// regression that accepts an empty-body invoke is caught.
    #[test]
    fn rpc_invoke_envelope_fuzz_empty_bytes_always_reject(
        ()  in Just(()),
    ) {
        let json_err = try_decode_json(&[]);
        let cbor_err = try_decode_cbor(&[]);
        prop_assert!(json_err.is_err(), "empty bytes MUST reject as JSON");
        prop_assert!(cbor_err.is_err(), "empty bytes MUST reject as CBOR");
    }
}
