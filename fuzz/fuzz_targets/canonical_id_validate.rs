#![no_main]

//! Fuzz target for `fcp_core::validate_canonical_id` and its typed
//! wrappers.
//!
//! `validate_canonical_id` (capability.rs:84) is the shared
//! NORMATIVE validator for the FCP identifier set:
//!   - `CapabilityId`
//!   - `ConnectorId`
//!   - `InstanceId`
//!   - `OperationId`
//!   - `PrincipalId`
//!   - `TailscaleNodeId`
//!
//! Each wrapper's serde gate is `#[serde(try_from = "String")]`, which
//! routes wire-supplied identifiers (audit receipts, capability tokens,
//! frame source ids, peer identifiers in session messages) through
//! `validate_canonical_id`. A regression here — an accept-on-malformed
//! input or a typed-wrapper / validator disagreement — is exactly the
//! attack class TailscaleNodeId's docstring at capability.rs:846 calls
//! out:
//!
//!   - empty / whitespace / NUL-embedded
//!   - bidi-override (e.g. `"\u{202E}revil-node"`) attempting to
//!     visually impersonate another identifier
//!   - namespace collision (e.g. `"z:owner"` smuggled as a node id)
//!
//! Properties asserted:
//!
//!   1. `validate_canonical_id` is panic-free over arbitrary UTF-8.
//!   2. **Typed-wrapper agreement**: every typed wrapper's
//!      `TryFrom<String>` accepts iff `validate_canonical_id` accepts.
//!      The wrappers must NOT add their own restrictions (or relax
//!      shared ones) without going through the central validator.
//!   3. Accepted IDs round-trip through `as_str()` → re-parse to the
//!      same byte sequence.
//!   4. Specific attack inputs (NUL, bidi-override, uppercase, leading
//!      `-`) are unconditionally rejected.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{
    validate_canonical_id, CapabilityId, ConnectorId, InstanceId, OperationId, PrincipalId,
    TailscaleNodeId,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_INPUT_LEN: usize = 256;

static ATTACKS_VERIFIED: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
}

fn truncate_at_char_boundary(s: &str) -> &str {
    if s.len() <= MAX_INPUT_LEN {
        return s;
    }
    let mut end = MAX_INPUT_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Tuple of validating-constructor agreement results: each variant is
/// `true` if the typed wrapper's `TryFrom<String>` (the serde gate)
/// accepted the input.
fn wrapper_acceptance(s: &str) -> [bool; 6] {
    [
        CapabilityId::try_from(s.to_owned()).is_ok(),
        ConnectorId::try_from(s.to_owned()).is_ok(),
        InstanceId::try_from(s.to_owned()).is_ok(),
        OperationId::try_from(s.to_owned()).is_ok(),
        PrincipalId::try_from(s.to_owned()).is_ok(),
        TailscaleNodeId::try_from(s.to_owned()).is_ok(),
    ]
}

fuzz_target!(|data: &[u8]| {
    // Run the static attack-input assertions exactly once per process.
    // Catches regressions in the documented threat model on every fuzz
    // run while staying off the per-iteration hot path.
    ATTACKS_VERIFIED.call_once(assert_known_attacks_rejected);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let s = truncate_at_char_boundary(&owned);

    // ── PROPERTY 1: validate is panic-free ──────────────────────────────
    let validator_ok = validate_canonical_id(s).is_ok();

    // ── PROPERTY 2: typed-wrapper agreement ─────────────────────────────
    let wrappers = wrapper_acceptance(s);
    for (idx, &accepted) in wrappers.iter().enumerate() {
        assert_eq!(
            accepted, validator_ok,
            "typed-wrapper {idx} disagrees with validate_canonical_id on input {s:?}: \
             wrapper={accepted} validator={validator_ok}"
        );
    }

    // ── PROPERTY 3: accepted round-trip ─────────────────────────────────
    if validator_ok {
        let cap = CapabilityId::try_from(s.to_owned()).expect("agreement holds");
        assert_eq!(cap.as_str(), s, "CapabilityId did not preserve input");
        // Spot-check one more wrapper to catch construction-vs-storage drift.
        let node = TailscaleNodeId::try_from(s.to_owned()).expect("agreement holds");
        assert_eq!(node.as_str(), s, "TailscaleNodeId did not preserve input");

        // Re-parse from the stored canonical form.
        let reparsed = CapabilityId::try_from(cap.as_str().to_owned())
            .expect("re-parsed CapabilityId must accept its own canonical form");
        assert_eq!(reparsed.as_str(), s);
    }
});

/// Static-input attacks: must always be rejected. Invoked once per
/// process via `Once`, so it runs on every fuzz session start without
/// adding cost to the inner loop.
fn assert_known_attacks_rejected() {
    // Empty.
    assert!(
        validate_canonical_id("").is_err(),
        "empty id MUST be rejected"
    );

    // NUL-embedded (capability.rs:846 specifically calls this out).
    assert!(
        validate_canonical_id("node\0poison").is_err(),
        "NUL-embedded id MUST be rejected"
    );

    // Bidi-override impersonation (\u{202E} = RIGHT-TO-LEFT OVERRIDE).
    assert!(
        validate_canonical_id("\u{202E}revil-node").is_err(),
        "bidi-override id MUST be rejected"
    );

    // Uppercase ASCII.
    assert!(
        validate_canonical_id("Node-1").is_err(),
        "uppercase id MUST be rejected"
    );

    // Leading dash (start char must be lowercase or digit).
    assert!(
        validate_canonical_id("-leading-dash").is_err(),
        "leading-dash id MUST be rejected"
    );

    // Whitespace.
    assert!(
        validate_canonical_id("has space").is_err(),
        "whitespace id MUST be rejected"
    );

    // Length cap (129 lowercase letters = 1 over the 128-byte cap).
    let oversized: String = std::iter::repeat_n('a', 129).collect();
    assert!(
        validate_canonical_id(&oversized).is_err(),
        "oversized id MUST be rejected"
    );

    // Anchor: a known-good id MUST still be accepted, otherwise the
    // attacker assertions above don't tell us anything (the validator
    // could be rejecting everything).
    assert!(
        validate_canonical_id("node-1.az_b:c").is_ok(),
        "canonical id sample MUST be accepted; if this trips the validator \
         is over-restrictive and the regression catalog is unsound"
    );
}
