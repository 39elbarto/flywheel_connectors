#![no_main]

//! Fuzz target for `RevocationRegistry::check_with_seal` /
//! `validate_seal`, `RevocationSeal`, and `SealValidation`
//! (revocation.rs:738-820).
//!
//! These are the C1.1 check-use atomicity primitives: a revocation
//! check at time T₀ produces a `RevocationSeal` capturing the
//! registry's `head_seq`, and the operation can re-validate that seal
//! at commit time T₁. If the registry advanced between T₀ and T₁ the
//! seal is `Stale` and the caller must re-check — closing the
//! TOCTOU window where a fresh revocation could have been added
//! between the check and the use.
//!
//! NOT covered as a discrete unit by any existing fuzz target.
//!
//! A regression that:
//!   - made `validate_seal` ignore the `head_seq` check would defeat
//!     the entire C1.1 atomicity defense — a stale seal would pass
//!     after a revocation.
//!   - dropped `token_id` matching would let an attacker present a
//!     seal for a different token and still satisfy validation.
//!   - flipped `Stale` and `Valid` for the equal-seq case would
//!     return the wrong result on the happy path.
//!
//! Properties asserted:
//!
//!   1. **Seal capture**: `check_with_seal(token, now)` returns a
//!      seal whose `head_seq == registry.head_seq`, `token_id ==
//!      token`, `checked_at == now`, and decision matches
//!      `is_revoked(token)`.
//!   2. **Validation Valid path**: `validate_seal(seal, token)`
//!      returns `Valid` when `seal.head_seq == registry.head_seq`
//!      AND `seal.token_id == token`.
//!   3. **TokenMismatch precedence**: a different `expected_token_id`
//!      MUST yield `TokenMismatch` regardless of the seq match.
//!   4. **Stale on advance**: after `update_head` increments the seq,
//!      the original seal MUST yield `Stale{seal_seq, current_seq}`
//!      with both fields preserved.
//!   5. **`is_valid` ⇔ `Valid`** variant.
//!   6. **Determinism**: repeated `check_with_seal` calls return
//!      identical seals (modulo `checked_at`).
//!
//!   Once-gated anchors verify each branch on hand-picked inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::SchemaId;
use fcp_core::{
    ObjectHeader, ObjectId, Provenance, RevocationDecision, RevocationObject, RevocationRegistry,
    RevocationScope, SealValidation, ZoneId,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static SEAL_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    token_id_bytes: [u8; 32],
    other_token_id_bytes: [u8; 32],
    head_id_bytes: [u8; 32],
    initial_seq: u64,
    advance_delta: u64,
    pre_revoke: bool,
    now: u64,
    last_updated: u64,
}

fn make_revocation(token_id: ObjectId) -> RevocationObject {
    RevocationObject {
        header: ObjectHeader {
            schema: SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        revoked: vec![token_id],
        scope: RevocationScope::Capability,
        reason: "fuzz".into(),
        effective_at: 0,
        expires_at: None,
        signature: [0u8; 64],
    }
}

fuzz_target!(|data: &[u8]| {
    SEAL_ANCHOR.call_once(assert_seal_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let token = ObjectId::from_bytes(input.token_id_bytes);
    let other_token = ObjectId::from_bytes(input.other_token_id_bytes);
    let head_id = ObjectId::from_bytes(input.head_id_bytes);

    let mut reg = RevocationRegistry::new();
    reg.update_head(head_id, input.initial_seq, input.last_updated);
    if input.pre_revoke {
        reg.add_revocation(&make_revocation(token));
    }

    // ── PROPERTY 1: seal captures registry state ────────────────────────
    let seal = reg.check_with_seal(&token, input.now);
    assert_eq!(
        seal.head_seq, reg.head_seq,
        "seal.head_seq != registry.head_seq"
    );
    assert_eq!(seal.token_id, token, "seal.token_id != input token");
    assert_eq!(seal.checked_at, input.now, "seal.checked_at != now");
    let expected_decision = if reg.is_revoked(&token) {
        RevocationDecision::Revoked
    } else {
        RevocationDecision::NotRevoked
    };
    assert_eq!(
        seal.decision, expected_decision,
        "seal.decision did not reflect is_revoked(token)"
    );

    // ── PROPERTY 6: determinism (modulo checked_at) ─────────────────────
    let seal2 = reg.check_with_seal(&token, input.now);
    assert_eq!(seal.head_seq, seal2.head_seq);
    assert_eq!(seal.token_id, seal2.token_id);
    assert_eq!(seal.decision, seal2.decision);

    // ── PROPERTY 2: Valid when token + seq match ────────────────────────
    let v = reg.validate_seal(&seal, &token);
    assert!(matches!(v, SealValidation::Valid));
    assert!(v.is_valid(), "is_valid must be true for Valid variant");

    // ── PROPERTY 3: TokenMismatch precedence ────────────────────────────
    if other_token != token {
        let mismatch = reg.validate_seal(&seal, &other_token);
        assert!(
            matches!(mismatch, SealValidation::TokenMismatch),
            "expected TokenMismatch on different expected_token_id, got {mismatch:?}"
        );
        assert!(!mismatch.is_valid(), "TokenMismatch.is_valid must be false");
    }

    // ── PROPERTY 4: Stale on advance ────────────────────────────────────
    let advance = input.advance_delta.max(1);
    let new_seq = input.initial_seq.saturating_add(advance);
    if new_seq > input.initial_seq {
        let new_head = ObjectId::from_bytes([0xFEu8; 32]);
        reg.update_head(new_head, new_seq, input.last_updated.saturating_add(1));
        let stale = reg.validate_seal(&seal, &token);
        match stale {
            SealValidation::Stale {
                seal_seq,
                current_seq,
            } => {
                assert_eq!(
                    seal_seq, input.initial_seq,
                    "Stale.seal_seq did not preserve seal's head_seq"
                );
                assert_eq!(
                    current_seq, reg.head_seq,
                    "Stale.current_seq did not match registry head_seq"
                );
            }
            other => panic!(
                "expected Stale after head advance, got {other:?} (seal.head_seq={}, registry.head_seq={})",
                seal.head_seq, reg.head_seq
            ),
        }
        assert!(!stale.is_valid(), "Stale.is_valid must be false");

        // TokenMismatch precedence holds even when stale.
        if other_token != token {
            let m = reg.validate_seal(&seal, &other_token);
            assert!(
                matches!(m, SealValidation::TokenMismatch),
                "TokenMismatch must take precedence over Stale, got {m:?}"
            );
        }
    }
});

/// Once-gated anchors: hand-picked branches.
fn assert_seal_anchored() {
    let token = ObjectId::from_bytes([0xAAu8; 32]);
    let other = ObjectId::from_bytes([0xBBu8; 32]);

    let mut reg = RevocationRegistry::new();
    reg.update_head(ObjectId::from_bytes([1u8; 32]), 5, 100);

    // (a) Seal captures registry state on a fresh token.
    let seal = reg.check_with_seal(&token, 1_000);
    assert_eq!(seal.head_seq, 5, "ANCHOR: seal.head_seq");
    assert_eq!(seal.token_id, token, "ANCHOR: seal.token_id");
    assert_eq!(seal.checked_at, 1_000, "ANCHOR: seal.checked_at");
    assert_eq!(
        seal.decision,
        RevocationDecision::NotRevoked,
        "ANCHOR: not-yet-revoked → NotRevoked"
    );

    // (b) Valid when seq matches and token matches.
    let v = reg.validate_seal(&seal, &token);
    assert!(matches!(v, SealValidation::Valid), "ANCHOR: Valid path");

    // (c) TokenMismatch on different expected_token_id.
    let m = reg.validate_seal(&seal, &other);
    assert!(
        matches!(m, SealValidation::TokenMismatch),
        "ANCHOR REGRESSION: validate_seal accepted wrong token"
    );

    // (d) Stale after head advance.
    reg.update_head(ObjectId::from_bytes([2u8; 32]), 10, 200);
    let s = reg.validate_seal(&seal, &token);
    match s {
        SealValidation::Stale {
            seal_seq: 5,
            current_seq: 10,
        } => {}
        other => panic!("ANCHOR REGRESSION: expected Stale{{5,10}}, got {other:?}"),
    }

    // (e) TokenMismatch precedence over Stale.
    let m = reg.validate_seal(&seal, &other);
    assert!(
        matches!(m, SealValidation::TokenMismatch),
        "ANCHOR REGRESSION: TokenMismatch must precede Stale"
    );

    // (f) Decision Revoked path.
    let mut reg2 = RevocationRegistry::new();
    reg2.add_revocation(&make_revocation(token));
    let seal2 = reg2.check_with_seal(&token, 0);
    assert_eq!(
        seal2.decision,
        RevocationDecision::Revoked,
        "ANCHOR: revoked token → Revoked decision"
    );

    // (g) is_valid mapping.
    assert!(SealValidation::Valid.is_valid());
    assert!(!SealValidation::TokenMismatch.is_valid());
    assert!(
        !SealValidation::Stale {
            seal_seq: 1,
            current_seq: 2
        }
        .is_valid()
    );
}
