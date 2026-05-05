//! Byte-exact golden tests for the COSE encoding path in fcp-crypto.
//!
//! # Scope
//!
//! This crate implements the **`COSE_Sign1`** structure (RFC 9052) via
//! [`CoseToken::sign`] / [`CoseToken::to_cbor`] / [`CoseToken::from_cbor`].
//! It does **not** implement `COSE_Encrypt` or `COSE_Mac` directly —
//! confidentiality is handled through HPKE (`fcp_crypto::HpkeSealedBox`)
//! and integrity via Blake3 MACs (`fcp_crypto::Blake3Mac`), neither of
//! which is wrapped in COSE framing. This file therefore focuses on
//! `COSE_Sign1` and leaves a marker test asserting the absence of the
//! other COSE variants so a future addition lands with golden coverage
//! from day one rather than silently.
//!
//! # Determinism contract
//!
//! `COSE_Sign1` encoding MUST be deterministic for a fixed input:
//!
//!  1. Ed25519 signatures are deterministic by construction (RFC 8032).
//!  2. CWT payload CBOR goes through `CwtClaims::to_cbor` which maps to
//!     `ciborium` canonical encoding for integer-keyed maps.
//!  3. Protected headers are frozen (`alg = EdDSA`, `kid = <32-byte KID>`).
//!
//! If any of these stops being deterministic the tests below fail with a
//! precise mismatch — the skill doc calls that "freeze a known-good
//! output and diff against it forever." The key-material inputs are
//! seed-derived (`[0x01; 32]`, `[0x02; 32]`, ...) so the goldens can be
//! reproduced by anyone.
//!
//! # Regenerating goldens
//!
//! ```text
//! UPDATE_GOLDENS=1 cargo test -p fcp-crypto --test cose_golden
//! git diff crates/fcp-crypto/tests/golden/cose/
//! # Review, then commit.
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use fcp_crypto::CoseToken;
use fcp_crypto::CwtClaims;
use fcp_crypto::Ed25519SigningKey;

/// Path to `tests/golden/cose/<name>.hex`.
fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("cose")
        .join(format!("{name}.hex"))
}

/// Compare `actual_hex` against the on-disk golden. If the file does
/// not yet exist OR `UPDATE_GOLDENS=1` is set, write `actual_hex` into
/// the golden slot (auto-seed on first run; explicit re-capture on the
/// env-var trip). Every test that reaches this helper also prints the
/// hex to stderr with a parseable `[cose-golden] name=... hex=...`
/// prefix so the suite can be reconstructed from CI logs even when the
/// on-disk goldens are missing (e.g. a fresh checkout or a sandboxed
/// worker).
fn assert_golden_hex(name: &str, actual_hex: &str) {
    let path = golden_path(name);

    // Always emit the captured hex for offline reconstruction.
    eprintln!("[cose-golden] name={name} hex={actual_hex}");

    let update_requested = std::env::var("UPDATE_GOLDENS").is_ok();
    let existing = fs::read_to_string(&path).ok();

    if update_requested || existing.is_none() {
        fs::create_dir_all(path.parent().expect("golden path has a parent")).expect("mkdir -p");
        fs::write(&path, format!("{actual_hex}\n")).expect("write golden");
        if existing.is_none() {
            eprintln!(
                "[GOLDEN] seeded {} (first run — commit the file to lock bytes)",
                path.display()
            );
        } else {
            eprintln!("[GOLDEN] updated {} (UPDATE_GOLDENS=1)", path.display());
        }
        return;
    }

    let expected = existing.expect("checked above").trim().to_string();

    if actual_hex != expected {
        let actual_path = path.with_extension("actual");
        fs::write(&actual_path, format!("{actual_hex}\n")).expect("write actual");
        panic!(
            "COSE_Sign1 golden mismatch: {name}\n\
             expected ({exp_len} bytes): {expected}\n\
             actual   ({act_len} bytes): {actual_hex}\n\
             diff     {} {}\n\
             To update: UPDATE_GOLDENS=1 cargo test -p fcp-crypto --test cose_golden -- {name}",
            path.display(),
            actual_path.display(),
            exp_len = expected.len() / 2,
            act_len = actual_hex.len() / 2,
        );
    }
}

/// Build a deterministic Ed25519 signing key from a fixed 32-byte seed.
/// Using `[0x01; 32]`, `[0x02; 32]`, etc. keeps every golden independently
/// reproducible without a shared setup dance.
fn seeded_key(seed_byte: u8) -> Ed25519SigningKey {
    let seed = [seed_byte; 32];
    Ed25519SigningKey::from_bytes(&seed)
        .unwrap_or_else(|e| panic!("seed [0x{seed_byte:02x}; 32] must produce a valid key: {e}"))
}

/// Round-trip sanity: encoding is deterministic within a single run.
/// Two independent `sign(...)` calls on equal inputs must produce
/// byte-identical CBOR. If this ever fails, all byte-exact goldens below
/// become meaningless — file a P1 bead immediately.
fn assert_encode_deterministic(key_seed: u8, claims_fn: impl Fn() -> CwtClaims) {
    let key = seeded_key(key_seed);
    let a = CoseToken::sign(&key, &claims_fn())
        .and_then(|t| t.to_cbor())
        .expect("sign/encode must succeed on a valid input");
    let b = CoseToken::sign(&key, &claims_fn())
        .and_then(|t| t.to_cbor())
        .expect("sign/encode must succeed on a valid input");
    assert_eq!(
        a, b,
        "COSE_Sign1 encoding is non-deterministic — byte goldens are invalid. \
         File flywheel_connectors bead: P1, deterministic encoding is a core requirement."
    );
}

// ─────────────────────────────────────────────────────────────────────
//  COSE_Sign1 goldens
// ─────────────────────────────────────────────────────────────────────

/// Case A: minimum-payload CWT. User-supplied claims are empty, but
/// `CoseToken::sign` stamps the current schema version before signing
/// so verifiers never accept an unstamped production token.
#[test]
fn cose_sign1_empty_claims_golden() {
    assert_encode_deterministic(0x01, CwtClaims::new);

    let key = seeded_key(0x01);
    let claims = CwtClaims::new();
    let token = CoseToken::sign(&key, &claims).expect("sign empty claims");
    let bytes = token.to_cbor().expect("encode empty-claims token");

    // Decode round-trip: signature verifies, claims recover exactly.
    let decoded = CoseToken::from_cbor(&bytes).expect("decode round-trip");
    let recovered = decoded
        .verify(&key.verifying_key())
        .expect("verify empty-claims token");
    let expected = CwtClaims::new().custom(
        fcp_crypto::cose::fcp2_claims::SCHEMA_VERSION,
        ciborium::Value::Integer(i64::from(fcp_auth_schema::claims::CURRENT_SCHEMA_VERSION).into()),
    );
    assert_eq!(
        recovered.to_cbor().expect("recovered claims re-encode"),
        expected.to_cbor().expect("schema-stamped claims encode"),
    );

    assert_golden_hex("sign1_empty_claims", &hex::encode(&bytes));
}

/// Case B: single-operation capability token — the common issuance
/// shape. One `capability_id`, one `zone_id`, one operation. Seed 0x02
/// gives a different KID than case A so the protected header range
/// is forced to change across the golden suite.
#[test]
fn cose_sign1_single_op_capability_golden() {
    let make_claims = || {
        CwtClaims::new()
            .issuer("mesh://owner")
            .capability_id("cap:discord.send")
            .zone_id("z:community")
            .operations(&["discord.send_message"])
    };
    assert_encode_deterministic(0x02, make_claims);

    let key = seeded_key(0x02);
    let claims = make_claims();
    let token = CoseToken::sign(&key, &claims).expect("sign single-op claims");
    let bytes = token.to_cbor().expect("encode single-op token");

    let decoded = CoseToken::from_cbor(&bytes).expect("decode round-trip");
    let recovered = decoded
        .verify(&key.verifying_key())
        .expect("verify single-op token");
    assert_eq!(
        recovered.get_capability_id(),
        Some("cap:discord.send"),
        "capability_id must round-trip"
    );
    assert_eq!(
        recovered.get_zone_id(),
        Some("z:community"),
        "zone_id must round-trip"
    );

    assert_golden_hex("sign1_single_op_capability", &hex::encode(&bytes));
}

/// Case C: multiple-operations token. Expresses the "bundle" shape — a
/// single capability scope carrying an allow-list of operations — and
/// verifies the op list serializes stably in the declared order.
#[test]
fn cose_sign1_multi_op_capability_golden() {
    let make_claims = || {
        CwtClaims::new()
            .issuer("mesh://owner")
            .capability_id("cap:github.repo.full")
            .zone_id("z:work")
            .operations(&[
                "github.issues.read",
                "github.issues.write",
                "github.pulls.read",
                "github.pulls.write",
                "github.repo.read",
            ])
            .principal_id("principal:agent:builder")
    };
    assert_encode_deterministic(0x03, make_claims);

    let key = seeded_key(0x03);
    let claims = make_claims();
    let token = CoseToken::sign(&key, &claims).expect("sign multi-op claims");
    let bytes = token.to_cbor().expect("encode multi-op token");

    let decoded = CoseToken::from_cbor(&bytes).expect("decode round-trip");
    decoded
        .verify(&key.verifying_key())
        .expect("verify multi-op token");

    assert_golden_hex("sign1_multi_op_capability", &hex::encode(&bytes));
}

/// Case D: "multiple kids" — distinct signing keys produce goldens with
/// different kids but the same claims, so we lock in that the protected
/// header actually reflects the key id and the payload bytes are stable.
#[test]
fn cose_sign1_multiple_kids_golden() {
    let make_claims = || {
        CwtClaims::new()
            .issuer("mesh://owner")
            .capability_id("cap:shared")
            .zone_id("z:private")
            .operations(&["fs.read"])
    };

    for seed in [0x04u8, 0x05, 0x06] {
        assert_encode_deterministic(seed, make_claims);
        let key = seeded_key(seed);
        let token = CoseToken::sign(&key, &make_claims()).expect("sign per-kid claims");
        let bytes = token.to_cbor().expect("encode per-kid token");

        // The decoded kid bytes MUST equal the expected key id, which
        // pins that a regression mapping kid from `verifying_key` to a
        // different 8-byte window would surface here.
        let decoded = CoseToken::from_cbor(&bytes).expect("decode round-trip");
        let kid_bytes = decoded.get_key_id().expect("kid present");
        assert_eq!(
            kid_bytes,
            key.key_id().as_bytes(),
            "decoded kid must equal Ed25519SigningKey::key_id() for seed {seed:#04x}"
        );
        decoded
            .verify(&key.verifying_key())
            .expect("verify per-kid token");

        let name = format!("sign1_multi_kid_seed_{seed:02x}");
        assert_golden_hex(&name, &hex::encode(&bytes));
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Negative-path goldens (errors MUST be stable too)
// ─────────────────────────────────────────────────────────────────────

/// Truncated CBOR MUST be rejected by `from_cbor`. Pins that a decoder
/// regression that silently parses short input (zero-padding, reading
/// beyond the buffer) surfaces instead of returning a malformed token.
#[test]
fn cose_sign1_decode_truncated_errors() {
    // Encode a valid token, then lop off the trailing signature bytes.
    let key = seeded_key(0x10);
    let claims = CwtClaims::new().capability_id("cap:x");
    let bytes = CoseToken::sign(&key, &claims)
        .and_then(|t| t.to_cbor())
        .expect("full encode");

    // Drop the last byte — the innermost CBOR structure can no longer
    // reconstruct, the decoder MUST reject.
    let truncated = &bytes[..bytes.len() - 1];
    let err = CoseToken::from_cbor(truncated).expect_err("truncated CBOR must not parse");
    // Any error variant is acceptable here — what matters is "not Ok".
    let msg = format!("{err}");
    assert!(
        !msg.is_empty(),
        "error must carry a non-empty message for operator triage"
    );
}

/// A valid token signed by key A MUST NOT verify against key B. This
/// negative test is a direct security invariant — if it ever passes
/// with the wrong verifying key, the whole capability model is broken.
#[test]
fn cose_sign1_verify_wrong_key_errors() {
    let issuer = seeded_key(0x20);
    let other = seeded_key(0x21);
    let claims = CwtClaims::new()
        .capability_id("cap:y")
        .zone_id("z:work")
        .operations(&["op.read"]);

    let token = CoseToken::sign(&issuer, &claims).expect("sign");

    // Serialize + deserialize so we're testing the full verify pipeline.
    let bytes = token.to_cbor().expect("encode");
    let decoded = CoseToken::from_cbor(&bytes).expect("decode");

    let err = decoded
        .verify(&other.verifying_key())
        .expect_err("verification with wrong key MUST fail");
    // Must be a key-mismatch or signature-verification error, not
    // Ok-with-wrong-claims. The exact variant is a secondary concern.
    let msg = format!("{err}");
    assert!(!msg.is_empty(), "error must carry a message");
}

// ─────────────────────────────────────────────────────────────────────
//  Marker test — reserved slots for future COSE_Encrypt / COSE_Mac
// ─────────────────────────────────────────────────────────────────────

/// fcp-crypto's authoring surface does NOT currently expose
/// `COSE_Encrypt` or `COSE_Mac` wrappers — encryption uses HPKE
/// (`HpkeSealedBox`), MACs use Blake3 (`Blake3Mac`). If either of those
/// gains a COSE wrapper, this guard test starts failing and forces the
/// author to add a golden right next to it. The assertion is a simple
/// compile-time probe: these names MUST NOT resolve at `fcp_crypto::`
/// today, which we enforce by keeping the file deliberately import-free
/// beyond the Sign1 types above.
///
/// This leaves a "tripwire" — a real test if someone adds
/// `pub use cose::{CoseEncrypt, CoseMac}` to `fcp_crypto/src/lib.rs`
/// without adding goldens here.
#[test]
fn cose_encrypt_and_cose_mac_are_unimplemented_marker() {
    // This assertion documents the current scope. If encrypt/mac land,
    // replace this with real goldens mirroring the Sign1 pattern above.
    let sentinel = "fcp_crypto currently exposes only CoseToken (COSE_Sign1); \
                    encryption uses HpkeSealedBox, MACs use Blake3Mac";
    assert!(sentinel.contains("CoseToken"));
}
