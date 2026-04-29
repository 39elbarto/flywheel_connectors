//! Pin hash determinism on the closest analogue to a "ManifestBundle"
//! (flywheel_connectors-j42c7).
//!
//! Bead asks for `ManifestBundle hash determinism`. No type literally
//! named `ManifestBundle` exists in fcp-core. The closest analogues
//! with a documented bundle-hash contract are:
//!
//!  - `compute_policy_bundle_hash` (policy.rs:280) — the canonical
//!    function that computes a deterministic `blake3-256:<hex>`
//!    digest over a `PolicyBundle`'s canonicalized payload (excluding
//!    signature + bundle_hash itself).
//!  - `PolicyBundle::signing_bytes` (policy.rs:381) — the canonical
//!    signing-bytes derivation that downstream signers feed Ed25519.
//!  - `to_deterministic_cbor` (used internally) — the deterministic
//!    CBOR step that drives the bundle-hash determinism contract.
//!
//! Targets:
//!
//!   1. **Same inputs → same hash** (call-determinism within a process).
//!   2. **Field permutations within `policies` produce the same hash**
//!      — `compute_policy_bundle_hash` sorts its policies internally
//!      (object_id, schema_id, object_hash) before hashing, so input
//!      order MUST NOT affect the output.
//!   3. **Different `bundle_id` produces different hash**.
//!   4. **Different `policy_seq` produces different hash**.
//!   5. **Different `zone_id` produces different hash**.
//!   6. **Different policy reference content produces different hash**.
//!   7. **`previous_bundle` Some vs None changes the hash** — pin the
//!      `skip_serializing_if = "Option::is_none"` round-tripping into
//!      a real input difference at hash time.
//!   8. **Empty `policies` rejected** with `InvalidBundle`.
//!   9. **Hash output format is `blake3-256:<hex>` with 64-char hex
//!      suffix**.
//!  10. **`PolicyBundle::signing_bytes` is deterministic** across
//!      multiple calls — repeated calls return identical bytes.

use chrono::{DateTime, Utc};
use fcp_core::{
    PolicyBundle, PolicyBundleError, PolicyBundlePolicyRef, PolicyBundleSignature, ZoneId,
    compute_policy_bundle_hash,
};

const POLICY_BUNDLE_HASH_ALGO: &str = "blake3-256";
const POLICY_BUNDLE_HASH_PREFIX: &str = "blake3-256:";

fn fixed_dt(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

fn policy_ref(seed: u8) -> PolicyBundlePolicyRef {
    PolicyBundlePolicyRef {
        object_id: format!("0x{:064x}", seed),
        schema_id: format!("fcp.policy:zone-policy@1.0.{seed}"),
        object_hash: format!("blake3-256:{:0>64}", format!("{seed:02x}").repeat(32)),
    }
}

fn invoke_hash(
    bundle_id: &str,
    zone_id: &ZoneId,
    policy_seq: u64,
    created_at: Option<DateTime<Utc>>,
    previous_bundle: Option<&str>,
    policies: &[PolicyBundlePolicyRef],
) -> String {
    compute_policy_bundle_hash(
        bundle_id,
        zone_id,
        policy_seq,
        created_at,
        previous_bundle,
        policies,
    )
    .expect("hash succeeds for non-empty policies")
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Same inputs → same hash (basic determinism)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn compute_policy_bundle_hash_is_deterministic_across_calls() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1), policy_ref(2)];
    let h1 = invoke_hash(
        "bundle-1",
        &zone,
        7,
        Some(fixed_dt(1_700_000_000)),
        None,
        &policies,
    );
    let h2 = invoke_hash(
        "bundle-1",
        &zone,
        7,
        Some(fixed_dt(1_700_000_000)),
        None,
        &policies,
    );
    assert_eq!(
        h1, h2,
        "compute_policy_bundle_hash MUST be deterministic across calls"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Policy permutations produce the same hash (internal sort)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_input_order_does_not_affect_hash() {
    // The function sorts policies by (object_id, schema_id,
    // object_hash) before hashing. Pin that the input order is
    // therefore irrelevant — different listings of the SAME set
    // produce the SAME hash.
    let zone = ZoneId::work();
    let p_a = policy_ref(0xAA);
    let p_b = policy_ref(0x42);
    let p_c = policy_ref(0xFF);

    let perm_1 = vec![p_a.clone(), p_b.clone(), p_c.clone()];
    let perm_2 = vec![p_c.clone(), p_a.clone(), p_b.clone()];
    let perm_3 = vec![p_b.clone(), p_c.clone(), p_a.clone()];

    let h1 = invoke_hash("b", &zone, 1, None, None, &perm_1);
    let h2 = invoke_hash("b", &zone, 1, None, None, &perm_2);
    let h3 = invoke_hash("b", &zone, 1, None, None, &perm_3);

    assert_eq!(h1, h2, "permutation 1 vs 2 MUST hash identically");
    assert_eq!(h2, h3, "permutation 2 vs 3 MUST hash identically");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3-7. Distinguishing inputs produce different hashes
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn different_bundle_id_produces_different_hash() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1)];
    let h1 = invoke_hash("alpha", &zone, 1, None, None, &policies);
    let h2 = invoke_hash("beta", &zone, 1, None, None, &policies);
    assert_ne!(h1, h2);
}

#[test]
fn different_policy_seq_produces_different_hash() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1)];
    let h1 = invoke_hash("b", &zone, 1, None, None, &policies);
    let h2 = invoke_hash("b", &zone, 2, None, None, &policies);
    assert_ne!(h1, h2);
}

#[test]
fn different_zone_id_produces_different_hash() {
    let policies = vec![policy_ref(1)];
    let h_work = invoke_hash("b", &ZoneId::work(), 1, None, None, &policies);
    let h_owner = invoke_hash("b", &ZoneId::owner(), 1, None, None, &policies);
    assert_ne!(h_work, h_owner);
}

#[test]
fn different_policy_reference_content_produces_different_hash() {
    let zone = ZoneId::work();
    let h1 = invoke_hash("b", &zone, 1, None, None, &[policy_ref(0x01)]);
    let h2 = invoke_hash("b", &zone, 1, None, None, &[policy_ref(0x02)]);
    assert_ne!(h1, h2);
}

#[test]
fn previous_bundle_some_vs_none_changes_hash() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1)];
    let h_none = invoke_hash("b", &zone, 1, None, None, &policies);
    let h_some = invoke_hash("b", &zone, 1, None, Some("prev-bundle-1"), &policies);
    assert_ne!(
        h_none, h_some,
        "Some(previous_bundle) and None MUST produce different hashes"
    );
}

#[test]
fn different_previous_bundle_value_changes_hash() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1)];
    let h_a = invoke_hash("b", &zone, 1, None, Some("prev-a"), &policies);
    let h_b = invoke_hash("b", &zone, 1, None, Some("prev-b"), &policies);
    assert_ne!(h_a, h_b);
}

#[test]
fn different_created_at_value_changes_hash() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1)];
    let h_a = invoke_hash("b", &zone, 1, Some(fixed_dt(1_000)), None, &policies);
    let h_b = invoke_hash("b", &zone, 1, Some(fixed_dt(2_000)), None, &policies);
    assert_ne!(h_a, h_b);
}

#[test]
fn created_at_some_vs_none_changes_hash() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1)];
    let h_none = invoke_hash("b", &zone, 1, None, None, &policies);
    let h_some = invoke_hash("b", &zone, 1, Some(fixed_dt(1_000)), None, &policies);
    assert_ne!(h_none, h_some);
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Empty policies rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_policies_rejected_with_invalid_bundle_error() {
    let zone = ZoneId::work();
    let result = compute_policy_bundle_hash("b", &zone, 1, None, None, &[]);
    let err = result.expect_err("empty policies MUST be rejected");
    match err {
        PolicyBundleError::InvalidBundle { reason } => {
            assert!(
                reason.contains("policies"),
                "InvalidBundle reason MUST mention `policies`: {reason}"
            );
        }
        other => panic!("expected InvalidBundle, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Hash output format
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hash_output_format_is_blake3_256_with_64_char_hex_suffix() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1)];
    let hash = invoke_hash("b", &zone, 1, None, None, &policies);

    assert!(
        hash.starts_with(POLICY_BUNDLE_HASH_PREFIX),
        "bundle hash MUST start with `blake3-256:`; got {hash}"
    );
    let hex_part = hash
        .strip_prefix(POLICY_BUNDLE_HASH_PREFIX)
        .expect("prefix stripping");
    assert_eq!(
        hex_part.len(),
        64,
        "blake3-256 hex MUST be 64 chars; got {hex_part} (len {})",
        hex_part.len()
    );
    assert!(
        hex_part
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "hex MUST be all-lowercase ASCII hex: {hex_part}"
    );
    // Algo constant matches expectation.
    assert_eq!(POLICY_BUNDLE_HASH_PREFIX, "blake3-256:");
    assert_eq!(POLICY_BUNDLE_HASH_ALGO, "blake3-256");
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. PolicyBundle::signing_bytes determinism
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn policy_bundle_signing_bytes_are_deterministic_across_calls() {
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1), policy_ref(2)];
    let bundle_hash = invoke_hash(
        "bundle-1",
        &zone,
        7,
        Some(fixed_dt(1_700_000_000)),
        None,
        &policies,
    );

    // Build a PolicyBundle directly. The fields here are pinned by
    // policy.rs:328 — we don't need a valid signature for
    // signing_bytes() determinism.
    let bundle = PolicyBundle {
        format: "fcp-policy-bundle".to_string(),
        schema_version: "1.0".to_string(),
        bundle_id: "bundle-1".to_string(),
        zone_id: zone,
        policy_seq: 7,
        created_at: Some(fixed_dt(1_700_000_000)),
        previous_bundle: None,
        hash_algo: POLICY_BUNDLE_HASH_ALGO.to_string(),
        bundle_hash,
        policies,
        signature: PolicyBundleSignature::new(
            "test-key",
            // 64 zero bytes base64-encoded — a placeholder signature
            // shape; we're only testing canonical-bytes determinism.
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            vec![
                "format".to_string(),
                "schema_version".to_string(),
                "bundle_id".to_string(),
                "zone_id".to_string(),
                "policy_seq".to_string(),
                "created_at".to_string(),
                "previous_bundle".to_string(),
                "hash_algo".to_string(),
                "bundle_hash".to_string(),
                "policies".to_string(),
            ],
        ),
    };

    let bytes_a = bundle.signing_bytes().expect("first signing_bytes");
    let bytes_b = bundle.signing_bytes().expect("second signing_bytes");
    assert_eq!(
        bytes_a, bytes_b,
        "PolicyBundle::signing_bytes MUST be deterministic across calls"
    );
    assert!(!bytes_a.is_empty(), "signing_bytes MUST be non-empty");
}

#[test]
fn policy_bundle_signing_bytes_change_when_bundle_hash_changes() {
    // Confirm that signing_bytes captures the bundle_hash field —
    // changing it produces different signing input, which is the
    // whole point of the bundle_hash being a signed field.
    let zone = ZoneId::work();
    let policies = vec![policy_ref(1)];
    let bundle_hash_a = invoke_hash("bundle-1", &zone, 1, None, None, &policies);
    let bundle_hash_b = format!("{POLICY_BUNDLE_HASH_PREFIX}{}", "ff".repeat(32));
    assert_ne!(bundle_hash_a, bundle_hash_b);

    let make_bundle = |bh: String| PolicyBundle {
        format: "fcp-policy-bundle".to_string(),
        schema_version: "1.0".to_string(),
        bundle_id: "bundle-1".to_string(),
        zone_id: zone.clone(),
        policy_seq: 1,
        created_at: None,
        previous_bundle: None,
        hash_algo: POLICY_BUNDLE_HASH_ALGO.to_string(),
        bundle_hash: bh,
        policies: policies.clone(),
        signature: PolicyBundleSignature::new(
            "k",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            vec![],
        ),
    };

    let bundle_a = make_bundle(bundle_hash_a);
    let bundle_b = make_bundle(bundle_hash_b);

    let bytes_a = bundle_a.signing_bytes().expect("a");
    let bytes_b = bundle_b.signing_bytes().expect("b");
    assert_ne!(
        bytes_a, bytes_b,
        "different bundle_hash MUST produce different signing_bytes"
    );
}
