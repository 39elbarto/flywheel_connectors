//! Frozen-byte golden tests for fcp-policy schema-evolving structs.
//!
//! AmberLark, 2026-05-02 — testing-golden-artifacts alpha-domain sweep.
//!
//! Pins the canonical CBOR byte layout for the policy types that
//! cross the wire as part of capability-token verification:
//!
//! - [`CapabilityConstraints`] — embedded inside every CapabilityToken
//!   via the `constraints` claim. Schema drift here silently breaks
//!   constraint enforcement on already-issued tokens.
//! - [`OperationalModelSelection`] — the V1/V2 truth-precedence
//!   decision struct (br-4la3k). Schema drift breaks operator-facing
//!   model-selection diagnostics.
//!
//! Existing inline tests check round-trip serde correctness. They do
//! NOT freeze the CANONICAL CBOR byte layout, so a refactor that
//! reordered fields, changed integer encoding (u32 → u64), or
//! inserted a new field would silently break wire-format
//! compatibility with already-issued tokens — every existing token's
//! `constraints` blob would still decode to *something*, but the
//! shape would shift in ways consumers wouldn't catch until prod.
//!
//! The golden snapshots in `snapshots/` lock down the exact
//! transcript. When you intentionally change the schema:
//!
//!     UPDATE_GOLDENS=1 cargo insta test -p fcp-policy
//!     cargo insta review        # human reviews every diff
//!     git add crates/fcp-policy/tests/snapshots/
//!
//! Any other change MUST fail these tests.

use std::fmt::Write as _;

use fcp_cbor::to_canonical_cbor;
use fcp_core::{CapabilityConstraints, CredentialId};
use fcp_policy::{
    OperationalModelSelection, OperationalModelVersion, select_operational_model_for_deployment,
};

/// Render bytes as a hex dump with section labels for human review.
/// Mirrors the helper in fcp-mesh/tests/wire_format_goldens.rs so the
/// snapshot format is consistent across the workspace.
fn dump(label: &str, bytes: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(label);
    out.push('\n');
    writeln!(&mut out, "len = {}", bytes.len()).expect("writing to String cannot fail");
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: String = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        writeln!(&mut out, "{:04x}  {:48}  {}", i * 16, hex, ascii)
            .expect("writing to String cannot fail");
    }
    out
}

/// Fixture: the empty/default `CapabilityConstraints`. Pins the
/// minimum on-wire encoding (every field is `skip_serializing_if`
/// elided so the CBOR map is empty). Critical because the
/// default-deny floor at the constraint enforcer depends on this
/// being unambiguously distinguishable from a non-empty constraint
/// set.
fn empty_constraints() -> CapabilityConstraints {
    CapabilityConstraints::default()
}

/// Fixture: minimal-resource-allow constraint. The single most
/// common constraint shape on the wire today (issued by every
/// capability token that gates a single resource URI).
fn single_resource_allow_constraints() -> CapabilityConstraints {
    CapabilityConstraints {
        resource_allow: vec!["/v1/messages".to_string()],
        ..CapabilityConstraints::default()
    }
}

/// Fixture: every field populated with a deterministic value. Pins
/// the FULL serialised shape, including field ORDER (canonical CBOR
/// encoding sorts map keys lexicographically).
fn full_constraints() -> CapabilityConstraints {
    let cred_a = CredentialId::from_uuid(uuid::Uuid::from_bytes([0x42; 16]));
    let cred_b = CredentialId::from_uuid(uuid::Uuid::from_bytes([0x69; 16]));
    CapabilityConstraints {
        resource_allow: vec!["/v1/messages".to_string(), "/v1/threads/*".to_string()],
        resource_deny: vec!["/v1/admin/*".to_string()],
        max_calls: Some(100),
        max_bytes: Some(1_048_576),
        idempotency_key: Some("idem-fixture-v1".to_string()),
        credential_allow: vec![cred_a, cred_b],
    }
}

#[test]
fn capability_constraints_canonical_cbor_empty_fixture() {
    let bytes = to_canonical_cbor(&empty_constraints()).expect("empty constraints encode");
    insta::assert_snapshot!(dump(
        "CapabilityConstraints (empty fixture) canonical CBOR",
        &bytes,
    ));
}

#[test]
fn capability_constraints_canonical_cbor_single_resource_allow_fixture() {
    let bytes = to_canonical_cbor(&single_resource_allow_constraints())
        .expect("single-resource constraints encode");
    insta::assert_snapshot!(dump(
        "CapabilityConstraints (single resource_allow fixture) canonical CBOR",
        &bytes,
    ));
}

#[test]
fn capability_constraints_canonical_cbor_full_fixture() {
    let bytes = to_canonical_cbor(&full_constraints()).expect("full constraints encode");
    insta::assert_snapshot!(dump(
        "CapabilityConstraints (full fixture, every field populated) canonical CBOR",
        &bytes,
    ));
}

/// Fixture: V1 explicitly requested on a non-single-host topology.
fn v1_selection() -> OperationalModelSelection {
    select_operational_model_for_deployment(
        OperationalModelVersion::V1HostFirst,
        false,
        false,
        false,
    )
}

/// Fixture: V2 requested with degraded opt-in on single-host. The
/// post-br-4la3k recommended single-host shape.
fn v2_with_degraded_opt_in_selection() -> OperationalModelSelection {
    select_operational_model_for_deployment(OperationalModelVersion::V2MeshNative, true, true, true)
}

/// Fixture: V2 requested without opt-in on single-host. Falls back to
/// V1 with a stable warning string. Pins the warning text so log-
/// aggregator alerts on the operational-model fallback don't drift.
fn v2_without_opt_in_falls_back_to_v1() -> OperationalModelSelection {
    select_operational_model_for_deployment(
        OperationalModelVersion::V2MeshNative,
        true,
        false,
        true,
    )
}

#[test]
fn operational_model_selection_v1_explicit_fixture() {
    let selection = v1_selection();
    insta::assert_json_snapshot!(
        "operational_model_selection_v1_explicit",
        serde_json::json!({
            "requested": format!("{:?}", selection.requested),
            "effective": format!("{:?}", selection.effective),
            "single_host_detected": selection.single_host_detected,
            "degraded_v2_opt_in": selection.degraded_v2_opt_in,
            "warning": selection.warning,
        })
    );
}

#[test]
fn operational_model_selection_v2_with_degraded_opt_in_fixture() {
    let selection = v2_with_degraded_opt_in_selection();
    insta::assert_json_snapshot!(
        "operational_model_selection_v2_with_degraded_opt_in",
        serde_json::json!({
            "requested": format!("{:?}", selection.requested),
            "effective": format!("{:?}", selection.effective),
            "single_host_detected": selection.single_host_detected,
            "degraded_v2_opt_in": selection.degraded_v2_opt_in,
            "warning": selection.warning,
        })
    );
}

#[test]
fn operational_model_selection_v2_fallback_warning_text_pin() {
    let selection = v2_without_opt_in_falls_back_to_v1();
    let warning_text = selection
        .warning
        .expect("v2-without-opt-in MUST produce a warning");
    // Pin the EXACT warning string so log-aggregator alerts don't
    // silently break when the warning text drifts. This is the
    // operator-facing diagnostic for the V2-fallback decision path.
    insta::assert_snapshot!("operational_model_v2_fallback_warning_text", warning_text);
}
