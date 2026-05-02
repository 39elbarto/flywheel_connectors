//! Frozen-byte golden tests for fcp-host RPC envelopes.
//!
//! AmberLark, 2026-05-02 — testing-golden-artifacts alpha-domain sweep.
//!
//! Pins the canonical CBOR byte layout for the wire envelopes the
//! fcp-host invoke path emits:
//!
//! - [`InvokeRequest`]  — what crosses HTTP `/rpc/invoke` and the
//!   subprocess stdin boundary
//! - [`InvokeResponse`] — what crosses HTTP `/rpc/invoke` reply and
//!   the subprocess stdout boundary
//!
//! Existing tests in fcp-core check round-trip serde correctness.
//! They do NOT freeze the canonical CBOR byte layout, so a refactor
//! that reordered fields, changed integer encoding, or inserted a
//! new field would silently break wire-format compatibility with
//! already-deployed gateway/connector pairs.
//!
//! Determinism note: `InvokeRequest` carries a real
//! `CapabilityToken` (COSE/CWT-encoded). Ed25519 is deterministic
//! per RFC 8032, so a token signed with a fixed seed + fixed
//! validity window produces identical bytes on every run. The
//! fixtures below construct the token with explicit `from_bytes`
//! seeds and explicit `DateTime<Utc>` validity bounds — never
//! `Utc::now()`.
//!
//! When you intentionally change the schema:
//!
//!     UPDATE_GOLDENS=1 cargo insta test -p fcp-host
//!     cargo insta review        # human reviews every diff
//!     git add crates/fcp-host/tests/snapshots/
//!
//! Any other change MUST fail these tests.

use std::fmt::Write as _;

use chrono::{TimeZone, Utc};
use fcp_cbor::to_canonical_cbor;
use fcp_core::{
    CapabilityToken, ConnectorId, CorrelationId, FcpError, InvokeRequest, InvokeResponse,
    InvokeStatus, OperationId, Provenance, RequestId, ZoneId,
};
use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use serde_json::json;

/// Render bytes as a hex dump with section labels for human review.
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

/// Deterministic Ed25519 signing key for golden fixtures. NEVER
/// change this seed in-place; bump the fixture name and add a new
/// test instead.
fn deterministic_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x55; 32]).expect("32-byte seed is always a valid Ed25519 key")
}

/// Deterministic `not_before` / `expires` DateTime pair so the
/// signed token is byte-stable. Both timestamps are in the past
/// (year 2026) so the test doesn't depend on wall-clock advance.
fn fixed_validity_window() -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    let not_before = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let expires = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
    (not_before, expires)
}

/// Build a deterministic CapabilityToken signed by a fixed Ed25519
/// key over a fixed CBOR-constraint blob and fixed validity window.
/// Ed25519's deterministic-signature property (RFC 8032) means the
/// resulting COSE bytes are byte-stable across runs and machines.
fn deterministic_capability_token() -> CapabilityToken {
    let constraints_cbor = {
        let map = ciborium::Value::Map(vec![(
            ciborium::Value::Text("resource_allow".into()),
            ciborium::Value::Array(vec![ciborium::Value::Text("/v1/golden".into())]),
        )]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&map, &mut bytes).expect("constraint cbor encodes");
        bytes
    };
    let (not_before, expires) = fixed_validity_window();
    let cose = CapabilityTokenBuilder::new()
        .capability_id("cap.golden.invoke")
        .zone_id("z:work")
        .principal("user:golden-fixture")
        .operations(&["op.golden.invoke"])
        .issuer("node:golden-gateway")
        .validity(not_before, expires)
        .try_constraints_cbor(&constraints_cbor)
        .expect("test constraint cbor is valid")
        .target_instance("instance:golden")
        .sign(&deterministic_signing_key())
        .expect("Ed25519 deterministic sign always succeeds");
    CapabilityToken::from_raw(cose)
}

fn deterministic_invoke_request() -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new("req-golden-fixture-1"),
        connector_id: ConnectorId::from_static("fcp.golden:utility:1.0.0"),
        operation: OperationId::from_static("op.golden.invoke"),
        zone_id: ZoneId::work(),
        input: json!({ "fixture": "golden", "version": 1 }),
        capability_token: deterministic_capability_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        // Deterministic UUID seed so the golden bytes are stable.
        correlation_id: Some(CorrelationId(uuid::Uuid::from_bytes([0xC0; 16]))),
        provenance: Some(Provenance::new(ZoneId::work())),
        approval_tokens: Vec::new(),
    }
}

fn deterministic_invoke_response_ok() -> InvokeResponse {
    InvokeResponse {
        r#type: "response".to_string(),
        id: RequestId::new("req-golden-fixture-1"),
        status: InvokeStatus::Ok,
        result: Some(json!({ "ok": true, "fixture": "golden-response" })),
        error: None,
        receipt_id: None,
        audit_event_id: None,
        decision_receipt_id: None,
        resource_uris: Vec::new(),
        next_cursor: None,
        usage_metrics: None,
        response_metadata: None,
    }
}

fn deterministic_invoke_response_error() -> InvokeResponse {
    InvokeResponse {
        r#type: "response".to_string(),
        id: RequestId::new("req-golden-fixture-2"),
        status: InvokeStatus::Error,
        result: None,
        error: Some(FcpError::Unauthorized {
            code: 2001,
            message: "golden fixture unauthorized".to_string(),
        }),
        receipt_id: None,
        audit_event_id: None,
        decision_receipt_id: None,
        resource_uris: Vec::new(),
        next_cursor: None,
        usage_metrics: None,
        response_metadata: None,
    }
}

#[test]
fn invoke_request_canonical_cbor_deterministic_fixture() {
    let request = deterministic_invoke_request();
    let bytes = to_canonical_cbor(&request).expect("invoke request encodes to canonical CBOR");
    insta::assert_snapshot!(dump(
        "InvokeRequest (deterministic Ed25519-signed token, fixed validity) canonical CBOR",
        &bytes,
    ));
}

#[test]
fn invoke_response_ok_canonical_cbor_deterministic_fixture() {
    let response = deterministic_invoke_response_ok();
    let bytes = to_canonical_cbor(&response).expect("invoke response (ok) encodes");
    insta::assert_snapshot!(dump(
        "InvokeResponse (Ok status, fixed result body) canonical CBOR",
        &bytes,
    ));
}

#[test]
fn invoke_response_error_canonical_cbor_deterministic_fixture() {
    let response = deterministic_invoke_response_error();
    let bytes = to_canonical_cbor(&response).expect("invoke response (err) encodes");
    insta::assert_snapshot!(dump(
        "InvokeResponse (Error status, PermissionDenied) canonical CBOR",
        &bytes,
    ));
}

/// Pin the deterministic-signature property of CapabilityTokenBuilder
/// + Ed25519: signing the SAME constraints + SAME validity + SAME
/// key MUST produce byte-identical COSE bytes across runs. If this
/// regresses, golden fixtures everywhere in the workspace become
/// flaky.
#[test]
fn capability_token_signing_is_deterministic_across_runs() {
    let token_a = deterministic_capability_token();
    let token_b = deterministic_capability_token();
    let bytes_a = to_canonical_cbor(&token_a).unwrap();
    let bytes_b = to_canonical_cbor(&token_b).unwrap();
    assert_eq!(
        bytes_a, bytes_b,
        "deterministic-signature property regressed: same key + same payload yielded different bytes"
    );
}
