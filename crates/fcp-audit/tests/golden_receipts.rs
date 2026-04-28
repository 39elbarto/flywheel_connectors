//! Golden artifact snapshots for fcp-audit event receipts.
//!
//! Freezes the on-wire JSON representation of every primary audit type so
//! any unintentional change to serde attributes, field ordering, tagged
//! enum representations, or default handling fails the next CI run with
//! a concrete diff of old vs. new output. These snapshots serve as the
//! canonical description of the audit protocol surface.
//!
//! Coverage:
//!
//! - [`AuditEntry`] — both a minimal entry (just the required fields)
//!   and a fully-populated entry with trace context, correlation id,
//!   connector/operation identifiers, and structured metadata. Covers
//!   every `skip_serializing_if` branch so regressions in default
//!   handling surface as diffs.
//! - [`DecisionReceipt`] — allow receipts (with evidence array) and
//!   deny receipts (with explanation text). Covers the `lowercase`
//!   enum rename on the `decision` field.
//! - [`ChainHead`] — checkpoint record with coverage and signature
//!   count; exercises the `f64` serialization shape.
//! - [`Severity`] — every variant serialized individually to freeze
//!   the `lowercase` renaming.
//! - [`TraceContext`] — W3C Trace Context with and without sampling
//!   flag set.
//!
//! `AuditEntry.occurred_at` and `DecisionReceipt.decided_at` are
//! `u64` Unix timestamps supplied by the caller (not by `now()`),
//! so no scrubbing is needed — the fixtures use fixed anchor
//! timestamps (`1_700_000_000` = `2023-11-14T22:13:20Z`).

use fcp_audit::{
    AuditEntryBuilder, AuditStatus, ChainHead, Decision, DecisionReceipt, FreshnessLevel,
    HeadSignature, Severity, TraceContext, VerifyIssue, VerifyReport, VerifyStatus,
};
use serde_json::json;

const ANCHOR_TS: u64 = 1_700_000_000;

#[derive(serde::Serialize)]
struct AuditReceiptEnvelope<T> {
    envelope: &'static str,
    version: u8,
    receipt_type: &'static str,
    receipt: T,
}

fn canonical_receipt_envelope_hex<T: serde::Serialize>(
    receipt_type: &'static str,
    receipt: T,
) -> String {
    let envelope = AuditReceiptEnvelope {
        envelope: "fcp-audit.receipt",
        version: 1,
        receipt_type,
        receipt,
    };

    hex::encode(
        fcp_cbor::to_canonical_cbor(&envelope)
            .expect("audit receipt envelope must encode as canonical CBOR"),
    )
}

#[test]
fn golden_audit_receipt_envelope_canonical_cbor() {
    let audit_entry = AuditEntryBuilder::new()
        .id("entry-cbor-0007")
        .event_type("capability.invoke")
        .severity(Severity::Info)
        .actor("agent:canonical-cbor")
        .zone_id("z:work")
        .seq(7)
        .occurred_at(ANCHOR_TS + 7)
        .prev("entry-cbor-0006")
        .correlation_id("req-cbor-0007")
        .trace_context(
            TraceContext::new("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331")
                .with_flags(0x01),
        )
        .connector_id("stripe")
        .operation_id("charges.create")
        .meta("amount_cents", json!(4200))
        .meta("currency", json!("USD"))
        .build()
        .expect("audit entry receipt must build");

    let decision_receipt = DecisionReceipt {
        id: "rcpt_cbor_0007".to_string(),
        request_id: "req-cbor-0007".to_string(),
        decision: Decision::Deny,
        reason_code: "policy.capability.missing".to_string(),
        evidence: vec![
            "cap:stripe.charges.create".to_string(),
            "zone:z:work".to_string(),
        ],
        audit_entry_id: Some("entry-cbor-0007".to_string()),
        explanation: Some("capability was not granted to z:work".to_string()),
        decided_at: ANCHOR_TS + 8,
        zone_id: "z:work".to_string(),
        correlation_id: Some("req-cbor-0007".to_string()),
        trace_context: Some(
            TraceContext::new("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331")
                .with_flags(0x01),
        ),
        connector_id: Some("stripe".to_string()),
        operation_id: Some("charges.create".to_string()),
        issuer_kid: None,
        signature: None,
    };

    let chain_head = ChainHead {
        zone_id: "z:work".to_string(),
        head_entry: "entry-cbor-0007".to_string(),
        head_seq: 7,
        coverage: 1.0,
        epoch_id: "epoch-cbor-0001".to_string(),
        signature_count: 1,
        signatures: vec![HeadSignature {
            issuer_kid: "kid:cbor-primary".to_string(),
            signature: vec![0x5a; 64],
        }],
    };

    let actual = json!({
        "audit_entry": canonical_receipt_envelope_hex("audit_entry", audit_entry),
        "decision_receipt": canonical_receipt_envelope_hex("decision_receipt", decision_receipt),
        "chain_head": canonical_receipt_envelope_hex("chain_head", chain_head),
    });

    let expected = json!({
        "audit_entry": "a46772656365697074ad6269646f656e7472792d63626f722d30303037637365710764707265766f656e7472792d63626f722d30303036656163746f72746167656e743a63616e6f6e6963616c2d63626f72677a6f6e655f6964667a3a776f726b686d65746164617461a26863757272656e6379635553446c616d6f756e745f63656e747319106868736576657269747964696e666f6a6576656e745f74797065716361706162696c6974792e696e766f6b656b6f636375727265645f61741a6553f1076c636f6e6e6563746f725f6964667374726970656c6f7065726174696f6e5f69646e636861726765732e6372656174656d74726163655f636f6e74657874a365666c61677301677370616e5f696470623761643662373136393230333333316874726163655f6964782030616637363531393136636434336464383434386562323131633830333139636e636f7272656c6174696f6e5f69646d7265712d63626f722d303030376776657273696f6e0168656e76656c6f7065716663702d61756469742e726563656970746c726563656970745f747970656b61756469745f656e747279",
        "decision_receipt": "a46772656365697074ad6269646e726370745f63626f725f30303037677a6f6e655f6964667a3a776f726b686465636973696f6e6464656e796865766964656e63658278196361703a7374726970652e636861726765732e6372656174656b7a6f6e653a7a3a776f726b6a646563696465645f61741a6553f1086a726571756573745f69646d7265712d63626f722d303030376b6578706c616e6174696f6e78246361706162696c69747920776173206e6f74206772616e74656420746f207a3a776f726b6b726561736f6e5f636f64657819706f6c6963792e6361706162696c6974792e6d697373696e676c636f6e6e6563746f725f6964667374726970656c6f7065726174696f6e5f69646e636861726765732e6372656174656d74726163655f636f6e74657874a365666c61677301677370616e5f696470623761643662373136393230333333316874726163655f6964782030616637363531393136636434336464383434386562323131633830333139636e61756469745f656e7472795f69646f656e7472792d63626f722d303030376e636f7272656c6174696f6e5f69646d7265712d63626f722d303030376776657273696f6e0168656e76656c6f7065716663702d61756469742e726563656970746c726563656970745f74797065706465636973696f6e5f72656365697074",
        "chain_head": "a46772656365697074a7677a6f6e655f6964667a3a776f726b68636f766572616765f93c006865706f63685f69646f65706f63682d63626f722d3030303168686561645f736571076a686561645f656e7472796f656e7472792d63626f722d303030376a7369676e61747572657381a2697369676e6174757265788035613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135613561356135616a6973737565725f6b6964706b69643a63626f722d7072696d6172796f7369676e61747572655f636f756e74016776657273696f6e0168656e76656c6f7065716663702d61756469742e726563656970746c726563656970745f747970656a636861696e5f68656164",
    });

    assert_eq!(
        actual, expected,
        "canonical audit receipt envelope CBOR changed; update this golden only for an intentional wire-format change",
    );
}

#[test]
fn snapshot_audit_entry_minimal() {
    // Just the required fields — no trace context, no connector,
    // no metadata. Every `skip_serializing_if` optional must be
    // omitted from the JSON.
    let entry = AuditEntryBuilder::new()
        .id("entry-min-0001")
        .event_type("capability.invoke")
        .actor("agent:local")
        .zone_id("z:work")
        .seq(0)
        .occurred_at(ANCHOR_TS)
        .build()
        .expect("minimal entry must build");

    insta::assert_json_snapshot!("audit_entry_minimal", entry);
}

#[test]
fn snapshot_audit_entry_full() {
    // Every optional field populated, trace context attached,
    // metadata sorted by BTreeMap. Exercises every serde branch.
    let entry = AuditEntryBuilder::new()
        .id("entry-full-0042")
        .event_type("secret.access")
        .severity(Severity::Warning)
        .actor("agent:service-account@example.com")
        .zone_id("z:prod")
        .seq(42)
        .occurred_at(ANCHOR_TS + 3600)
        .prev("entry-full-0041")
        .correlation_id("req-abc-123")
        .trace_context(TraceContext::new(
            "0af7651916cd43dd8448eb211c80319c",
            "b7ad6b7169203331",
        ))
        .connector_id("stripe")
        .operation_id("charges.create")
        .meta("amount_cents", json!(4200))
        .meta("currency", json!("USD"))
        .meta("masked_card", json!("****4242"))
        .build()
        .expect("full entry must build");

    insta::assert_json_snapshot!("audit_entry_full", entry);
}

#[test]
fn snapshot_audit_entry_genesis() {
    // Genesis entry: seq == 0, no prev. Must still be accepted by
    // the builder so fresh chains can materialise their first
    // entry without a synthetic predecessor.
    let entry = AuditEntryBuilder::new()
        .id("entry-genesis")
        .event_type("chain.bootstrap")
        .severity(Severity::Info)
        .actor("host:fcp-mesh")
        .zone_id("z:genesis")
        .seq(0)
        .occurred_at(ANCHOR_TS)
        .build()
        .expect("genesis entry must build");

    assert!(entry.is_genesis(), "sanity: is_genesis() must agree");
    insta::assert_json_snapshot!("audit_entry_genesis", entry);
}

#[test]
fn snapshot_decision_receipt_allow_with_evidence() {
    // Allow decision with evidence references — the most common
    // shape for `fcp explain` output.
    let receipt = DecisionReceipt {
        id: "rcpt_allow_001".to_string(),
        request_id: "req_invoke_42".to_string(),
        decision: Decision::Allow,
        reason_code: "policy.capability.granted".to_string(),
        evidence: vec![
            "cap:stripe.charges.create".to_string(),
            "zone:work".to_string(),
            "role:billing-writer".to_string(),
        ],
        audit_entry_id: Some("entry-full-0042".to_string()),
        explanation: None,
        decided_at: ANCHOR_TS,
        zone_id: "z:work".to_string(),
        correlation_id: Some("req_invoke_42".to_string()),
        trace_context: Some(
            TraceContext::new("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331")
                .with_flags(0x01),
        ),
        connector_id: Some("stripe".to_string()),
        operation_id: Some("charges.create".to_string()),
        issuer_kid: None,
        signature: None,
    };

    insta::assert_json_snapshot!("decision_receipt_allow_with_evidence", receipt);
}

#[test]
fn snapshot_decision_receipt_deny_with_explanation() {
    // Deny decision with a human-readable explanation — what the
    // operator sees when they drill into a blocked request.
    let receipt = DecisionReceipt {
        id: "rcpt_deny_002".to_string(),
        request_id: "req_invoke_99".to_string(),
        decision: Decision::Deny,
        reason_code: "policy.capability.revoked".to_string(),
        evidence: vec!["revocation:2026-04-19T12:00:00Z".to_string()],
        audit_entry_id: Some("entry-deny-0099".to_string()),
        explanation: Some(
            "capability cap:stripe.refunds.create was revoked by operator@example.com \
             on 2026-04-19 with reason \"incident-2026-Q2-001\""
                .to_string(),
        ),
        decided_at: ANCHOR_TS + 86_400,
        zone_id: "z:prod".to_string(),
        correlation_id: Some("req_invoke_99".to_string()),
        trace_context: None,
        connector_id: Some("stripe".to_string()),
        operation_id: Some("refunds.create".to_string()),
        issuer_kid: None,
        signature: None,
    };

    insta::assert_json_snapshot!("decision_receipt_deny_with_explanation", receipt);
}

#[test]
fn snapshot_decision_receipt_allow_minimal() {
    // Allow with no evidence and no optional metadata — freezes the
    // minimal fast-path allow wire shape independently of the richer
    // allow-with-evidence snapshot above.
    let receipt = DecisionReceipt {
        id: "rcpt_allow_minimal".to_string(),
        request_id: "req_allow_minimal".to_string(),
        decision: Decision::Allow,
        reason_code: "policy.capability.granted".to_string(),
        evidence: Vec::new(),
        audit_entry_id: None,
        explanation: None,
        decided_at: ANCHOR_TS + 120,
        zone_id: "z:work".to_string(),
        correlation_id: None,
        trace_context: None,
        connector_id: None,
        operation_id: None,
        issuer_kid: None,
        signature: None,
    };

    insta::assert_json_snapshot!("decision_receipt_allow_minimal", receipt);
}

#[test]
fn snapshot_decision_receipt_minimal_deny() {
    // Deny with no evidence and no explanation — the wire shape
    // any policy engine can produce in the fast-path (skip
    // evidence + explanation branches).
    let receipt = DecisionReceipt {
        id: "rcpt_deny_minimal".to_string(),
        request_id: "req_minimal".to_string(),
        decision: Decision::Deny,
        reason_code: "policy.default_deny".to_string(),
        evidence: Vec::new(),
        audit_entry_id: None,
        explanation: None,
        decided_at: ANCHOR_TS,
        zone_id: "z:work".to_string(),
        correlation_id: None,
        trace_context: None,
        connector_id: None,
        operation_id: None,
        issuer_kid: None,
        signature: None,
    };

    insta::assert_json_snapshot!("decision_receipt_minimal_deny", receipt);
}

#[test]
fn snapshot_chain_head() {
    // Chain checkpoint with partial quorum coverage. Exercises
    // the `f64` serialization shape and the u32 signature count.
    // `signatures` is empty here — the wire skips the field so
    // legacy unsigned heads remain decodable and the snapshot
    // remains byte-stable vs the pre-signatures release.
    let head = ChainHead {
        zone_id: "z:work".to_string(),
        head_entry: "entry-cafe-1234".to_string(),
        head_seq: 4096,
        coverage: 0.875,
        epoch_id: "epoch-2026-04-20".to_string(),
        signature_count: 7,
        signatures: vec![],
    };

    insta::assert_json_snapshot!("chain_head_partial_quorum", head);
}

#[test]
fn snapshot_chain_head_full_quorum() {
    // Full-coverage, high-signature-count head — what the steady-
    // state mesh should publish.
    let head = ChainHead {
        zone_id: "z:prod".to_string(),
        head_entry: "entry-beef-5678".to_string(),
        head_seq: u64::MAX / 2,
        coverage: 1.0,
        epoch_id: "epoch-stable".to_string(),
        signature_count: u32::from(u16::MAX),
        signatures: vec![],
    };

    insta::assert_json_snapshot!("chain_head_full_quorum", head);
}

#[test]
fn snapshot_chain_head_with_signatures() {
    // Exercises the HeadSignature wire shape: hex-encoded 64-byte
    // opaque bytes plus `issuer_kid` string. Count MUST equal
    // signatures.len() or verify_chain will flag as inconsistent.
    let head = ChainHead {
        zone_id: "z:work".to_string(),
        head_entry: "entry-signed-0001".to_string(),
        head_seq: 42,
        coverage: 1.0,
        epoch_id: "epoch-signed".to_string(),
        signature_count: 2,
        signatures: vec![
            HeadSignature {
                issuer_kid: "kid:alpha".to_string(),
                signature: vec![0xAA; 64],
            },
            HeadSignature {
                issuer_kid: "kid:beta".to_string(),
                signature: vec![0xBB; 64],
            },
        ],
    };

    insta::assert_json_snapshot!("chain_head_with_signatures", head);
}

#[test]
fn snapshot_severity_lowercase_serde() {
    // Freeze the `#[serde(rename_all = "lowercase")]` renaming for
    // every variant; any rename regression or reorder turns into a
    // snapshot diff.
    let all: Vec<Severity> = vec![
        Severity::Info,
        Severity::Warning,
        Severity::Error,
        Severity::Critical,
    ];
    insta::assert_json_snapshot!("severity_all_variants", all);
}

#[test]
fn snapshot_trace_context_sampled_and_unsampled() {
    // W3C Trace Context: both the default (flags=0, unsampled)
    // and the explicit sampled form. These are what correlates
    // audit entries to upstream distributed-trace spans.
    let unsampled = TraceContext::new("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331");
    let sampled =
        TraceContext::new("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331").with_flags(0x01);

    insta::assert_json_snapshot!(
        "trace_context_both_flags",
        json!({
            "unsampled": unsampled,
            "sampled": sampled,
        })
    );
}

#[test]
fn snapshot_decision_enum_lowercase_serde() {
    // Freeze `Decision::Allow` and `Decision::Deny` lowercase
    // serde output independently of any containing struct.
    insta::assert_json_snapshot!(
        "decision_enum_both_variants",
        json!({
            "allow": Decision::Allow,
            "deny": Decision::Deny,
        })
    );
}

// ────────────────────────────────────────────────────────────────────────
// VerifyReport / AuditStatus / FreshnessLevel — operator-visible surfaces
// ────────────────────────────────────────────────────────────────────────
// Goldens below round out the previously-uncovered half of the fcp-audit
// public wire surface. Every one of these types is serialized into output
// an operator reads (`fcp verify`, `fcp audit status`); freezing their
// JSON shape prevents a casual serde attribute change from silently
// breaking downstream CLI / dashboard parsers.

#[test]
fn snapshot_verify_report_empty_chain_ok() {
    // EMPTY CASE. A fresh zone with zero entries and no head must produce
    // a clean, minimal OK report. Every `skip_serializing_if` branch on
    // `VerifyReport` MUST be exercised here (zone_id, head_seq, head_entry
    // all None; issues empty). A change that starts serializing absent
    // optionals as `null` instead of omitting them flips this snapshot
    // and fails CI.
    let report = VerifyReport::ok(0);
    insta::assert_json_snapshot!("verify_report_empty_chain_ok", report);
}

#[test]
fn snapshot_audit_status_missing_single_field() {
    // SINGLE-FIELD CASE. `AuditStatus::missing()` populates only
    // `freshness`; head_seq, coverage, and reason are all None. The
    // resulting JSON is `{"freshness": "missing"}` — the smallest valid
    // AuditStatus an operator can see. Freezing this guards against a
    // serde attribute change that would suddenly start emitting
    // `"head_seq": null` or similar.
    let status = AuditStatus::missing();
    insta::assert_json_snapshot!("audit_status_missing_single_field", status);
}

#[test]
fn snapshot_verify_report_deeply_nested_with_chain_head() {
    // DEEPLY-NESTED CASE. A failing verify report bundled with the
    // ChainHead it was computed against and the signatures the head
    // carries — three levels of nested objects plus embedded arrays.
    // This is exactly what the `fcp verify --with-head` envelope looks
    // like on the wire and it exercises nested Option handling
    // (head_seq, head_entry, zone_id all populated; each VerifyIssue
    // carries both seq and entry_id; HeadSignatures carry 64-byte
    // payloads rendered as JSON arrays of integers).
    let head = ChainHead {
        zone_id: "z:prod".to_string(),
        head_entry: "entry-nested-9999".to_string(),
        head_seq: 9_999,
        coverage: 0.75,
        epoch_id: "epoch-2026-04-22".to_string(),
        signature_count: 2,
        signatures: vec![
            HeadSignature {
                issuer_kid: "kid:primary".to_string(),
                signature: vec![0x11; 64],
            },
            HeadSignature {
                issuer_kid: "kid:witness".to_string(),
                signature: vec![0x22; 64],
            },
        ],
    };

    let report = VerifyReport {
        status: VerifyStatus::Warn,
        zone_id: Some("z:prod".to_string()),
        chain_len: 10_000,
        head_seq: Some(9_999),
        head_entry: Some("entry-nested-9999".to_string()),
        issues: vec![
            VerifyIssue::new("audit.timestamp_drift", "entry timestamp skewed 3s")
                .with_seq(4_200)
                .with_entry_id("entry-drift-4200"),
            VerifyIssue::new("audit.metadata_size_warn", "metadata exceeds soft cap")
                .with_seq(7_500)
                .with_entry_id("entry-meta-7500"),
        ],
    };

    insta::assert_json_snapshot!(
        "verify_report_deeply_nested_with_chain_head",
        json!({
            "head": head,
            "report": report,
        })
    );
}

#[test]
fn snapshot_chain_head_max_signature_quorum() {
    // MAX-SIZE CASE. A quorum-signed ChainHead at the upper realistic
    // signature-count range (16 signers), with each signature taking the
    // full 64-byte Ed25519 shape. This is the `head.json` that a large
    // multi-node mesh publishes at steady state. Freezing it pins the
    // JSON-array encoding of the signature bytes; a serde attribute
    // change to base64/hex/etc. would flip this snapshot.
    let signatures = (0..16u8)
        .map(|i| HeadSignature {
            issuer_kid: format!("kid:signer-{i:02}"),
            // 64 bytes filled with the signer index so the snapshot is
            // legible when diffed.
            signature: vec![i; 64],
        })
        .collect::<Vec<_>>();

    let head = ChainHead {
        zone_id: "z:mesh-prod".to_string(),
        head_entry: "entry-max-quorum-0001".to_string(),
        head_seq: 1_000_000,
        coverage: 1.0,
        epoch_id: "epoch-max-quorum".to_string(),
        signature_count: u32::try_from(signatures.len()).expect("fits in u32"),
        signatures,
    };

    insta::assert_json_snapshot!("chain_head_max_signature_quorum", head);
}

#[test]
fn snapshot_verify_report_fail_with_critical_issues() {
    // ERROR CASE. A VerifyReport in its terminal Fail state, carrying
    // the three critical codes that `is_critical()` gates on. Freezing
    // this is what lets a downstream alerting pipeline grep the JSON
    // for `"code": "audit.fork_detected"` without reading the code. A
    // future rename of any critical code MUST either update this
    // snapshot or the consumers will silently stop alerting.
    let report = VerifyReport {
        status: VerifyStatus::Fail,
        zone_id: Some("z:prod".to_string()),
        chain_len: 500,
        head_seq: Some(499),
        head_entry: Some("entry-fail-499".to_string()),
        issues: vec![
            VerifyIssue::new("audit.fork_detected", "two entries share the same prev")
                .with_seq(200)
                .with_entry_id("entry-fork-200"),
            VerifyIssue::new("audit.seq_gap", "sequence jumped from 300 to 305")
                .with_seq(305)
                .with_entry_id("entry-gap-305"),
            VerifyIssue::new("audit.prev_mismatch", "entry.prev does not match prior id")
                .with_seq(450)
                .with_entry_id("entry-pm-450"),
        ],
    };

    // Sanity: the report is recognised as Fail and every issue is critical.
    assert!(matches!(report.status, VerifyStatus::Fail));
    assert_eq!(report.critical_count(), 3);

    insta::assert_json_snapshot!("verify_report_fail_with_critical_issues", report);
}

#[test]
fn snapshot_freshness_level_all_variants() {
    // Bonus: freeze the FreshnessLevel lowercase rename for all four
    // variants. A rename regression here would break any dashboard
    // that groups by `"freshness": "fresh"` etc.
    let all: Vec<FreshnessLevel> = vec![
        FreshnessLevel::Fresh,
        FreshnessLevel::Stale,
        FreshnessLevel::Degraded,
        FreshnessLevel::Missing,
    ];
    insta::assert_json_snapshot!("freshness_level_all_variants", all);
}
