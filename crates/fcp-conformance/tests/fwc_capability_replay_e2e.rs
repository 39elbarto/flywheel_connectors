//! Conformance coverage for `fwc capability replay`.

use std::path::PathBuf;

use fcp_audit::{AuditEntry, AuditEntryBuilder, event_types};
use fwc::capability_replay::{
    CapabilityReplayError, ReplayOutput, build_replay_payload_from_entries,
};
use jsonschema::Validator;
use serde_json::{Value, json};

const NOW: u64 = 1_715_630_500;
const TOKEN: &str = "cap-token-secret";
const DEFAULT_WINDOW_SECS: u64 = fcp_audit::replay::DEFAULT_REPLAY_WINDOW_SECS;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join("capability_replay.schema.json")
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("tests")
        .join("fixtures")
        .join("capability_replay")
        .join(name)
}

fn validator() -> Validator {
    let schema = std::fs::read_to_string(schema_path()).expect("capability replay schema readable");
    let schema: Value = serde_json::from_str(&schema).expect("schema parses");
    Validator::new(&schema).expect("capability replay schema compiles")
}

fn entry(seq: u64, metadata: Vec<(&str, Value)>) -> AuditEntry {
    metadata
        .into_iter()
        .fold(
            AuditEntryBuilder::new()
                .id(format!("entry-{seq}"))
                .event_type(event_types::CAPABILITY_INVOKE)
                .actor("user:alice")
                .zone_id("z:work")
                .seq(seq)
                .occurred_at(NOW - 60 + seq.saturating_sub(12_034)),
            |builder, (key, value)| builder.meta(key, value),
        )
        .build()
        .expect("audit entry builds")
}

fn accepted_entries() -> Vec<AuditEntry> {
    let token_hash = fcp_audit::replay::token_hash(TOKEN);
    vec![
        entry(
            12_034,
            vec![
                ("token_hash", json!(token_hash)),
                ("rule_name", json!("zone_match")),
                (
                    "inputs_json",
                    json!({"src_zone": "z:work", "dst_zone": "z:work"}),
                ),
                ("output", json!(true)),
                ("latency_us", json!(45)),
                ("evaluator_version", json!("1.2.0")),
            ],
        ),
        entry(
            12_035,
            vec![
                ("token_id", json!(TOKEN)),
                ("rule_name", json!("capability_token_signature_verify")),
                (
                    "inputs_json",
                    json!({"alg": "ml-dsa-65", "issuer": "owner-key-v4"}),
                ),
                ("output", json!(true)),
                ("latency_us", json!(50)),
                ("evaluator_version", json!("1.2.0")),
            ],
        ),
        entry(
            12_036,
            vec![
                ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
                ("rule_name", json!("instance_binding_match")),
                (
                    "inputs_json",
                    json!({
                        "claimed_instance_id": "inst-7a3f",
                        "requested_instance_id": "inst-7a3f"
                    }),
                ),
                ("output", json!(true)),
                ("latency_us", json!(50)),
                ("evaluator_version", json!("1.2.0")),
            ],
        ),
        entry(
            12_037,
            vec![
                ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
                ("rule_name", json!("revocation_check")),
                (
                    "inputs_json",
                    json!({"registry_root": "blake3:9a2b3c4d5e6f", "freshness_secs": 12}),
                ),
                ("output", json!(true)),
                ("witness_chain_indices", json!([12_037, 12_038])),
                ("latency_us", json!(50)),
                ("evaluator_version", json!("1.2.0")),
            ],
        ),
        entry(
            12_039,
            vec![
                ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
                ("rule_name", json!("expiry_check")),
                (
                    "inputs_json",
                    json!({
                        "not_before_unix": 1_715_587_200_u64,
                        "not_after_unix": 1_715_673_600_u64,
                        "now_unix": 1_715_630_400_u64
                    }),
                ),
                ("output", json!(true)),
                ("witness_chain_indices", json!([12_039, 12_040])),
                ("latency_us", json!(50)),
                ("evaluator_version", json!("1.2.0")),
            ],
        ),
    ]
}

#[test]
fn test_replay_accepted_token_reconstructs_full_trace() {
    let payload = build_replay_payload_from_entries(
        TOKEN,
        DEFAULT_WINDOW_SECS,
        false,
        &accepted_entries(),
        ReplayOutput::Json,
        NOW,
    )
    .expect("accepted replay reconstructs");

    assert_eq!(payload["final_verdict"], "accepted");
    assert_eq!(payload["total_steps"], 5);
    assert_eq!(payload["total_latency_us"], 245);
    assert_eq!(
        payload["audit_chain_range"],
        json!({"start_seq": 12_034, "end_seq": 12_040})
    );
    assert_eq!(payload["trace"][0]["rule_name"], "zone_match");
    validator()
        .validate(&payload)
        .expect("accepted replay payload matches schema");
}

#[test]
fn test_replay_revoked_token_shows_revocation_step() {
    let entries = vec![entry(
        7,
        vec![
            ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
            ("rule_name", json!("revocation_check")),
            ("inputs_json", json!({"registry_root": "blake3:revoked"})),
            ("output", json!(false)),
            ("evaluator_version", json!("1.2.0")),
        ],
    )];

    let payload = build_replay_payload_from_entries(
        TOKEN,
        DEFAULT_WINDOW_SECS,
        false,
        &entries,
        ReplayOutput::Json,
        NOW,
    )
    .expect("revoked replay reconstructs");

    assert_eq!(payload["final_verdict"], "rejected_revocation");
    assert_eq!(payload["trace"][0]["rule_name"], "revocation_check");
    assert_eq!(payload["trace"][0]["output"], false);
}

#[test]
fn test_replay_unknown_token_returns_error_3() {
    let entries = vec![entry(
        1,
        vec![
            (
                "token_hash",
                json!(fcp_audit::replay::token_hash("other-token")),
            ),
            ("rule_name", json!("zone_match")),
            ("output", json!(true)),
            ("evaluator_version", json!("1.2.0")),
        ],
    )];

    let error = build_replay_payload_from_entries(
        TOKEN,
        DEFAULT_WINDOW_SECS,
        false,
        &entries,
        ReplayOutput::Json,
        NOW,
    )
    .expect_err("unknown token returns a typed error");

    assert!(matches!(
        error,
        CapabilityReplayError::Replay(
            fcp_audit::replay::ReplayError::TokenNotFoundInAuditChain { .. }
        )
    ));
    assert_eq!(error.error_type(), "TokenNotFoundInAuditChain");
}

#[test]
fn test_replay_output_schema_stable() {
    let golden = std::fs::read_to_string(fixture_path("golden_accepted.json"))
        .expect("golden fixture readable");
    let golden: Value = serde_json::from_str(&golden).expect("golden fixture parses");
    let validator = validator();

    validator
        .validate(&golden)
        .expect("golden fixture stays schema-valid");

    let payload = build_replay_payload_from_entries(
        TOKEN,
        DEFAULT_WINDOW_SECS,
        false,
        &accepted_entries(),
        ReplayOutput::Jsonl,
        NOW,
    )
    .expect("jsonl replay payload builds");

    validator
        .validate(&payload)
        .expect("runtime payload stays schema-valid");
    assert!(
        payload["jsonl"]
            .as_str()
            .expect("jsonl output")
            .contains("zone_match")
    );
}

#[test]
fn test_replay_redacts_secret_payloads() {
    let entries = vec![entry(
        42,
        vec![
            ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
            ("rule_name", json!("credential_scope")),
            (
                "inputs_json",
                json!({
                    "service_account_key": "super-secret-key",
                    "bearer": format!("Bearer {TOKEN}"),
                    "visible": "safe"
                }),
            ),
            ("output", json!(true)),
            ("evaluator_version", json!("1.2.0")),
        ],
    )];

    let payload = build_replay_payload_from_entries(
        TOKEN,
        DEFAULT_WINDOW_SECS,
        false,
        &entries,
        ReplayOutput::Json,
        NOW,
    )
    .expect("redacted replay payload builds");
    let serialized = serde_json::to_string(&payload).expect("payload serializes");

    assert!(!serialized.contains(TOKEN));
    assert!(!serialized.contains("super-secret-key"));
    assert!(serialized.contains("safe"));
    assert!(serialized.contains("<redacted>"));
}

#[test]
fn test_replay_above_default_cap_requires_confirm() {
    let error = build_replay_payload_from_entries(
        TOKEN,
        DEFAULT_WINDOW_SECS + 1,
        false,
        &accepted_entries(),
        ReplayOutput::Json,
        NOW,
    )
    .expect_err("wide replay requires confirm");

    assert_eq!(error.error_type(), "wide-window-requires-confirm");
}
