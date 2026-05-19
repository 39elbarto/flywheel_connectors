//! Conformance coverage for A.5 `fwc` truth-source command envelopes.

use jsonschema::Validator;
use serde_json::{Value, json};
use std::path::PathBuf;

const TRUTH_SOURCES: &[&str] = &[
    "mesh",
    "host",
    "node-local",
    "offline",
    "degraded",
    "fallback-derived",
    "simulated",
    "unavailable",
];

#[derive(Clone, Copy)]
struct CommandSchemaCase {
    file: &'static str,
    command: &'static str,
    subcommand: Option<&'static str>,
    command_required_on_success: bool,
    success_schema_version: &'static str,
    error_schema_version: &'static str,
}

const CASES: &[CommandSchemaCase] = &[
    CommandSchemaCase {
        file: "list.schema.json",
        command: "list",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "show.schema.json",
        command: "show",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "status.schema.json",
        command: "status",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "doctor.schema.json",
        command: "doctor",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "context_current.schema.json",
        command: "context",
        subcommand: Some("current"),
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "schema.schema.json",
        command: "schema",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "history.schema.json",
        command: "history",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "search.schema.json",
        command: "search",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "audit_chain_status.schema.json",
        command: "audit",
        subcommand: Some("chain status"),
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.audit_chain_status.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "audit_verify.schema.json",
        command: "audit",
        subcommand: Some("verify"),
        command_required_on_success: false,
        success_schema_version: "fcp.fwc.audit_verify.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
];

fn schema_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join(file)
}

fn load_schema(file: &str) -> Value {
    let schema =
        std::fs::read_to_string(schema_path(file)).expect("failed to read fwc command schema");
    serde_json::from_str(&schema).expect("failed to parse fwc command schema JSON")
}

fn validator(file: &str) -> Validator {
    Validator::new(&load_schema(file)).expect("fwc command schema must compile")
}

fn envelope_payload(
    case: CommandSchemaCase,
    status: &str,
    schema_version: &str,
    truth_source: &str,
) -> Value {
    let mut payload = json!({
        "status": status,
        "schema_version": schema_version,
        "_truth_source": truth_source,
    });
    if status == "error" || case.command_required_on_success {
        payload["command"] = json!(case.command);
        if let Some(subcommand) = case.subcommand {
            payload["subcommand"] = json!(subcommand);
        }
    }
    payload
}

fn availability(availability: &str) -> Value {
    json!({
        "availability": availability,
        "command": "history",
        "authoritative": false,
        "explanation": "History is resolved from local CLI history artifacts.",
        "recoverable": true,
        "next_actions": ["fwc history"]
    })
}

fn history_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "history",
        "scope": "list",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "total_entries": 0,
        "returned": 0,
        "filter": {
            "connector": null,
            "status": null,
            "since": null,
            "limit": 20
        },
        "entries": [],
        "next_actions": ["fwc history <entry_id>"],
        "availability": availability("offline-artifact")
    })
}

fn success_payload(case: CommandSchemaCase, truth_source: &str) -> Value {
    if case.file == "history.schema.json" {
        return history_success_payload(truth_source);
    }
    envelope_payload(case, "ok", case.success_schema_version, truth_source)
}

fn error_payload(case: CommandSchemaCase) -> Value {
    if case.file == "history.schema.json" {
        return json!({
            "status": "error",
            "command": "history",
            "schema_version": "fcp.fwc.truth-source.v1",
            "_truth_source": "offline",
            "error": {
                "type": "truth-source-unavailable",
                "required": "any-live",
                "actual": "offline",
                "message": "`fwc history` resolved from `offline` truth, which does not satisfy `--require-source any-live`.",
                "recoverable": true
            },
            "next_actions": [
                "Retry after the required live truth source is reachable.",
                "Relax the requirement if `offline` truth is acceptable for this workflow."
            ],
            "availability": availability("unavailable")
        });
    }

    let mut payload = envelope_payload(case, "error", case.error_schema_version, "offline");
    payload["error"] = json!({
        "type": "truth-source-unavailable",
        "required": "any-live",
        "actual": "offline",
    });
    payload
}

fn assert_valid(validator: &Validator, payload: &Value, label: &str) {
    let errors = validator
        .iter_errors(payload)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "{label} should validate against fwc command schema: {errors:?}"
    );
}

#[test]
fn fwc_command_truth_source_schemas_compile_and_validate_envelopes() {
    for case in CASES {
        let validator = validator(case.file);
        for truth_source in TRUTH_SOURCES {
            let payload = success_payload(*case, truth_source);
            assert_valid(&validator, &payload, case.file);
        }

        assert_valid(&validator, &error_payload(*case), case.file);
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_missing_truth_source() {
    for case in CASES {
        let validator = validator(case.file);
        let mut payload = success_payload(*case, "offline");
        payload
            .as_object_mut()
            .expect("envelope payload must be an object")
            .remove("_truth_source");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject envelopes missing _truth_source",
            case.file
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_unknown_truth_source() {
    for case in CASES {
        let validator = validator(case.file);
        let payload = success_payload(*case, "probably-live");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject unknown truth sources",
            case.file
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_wrong_command_identity() {
    for case in CASES.iter().filter(|case| case.command_required_on_success) {
        let validator = validator(case.file);
        let mut payload = success_payload(*case, "offline");
        payload["command"] = json!("wrong");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject the wrong command identity",
            case.file
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_wrong_subcommand_identity() {
    for case in CASES
        .iter()
        .filter(|case| case.command_required_on_success && case.subcommand.is_some())
    {
        let validator = validator(case.file);
        let mut payload = success_payload(*case, "offline");
        payload["subcommand"] = json!("wrong");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject the wrong subcommand identity",
            case.file
        );
    }
}
