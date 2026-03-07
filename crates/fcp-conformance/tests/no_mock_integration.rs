//! No-mock integration tests for fcp-conformance.
//!
//! These tests exercise cross-module interactions without mocking frameworks,
//! verifying that compliance, schemas, interop, reqcheck, and vector modules
//! compose correctly across boundaries.

use fcp_conformance::compliance::{
    CheckStatus, ComplianceFinding, ComplianceReport, DynamicCompliance, StaticCompliance,
};
use fcp_conformance::interop::{InteropTestSummary, TestFailure};
use fcp_conformance::reqcheck::{
    RequirementEntry, RequirementsIndexParser, ValidationError, ValidationReport, ValidationWarning,
};
use fcp_conformance::schemas::{self, ForensicsRuleDiagnostic, ForensicsValidationError};
use serde_json::json;

// ═══════════════════════════════════════════════════════════════
// 1. CheckStatus + ComplianceFinding construction
// ═══════════════════════════════════════════════════════════════

#[test]
fn check_status_serde_roundtrip() {
    for status in [CheckStatus::Pass, CheckStatus::Fail, CheckStatus::Skipped] {
        let json = serde_json::to_string(&status).unwrap();
        let back: CheckStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn check_status_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&CheckStatus::Pass).unwrap(),
        "\"pass\""
    );
    assert_eq!(
        serde_json::to_string(&CheckStatus::Fail).unwrap(),
        "\"fail\""
    );
    assert_eq!(
        serde_json::to_string(&CheckStatus::Skipped).unwrap(),
        "\"skipped\""
    );
}

#[test]
fn compliance_finding_serde_roundtrip() {
    let finding = ComplianceFinding {
        check: "manifest.parse".into(),
        status: CheckStatus::Pass,
        message: "manifest parsed ok".into(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: ComplianceFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.check, "manifest.parse");
    assert_eq!(back.status, CheckStatus::Pass);
    assert_eq!(back.message, "manifest parsed ok");
}

// ═══════════════════════════════════════════════════════════════
// 2. StaticCompliance manifest validation
// ═══════════════════════════════════════════════════════════════

#[test]
fn static_compliance_invalid_manifest() {
    let result = StaticCompliance::run_manifest("not valid toml {{{");
    assert!(!result.passed);
    assert!(!result.findings.is_empty());
    assert_eq!(result.findings[0].status, CheckStatus::Fail);
    assert_eq!(result.findings[0].check, "manifest.parse_validate");
}

#[test]
fn static_compliance_empty_manifest() {
    let result = StaticCompliance::run_manifest("");
    assert!(!result.passed);
    assert_eq!(result.findings[0].status, CheckStatus::Fail);
}

#[test]
fn static_compliance_serde_roundtrip() {
    let compliance = StaticCompliance {
        passed: true,
        findings: vec![ComplianceFinding {
            check: "test".into(),
            status: CheckStatus::Pass,
            message: "ok".into(),
        }],
    };
    let json = serde_json::to_string(&compliance).unwrap();
    let back: StaticCompliance = serde_json::from_str(&json).unwrap();
    assert!(back.passed);
    assert_eq!(back.findings.len(), 1);
}

// ═══════════════════════════════════════════════════════════════
// 3. ComplianceReport aggregation
// ═══════════════════════════════════════════════════════════════

#[test]
fn compliance_report_passes_when_both_pass() {
    let report = ComplianceReport {
        static_checks: StaticCompliance {
            passed: true,
            findings: vec![],
        },
        dynamic_checks: DynamicCompliance {
            passed: true,
            findings: vec![],
        },
    };
    assert!(report.passed());
}

#[test]
fn compliance_report_fails_when_static_fails() {
    let report = ComplianceReport {
        static_checks: StaticCompliance {
            passed: false,
            findings: vec![ComplianceFinding {
                check: "manifest.parse_validate".into(),
                status: CheckStatus::Fail,
                message: "bad manifest".into(),
            }],
        },
        dynamic_checks: DynamicCompliance {
            passed: true,
            findings: vec![],
        },
    };
    assert!(!report.passed());
}

#[test]
fn compliance_report_fails_when_dynamic_fails() {
    let report = ComplianceReport {
        static_checks: StaticCompliance {
            passed: true,
            findings: vec![],
        },
        dynamic_checks: DynamicCompliance {
            passed: false,
            findings: vec![ComplianceFinding {
                check: "configure".into(),
                status: CheckStatus::Fail,
                message: "configure failed".into(),
            }],
        },
    };
    assert!(!report.passed());
}

#[test]
fn compliance_report_serde_roundtrip() {
    let report = ComplianceReport {
        static_checks: StaticCompliance {
            passed: true,
            findings: vec![ComplianceFinding {
                check: "a".into(),
                status: CheckStatus::Pass,
                message: "ok".into(),
            }],
        },
        dynamic_checks: DynamicCompliance {
            passed: false,
            findings: vec![ComplianceFinding {
                check: "b".into(),
                status: CheckStatus::Fail,
                message: "err".into(),
            }],
        },
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ComplianceReport = serde_json::from_str(&json).unwrap();
    assert!(!back.passed());
    assert!(back.static_checks.passed);
    assert!(!back.dynamic_checks.passed);
}

#[test]
fn dynamic_compliance_skipped() {
    let dynamic = DynamicCompliance::skipped("no config available");
    assert!(dynamic.passed);
    assert_eq!(dynamic.findings.len(), 1);
    assert_eq!(dynamic.findings[0].status, CheckStatus::Skipped);
    assert_eq!(dynamic.findings[0].check, "dynamic.skip");
}

// ═══════════════════════════════════════════════════════════════
// 4. InteropTestSummary cross-category merge
// ═══════════════════════════════════════════════════════════════

#[test]
fn interop_summary_merge_multiple_categories() {
    let mut session = InteropTestSummary {
        total: 5,
        passed: 5,
        failed: 0,
        failures: vec![],
    };
    let fcps = InteropTestSummary {
        total: 3,
        passed: 2,
        failed: 1,
        failures: vec![TestFailure {
            name: "mac_suite1".into(),
            category: "fcps".into(),
            message: "MAC mismatch".into(),
        }],
    };
    let framing = InteropTestSummary {
        total: 4,
        passed: 3,
        failed: 1,
        failures: vec![TestFailure {
            name: "frame_order".into(),
            category: "fcpc".into(),
            message: "out of order".into(),
        }],
    };

    session.merge(fcps);
    session.merge(framing);

    assert_eq!(session.total, 12);
    assert_eq!(session.passed, 10);
    assert_eq!(session.failed, 2);
    assert!(!session.all_passed());
    assert_eq!(session.failures.len(), 2);
    assert_eq!(session.failures[0].category, "fcps");
    assert_eq!(session.failures[1].category, "fcpc");
}

#[test]
fn interop_summary_all_passed_zero_total() {
    let summary = InteropTestSummary::default();
    assert!(summary.all_passed());
    assert_eq!(summary.total, 0);
}

#[test]
fn interop_summary_clone_preserves_failures() {
    let summary = InteropTestSummary {
        total: 2,
        passed: 1,
        failed: 1,
        failures: vec![TestFailure {
            name: "test1".into(),
            category: "session".into(),
            message: "transcript mismatch".into(),
        }],
    };
    #[allow(clippy::redundant_clone)]
    let cloned = summary.clone();
    assert_eq!(cloned.total, 2);
    assert_eq!(cloned.failures.len(), 1);
    assert_eq!(cloned.failures[0].name, "test1");
}

// ═══════════════════════════════════════════════════════════════
// 5. Forensics validation + error diagnostics
// ═══════════════════════════════════════════════════════════════

fn valid_forensics_entry() -> serde_json::Value {
    json!({
        "schema_version": "asupersync-forensics/v1",
        "run_id": "run-001",
        "scenario_id": "scen-1",
        "trace_id": "trace-1",
        "correlation_id": "corr-1",
        "connector": "test-connector",
        "zone": "z:test",
        "operation": "invoke",
        "attempt": 1,
        "timeout_budget_ms": 5000,
        "cancellation_reason": null,
        "queue_depth": null,
        "decode_budget": null,
        "outcome": "pass",
        "elapsed_ms": 42
    })
}

#[test]
fn forensics_valid_entry_passes() {
    let entry = valid_forensics_entry();
    let result = schemas::validate_asupersync_forensics_entry(&entry, Some("run-001"));
    assert!(result.is_ok());
}

#[test]
fn forensics_valid_entry_without_run_id_check() {
    let entry = valid_forensics_entry();
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    assert!(result.is_ok());
}

#[test]
fn forensics_wrong_run_id_fails() {
    let entry = valid_forensics_entry();
    let result = schemas::validate_asupersync_forensics_entry(&entry, Some("run-999"));
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.run_id.match");
            assert_eq!(diagnostic.field, "run_id");
            assert!(diagnostic.message.contains("run-999"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_missing_schema_version() {
    let mut entry = valid_forensics_entry();
    entry.as_object_mut().unwrap().remove("schema_version");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.schema_version");
            assert_eq!(diagnostic.field, "schema_version");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_wrong_schema_version() {
    let mut entry = valid_forensics_entry();
    entry["schema_version"] = json!("wrong/v2");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.schema_version");
            assert!(diagnostic.message.contains("wrong/v2"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_attempt_zero_fails() {
    let mut entry = valid_forensics_entry();
    entry["attempt"] = json!(0);
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.attempt");
            assert!(diagnostic.message.contains("greater than"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_invalid_outcome() {
    let mut entry = valid_forensics_entry();
    entry["outcome"] = json!("unknown");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.outcome");
            assert!(diagnostic.message.contains("unknown"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_not_object_fails() {
    let result = schemas::validate_asupersync_forensics_entry(&json!([1, 2, 3]), None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.record.object");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_missing_identity_field_fails() {
    let mut entry = valid_forensics_entry();
    entry.as_object_mut().unwrap().remove("connector");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.connector");
            assert_eq!(diagnostic.field, "connector");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_empty_string_field_fails() {
    let mut entry = valid_forensics_entry();
    entry["zone"] = json!("  ");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.zone");
            assert!(diagnostic.message.contains("non-empty"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════
// 6. Forensics JSONL multi-line validation
// ═══════════════════════════════════════════════════════════════

#[test]
fn forensics_jsonl_valid_multi_line() {
    let line1 = serde_json::to_string(&valid_forensics_entry()).unwrap();
    let mut entry2 = valid_forensics_entry();
    entry2["attempt"] = json!(2);
    entry2["outcome"] = json!("fail");
    let line2 = serde_json::to_string(&entry2).unwrap();

    let input = format!("{line1}\n{line2}\n");
    let result = schemas::validate_asupersync_forensics_jsonl(&input, Some("run-001"));
    assert!(result.is_ok());
}

#[test]
fn forensics_jsonl_skips_empty_lines() {
    let line = serde_json::to_string(&valid_forensics_entry()).unwrap();
    let input = format!("\n{line}\n\n");
    let result = schemas::validate_asupersync_forensics_jsonl(&input, None);
    assert!(result.is_ok());
}

#[test]
fn forensics_jsonl_invalid_json_line() {
    let input = "not valid json\n";
    let result = schemas::validate_asupersync_forensics_jsonl(input, None);
    match result {
        Err(ForensicsValidationError::InvalidJsonLine { line, message }) => {
            assert_eq!(line, 1);
            assert!(!message.is_empty());
        }
        other => panic!("expected InvalidJsonLine, got {other:?}"),
    }
}

#[test]
fn forensics_jsonl_second_line_fails() {
    let line1 = serde_json::to_string(&valid_forensics_entry()).unwrap();
    let input = format!("{line1}\n{{\"bad\": true}}\n");
    let result = schemas::validate_asupersync_forensics_jsonl(&input, None);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.line(), Some(2));
}

// ═══════════════════════════════════════════════════════════════
// 7. ForensicsValidationError + ForensicsRuleDiagnostic
// ═══════════════════════════════════════════════════════════════

#[test]
fn forensics_rule_diagnostic_display() {
    let diag = ForensicsRuleDiagnostic {
        rule_id: "asupersync.forensics.v1.run_id",
        field: "run_id",
        message: "missing required field".into(),
    };
    let display = format!("{diag}");
    assert!(display.contains("asupersync.forensics.v1.run_id"));
    assert!(display.contains("[run_id]"));
    assert!(display.contains("missing required field"));
}

#[test]
fn forensics_validation_error_display_with_line() {
    let err = ForensicsValidationError::RuleViolation {
        line: Some(42),
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "asupersync.forensics.v1.outcome",
            field: "outcome",
            message: "invalid value".into(),
        },
    };
    let display = format!("{err}");
    assert!(display.contains("line 42"));
    assert!(display.contains("outcome"));
}

#[test]
fn forensics_validation_error_display_without_line() {
    let err = ForensicsValidationError::RuleViolation {
        line: None,
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "asupersync.forensics.v1.run_id",
            field: "run_id",
            message: "missing".into(),
        },
    };
    let display = format!("{err}");
    assert!(!display.contains("line"));
    assert!(display.contains("run_id"));
}

#[test]
fn forensics_validation_error_invalid_json_line_display() {
    let err = ForensicsValidationError::InvalidJsonLine {
        line: 5,
        message: "unexpected EOF".into(),
    };
    let display = format!("{err}");
    assert!(display.contains("line 5"));
    assert!(display.contains("invalid JSON"));
    assert!(display.contains("unexpected EOF"));
}

#[test]
fn forensics_validation_error_rule_id_accessor() {
    let err = ForensicsValidationError::RuleViolation {
        line: None,
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "asupersync.forensics.v1.zone",
            field: "zone",
            message: "bad".into(),
        },
    };
    assert_eq!(err.rule_id(), Some("asupersync.forensics.v1.zone"));

    let json_err = ForensicsValidationError::InvalidJsonLine {
        line: 1,
        message: "bad json".into(),
    };
    assert_eq!(json_err.rule_id(), None);
}

#[test]
fn forensics_validation_error_line_accessor() {
    let err_with_line = ForensicsValidationError::RuleViolation {
        line: Some(10),
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "test",
            field: "f",
            message: "m".into(),
        },
    };
    assert_eq!(err_with_line.line(), Some(10));

    let err_no_line = ForensicsValidationError::RuleViolation {
        line: None,
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "test",
            field: "f",
            message: "m".into(),
        },
    };
    assert_eq!(err_no_line.line(), None);
}

#[test]
fn forensics_validation_error_equality() {
    let a = ForensicsValidationError::RuleViolation {
        line: Some(1),
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "rule.a",
            field: "field_a",
            message: "msg".into(),
        },
    };
    let b = ForensicsValidationError::RuleViolation {
        line: Some(1),
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "rule.a",
            field: "field_a",
            message: "msg".into(),
        },
    };
    assert_eq!(a, b);
}

// ═══════════════════════════════════════════════════════════════
// 8. Schema constants availability
// ═══════════════════════════════════════════════════════════════

#[test]
fn schema_constants_are_non_empty() {
    assert!(!schemas::FZPF_V01_SCHEMA.is_empty());
    assert!(!schemas::E2E_LOG_V1_SCHEMA.is_empty());
    assert!(!schemas::E2E_LOG_V2_SCHEMA.is_empty());
    assert!(!schemas::POLICY_BUNDLE_V1_SCHEMA.is_empty());
    assert!(!schemas::RELEASE_MANIFEST_V1_SCHEMA.is_empty());
    assert!(!schemas::ROLLOUT_POLICY_V1_SCHEMA.is_empty());
    assert!(!schemas::TRACE_V1_SCHEMA.is_empty());
    assert!(!schemas::CAPABILITY_USAGE_V1_SCHEMA.is_empty());
    assert!(!schemas::SUPPLY_CHAIN_ATTESTATION_V1_SCHEMA.is_empty());
    assert!(!schemas::SBOM_V1_SCHEMA.is_empty());
    assert!(!schemas::ASUPERSYNC_FORENSICS_V1_SCHEMA.is_empty());
}

#[test]
fn schema_constants_are_valid_json() {
    let schemas = [
        ("FZPF_V01", schemas::FZPF_V01_SCHEMA),
        ("E2E_LOG_V1", schemas::E2E_LOG_V1_SCHEMA),
        ("E2E_LOG_V2", schemas::E2E_LOG_V2_SCHEMA),
        ("POLICY_BUNDLE_V1", schemas::POLICY_BUNDLE_V1_SCHEMA),
        ("RELEASE_MANIFEST_V1", schemas::RELEASE_MANIFEST_V1_SCHEMA),
        ("ROLLOUT_POLICY_V1", schemas::ROLLOUT_POLICY_V1_SCHEMA),
        ("TRACE_V1", schemas::TRACE_V1_SCHEMA),
        ("CAPABILITY_USAGE_V1", schemas::CAPABILITY_USAGE_V1_SCHEMA),
        (
            "SUPPLY_CHAIN_V1",
            schemas::SUPPLY_CHAIN_ATTESTATION_V1_SCHEMA,
        ),
        ("SBOM_V1", schemas::SBOM_V1_SCHEMA),
        (
            "ASUPERSYNC_FORENSICS_V1",
            schemas::ASUPERSYNC_FORENSICS_V1_SCHEMA,
        ),
    ];

    for (name, schema) in schemas {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(schema);
        assert!(
            parsed.is_ok(),
            "{name} schema is not valid JSON: {}",
            parsed.unwrap_err()
        );
    }
}

#[test]
fn asupersync_forensics_version_marker() {
    assert_eq!(schemas::ASUPERSYNC_FORENSICS_V1, "asupersync-forensics/v1");
}

// ═══════════════════════════════════════════════════════════════
// 9. Reqcheck types + parser
// ═══════════════════════════════════════════════════════════════

#[test]
fn requirement_entry_serde_roundtrip() {
    let entry = RequirementEntry {
        section: "§1: Introduction".into(),
        line_number: 42,
        owners: vec!["fc-1n78.21".into(), "bd-3frf".into()],
        tests: vec!["fc-1n78.21.1".into()],
        notes: Some("golden vectors".into()),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RequirementEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.section, "§1: Introduction");
    assert_eq!(back.owners.len(), 2);
    assert_eq!(back.tests.len(), 1);
    assert_eq!(back.notes.as_deref(), Some("golden vectors"));
}

#[test]
fn validation_error_serde_roundtrip() {
    let err = ValidationError {
        section: "§3: Protocol".into(),
        line_number: Some(100),
        error_type: "missing_bead".into(),
        value: "fc-nonexist".into(),
        message: "bead not found".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(back.section, "§3: Protocol");
    assert_eq!(back.error_type, "missing_bead");
}

#[test]
fn validation_warning_serde_roundtrip() {
    let warn = ValidationWarning {
        section: "§2: Overview".into(),
        line_number: Some(50),
        warning_type: "empty_owners".into(),
        message: "no owners specified".into(),
    };
    let json = serde_json::to_string(&warn).unwrap();
    let back: ValidationWarning = serde_json::from_str(&json).unwrap();
    assert_eq!(back.warning_type, "empty_owners");
}

#[test]
fn validation_report_is_valid_when_no_errors() {
    let report = ValidationReport {
        total_entries: 10,
        unique_beads: 5,
        missing_beads: vec![],
        errors: vec![],
        warnings: vec![],
        entries: None,
    };
    assert!(report.is_valid());
}

#[test]
fn validation_report_is_invalid_when_errors_present() {
    let report = ValidationReport {
        total_entries: 10,
        unique_beads: 5,
        missing_beads: vec!["fc-missing".into()],
        errors: vec![ValidationError {
            section: "§1".into(),
            line_number: Some(10),
            error_type: "missing_bead".into(),
            value: "fc-missing".into(),
            message: "not found".into(),
        }],
        warnings: vec![],
        entries: None,
    };
    assert!(!report.is_valid());
}

#[test]
fn validation_report_serde_none_entries() {
    let report = ValidationReport {
        total_entries: 0,
        unique_beads: 0,
        missing_beads: vec![],
        errors: vec![],
        warnings: vec![],
        entries: None,
    };
    let json = serde_json::to_string(&report).unwrap();
    // entries field should serialize as null or be omitted depending on serde config
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let entries = parsed.get("entries");
    assert!(
        entries.is_none() || entries == Some(&serde_json::Value::Null),
        "entries should be null or absent when None"
    );
}

#[test]
fn validation_report_serde_includes_some_entries() {
    let report = ValidationReport {
        total_entries: 1,
        unique_beads: 1,
        missing_beads: vec![],
        errors: vec![],
        warnings: vec![],
        entries: Some(vec![RequirementEntry {
            section: "§1".into(),
            line_number: 1,
            owners: vec!["fc-abc".into()],
            tests: vec![],
            notes: None,
        }]),
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("entries"));
}

#[test]
fn requirements_parser_default() {
    let parser = RequirementsIndexParser::new();
    let debug = format!("{parser:?}");
    assert!(debug.contains("RequirementsIndexParser"));
}

// ═══════════════════════════════════════════════════════════════
// 10. Reqcheck parser + validation report types
// ═══════════════════════════════════════════════════════════════

#[test]
fn requirements_parser_new_is_default() {
    let parser = RequirementsIndexParser::new();
    let default_parser = RequirementsIndexParser::default();
    // Both should produce equivalent debug output
    let d1 = format!("{parser:?}");
    let d2 = format!("{default_parser:?}");
    assert_eq!(d1, d2);
}

#[test]
fn validation_report_with_warnings_but_no_errors_is_valid() {
    let report = ValidationReport {
        total_entries: 5,
        unique_beads: 3,
        missing_beads: vec![],
        errors: vec![],
        warnings: vec![ValidationWarning {
            section: "§1".into(),
            line_number: None,
            warning_type: "empty_tests".into(),
            message: "no tests specified".into(),
        }],
        entries: None,
    };
    assert!(report.is_valid());
    assert_eq!(report.warnings.len(), 1);
}

// ═══════════════════════════════════════════════════════════════
// 11. Cross-module: forensics + compliance report
// ═══════════════════════════════════════════════════════════════

#[test]
fn forensics_entry_validates_all_outcomes() {
    for outcome in ["pass", "fail", "planned"] {
        let mut entry = valid_forensics_entry();
        entry["outcome"] = json!(outcome);
        let result = schemas::validate_asupersync_forensics_entry(&entry, None);
        assert!(result.is_ok(), "outcome '{outcome}' should be valid");
    }
}

#[test]
fn forensics_entry_with_optional_fields() {
    let mut entry = valid_forensics_entry();
    entry["span_id"] = json!("0123456789abcdef");
    entry["result_code"] = json!("SUCCESS");
    entry["cancellation_reason"] = json!("timeout");
    entry["queue_depth"] = json!(5);
    entry["decode_budget"] = json!(1024.5);
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    assert!(result.is_ok());
}

#[test]
fn forensics_invalid_span_id() {
    let mut entry = valid_forensics_entry();
    entry["span_id"] = json!("short");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.span_id");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_empty_result_code() {
    let mut entry = valid_forensics_entry();
    entry["result_code"] = json!("  ");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.result_code");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════
// 12. Cross-module: compliance finding aggregation
// ═══════════════════════════════════════════════════════════════

#[test]
fn static_compliance_finding_flow_to_report() {
    let static_result = StaticCompliance::run_manifest("invalid toml");
    assert!(!static_result.passed);

    let report = ComplianceReport {
        static_checks: static_result,
        dynamic_checks: DynamicCompliance::skipped("not applicable"),
    };

    assert!(!report.passed());
    assert_eq!(report.static_checks.findings[0].status, CheckStatus::Fail);
    assert_eq!(
        report.dynamic_checks.findings[0].status,
        CheckStatus::Skipped
    );
}

// ═══════════════════════════════════════════════════════════════
// 13. E2E log validation
// ═══════════════════════════════════════════════════════════════

#[test]
fn e2e_log_empty_input_passes() {
    let result = schemas::validate_e2e_log_jsonl("");
    assert!(result.is_ok());
}

#[test]
fn e2e_log_blank_lines_only_passes() {
    let result = schemas::validate_e2e_log_jsonl("\n\n  \n");
    assert!(result.is_ok());
}

#[test]
fn e2e_log_invalid_json_fails() {
    let result = schemas::validate_e2e_log_jsonl("not json\n");
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════
// 14. SchemaValidationError display
// ═══════════════════════════════════════════════════════════════

#[test]
fn schema_validation_error_from_invalid_json() {
    // Schema validation errors occur naturally from validate functions
    let result = schemas::validate_e2e_log_entry(&json!("not an object"));
    assert!(result.is_err());
    let err = result.unwrap_err();
    let display = format!("{err}");
    assert!(!display.is_empty());
}

#[test]
fn schema_validation_error_is_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = schemas::validate_e2e_log_entry(&json!("bad")).unwrap_err();
    assert_error(&err);
}

// ═══════════════════════════════════════════════════════════════
// 15. Interop + compliance summary integration
// ═══════════════════════════════════════════════════════════════

#[test]
fn interop_summary_to_compliance_findings() {
    let summary = InteropTestSummary {
        total: 3,
        passed: 2,
        failed: 1,
        failures: vec![TestFailure {
            name: "mac_suite1".into(),
            category: "fcps".into(),
            message: "MAC mismatch on vector 3".into(),
        }],
    };

    // Convert interop failures to compliance findings
    let findings: Vec<ComplianceFinding> = summary
        .failures
        .iter()
        .map(|f| ComplianceFinding {
            check: format!("interop.{}.{}", f.category, f.name),
            status: CheckStatus::Fail,
            message: f.message.clone(),
        })
        .collect();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].check, "interop.fcps.mac_suite1");
    assert_eq!(findings[0].status, CheckStatus::Fail);
}

// ═══════════════════════════════════════════════════════════════
// 16. Forensics + compliance pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn forensics_validation_produces_deterministic_diagnostics() {
    let mut entry = valid_forensics_entry();
    entry.as_object_mut().unwrap().remove("trace_id");

    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    let err = result.unwrap_err();

    // Verify error has deterministic rule_id and field
    match &err {
        ForensicsValidationError::RuleViolation { diagnostic, .. } => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.trace_id");
            assert_eq!(diagnostic.field, "trace_id");
        }
        ForensicsValidationError::InvalidJsonLine { .. } => {
            panic!("expected RuleViolation, got {err:?}")
        }
    }

    // Convert to compliance finding for reporting
    let finding = ComplianceFinding {
        check: format!("forensics.{}", err.rule_id().unwrap_or("unknown")),
        status: CheckStatus::Fail,
        message: format!("{err}"),
    };
    assert_eq!(finding.check, "forensics.asupersync.forensics.v1.trace_id");
    assert_eq!(finding.status, CheckStatus::Fail);
}
