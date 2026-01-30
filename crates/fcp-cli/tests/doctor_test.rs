//! Integration tests for `fcp doctor` command.

use assert_cmd::Command;
use predicates::prelude::*;

/// Get the `fcp` command for testing.
fn fcp_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fcp"));
    // Suppress tracing output during tests
    cmd.env("RUST_LOG", "error");
    cmd
}

mod doctor {
    use super::*;

    #[test]
    fn doctor_requires_zone_flag() {
        fcp_cmd()
            .arg("doctor")
            .assert()
            .failure()
            .stderr(predicate::str::contains("--zone"));
    }

    #[test]
    fn doctor_with_valid_zone() {
        fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work"])
            .assert()
            .success()
            .stdout(predicate::str::contains("FCP Doctor Report"))
            .stdout(predicate::str::contains("Zone:"))
            .stdout(predicate::str::contains("z:work"));
    }

    #[test]
    fn doctor_with_private_zone() {
        fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:private"])
            .assert()
            .success()
            .stdout(predicate::str::contains("z:private"));
    }

    #[test]
    fn doctor_with_project_zone() {
        fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:project:myapp"])
            .assert()
            .success()
            .stdout(predicate::str::contains("z:project:myapp"));
    }

    #[test]
    fn doctor_invalid_zone_format() {
        // Zone ID must start with "z:"
        fcp_cmd()
            .arg("doctor")
            .args(["--zone", "invalid"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("zone").or(predicate::str::contains("Zone")));
    }

    #[test]
    fn doctor_json_output() {
        fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work", "--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"schema_version\""))
            .stdout(predicate::str::contains("\"zone_id\""))
            .stdout(predicate::str::contains("\"overall_status\""));
    }

    #[test]
    fn doctor_json_valid_structure() {
        let output = fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value =
            serde_json::from_slice(&output).expect("Output should be valid JSON");

        // Verify required fields are present
        assert!(json["schema_version"].is_string());
        assert!(json["zone_id"].is_string());
        assert!(json["overall_status"].is_string());
        assert!(json["checkpoint"].is_object());
        assert!(json["revocation"].is_object());
        assert!(json["audit"].is_object());
        assert!(json["transport_policy"].is_object());
        assert!(json["store_coverage"].is_object());
        assert!(json["degraded_mode"].is_object());
        assert!(json["checks"].is_array());
    }

    #[test]
    fn doctor_json_schema_version() {
        let output = fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["schema_version"], "1.1.0");
    }

    #[test]
    fn doctor_human_readable_has_freshness() {
        fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Freshness:"))
            .stdout(predicate::str::contains("Checkpoint:"))
            .stdout(predicate::str::contains("Revocation:"))
            .stdout(predicate::str::contains("Audit:"));
    }

    #[test]
    fn doctor_human_readable_has_checks() {
        fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Checks:"));
    }

    #[test]
    fn doctor_zone_short_flag() {
        // Test short flag -z works
        fcp_cmd()
            .arg("doctor")
            .args(["-z", "z:work"])
            .assert()
            .success()
            .stdout(predicate::str::contains("z:work"));
    }

    #[test]
    fn doctor_help() {
        fcp_cmd()
            .args(["doctor", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Diagnose zone health"))
            .stdout(predicate::str::contains("--zone"))
            .stdout(predicate::str::contains("--json"))
            .stdout(predicate::str::contains("--connector"));
    }

    #[test]
    fn doctor_with_connector_self_check_json() {
        let output = fcp_cmd()
            .arg("doctor")
            .args([
                "--zone",
                "z:work",
                "--connector",
                "fcp.telegram:messaging:v1",
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert!(json["connector_self_checks"].is_array());
        assert_eq!(
            json["connector_self_checks"][0]["connector_id"],
            "fcp.telegram:messaging:v1"
        );
    }
}
