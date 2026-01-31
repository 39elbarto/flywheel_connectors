//! Integration tests for `fcp doctor` command.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::JoinHandle;

/// Get the `fcp` command for testing.
fn fcp_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fcp"));
    // Suppress tracing output during tests
    cmd.env("RUST_LOG", "error");
    cmd
}

fn spawn_doctor_server(response_body: &'static str) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("server addr");
    let endpoint = format!("http://{addr}");
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (endpoint, handle)
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
            .stdout(predicate::str::contains("--connector"))
            .stdout(predicate::str::contains("--self-check"));
    }

    #[test]
    fn doctor_self_check_requires_connector() {
        fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work", "--self-check"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--self-check requires"));
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

    #[test]
    fn doctor_self_check_failure_sets_failed_status() {
        let output = fcp_cmd()
            .arg("doctor")
            .args([
                "--zone",
                "z:work",
                "--connector",
                "fcp.telegram:messaging:v1",
                "--self-check",
                "--scenario",
                "critical",
                "--json",
            ])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["overall_status"], "FAIL");
        assert_eq!(
            json["connector_self_checks"][0]["report"]["status"],
            "failed"
        );
    }

    #[test]
    fn doctor_uses_mesh_endpoint_when_set() {
        let report = r#"{
  "schema_version": "1.1.0",
  "generated_at": "2026-01-30T00:00:00Z",
  "zone_id": "z:work",
  "overall_status": "OK",
  "checkpoint": { "freshness": "fresh" },
  "revocation": { "freshness": "fresh" },
  "audit": { "freshness": "fresh" },
  "transport_policy": {
    "allow_lan": true,
    "allow_derp": false,
    "allow_funnel": false
  },
  "store_coverage": { "store_healthy": true },
  "degraded_mode": { "is_degraded": false },
  "checks": []
}"#;
        let (endpoint, handle) = spawn_doctor_server(report);
        let output = fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work", "--json"])
            .env("FCP_MESH_ENDPOINT", endpoint)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["overall_status"], "OK");
        assert_eq!(json["zone_id"], "z:work");
        handle.join().expect("join server thread");
    }

    #[test]
    fn doctor_reads_report_from_stdin() {
        let report = r#"{
  "schema_version": "1.1.0",
  "generated_at": "2026-01-30T00:00:00Z",
  "zone_id": "z:work",
  "overall_status": "OK",
  "checkpoint": { "freshness": "fresh" },
  "revocation": { "freshness": "fresh" },
  "audit": { "freshness": "fresh" },
  "transport_policy": {
    "allow_lan": true,
    "allow_derp": false,
    "allow_funnel": false
  },
  "store_coverage": { "store_healthy": true },
  "degraded_mode": { "is_degraded": false },
  "checks": [],
  "connector_self_checks": [
    {
      "connector_id": "fcp.telegram:messaging:v1",
      "report": { "status": "ok" }
    }
  ]
}"#;

        let output = fcp_cmd()
            .arg("doctor")
            .args(["--zone", "z:work", "--json", "--input-stdin"])
            .write_stdin(report)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["overall_status"], "OK");
        assert_eq!(json["zone_id"], "z:work");
        assert_eq!(
            json["connector_self_checks"][0]["connector_id"],
            "fcp.telegram:messaging:v1"
        );
        assert_eq!(json["connector_self_checks"][0]["report"]["status"], "ok");
    }
}
