//! Integration tests for `fcp trace replay`.

use std::io::Write;

use serde_json::json;
use tempfile::NamedTempFile;

fn fcp_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_fcp"));
    cmd.env("RUST_LOG", "error");
    cmd
}

fn write_sample_trace_json() -> NamedTempFile {
    let trace = json!({
        "id": "trace-cli-test",
        "version": 1,
        "started_at": 1_706_832_000_000u64,
        "ended_at": 1_706_832_000_100u64,
        "capturing_node": "node-cli",
        "events": [
            {
                "event_type": "routing",
                "timestamp": 1_706_832_000_001u64,
                "trace_id": "trace-a",
                "source_node": "node-1",
                "target_node": "node-2",
                "object_id": "obj-1",
                "path_type": "direct",
                "decision": "routed",
                "reason": null
            },
            {
                "event_type": "policy",
                "timestamp": 1_706_832_000_002u64,
                "trace_id": "trace-a",
                "zone_id": "z:work",
                "operation": "telegram.send_message",
                "connector_id": "fcp.telegram",
                "decision": "allow",
                "reason_code": "CAP_OK",
                "evidence": ["obj-1"]
            }
        ],
        "redacted": false
    });

    let mut file = NamedTempFile::new().expect("create temp trace file");
    let payload = serde_json::to_string_pretty(&trace).expect("serialize trace");
    file.write_all(payload.as_bytes()).expect("write trace");
    file.flush().expect("flush trace");
    file
}

#[test]
fn trace_replay_json_output_is_machine_parseable() {
    let trace_file = write_sample_trace_json();

    let output = fcp_cmd()
        .args(["trace", "replay"])
        .arg(trace_file.path())
        .args(["--format", "json", "--json"])
        .output()
        .expect("run trace replay");

    assert!(
        output.status.success(),
        "trace replay should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse replay JSON");

    assert_eq!(report["source_trace_id"], "trace-cli-test");
    assert_eq!(report["input_events"], 2);
    assert_eq!(report["replayed_events"], 2);
    assert_eq!(report["summary"]["mismatched_events"], 0);
    assert_eq!(report["summary"]["mismatched_decisions"], 0);
    assert!(
        report["diffs"]
            .as_array()
            .is_some_and(std::vec::Vec::is_empty)
    );
}

#[test]
fn trace_replay_output_is_deterministic_for_same_input() {
    let trace_file = write_sample_trace_json();

    let run_once = || {
        let output = fcp_cmd()
            .args(["trace", "replay"])
            .arg(trace_file.path())
            .args(["--format", "json", "--json"])
            .output()
            .expect("run trace replay");
        assert!(output.status.success(), "trace replay should succeed");
        String::from_utf8(output.stdout).expect("stdout utf8")
    };

    let first = run_once();
    let second = run_once();
    assert_eq!(first, second, "replay output should be deterministic");
}
