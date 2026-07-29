//! CLI coverage for RCH proof-capacity classification.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

const NOW_MS: u64 = 1_700_086_400_000;

fn run_fwc(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args(args)
        .output()
        .expect("fwc process should launch")
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout should be JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("json serializes"),
    )
    .expect("json fixture writes");
}

fn source(path: &str, line: u64) -> Value {
    json!({
        "source_id": format!("source:{line}"),
        "path": path,
        "line": line
    })
}

fn write_remote_required_corpus(path: &Path) {
    write_json(
        path,
        &json!({
            "schema": "fcp.proof-graph-indexer-corpus.v1",
            "readme_rows": [{
                "claim_key": "latency-proof",
                "feature": "Latency Proof",
                "status": "NOT YET",
                "summary": "Latency proof status",
                "evidence_summary": "redaction-safe evidence summary",
                "source": source("README.md", 10)
            }],
            "bead_issues": [{
                "id": "flywheel_connectors-angoc.6.3.1",
                "claim_key": "latency-proof",
                "title": "latency proof bead",
                "status": "open",
                "priority": 1,
                "acceptance_summary": "Acceptance requires rerunnable remote proof",
                "labels": ["proofgraph"],
                "assignee": "Codex",
                "updated_at_unix_ms": NOW_MS,
                "source": source(".beads/issues.jsonl", 42),
                "proof_comments": []
            }],
            "verification_scripts": [{
                "claim_key": "latency-proof",
                "script_path": "crates/fwc/tests/proof_latency.rs",
                "purpose": "Run latency proof command",
                "rerun_argv": ["cargo", "test", "-p", "fcp-evidence", "proof_graph_indexer", "--lib"],
                "required_env_keys": [],
                "source": source("crates/fwc/tests/proof_latency.rs", 1)
            }]
        }),
    );
}

#[test]
fn proof_rch_status_cli_classifies_recorded_rch_fixtures() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let fixtures = [
        (
            "healthy",
            json!({"workers": [{"id": "worker-a", "healthy": true, "available_slots": 2, "total_slots": 8}]}),
            vec!["[RCH] remote worker-a (cargo test passed)"],
            "admissible",
            true,
        ),
        (
            "pressure",
            json!({"workers": [{"id": "worker-b", "healthy": true, "available_slots": 0, "pressure": "critical_pressure=5"}]}),
            Vec::new(),
            "proof_infra_blocked",
            false,
        ),
        (
            "stale-binary",
            json!({"workers": [{"id": "worker-c", "healthy": true, "available_slots": 1, "status": "stale telemetry"}]}),
            Vec::new(),
            "degraded_stale_tooling",
            false,
        ),
        (
            "connection-failure",
            json!({"worker_selection": {"worker": null}, "error": "connection refused while probing worker pool"}),
            Vec::new(),
            "proof_infra_blocked",
            false,
        ),
        (
            "local-fallback",
            json!({"worker_selection": {"worker": null}, "no_admissible_workers": "critical_pressure=5"}),
            vec!["[RCH] local (no admissible workers: critical_pressure=5)"],
            "proof_infra_blocked",
            false,
        ),
        (
            "remote-required-local-fallback",
            json!({"worker_selection": {"worker": null}}),
            vec!["[RCH] remote required; refusing local fallback (no worker assigned)"],
            "proof_infra_blocked",
            false,
        ),
    ];

    for (fixture_id, telemetry, summary_lines, decision, allowed) in fixtures {
        let path = tempdir.path().join(format!("{fixture_id}.json"));
        write_json(&path, &telemetry);

        let mut args = vec![
            "--json",
            "proof",
            "rch-status",
            "--workers-json",
            path.to_str().expect("temp path is UTF-8"),
        ];
        for line in summary_lines {
            args.push("--summary-line");
            args.push(line);
        }

        let output = run_fwc(&args);
        assert!(
            output.status.success(),
            "fixture {fixture_id} should classify successfully:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let payload = stdout_json(&output);
        assert_eq!(payload["status"], "ok", "fixture {fixture_id}");
        assert_eq!(payload["subcommand"], "rch-status", "fixture {fixture_id}");
        assert_eq!(
            payload["capacity"]["decision"], decision,
            "fixture {fixture_id}"
        );
        assert_eq!(
            payload["capacity"]["remote_required_allowed"], allowed,
            "fixture {fixture_id}"
        );
    }
}

#[test]
fn proof_rch_status_cli_redacts_malformed_json_contents() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let path = tempdir.path().join("malformed.json");
    std::fs::write(&path, "{ not-json-token SECRET_VALUE").expect("malformed fixture writes");

    let output = run_fwc(&[
        "--json",
        "proof",
        "rch-status",
        "--workers-json",
        path.to_str().expect("temp path is UTF-8"),
    ]);

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let payload: Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["capacity"]["decision"], "telemetry_parse_error");
    assert_eq!(payload["capacity"]["remote_required_allowed"], false);
    assert!(!stdout.contains("SECRET_VALUE"));
}

#[test]
fn proof_run_cli_refuses_remote_execution_before_spawning_rch_when_capacity_is_queued() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let corpus_path = tempdir.path().join("proof-corpus.json");
    let workers_path = tempdir.path().join("workers.json");
    write_remote_required_corpus(&corpus_path);
    write_json(
        &workers_path,
        &json!({"workers": [{"id": "worker-a", "healthy": true, "available_slots": 0, "total_slots": 4}]}),
    );

    let output = run_fwc(&[
        "--json",
        "proof",
        "run",
        "claim:latency-proof",
        "--corpus",
        corpus_path.to_str().expect("temp path is UTF-8"),
        "--now-unix-ms",
        &NOW_MS.to_string(),
        "--execute",
        "--workers-json",
        workers_path.to_str().expect("temp path is UTF-8"),
    ]);

    assert!(!output.status.success());
    let payload = stdout_json(&output);
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["subcommand"], "run");
    assert_eq!(payload["plan"]["requires_remote"], true);
    assert_eq!(payload["capacity_preflight"]["decision"], "queued");
    assert_eq!(
        payload["capacity_preflight"]["remote_required_allowed"],
        false
    );
    assert!(payload["execution"].is_null());
    assert_eq!(
        payload["message"],
        "Remote-required proof execution refused by RCH capacity preflight."
    );
}

#[test]
fn proof_queue_cli_enqueues_statuses_and_drains_without_execution() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let queue_path = tempdir.path().join("proof-queue.json");
    let event_log_path = tempdir.path().join("events.jsonl");
    let workers_path = tempdir.path().join("workers.json");
    write_json(
        &workers_path,
        &json!({"workers": [{"id": "worker-a", "healthy": true, "available_slots": 1, "total_slots": 4}]}),
    );

    let enqueue = run_fwc(&[
        "--json",
        "proof",
        "enqueue",
        "--queue",
        queue_path.to_str().expect("queue path is UTF-8"),
        "--bead-id",
        "flywheel_connectors-angoc.6.3.2",
        "--lane",
        "crate-test",
        "--crate",
        "fwc",
        "--test-filter",
        "proof_queue",
        "--workers-json",
        workers_path.to_str().expect("workers path is UTF-8"),
        "--event-log",
        event_log_path.to_str().expect("event log path is UTF-8"),
    ]);
    assert!(
        enqueue.status.success(),
        "enqueue should succeed:\\n{}",
        String::from_utf8_lossy(&enqueue.stderr)
    );
    let enqueue_payload = stdout_json(&enqueue);
    assert_eq!(enqueue_payload["subcommand"], "enqueue");
    assert_eq!(enqueue_payload["job"]["state"], "active");
    assert_eq!(enqueue_payload["job"]["admission"]["decision"], "accepted");
    assert_eq!(enqueue_payload["job"]["target_dir_policy"], "isolated-temp");
    assert_eq!(
        enqueue_payload["job"]["environment"]["CARGO_INCREMENTAL"],
        "0"
    );
    let job_id = enqueue_payload["job"]["job_id"]
        .as_str()
        .expect("job id")
        .to_owned();

    let status = run_fwc(&[
        "--json",
        "proof",
        "queue",
        "--queue",
        queue_path.to_str().expect("queue path is UTF-8"),
    ]);
    assert!(status.status.success());
    let status_payload = stdout_json(&status);
    assert_eq!(status_payload["subcommand"], "queue");
    assert_eq!(status_payload["summary"]["pending_jobs"], 1);
    assert_eq!(status_payload["jobs"][0]["job"]["argv"][0], "cargo");

    let drain = run_fwc(&[
        "--json",
        "proof",
        "drain",
        "--queue",
        queue_path.to_str().expect("queue path is UTF-8"),
        "--cancel-job",
        &job_id,
        "--reason",
        "duplicate queued proof",
        "--event-log",
        event_log_path.to_str().expect("event log path is UTF-8"),
    ]);
    assert!(
        drain.status.success(),
        "drain should succeed:\\n{}",
        String::from_utf8_lossy(&drain.stderr)
    );
    let drain_payload = stdout_json(&drain);
    assert_eq!(drain_payload["summary"]["pending_jobs"], 0);
    assert_eq!(drain_payload["jobs"][0]["job"]["state"], "cancelled");
    let event_log = std::fs::read_to_string(event_log_path).expect("event log reads");
    let events = event_log.lines().collect::<Vec<_>>();
    assert_eq!(events.len(), 2);
    assert!(events[0].contains("\"event\":\"enqueue\""));
    assert!(events[1].contains("\"event\":\"cancel\""));
}
