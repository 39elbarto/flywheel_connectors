//! CLI coverage for `fwc capability replay`.

use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_audit::{AuditEntry, AuditEntryBuilder, event_types};
use serde_json::{Value, json};

const TOKEN: &str = "cap-token-secret";

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn audit_entry(seq: u64, metadata: Vec<(&str, Value)>) -> AuditEntry {
    metadata
        .into_iter()
        .fold(
            AuditEntryBuilder::new()
                .id(format!("entry-{seq}"))
                .event_type(event_types::CAPABILITY_INVOKE)
                .actor("user:alice")
                .zone_id("z:work")
                .seq(seq)
                .occurred_at(current_unix_seconds().saturating_sub(60)),
            |builder, (key, value)| builder.meta(key, value),
        )
        .build()
        .expect("audit entry builds")
}

fn write_audit_chain(path: &Path) {
    let entries = vec![audit_entry(
        12_034,
        vec![
            ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
            ("rule_name", json!("zone_match")),
            (
                "inputs_json",
                json!({"src_zone": "z:work", "bearer": format!("Bearer {TOKEN}")}),
            ),
            ("output", json!(true)),
            ("latency_us", json!(45)),
            ("evaluator_version", json!("1.2.0")),
        ],
    )];
    std::fs::write(
        path,
        serde_json::to_vec(&entries).expect("audit chain serializes"),
    )
    .expect("audit chain writes");
}

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

#[test]
fn capability_replay_cli_returns_json_trace_without_raw_token() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let audit_path = tempdir.path().join("audit-chain.json");
    write_audit_chain(&audit_path);

    let output = run_fwc(&[
        "--json",
        "capability",
        "replay",
        TOKEN,
        "--audit-chain",
        audit_path.to_str().expect("temp path is UTF-8"),
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let payload: Value = serde_json::from_str(&stdout).expect("stdout is JSON");

    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["trace"][0]["rule_name"], "zone_match");
    assert!(!stdout.contains(TOKEN));
    assert!(stdout.contains("<redacted>"));
}

#[test]
fn capability_replay_cli_maps_not_found_and_wide_window_exit_codes() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let audit_path = tempdir.path().join("audit-chain.json");
    write_audit_chain(&audit_path);
    let audit_path = audit_path.to_str().expect("temp path is UTF-8");

    let not_found = run_fwc(&[
        "--json",
        "capability",
        "replay",
        "other-token",
        "--audit-chain",
        audit_path,
    ]);
    assert_eq!(not_found.status.code(), Some(3));
    let payload = stdout_json(&not_found);
    assert_eq!(payload["error"]["type"], "TokenNotFoundInAuditChain");
    assert!(!String::from_utf8_lossy(&not_found.stdout).contains("other-token"));

    let wide_window = run_fwc(&[
        "--json",
        "capability",
        "replay",
        TOKEN,
        "--audit-chain",
        audit_path,
        "--since",
        "8d",
    ]);
    assert_eq!(wide_window.status.code(), Some(2));
    let payload = stdout_json(&wide_window);
    assert_eq!(payload["error"]["type"], "wide-window-requires-confirm");
}
