#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    io::Write,
    process::{Command, Stdio},
    time::Instant,
};

use fcp_prelude::FcpError;
use fcp_tlon::TlonConnector;
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.tlon";
const BEAD_ID: &str = "flywheel_connectors-4kw5f.11.13";
const SKIP_REASON: &str = "invoke_surface_unimplemented";
const DM_OPERATION: &str = "tlon.dm.send";
const CHANNEL_OPERATION: &str = "tlon.channel.send";
const RESOLVE_OPERATION: &str = "tlon.target.resolve";
const SHIP_FIXTURE: &str = "~zod";
const CHANNEL_FIXTURE: &str = "/ship/~zod/general";
const MESSAGE_FIXTURE: &str = "body text that must stay out of evidence";

#[derive(Clone, Copy)]
struct Evidence<'a> {
    test: &'a str,
    operation_id: &'a str,
    capability: &'a str,
    fixture_id: &'a str,
    lifecycle_phase: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    cleanup_result: &'a str,
    skip_reason: Option<&'a str>,
}

fn stable_hash(kind: &str, raw: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in kind.bytes().chain(*b":").chain(raw.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{kind}:{hash:016x}")
}

fn test_command_line() -> String {
    std::env::var("FCP_TEST_COMMAND_LINE")
        .unwrap_or_else(|_| "cargo test -p fcp-tlon --tests -- --nocapture".to_owned())
}

fn git_revision() -> String {
    std::env::var("FCP_TEST_GIT_REVISION").unwrap_or_else(|_| "unknown".to_owned())
}

fn evidence_json(evidence: Evidence<'_>) -> Value {
    json!({
        "schema_version": "1",
        "bead_id": BEAD_ID,
        "test": evidence.test,
        "command_line": test_command_line(),
        "git_revision": git_revision(),
        "connector_id": CONNECTOR_ID,
        "operation_id": evidence.operation_id,
        "capability": evidence.capability,
        "zone": "z:community",
        "instance_id": "planned-only",
        "fixture_id": evidence.fixture_id,
        "ship_hash": stable_hash("ship", SHIP_FIXTURE),
        "group_channel_id_hash": stable_hash("channel", CHANNEL_FIXTURE),
        "lifecycle_phase": evidence.lifecycle_phase,
        "latency_ms": evidence.latency_ms,
        "result": evidence.result,
        "error_code": evidence.error_code,
        "audit_receipt_id": stable_hash("audit", evidence.fixture_id),
        "cleanup_result": evidence.cleanup_result,
        "skip_reason": evidence.skip_reason,
    })
}

fn assert_redacted(serialized: &str) {
    for forbidden in [
        SHIP_FIXTURE,
        CHANNEL_FIXTURE,
        MESSAGE_FIXTURE,
        "/Users/",
        "/private/",
        "provider response body",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "sensitive fixture value leaked in Tlon evidence: {forbidden}"
        );
    }
}

fn emit_redacted_evidence(evidence: Evidence<'_>) {
    let serialized = evidence_json(evidence).to_string();
    assert_redacted(&serialized);
    eprintln!("{serialized}");
}

async fn configured_connector() -> TlonConnector {
    let mut connector = TlonConnector::new();
    connector
        .handle_configure(json!({
            "base_url": "https://fixture.tlon.example",
            "auth_ref": "fixture-auth-ref"
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:community"
        }))
        .await
        .expect("handshake should succeed");
    connector
}

fn assert_invalid_request(error: FcpError, expected_code: u16, expected_text: &str) {
    assert!(
        matches!(&error, FcpError::InvalidRequest { .. }),
        "expected InvalidRequest, got {error:?}"
    );
    let FcpError::InvalidRequest { code, message } = error else {
        return;
    };
    assert_eq!(code, expected_code);
    assert!(
        message.contains(expected_text),
        "expected `{message}` to contain `{expected_text}`"
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_and_shutdown_emit_redacted_jsonl() {
    let started = Instant::now();
    let mut connector = TlonConnector::new();

    let health = connector
        .handle_health()
        .await
        .expect("health before configure should succeed");
    assert_eq!(health["status"], "unconfigured");

    connector
        .handle_configure(json!({"base_url": "https://fixture.tlon.example"}))
        .await
        .expect("configure should succeed");
    let handshake = connector
        .handle_handshake(json!({"protocol_version": "2.0", "zone": "z:community"}))
        .await
        .expect("handshake should succeed");
    assert_eq!(handshake["surface_status"], "incubating");
    assert_eq!(
        handshake["planned_capabilities"],
        json!(["tlon.dm", "tlon.channel"])
    );

    let health = connector
        .handle_health()
        .await
        .expect("health after handshake should succeed");
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["live_requests_supported"], false);

    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");
    assert_eq!(doctor["status"], "degraded");
    assert_eq!(doctor["checks"][2]["passed"], false);

    let self_check = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed");
    assert_eq!(self_check["status"], "unsupported");
    assert_eq!(self_check["reason_code"], SKIP_REASON);

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    let health = connector
        .handle_health()
        .await
        .expect("health after shutdown should succeed");
    assert_eq!(health["status"], "unconfigured");

    emit_redacted_evidence(Evidence {
        test: "lifecycle_and_shutdown_emit_redacted_jsonl",
        operation_id: "lifecycle",
        capability: "tlon.lifecycle",
        fixture_id: "tlon-planned-only-lifecycle",
        lifecycle_phase: "shutdown",
        latency_ms: started.elapsed().as_millis(),
        result: "pass",
        error_code: None,
        cleanup_result: "shutdown_accepted",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn planned_urbit_fixture_paths_emit_skipped_jsonl_without_live_credentials() {
    let connector = configured_connector().await;

    for (operation_id, capability, input) in [
        (
            DM_OPERATION,
            "tlon.dm",
            json!({"ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE}),
        ),
        (
            CHANNEL_OPERATION,
            "tlon.channel",
            json!({"channel": CHANNEL_FIXTURE, "message": MESSAGE_FIXTURE}),
        ),
        (
            RESOLVE_OPERATION,
            "tlon.channel",
            json!({"target": CHANNEL_FIXTURE}),
        ),
    ] {
        let started = Instant::now();
        let error = connector
            .handle_invoke(json!({
                "operation_id": operation_id,
                "input": input
            }))
            .await
            .expect_err("planned operation should refuse execution");
        assert_invalid_request(error, 1002, "planned but not implemented");

        let simulate = connector
            .handle_simulate(json!({"operation_id": operation_id}))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], false);
        assert_eq!(simulate["simulate_capability"], "unsupported");
        assert_eq!(
            simulate["reason"],
            "This connector scaffold only declares planned operations. Live invoke support is not implemented yet."
        );

        emit_redacted_evidence(Evidence {
            test: "planned_urbit_fixture_paths_emit_skipped_jsonl_without_live_credentials",
            operation_id,
            capability,
            fixture_id: "tlon-urbit-no-live-credential-fixture",
            lifecycle_phase: "invoke",
            latency_ms: started.elapsed().as_millis(),
            result: "skipped",
            error_code: Some(SKIP_REASON),
            cleanup_result: "no_provider_socket_opened",
            skip_reason: Some(SKIP_REASON),
        });
    }
}

#[fcp_async_core::runtime::test]
async fn malformed_unknown_and_pre_handshake_requests_are_denied() {
    let unready = TlonConnector::new();
    let not_configured = unready
        .handle_invoke(json!({"operation_id": DM_OPERATION}))
        .await
        .expect_err("invoke before configure should fail readiness");
    assert!(matches!(not_configured, FcpError::NotConfigured));

    let connector = configured_connector().await;

    let missing_operation = connector
        .handle_invoke(json!({"input": {"ship": SHIP_FIXTURE}}))
        .await
        .expect_err("missing operation id should be rejected");
    assert_invalid_request(missing_operation, 1003, "Missing operation_id");

    let unknown_operation = connector
        .handle_invoke(json!({"operation_id": "tlon.unexpected.operation"}))
        .await
        .expect_err("unknown operation should be rejected");
    assert_invalid_request(unknown_operation, 1002, "Unknown operation");

    let simulate = connector
        .handle_simulate(json!({"operation_id": "tlon.unexpected.operation"}))
        .await
        .expect("simulate should succeed");
    assert_eq!(simulate["allowed"], false);
    assert_eq!(simulate["reason"], "Unknown operation.");

    emit_redacted_evidence(Evidence {
        test: "malformed_unknown_and_pre_handshake_requests_are_denied",
        operation_id: "tlon.unexpected.operation",
        capability: "tlon.none",
        fixture_id: "tlon-denial-fixture",
        lifecycle_phase: "invoke",
        latency_ms: 0,
        result: "denied",
        error_code: Some("invalid_request"),
        cleanup_result: "no_provider_socket_opened",
        skip_reason: None,
    });
}

#[test]
fn jsonrpc_process_handles_invalid_json_lifecycle_and_shutdown() {
    let executable =
        std::env::var("CARGO_BIN_EXE_fcp-tlon").expect("cargo should expose fcp-tlon test binary");
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fcp-tlon process");

    {
        let mut stdin = child.stdin.take().expect("child stdin should be piped");
        writeln!(stdin, "{{not-json").expect("write invalid JSON request");
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 1, "method": "configure", "params": {}})
        )
        .expect("write configure request");
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 2, "method": "handshake", "params": {}})
        )
        .expect("write handshake request");
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}})
        )
        .expect("write shutdown request");
    }

    let output = child
        .wait_with_output()
        .expect("fcp-tlon process should exit after stdin closes");
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_redacted(&stdout);
    let responses = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("response should be JSON"))
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 4);
    assert_eq!(responses[0]["error"]["code"], "FCP-1001");
    assert_eq!(responses[1]["id"], 1);
    assert_eq!(responses[1]["result"]["configured"], true);
    assert_eq!(responses[2]["id"], 2);
    assert_eq!(responses[2]["result"]["surface_status"], "incubating");
    assert_eq!(responses[3]["id"], 3);
    assert_eq!(responses[3]["result"], json!({}));

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert_redacted(&stderr);
}
