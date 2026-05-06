use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_matrix::MatrixConnector;
use fcp_sdk::prelude::*;
use serde_json::{Value, json};

fn open_jsonl_log() -> (File, PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fcp-matrix-e2ee-status-e2e-{}-{now}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create Matrix E2EE e2e log dir");
    let path = dir.join("matrix_e2ee_status_e2e.jsonl");
    let file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .expect("open Matrix E2EE e2e log");
    (file, path)
}

fn log_step(logs: &mut File, step: &str, status: &str, details: &Value) {
    let record = json!({
        "step": step,
        "status": status,
        "details": details,
    });
    writeln!(logs, "{record}").expect("write Matrix E2EE e2e log line");
    logs.flush().expect("flush Matrix E2EE e2e log");
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        })
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unavailable".into())
}

fn shutdown_request(reason: &str) -> ShutdownRequest {
    ShutdownRequest {
        r#type: "shutdown".into(),
        deadline_ms: 1_000,
        drain: true,
        reason: Some(reason.into()),
    }
}

fn e2ee_details(doctor: &Value) -> &Value {
    doctor
        .pointer("/details/e2ee")
        .expect("doctor includes E2EE details")
}

#[fcp_async_core::runtime::test]
async fn e2ee_status_structured_skip_logs_requested_crypto_gap_and_shutdown() {
    let (mut logs, log_path) = open_jsonl_log();
    println!("matrix_e2ee_status_e2e_log={}", log_path.display());
    log_step(
        &mut logs,
        "log_start",
        "ok",
        &json!({
            "path": log_path.display().to_string(),
            "command_line": std::env::args().collect::<Vec<_>>(),
            "git_revision": git_revision(),
            "feature_flags": {
                "matrix_sdk_crypto_backend": cfg!(feature = "matrix-sdk-crypto-backend"),
            },
        }),
    );

    let mut default_connector = MatrixConnector::new();
    default_connector
        .configure(json!({
            "homeserver_url": "https://matrix.example.test",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .expect("configure default E2EE connector");
    let default_doctor = default_connector.doctor();
    let default_e2ee = e2ee_details(&default_doctor);
    assert_eq!(
        default_e2ee
            .get("decryption_status")
            .and_then(Value::as_str),
        Some("not_requested")
    );
    assert_eq!(
        default_e2ee
            .get("encrypted_event_delivery_policy")
            .and_then(Value::as_str),
        Some("fail_closed")
    );
    assert_eq!(
        default_e2ee
            .pointer("/crypto_backend/dependency")
            .and_then(Value::as_str),
        Some("matrix-sdk-crypto")
    );
    assert_eq!(
        default_e2ee
            .pointer("/crypto_backend/network_io_model")
            .and_then(Value::as_str),
        Some(fcp_matrix::crypto::MATRIX_CRYPTO_NETWORK_IO_MODEL)
    );
    log_step(
        &mut logs,
        "encryption_default_fail_closed",
        "ok",
        default_e2ee,
    );
    default_connector
        .shutdown(shutdown_request("e2ee-default-case-complete"))
        .await
        .expect("shutdown default E2EE connector");
    log_step(&mut logs, "default_shutdown", "ok", &json!({}));

    let mut metadata_connector = MatrixConnector::new();
    metadata_connector
        .configure(json!({
            "homeserver_url": "https://matrix.example.test",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "inbound_policy": {
                "encrypted_events": "metadata_only"
            },
            "e2ee": {
                "recovery": { "status": "missing" },
                "room_key_backup": { "status": "unknown" },
                "undecrypted_retry": {
                    "max_attempts": 0,
                    "retry_after_ms": 1000
                }
            }
        }))
        .await
        .expect("configure metadata-only E2EE connector");
    let metadata_doctor = metadata_connector.doctor();
    let metadata_e2ee = e2ee_details(&metadata_doctor);
    assert_eq!(
        metadata_e2ee
            .get("encrypted_event_delivery_policy")
            .and_then(Value::as_str),
        Some("metadata_only")
    );
    assert_eq!(
        metadata_e2ee
            .pointer("/undecrypted_retry/classification")
            .and_then(Value::as_str),
        Some("final_failure")
    );
    log_step(&mut logs, "metadata_only_projection", "ok", metadata_e2ee);
    metadata_connector
        .shutdown(shutdown_request("e2ee-metadata-case-complete"))
        .await
        .expect("shutdown metadata E2EE connector");
    log_step(&mut logs, "metadata_shutdown", "ok", &json!({}));

    let mut requested_connector = MatrixConnector::new();
    requested_connector
        .configure(json!({
            "homeserver_url": "https://matrix.example.test",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.example.test",
                "device_id": "DEVICE123",
                "recovery": { "status": "present_unverified" },
                "room_key_backup": {
                    "status": "missing",
                    "backup_version": "1"
                },
                "undecrypted_retry": {
                    "max_attempts": 2,
                    "retry_after_ms": 500
                }
            }
        }))
        .await
        .expect("configure requested E2EE connector");

    let requested_doctor = requested_connector.doctor();
    let requested_e2ee = e2ee_details(&requested_doctor);
    assert_eq!(
        requested_e2ee
            .get("decryption_status")
            .and_then(Value::as_str),
        Some("denied_unavailable")
    );
    assert_eq!(
        requested_e2ee
            .pointer("/structured_skip/reason_code")
            .and_then(Value::as_str),
        Some("matrix_e2ee_verified_crypto_unimplemented")
    );
    assert_eq!(
        requested_e2ee
            .pointer("/crypto_backend/dependency_version")
            .and_then(Value::as_str),
        Some(fcp_matrix::crypto::MATRIX_SDK_CRYPTO_VERSION)
    );
    assert_eq!(
        requested_e2ee
            .pointer("/crypto_backend/outgoing_requests/total_pending")
            .and_then(Value::as_u64),
        Some(0)
    );
    log_step(
        &mut logs,
        "requested_verified_decryption_denied",
        "ok",
        requested_e2ee,
    );
    log_step(
        &mut logs,
        "crypto_backend_boundary",
        "structured_skip",
        requested_e2ee
            .get("crypto_backend")
            .expect("E2EE details include crypto backend boundary"),
    );

    let health = requested_connector.health().await;
    assert!(matches!(
        health.status,
        HealthState::Degraded { ref reason }
            if reason == "verified Matrix E2EE decryption requested but unavailable"
    ));
    log_step(
        &mut logs,
        "requested_health",
        "ok",
        &json!({
            "status": format!("{:?}", health.status),
            "details": health.details,
        }),
    );

    let self_check = requested_connector.self_check().await.expect("self_check");
    assert_eq!(self_check.status, SelfCheckStatus::Failed);
    assert_eq!(
        self_check.reason_code.as_deref(),
        Some("e2ee_verified_decryption_unavailable")
    );
    log_step(
        &mut logs,
        "requested_self_check",
        "ok",
        &json!({
            "status": format!("{:?}", self_check.status),
            "reason_code": self_check.reason_code,
            "message": self_check.message,
            "details": self_check.details,
        }),
    );

    for skipped_case in [
        "verified_decrypt_success",
        "wrong_device_trust_failure",
        "wrong_room_key_failure",
        "backup_mismatch_failure",
        "encrypted_media_decrypt_success",
    ] {
        log_step(
            &mut logs,
            skipped_case,
            "structured_skip",
            &json!({
                "reason_code": "matrix_e2ee_verified_crypto_unimplemented",
                "ciphertext_emitted": false,
                "decrypted_content_emitted": false,
            }),
        );
    }

    requested_connector
        .shutdown(shutdown_request("e2ee-requested-case-complete"))
        .await
        .expect("shutdown requested E2EE connector");
    log_step(&mut logs, "requested_shutdown", "ok", &json!({}));
}
