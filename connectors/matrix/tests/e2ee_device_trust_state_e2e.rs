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
        "fcp-matrix-e2ee-device-trust-e2e-{}-{now}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create Matrix E2EE trust-state e2e log dir");
    let path = dir.join("matrix_e2ee_device_trust_state_e2e.jsonl");
    let file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .expect("open Matrix E2EE trust-state e2e log");
    (file, path)
}

fn log_step(logs: &mut File, step: &str, status: &str, details: &Value) {
    let record = json!({
        "step": step,
        "status": status,
        "details": details,
    });
    writeln!(logs, "{record}").expect("write Matrix E2EE trust-state e2e log line");
    logs.flush().expect("flush Matrix E2EE trust-state e2e log");
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

fn assert_no_scope_secrets(value: &Value) {
    let rendered = value.to_string();
    assert!(!rendered.contains("@bot:matrix.example.test"));
    assert!(!rendered.contains("@alice:matrix.example.test"));
    assert!(!rendered.contains("DEVICE123"));
    assert!(!rendered.contains("WRONGDEVICE"));
    assert!(!rendered.contains("batch_restore"));
}

#[fcp_async_core::runtime::test]
async fn e2ee_device_trust_state_logs_scope_readiness_denials_and_shutdown() {
    let (mut logs, log_path) = open_jsonl_log();
    println!(
        "matrix_e2ee_device_trust_state_e2e_log={}",
        log_path.display()
    );
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

    let mut fresh_store = MatrixConnector::new();
    fresh_store
        .configure(json!({
            "homeserver_url": "https://matrix.example.test",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.example.test",
                "device_id": "DEVICE123",
                "trust_state": {
                    "own_device": "present_unverified",
                    "device_keys": "missing",
                    "device_list": { "status": "missing" },
                    "cross_signing": "missing",
                    "tracked_users": [],
                    "tracked_rooms": []
                },
                "room_key_backup": { "status": "missing" }
            }
        }))
        .await
        .expect("configure fresh memory-only E2EE store");
    let fresh_doctor = fresh_store.doctor();
    let fresh_e2ee = e2ee_details(&fresh_doctor);
    assert_eq!(
        fresh_e2ee
            .pointer("/trust_state/store_scope/lifecycle")
            .and_then(Value::as_str),
        Some("memory_only_crypto_store")
    );
    assert_eq!(
        fresh_e2ee
            .pointer("/trust_state/readiness/trust_state_ready")
            .and_then(Value::as_bool),
        Some(false)
    );
    log_step(&mut logs, "fresh_store_bootstrap", "ok", fresh_e2ee);
    fresh_store
        .shutdown(shutdown_request("fresh-store-case-complete"))
        .await
        .expect("shutdown fresh store connector");
    log_step(&mut logs, "fresh_store_shutdown", "ok", &json!({}));

    let mut restored = MatrixConnector::new();
    restored
        .configure(json!({
            "homeserver_url": "https://matrix.example.test",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.example.test",
                "device_id": "DEVICE123",
                "trust_state": {
                    "own_device": "verified",
                    "device_keys": "verified",
                    "device_list": {
                        "status": "fresh",
                        "last_refresh_age_ms": 15
                    },
                    "cross_signing": "verified",
                    "tracked_users": ["@alice:matrix.example.test"],
                    "tracked_rooms": ["!secure:matrix.example.test"]
                },
                "recovery": { "status": "verified" },
                "room_key_backup": {
                    "status": "verified",
                    "backup_version": "1"
                }
            },
            "state_persistence": {
                "enabled": true,
                "backend": "host_managed_snapshot",
                "zone_id": "z:work",
                "account_user_id": "@bot:matrix.example.test",
                "device_id": "DEVICE123",
                "restore": {
                    "last_sync_token": "batch_restore",
                    "dynamic_direct_message_rooms": ["!secure:matrix.example.test"],
                    "thread_participation_roots": ["$thread-root"]
                }
            }
        }))
        .await
        .expect("configure restored matching E2EE scope");
    let restored_doctor = restored.doctor();
    let restored_e2ee = e2ee_details(&restored_doctor);
    assert_eq!(
        restored_e2ee
            .pointer("/trust_state/store_scope/account_matches_e2ee")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        restored_e2ee
            .pointer("/trust_state/store_scope/device_matches_e2ee")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        restored_e2ee
            .pointer("/trust_state/readiness/trust_state_ready")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        restored_e2ee
            .pointer("/trust_state/readiness/decrypted_delivery_enabled")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_no_scope_secrets(restored_e2ee);
    log_step(&mut logs, "restored_matching_scope", "ok", restored_e2ee);

    for (step, config_patch, expected) in [
        (
            "restored_wrong_account",
            json!({
                "account_user_id": "@other:matrix.example.test",
                "device_id": "DEVICE123"
            }),
            "state_persistence.account_user_id must match",
        ),
        (
            "restored_wrong_device",
            json!({
                "account_user_id": "@bot:matrix.example.test",
                "device_id": "WRONGDEVICE"
            }),
            "state_persistence.device_id must match",
        ),
    ] {
        let mut connector = MatrixConnector::new();
        let result = connector
            .configure(json!({
                "homeserver_url": "https://matrix.example.test",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "e2ee": {
                    "verified_decryption_requested": true,
                    "account_user_id": "@bot:matrix.example.test",
                    "device_id": "DEVICE123"
                },
                "state_persistence": {
                    "enabled": true,
                    "backend": "host_managed_snapshot",
                    "zone_id": "z:work",
                    "account_user_id": config_patch["account_user_id"],
                    "device_id": config_patch["device_id"]
                }
            }))
            .await;
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains(expected));
        log_step(
            &mut logs,
            step,
            "expected_error",
            &json!({
                "error_contains": expected,
                "error": error,
            }),
        );
    }

    let mut unverified = MatrixConnector::new();
    unverified
        .configure(json!({
            "homeserver_url": "https://matrix.example.test",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.example.test",
                "device_id": "DEVICE123",
                "trust_state": {
                    "own_device": "present_unverified",
                    "device_keys": "verified",
                    "device_list": { "status": "stale", "last_refresh_age_ms": 120_000 },
                    "cross_signing": "missing",
                    "tracked_users": ["@alice:matrix.example.test"],
                    "tracked_rooms": ["!secure:matrix.example.test"]
                },
                "room_key_backup": { "status": "verified" }
            }
        }))
        .await
        .expect("configure unverified trust state");
    let unverified_doctor = unverified.doctor();
    let unverified_e2ee = e2ee_details(&unverified_doctor);
    let reasons = unverified_e2ee
        .pointer("/trust_state/readiness/denial_reason_codes")
        .and_then(Value::as_array)
        .expect("denial reasons");
    assert!(
        reasons
            .iter()
            .any(|reason| reason == "own_device_unverified")
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason == "device_list_not_fresh")
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason == "cross_signing_unverified")
    );
    assert_no_scope_secrets(unverified_e2ee);
    log_step(
        &mut logs,
        "unverified_own_device_and_missing_cross_signing",
        "structured_skip",
        unverified_e2ee,
    );
    unverified
        .shutdown(shutdown_request("unverified-case-complete"))
        .await
        .expect("shutdown unverified connector");
    log_step(&mut logs, "unverified_shutdown", "ok", &json!({}));

    log_step(
        &mut logs,
        "verified_trust_state_readiness",
        "structured_skip",
        &json!({
            "trust_state_ready": true,
            "decrypted_delivery_enabled": false,
            "skip_reason": "matrix_e2ee_verified_crypto_unimplemented",
            "ciphertext_emitted": false,
            "decrypted_content_emitted": false,
        }),
    );
    restored
        .shutdown(shutdown_request("restored-case-complete"))
        .await
        .expect("shutdown restored connector");
    log_step(&mut logs, "restored_shutdown", "ok", &json!({}));
}
