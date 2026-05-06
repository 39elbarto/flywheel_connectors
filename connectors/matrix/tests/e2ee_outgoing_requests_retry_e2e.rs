use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fcp_matrix::client::MatrixClient;
use fcp_matrix::crypto::{
    MatrixCryptoEngine, MatrixCryptoMaintenanceOutcome, MatrixCryptoOutgoingRequestKind,
    classify_outgoing_request_failure, key_share_after_initial_sync_snapshot,
    mark_outgoing_request_sent, recovery_guidance_snapshot, room_key_backup_version_decision,
    stale_room_key_decision_snapshot, undecrypted_retry_decision_snapshot,
};
use fcp_matrix::error::MatrixError;
use fcp_matrix::types::{
    MatrixDeviceKeysClaimRequest, MatrixE2eeBackupConfig, MatrixE2eeConfig,
    MatrixE2eeDeviceListConfig, MatrixE2eeDeviceListStatus, MatrixE2eeMaterialStatus,
    MatrixE2eeRecoveryConfig, MatrixE2eeTrustStateConfig, MatrixUndecryptedRetryConfig,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
struct Fixture {
    method: &'static str,
    path: &'static str,
    status: u16,
    body: Value,
}

#[derive(Debug, Clone)]
struct ObservedRequest {
    method: String,
    path: String,
    body_len: usize,
    body_sha256: String,
}

fn open_jsonl_log() -> (File, PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fcp-matrix-e2ee-outgoing-requests-e2e-{}-{now}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create Matrix E2EE outgoing e2e log dir");
    let path = dir.join("matrix_e2ee_outgoing_requests_retry_e2e.jsonl");
    let file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .expect("open Matrix E2EE outgoing e2e log");
    (file, path)
}

fn log_step(logs: &mut File, step: &str, status: &str, details: &Value) {
    let record = json!({
        "step": step,
        "status": status,
        "details": details,
    });
    writeln!(logs, "{record}").expect("write Matrix E2EE outgoing e2e log line");
    logs.flush().expect("flush Matrix E2EE outgoing e2e log");
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

fn body_hash(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_http_request(stream: &mut TcpStream) -> ObservedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set loopback read timeout");
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read loopback request");
        assert!(read > 0, "client closed before headers");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = find_header_end(&buffer) {
            break header_end;
        }
    };
    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().expect("request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().expect("request method").to_string();
    let path = parts.next().expect("request path").to_string();
    let content_len = lines
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_len {
        let read = stream.read(&mut chunk).expect("read loopback request body");
        assert!(read > 0, "client closed before body");
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = &buffer[body_start..body_start + content_len];
    ObservedRequest {
        method,
        path,
        body_len: body.len(),
        body_sha256: body_hash(body),
    }
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &Value) {
    let body = body.to_string();
    let reason = if (200..300).contains(&status) {
        "OK"
    } else {
        "ERROR"
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write loopback response");
}

fn start_loopback_server(
    fixtures: Vec<Fixture>,
) -> (String, thread::JoinHandle<Vec<ObservedRequest>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback Matrix fixture server");
    let addr = listener.local_addr().expect("read loopback addr");
    let handle = thread::spawn(move || {
        let mut observed = Vec::new();
        for fixture in fixtures {
            let (mut stream, _) = listener.accept().expect("accept loopback request");
            let request = read_http_request(&mut stream);
            assert_eq!(request.method, fixture.method, "method mismatch");
            assert_eq!(request.path, fixture.path, "path mismatch");
            write_http_response(&mut stream, fixture.status, &fixture.body);
            observed.push(request);
        }
        observed
    });
    (format!("http://{addr}"), handle)
}

fn observed_requests_json(requests: &[ObservedRequest]) -> Value {
    json!(
        requests
            .iter()
            .map(|request| {
                json!({
                    "method": request.method,
                    "path": request.path,
                    "body_len": request.body_len,
                    "body_sha256": request.body_sha256,
                })
            })
            .collect::<Vec<_>>()
    )
}

#[allow(clippy::too_many_lines)]
#[fcp_async_core::runtime::test]
async fn e2ee_outgoing_requests_retry_driver_logs_loopback_sequence_and_denials() {
    let (mut logs, log_path) = open_jsonl_log();
    println!(
        "matrix_e2ee_outgoing_requests_retry_e2e_log={}",
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

    let fixtures = vec![
        Fixture {
            method: "POST",
            path: "/_matrix/client/v3/keys/upload",
            status: 200,
            body: json!({ "one_time_key_counts": { "signed_curve25519": 1 } }),
        },
        Fixture {
            method: "POST",
            path: "/_matrix/client/v3/keys/query",
            status: 200,
            body: json!({
                "device_keys": {},
                "master_keys": {},
                "self_signing_keys": {},
                "user_signing_keys": {},
                "failures": {}
            }),
        },
        Fixture {
            method: "POST",
            path: "/_matrix/client/v3/keys/claim",
            status: 200,
            body: json!({ "one_time_keys": {}, "failures": {} }),
        },
        Fixture {
            method: "PUT",
            path: "/_matrix/client/v3/sendToDevice/m.room.encrypted/txn-e2ee-1",
            status: 200,
            body: json!({}),
        },
        Fixture {
            method: "GET",
            path: "/_matrix/client/v3/room_keys/version",
            status: 200,
            body: json!({
                "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
                "auth_data": {},
                "count": "0",
                "etag": "etag-1",
                "version": "1"
            }),
        },
        Fixture {
            method: "PUT",
            path: "/_matrix/client/v3/room_keys/keys?version=1",
            status: 200,
            body: json!({ "count": "1", "etag": "etag-2" }),
        },
        Fixture {
            method: "DELETE",
            path: "/_matrix/client/v3/room_keys/keys/%21room%3Amatrix.example/session-1?version=1",
            status: 200,
            body: json!({}),
        },
    ];
    let (homeserver, server) = start_loopback_server(fixtures);
    let client = MatrixClient::new(&homeserver, "tok", Duration::from_secs(10))
        .expect("create Matrix loopback client");

    let upload = client
        .upload_device_keys(&json!({
            "device_keys": {
                "user_id": "@bot:matrix.example",
                "device_id": "DEVICE123"
            },
            "one_time_keys": {}
        }))
        .await
        .expect("upload device keys");
    let query = client
        .query_device_keys(&fcp_matrix::types::MatrixDeviceKeysQueryRequest {
            device_keys: BTreeMap::from([("@bot:matrix.example".to_string(), vec![])]),
            timeout: Some(5000),
            token: Some("sync-token".into()),
        })
        .await
        .expect("query device keys");
    let claim = client
        .claim_one_time_keys(&MatrixDeviceKeysClaimRequest {
            one_time_keys: BTreeMap::from([(
                "@alice:matrix.example".to_string(),
                BTreeMap::from([("ALICEDEVICE".to_string(), "signed_curve25519".to_string())]),
            )]),
            timeout: Some(5000),
        })
        .await
        .expect("claim one-time keys");
    let to_device = client
        .send_to_device(
            "m.room.encrypted",
            "txn-e2ee-1",
            &json!({
                "messages": {
                    "@alice:matrix.example": {
                        "ALICEDEVICE": {
                            "algorithm": "m.olm.v1.curve25519-aes-sha2"
                        }
                    }
                }
            }),
        )
        .await
        .expect("send to-device key request");
    let backup = client
        .room_key_backup_version()
        .await
        .expect("get room-key backup version");
    let backup_upload = client
        .upload_room_keys("1", &json!({ "rooms": {} }))
        .await
        .expect("upload room keys");
    let backup_delete = client
        .delete_room_key("1", "!room:matrix.example", "session-1")
        .await
        .expect("delete stale room key");

    assert_eq!(
        upload.one_time_key_counts.get("signed_curve25519"),
        Some(&1)
    );
    assert!(query.failures.is_empty());
    assert!(claim.one_time_keys.is_empty());
    assert_eq!(to_device, json!({}));
    assert_eq!(backup.version.as_deref(), Some("1"));
    assert_eq!(backup_upload.etag.as_deref(), Some("etag-2"));
    assert_eq!(backup_delete, json!({}));

    let observed = server
        .join()
        .expect("Matrix loopback fixture server panicked");
    assert_eq!(observed.len(), 7);
    log_step(
        &mut logs,
        "loopback_request_sequence",
        "ok",
        &json!({
            "request_count": observed.len(),
            "requests": observed_requests_json(&observed),
            "body_policy": "hash_and_length_only",
        }),
    );

    let retry_config = MatrixUndecryptedRetryConfig {
        max_attempts: 2,
        retry_after_ms: 500,
    };
    let sent = mark_outgoing_request_sent(MatrixCryptoOutgoingRequestKind::DeviceKeysUpload);
    let retry = classify_outgoing_request_failure(
        MatrixCryptoOutgoingRequestKind::ToDevice,
        &MatrixError::RateLimited {
            retry_after_ms: 250,
        },
        1,
        &retry_config,
    );
    let final_failure = classify_outgoing_request_failure(
        MatrixCryptoOutgoingRequestKind::ToDevice,
        &MatrixError::Runtime("temporary crypto queue flush failure".into()),
        2,
        &retry_config,
    );
    let auth_failure = classify_outgoing_request_failure(
        MatrixCryptoOutgoingRequestKind::DeviceKeysQuery,
        &MatrixError::Unauthorized("expired token".into()),
        1,
        &retry_config,
    );
    assert_eq!(sent.outcome, MatrixCryptoMaintenanceOutcome::Sent);
    assert_eq!(
        retry.outcome,
        MatrixCryptoMaintenanceOutcome::RetryScheduled
    );
    assert_eq!(
        final_failure.outcome,
        MatrixCryptoMaintenanceOutcome::FinalFailure
    );
    assert_eq!(auth_failure.outcome, MatrixCryptoMaintenanceOutcome::Denied);
    log_step(
        &mut logs,
        "retry_and_final_failure_decisions",
        "ok",
        &json!({
            "sent": sent.snapshot(),
            "retry": retry.snapshot(),
            "final_failure": final_failure.snapshot(),
            "auth_failure": auth_failure.snapshot(),
        }),
    );

    let backup_mismatch = room_key_backup_version_decision(
        true,
        Some("SECRET_EXPECTED_BACKUP"),
        backup.version.as_deref(),
    );
    assert_eq!(
        backup_mismatch.outcome,
        MatrixCryptoMaintenanceOutcome::Denied
    );
    let stale_reupload = stale_room_key_decision_snapshot(true, false);
    let stale_delete = stale_room_key_decision_snapshot(true, true);
    log_step(
        &mut logs,
        "backup_mismatch_and_stale_key_paths",
        "ok",
        &json!({
            "backup_mismatch": backup_mismatch.snapshot(),
            "stale_reupload": stale_reupload,
            "stale_delete": stale_delete,
        }),
    );

    let key_share_blocked = key_share_after_initial_sync_snapshot(false, 1);
    let key_share_allowed = key_share_after_initial_sync_snapshot(true, 1);
    assert_eq!(key_share_blocked["allowed"].as_bool(), Some(false));
    assert_eq!(key_share_allowed["allowed"].as_bool(), Some(true));
    log_step(
        &mut logs,
        "key_share_after_initial_sync_gating",
        "ok",
        &json!({
            "blocked": key_share_blocked,
            "allowed": key_share_allowed,
        }),
    );

    let e2ee = MatrixE2eeConfig {
        verified_decryption_requested: true,
        account_user_id: Some("@bot:matrix.example".into()),
        device_id: Some("SECRET_DEVICE_ID".into()),
        trust_state: MatrixE2eeTrustStateConfig {
            device_list: MatrixE2eeDeviceListConfig {
                status: MatrixE2eeDeviceListStatus::Stale,
                last_refresh_age_ms: Some(120_000),
            },
            cross_signing: MatrixE2eeMaterialStatus::Missing,
            tracked_rooms: vec!["!room:matrix.example".into()],
            ..MatrixE2eeTrustStateConfig::default()
        },
        recovery: MatrixE2eeRecoveryConfig {
            status: MatrixE2eeMaterialStatus::Missing,
        },
        room_key_backup: MatrixE2eeBackupConfig {
            status: MatrixE2eeMaterialStatus::PresentUnverified,
            backup_version: Some("SECRET_BACKUP_VERSION".into()),
        },
        undecrypted_retry: retry_config.clone(),
        ..MatrixE2eeConfig::default()
    };
    let guidance = recovery_guidance_snapshot(&e2ee);
    let undecrypted_retry = undecrypted_retry_decision_snapshot(
        Some("$SECRET_EVENT"),
        "!room:matrix.example",
        2,
        &retry_config,
    );
    let structured_skip = MatrixCryptoEngine::new().status_snapshot(&e2ee);
    let combined = json!({
        "guidance": guidance,
        "undecrypted_retry": undecrypted_retry,
        "structured_skip": structured_skip,
        "decrypted_delivery_enabled": false,
    });
    let combined_text = combined.to_string();
    assert!(!combined_text.contains("SECRET_DEVICE_ID"));
    assert!(!combined_text.contains("SECRET_BACKUP_VERSION"));
    assert!(!combined_text.contains("$SECRET_EVENT"));
    log_step(
        &mut logs,
        "recovery_guidance_and_structured_skip",
        "structured_skip",
        &combined,
    );
    log_step(
        &mut logs,
        "shutdown",
        "ok",
        &json!({
            "loopback_server_joined": true,
            "ciphertext_emitted": false,
            "decrypted_content_emitted": false,
        }),
    );
}
