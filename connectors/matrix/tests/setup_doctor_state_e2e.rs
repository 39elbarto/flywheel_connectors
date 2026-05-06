use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fcp_matrix::MatrixConnector;
use fcp_sdk::prelude::*;
use serde_json::{Value, json};

struct SetupDoctorLoopbackServer {
    uri: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SetupDoctorLoopbackServer {
    fn start(logs: &Arc<Mutex<File>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind setup doctor Matrix server");
        listener
            .set_nonblocking(true)
            .expect("configure nonblocking listener");
        let uri = format!(
            "http://{}",
            listener.local_addr().expect("read listener address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let thread_logs = Arc::clone(logs);
        let handle = thread::spawn(move || {
            loopback_server_loop(&listener, &thread_stop, &thread_requests, &thread_logs);
        });
        log_step(
            logs,
            "server_start",
            "ok",
            &json!({ "uri": uri, "mode": "raw_tcp_matrix_setup_doctor_loopback" }),
        );
        Self {
            uri,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn uri(&self) -> &str {
        &self.uri
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("request log lock").clone()
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("join Matrix setup doctor server");
        }
    }
}

impl Drop for SetupDoctorLoopbackServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn loopback_server_loop(
    listener: &TcpListener,
    stop: &Arc<AtomicBool>,
    requests: &Arc<Mutex<Vec<Value>>>,
    logs: &Arc<Mutex<File>>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _peer)) => handle_connection(&mut stream, requests, logs),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                log_step(
                    logs,
                    "server_accept",
                    "error",
                    &json!({ "error": error.to_string() }),
                );
                break;
            }
        }
    }
    log_step(logs, "server_stop", "ok", &json!({}));
}

fn handle_connection(
    stream: &mut TcpStream,
    requests: &Arc<Mutex<Vec<Value>>>,
    logs: &Arc<Mutex<File>>,
) {
    let request = match read_request(stream) {
        Ok(request) => request,
        Err(error) => {
            log_step(
                logs,
                "server_read",
                "error",
                &json!({ "error": error.to_string() }),
            );
            return;
        }
    };
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let authorization = request
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .map(redact_authorization);
    let record = json!({
        "request_line": request_line,
        "path": path,
        "authorization_header": authorization,
    });
    requests
        .lock()
        .expect("request log lock")
        .push(record.clone());
    log_step(logs, "server_request", "ok", &record);

    if path == "/_matrix/client/v3/account/whoami" {
        respond_json(
            stream,
            200,
            &json!({ "user_id": "@bot:matrix.test", "device_id": "DEVICE123" }),
        );
    } else {
        respond_json(
            stream,
            404,
            &json!({ "errcode": "M_NOT_FOUND", "error": "unknown endpoint" }),
        );
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes = stream.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..bytes]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&request).into_owned())
}

fn respond_json(stream: &mut TcpStream, status: u16, body: &Value) {
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let body = body.to_string();
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write loopback response");
}

fn redact_authorization(header: &str) -> String {
    if header.contains("Bearer ") {
        "authorization: Bearer [REDACTED]".into()
    } else {
        "authorization: [REDACTED]".into()
    }
}

fn open_jsonl_log() -> (Arc<Mutex<File>>, PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fcp-matrix-setup-doctor-state-e2e-{}-{now}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create Matrix setup doctor e2e log dir");
    let path = dir.join("matrix_setup_doctor_state_e2e.jsonl");
    let file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .expect("open Matrix setup doctor e2e log");
    (Arc::new(Mutex::new(file)), path)
}

fn log_step(logs: &Arc<Mutex<File>>, step: &str, status: &str, details: &Value) {
    let record = json!({
        "step": step,
        "status": status,
        "details": details,
    });
    let mut logs = logs.lock().expect("Matrix setup doctor log lock");
    writeln!(logs, "{record}").expect("write Matrix setup doctor e2e log line");
    logs.flush().expect("flush Matrix setup doctor e2e log");
}

fn shutdown_request(reason: &str) -> ShutdownRequest {
    ShutdownRequest {
        r#type: "shutdown".into(),
        deadline_ms: 1_000,
        drain: true,
        reason: Some(reason.into()),
    }
}

#[fcp_async_core::runtime::test]
async fn setup_doctor_state_e2e_logs_readiness_persistence_and_shutdown() {
    let (logs, log_path) = open_jsonl_log();
    log_step(
        &logs,
        "log_start",
        "ok",
        &json!({ "path": log_path.display().to_string() }),
    );
    let mut server = SetupDoctorLoopbackServer::start(&logs);

    let mut direct = MatrixConnector::new();
    direct
        .configure(json!({
            "homeserver_url": server.uri(),
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .expect("configure direct token connector");
    let direct_report = direct
        .self_check()
        .await
        .expect("run direct token self_check");
    assert_eq!(direct_report.status, SelfCheckStatus::Ok);
    let direct_doctor = direct.doctor();
    assert_eq!(
        direct_doctor
            .pointer("/details/state_persistence/enabled")
            .and_then(Value::as_bool),
        Some(false)
    );
    log_step(
        &logs,
        "direct_token_readiness",
        "ok",
        &json!({
            "self_check_status": format!("{:?}", direct_report.status),
            "doctor": direct_doctor,
            "requests": server.requests(),
        }),
    );

    let mut credential = MatrixConnector::new();
    credential
        .configure(json!({
            "homeserver_url": server.uri(),
            "auth": { "mode": "credential_id", "credential_id": "matrix_cred" }
        }))
        .await
        .expect("configure credential connector");
    let credential_report = credential
        .self_check()
        .await
        .expect("run credential self_check");
    assert_eq!(credential_report.status, SelfCheckStatus::Degraded);
    assert_eq!(
        credential_report.reason_code.as_deref(),
        Some("credential_injection_required")
    );
    log_step(
        &logs,
        "credential_id_degraded_readiness",
        "ok",
        &json!({ "reason_code": credential_report.reason_code }),
    );

    let mut remote_http = MatrixConnector::new();
    remote_http
        .configure(json!({
            "homeserver_url": "http://matrix.example.test",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .expect("configure remote http connector");
    let remote_http_report = remote_http
        .self_check()
        .await
        .expect("run remote http self_check");
    assert_eq!(remote_http_report.status, SelfCheckStatus::Failed);
    assert_eq!(
        remote_http_report.reason_code.as_deref(),
        Some("homeserver_transport_invalid")
    );
    log_step(
        &logs,
        "plain_http_remote_denied",
        "ok",
        &json!({ "reason_code": remote_http_report.reason_code }),
    );

    let mut restored = MatrixConnector::new();
    restored
        .configure(json!({
            "homeserver_url": server.uri(),
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "account_user_id": "@bot:matrix.test",
                "device_id": "DEVICE123"
            },
            "state_persistence": {
                "enabled": true,
                "backend": "host_managed_snapshot",
                "zone_id": "z:work",
                "account_user_id": "@bot:matrix.test",
                "device_id": "DEVICE123",
                "restore": {
                    "last_sync_token": "restore_batch",
                    "dynamic_direct_message_rooms": ["!dm:matrix.test"],
                    "thread_participation_roots": ["$thread-root"]
                }
            }
        }))
        .await
        .expect("configure state persistence connector");
    let restored_doctor = restored.doctor();
    assert_eq!(
        restored_doctor["sync_tracking"]["last_sync_token"].as_str(),
        Some("restore_batch")
    );
    assert_eq!(
        restored_doctor["details"]["state_persistence"]["restore"]["last_sync_token_configured"]
            .as_bool(),
        Some(true)
    );
    let persistence_details = restored_doctor["details"]["state_persistence"].to_string();
    assert!(!persistence_details.contains("@bot:matrix.test"));
    assert!(!persistence_details.contains("DEVICE123"));
    assert!(!persistence_details.contains("restore_batch"));
    log_step(
        &logs,
        "state_persistence_restore",
        "ok",
        &json!({
            "sync_tracking": {
                "last_sync_token_configured": restored_doctor["sync_tracking"]["last_sync_token"].is_string(),
                "dynamic_direct_message_room_count": restored_doctor["sync_tracking"]["dynamic_direct_message_rooms"].as_array().map_or(0, Vec::len),
                "thread_participation_root_count": restored_doctor["sync_tracking"]["thread_participation_roots"].as_array().map_or(0, Vec::len),
            },
            "state_persistence": restored_doctor["details"]["state_persistence"].clone(),
        }),
    );

    let mut invalid = MatrixConnector::new();
    let invalid_config = invalid
        .configure(json!({
            "homeserver_url": "javascript:alert(1)",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await;
    assert!(invalid_config.is_err());
    log_step(
        &logs,
        "invalid_homeserver_url_denied",
        "ok",
        &json!({ "error": invalid_config.unwrap_err().to_string() }),
    );

    let mut e2ee_missing = MatrixConnector::new();
    e2ee_missing
        .configure(json!({
            "homeserver_url": server.uri(),
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.test",
                "device_id": "DEVICE123",
                "recovery": { "status": "missing" },
                "room_key_backup": { "status": "missing" }
            }
        }))
        .await
        .expect("configure missing recovery connector");
    let e2ee_doctor = e2ee_missing.doctor();
    assert_eq!(
        e2ee_doctor
            .pointer("/details/e2ee/structured_skip/reason_code")
            .and_then(Value::as_str),
        Some("matrix_e2ee_verified_crypto_unimplemented")
    );
    assert!(
        e2ee_doctor["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| {
                check["name"].as_str() == Some("migration_recovery")
                    && check["passed"].as_bool() == Some(false)
                    && check["critical"].as_bool() == Some(false)
            })
    );
    log_step(
        &logs,
        "e2ee_recovery_structured_skip",
        "ok",
        &json!({ "e2ee": e2ee_doctor["details"]["e2ee"].clone() }),
    );

    direct
        .shutdown(shutdown_request("setup-doctor-direct-complete"))
        .await
        .expect("shutdown direct connector");
    credential
        .shutdown(shutdown_request("setup-doctor-credential-complete"))
        .await
        .expect("shutdown credential connector");
    remote_http
        .shutdown(shutdown_request("setup-doctor-http-complete"))
        .await
        .expect("shutdown remote http connector");
    restored
        .shutdown(shutdown_request("setup-doctor-restore-complete"))
        .await
        .expect("shutdown restored connector");
    e2ee_missing
        .shutdown(shutdown_request("setup-doctor-e2ee-complete"))
        .await
        .expect("shutdown e2ee connector");
    log_step(&logs, "connectors_shutdown", "ok", &json!({}));

    server.stop();
    log_step(&logs, "server_shutdown", "ok", &json!({}));
}
