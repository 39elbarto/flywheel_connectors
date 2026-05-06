use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_matrix::MatrixConnector;
use fcp_sdk::prelude::*;
use serde_json::{Value, json};

const CAP_READ: &str = "matrix.read";
const OP_SYNC: &str = "matrix.sync";
const EVENT_MESSAGE_AUTHORIZED: &str = "matrix.message.authorized";
const EVENT_DROPPED: &str = "matrix.event.dropped";
const EVENT_REACTION: &str = "matrix.reaction";
const EVENT_ENCRYPTED: &str = "matrix.encrypted";

struct LoopbackMatrixServer {
    uri: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop_tx: Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl LoopbackMatrixServer {
    fn start(logs: &Arc<Mutex<File>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback Matrix server");
        listener
            .set_nonblocking(true)
            .expect("configure nonblocking listener");
        let uri = format!(
            "http://{}",
            listener.local_addr().expect("read listener address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_count = Arc::new(AtomicUsize::new(0));
        let (stop_tx, stop_rx) = mpsc::channel();
        let thread_requests = Arc::clone(&requests);
        let thread_logs = Arc::clone(logs);
        let thread_count = Arc::clone(&request_count);
        let handle = thread::spawn(move || {
            serve_loop(
                &listener,
                &stop_rx,
                &thread_count,
                &thread_requests,
                &thread_logs,
            );
        });

        log_step(
            logs,
            "server_start",
            "ok",
            json!({
                "uri": uri,
                "mode": "raw_tcp_matrix_loopback"
            }),
        );

        Self {
            uri,
            requests,
            stop_tx,
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
        let _ = self.stop_tx.send(());
        if let Some(handle) = self.handle.take() {
            handle.join().expect("join loopback server thread");
        }
    }
}

impl Drop for LoopbackMatrixServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_loop(
    listener: &TcpListener,
    stop_rx: &Receiver<()>,
    request_count: &AtomicUsize,
    requests: &Arc<Mutex<Vec<Value>>>,
    logs: &Arc<Mutex<File>>,
) {
    loop {
        if stop_rx.try_recv().is_ok() {
            log_step(logs, "server_stop", "ok", json!({}));
            break;
        }
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                handle_connection(&mut stream, request_count, requests, logs);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                log_step(
                    logs,
                    "server_accept",
                    "error",
                    json!({ "error": error.to_string() }),
                );
                break;
            }
        }
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    request_count: &AtomicUsize,
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
                json!({ "error": error.to_string() }),
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
        .map(ToOwned::to_owned);
    let since = query_param(&path, "since");
    let timeout = query_param(&path, "timeout");
    let request_index = request_count.fetch_add(1, Ordering::SeqCst);
    let request_record = json!({
        "index": request_index,
        "request_line": request_line,
        "path": path,
        "since": since,
        "timeout": timeout,
        "authorization_header": authorization.as_deref().map(redact_authorization),
    });
    requests
        .lock()
        .expect("request log lock")
        .push(request_record.clone());
    log_step(logs, "server_request", "ok", request_record);

    if !path.starts_with("/_matrix/client/v3/sync") {
        respond_json(
            stream,
            404,
            &json!({ "errcode": "M_NOT_FOUND", "error": "unknown endpoint" }),
            &[],
        );
        return;
    }

    match request_index {
        0 => respond_json(stream, 200, &initial_sync_body(), &[]),
        1 => respond_json(stream, 200, &incremental_sync_body(), &[]),
        2 => respond_json(
            stream,
            429,
            &json!({ "errcode": "M_LIMIT_EXCEEDED", "error": "retry later" }),
            &[("retry-after", "0")],
        ),
        _ => respond_json(
            stream,
            401,
            &json!({ "errcode": "M_UNKNOWN_TOKEN", "error": "expired token" }),
            &[],
        ),
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

fn respond_json(stream: &mut TcpStream, status: u16, body: &Value, headers: &[(&str, &str)]) {
    let status_text = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let body = body.to_string();
    let mut response = format!(
        "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.push_str(&body);
    stream
        .write_all(response.as_bytes())
        .expect("write loopback response");
}

fn query_param(path: &str, name: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| value.to_string())
    })
}

fn redact_authorization(header: &str) -> String {
    if header.contains("Bearer ") {
        "authorization: Bearer [REDACTED]".into()
    } else {
        "authorization: [REDACTED]".into()
    }
}

fn initial_sync_body() -> Value {
    json!({
        "next_batch": "batch_1",
        "rooms": {
            "join": {
                "!room:matrix.test": {
                    "state": {
                        "events": [
                            {
                                "event_id": "$state-name",
                                "type": "m.room.name",
                                "state_key": "",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 10,
                                "content": { "name": "Ops" },
                                "room_id": "!room:matrix.test"
                            },
                            {
                                "event_id": "$member-alice",
                                "type": "m.room.member",
                                "state_key": "@alice:matrix.test",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 11,
                                "content": { "membership": "join" },
                                "room_id": "!room:matrix.test"
                            }
                        ]
                    },
                    "timeline": {
                        "events": [
                            {
                                "event_id": "$allowed",
                                "type": "m.room.message",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 12,
                                "content": {
                                    "msgtype": "m.text",
                                    "body": "hello @bot:matrix.test",
                                    "m.mentions": { "user_ids": ["@bot:matrix.test"] }
                                },
                                "room_id": "!room:matrix.test"
                            }
                        ]
                    }
                }
            },
            "invite": {
                "!invite:matrix.test": {
                    "invite_state": {
                        "events": [
                            {
                                "event_id": "$invite",
                                "type": "m.room.member",
                                "state_key": "@bot:matrix.test",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 13,
                                "content": { "membership": "invite" },
                                "room_id": "!invite:matrix.test"
                            }
                        ]
                    }
                }
            }
        }
    })
}

fn incremental_sync_body() -> Value {
    json!({
        "next_batch": "batch_2",
        "rooms": {
            "join": {
                "!room:matrix.test": {
                    "state": { "events": [] },
                    "timeline": {
                        "prev_batch": "batch_1",
                        "events": [
                            {
                                "event_id": "$allowed",
                                "type": "m.room.message",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 12,
                                "content": {
                                    "msgtype": "m.text",
                                    "body": "duplicate @bot:matrix.test",
                                    "m.mentions": { "user_ids": ["@bot:matrix.test"] }
                                },
                                "room_id": "!room:matrix.test"
                            },
                            {
                                "event_id": "$missing-mention",
                                "type": "m.room.message",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 20,
                                "content": { "msgtype": "m.text", "body": "missing mention" },
                                "room_id": "!room:matrix.test"
                            },
                            {
                                "event_id": "$disallowed",
                                "type": "m.room.message",
                                "sender": "@mallory:matrix.test",
                                "origin_server_ts": 21,
                                "content": {
                                    "msgtype": "m.text",
                                    "body": "hi @bot:matrix.test",
                                    "m.mentions": { "user_ids": ["@bot:matrix.test"] }
                                },
                                "room_id": "!room:matrix.test"
                            },
                            {
                                "event_id": "$reaction",
                                "type": "m.reaction",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 22,
                                "content": {
                                    "m.relates_to": {
                                        "rel_type": "m.annotation",
                                        "event_id": "$allowed",
                                        "key": "approve"
                                    }
                                },
                                "room_id": "!room:matrix.test"
                            },
                            {
                                "event_id": "$encrypted",
                                "type": "m.room.encrypted",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 23,
                                "content": {
                                    "algorithm": "m.megolm.v1.aes-sha2",
                                    "session_id": "sess"
                                },
                                "room_id": "!room:matrix.test"
                            }
                        ]
                    }
                }
            }
        }
    })
}

fn open_jsonl_log() -> (Arc<Mutex<File>>, std::path::PathBuf) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis();
    let dir = std::env::temp_dir().join(format!(
        "fcp-matrix-supervised-sync-e2e-{}-{unique}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create persistent Matrix e2e log directory");
    let path = dir.join("matrix_supervised_sync_e2e.jsonl");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("open Matrix e2e JSONL log");
    (Arc::new(Mutex::new(file)), path)
}

fn log_step(logs: &Arc<Mutex<File>>, phase: &str, status: &str, details: impl Into<Value>) {
    let line = json!({
        "phase": phase,
        "status": status,
        "details": details.into(),
    });
    let mut file = logs.lock().expect("log file lock");
    writeln!(file, "{line}").expect("write JSONL log line");
    drop(file);
}

fn signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::generate()
}

fn capability_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(1);
    let cose_token = CapabilityTokenBuilder::new()
        .capability_id(CAP_READ)
        .zone_id("z:work")
        .principal("matrix-loopback")
        .issuer("node:loopback")
        .validity(now, expires)
        .target_instance(instance_id.as_str())
        .operations(&[OP_SYNC])
        .try_constraints_cbor(&cbor)
        .expect("valid constraints")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose_token)
}

async fn wait_for_supervised_stop(connector: &MatrixConnector, logs: &Arc<Mutex<File>>) -> Value {
    let started = Instant::now();
    loop {
        let doctor = connector.doctor();
        let status = doctor["details"]["supervised_sync"].clone();
        if status["running"].as_bool() == Some(false)
            && status["last_stop_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("fatal:Unauthorized"))
        {
            log_step(logs, "supervised_stop", "ok", status.clone());
            return status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "supervised sync did not stop after auth failure; last status: {status}"
        );
        fcp_async_core::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn collect_until_auth_stop(
    connector: &MatrixConnector,
    events: &mut fcp_async_core::channel::broadcast::Receiver<FcpResult<EventEnvelope>>,
    logs: &Arc<Mutex<File>>,
) -> Vec<EventEnvelope> {
    let mut received = Vec::new();
    let started = Instant::now();
    loop {
        if let Ok(receive_result) =
            fcp_async_core::time::timeout(Duration::from_millis(250), events.recv()).await
        {
            let event = receive_result
                .expect("broadcast receive")
                .expect("event payload");
            log_step(
                logs,
                "event",
                "ok",
                json!({
                    "topic": event.topic.clone(),
                    "seq": event.seq,
                    "cursor": event.cursor.clone(),
                    "stream_key": event.stream_key.clone(),
                    "payload": event.data.payload.clone(),
                }),
            );
            received.push(event);
        }
        let doctor = connector.doctor();
        let stopped_for_auth = doctor["details"]["supervised_sync"]["last_stop_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("fatal:Unauthorized"));
        if stopped_for_auth && received.len() >= 6 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "timed out collecting Matrix supervised sync events; received={}",
            received.len()
        );
    }
    received
}

#[fcp_async_core::runtime::test]
async fn supervised_sync_loopback_e2e_logs_policy_retry_auth_stop_and_shutdown() {
    let (logs, log_path) = open_jsonl_log();
    log_step(
        &logs,
        "log_start",
        "ok",
        json!({ "path": log_path.display().to_string() }),
    );
    let mut server = LoopbackMatrixServer::start(&logs);
    let key = signing_key();
    let mut connector = MatrixConnector::new();
    connector
        .configure(json!({
            "homeserver_url": server.uri(),
            "auth": { "mode": "access_token", "access_token": "tok" },
            "inbound_policy": {
                "allowed_users": ["@alice:matrix.test"],
                "bot_user_id": "@bot:matrix.test",
                "require_mention": true,
                "process_reactions": true,
                "encrypted_events": "fail_closed"
            },
            "supervised_sync": {
                "enabled": true,
                "poll_interval_ms": 20,
                "timeout_ms": 10,
                "supervisor": {
                    "base_backoff_ms": 10,
                    "max_backoff_ms": 20,
                    "jitter_enabled": false,
                    "max_consecutive_failures": 3,
                    "shutdown_timeout_ms": 1000
                }
            }
        }))
        .await
        .expect("configure connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: key.verifying_key().to_bytes(),
            nonce: [0_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake connector");
    log_step(
        &logs,
        "connector_ready",
        "ok",
        connector.doctor()["details"].clone(),
    );

    let mut event_rx = connector.subscribe_events();
    let token = capability_token(&key, connector.instance_id());
    let subscribed = connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("matrix-supervised-loopback"),
            topics: vec![
                EVENT_MESSAGE_AUTHORIZED.into(),
                EVENT_DROPPED.into(),
                EVENT_REACTION.into(),
                EVENT_ENCRYPTED.into(),
            ],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: Some(token),
        })
        .await
        .expect("subscribe to Matrix events");
    log_step(
        &logs,
        "subscribe",
        "ok",
        json!({ "confirmed_topics": subscribed.result.confirmed_topics }),
    );

    let events = collect_until_auth_stop(&connector, &mut event_rx, &logs).await;
    let stopped_status = wait_for_supervised_stop(&connector, &logs).await;
    assert_eq!(stopped_status["last_used_since"].as_str(), Some("batch_2"));

    let authorized = events
        .iter()
        .filter(|event| event.topic == EVENT_MESSAGE_AUTHORIZED)
        .collect::<Vec<_>>();
    assert_eq!(
        authorized.len(),
        1,
        "duplicate Matrix event must not re-emit"
    );
    assert_eq!(
        authorized[0].data.payload["event_id"].as_str(),
        Some("$allowed")
    );

    let dropped_reasons = events
        .iter()
        .filter(|event| event.topic == EVENT_DROPPED)
        .filter_map(|event| event.data.payload["reason"].as_str())
        .collect::<Vec<_>>();
    assert!(dropped_reasons.contains(&"mention_required"));
    assert!(dropped_reasons.contains(&"sender_not_allowed"));
    assert!(dropped_reasons.contains(&"encrypted_event_fail_closed"));
    assert!(events.iter().any(|event| {
        event.topic == EVENT_REACTION
            && event.data.payload["target_event_id"].as_str() == Some("$allowed")
            && event.data.payload["key"].as_str() == Some("approve")
    }));
    assert!(events.iter().any(|event| {
        event.topic == EVENT_ENCRYPTED
            && event.data.payload["delivery_policy"].as_str() == Some("fail_closed")
            && event.data.payload.get("ciphertext").is_none()
    }));

    let requests = server.requests();
    assert!(requests.len() >= 4);
    assert_eq!(requests[0]["since"].as_str(), None);
    assert_eq!(requests[1]["since"].as_str(), Some("batch_1"));
    assert_eq!(requests[2]["since"].as_str(), Some("batch_2"));
    assert_eq!(requests[3]["since"].as_str(), Some("batch_2"));
    log_step(
        &logs,
        "requests",
        "ok",
        json!({ "requests": requests.clone() }),
    );

    let doctor = connector.doctor();
    assert_eq!(
        doctor["details"]["sync_tracking"]["last_sync_token"].as_str(),
        Some("batch_2")
    );
    assert_eq!(
        doctor["details"]["sync_tracking"]["emitted_event_dedupe_keys"].as_u64(),
        Some(6)
    );
    log_step(&logs, "doctor_final", "ok", doctor["details"].clone());

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("matrix supervised sync loopback e2e complete".into()),
        })
        .await
        .expect("shutdown connector");
    server.stop();
    log_step(
        &logs,
        "shutdown",
        "ok",
        json!({ "log_path": log_path.display().to_string() }),
    );
}
