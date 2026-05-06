use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_matrix::MatrixConnector;
use fcp_prelude::OperationId;
use fcp_sdk::prelude::*;
use serde_json::{Value, json};

const CAP_READ: &str = "matrix.read";
const OP_SYNC: &str = "matrix.sync";

struct WorkflowLoopbackServer {
    uri: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl WorkflowLoopbackServer {
    fn start(logs: &Arc<Mutex<File>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind workflow Matrix server");
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
            &json!({ "uri": uri, "mode": "raw_tcp_matrix_workflow_loopback" }),
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
            handle.join().expect("join Matrix workflow loopback server");
        }
    }
}

impl Drop for WorkflowLoopbackServer {
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

    if path.starts_with("/_matrix/client/v3/sync") {
        respond_json(stream, 200, &workflow_sync_body());
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

#[allow(clippy::too_many_lines)]
fn workflow_sync_body() -> Value {
    json!({
        "next_batch": "workflow_batch_1",
        "rooms": {
            "join": {
                "!dm-auto:matrix.test": {
                    "state": {
                        "events": [
                            {
                                "event_id": "$bot-member",
                                "type": "m.room.member",
                                "state_key": "@bot:matrix.test",
                                "sender": "@bot:matrix.test",
                                "origin_server_ts": 1,
                                "content": { "membership": "join" },
                                "room_id": "!dm-auto:matrix.test"
                            },
                            {
                                "event_id": "$alice-member",
                                "type": "m.room.member",
                                "state_key": "@alice:matrix.test",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 2,
                                "content": { "membership": "join" },
                                "room_id": "!dm-auto:matrix.test"
                            }
                        ]
                    },
                    "timeline": {
                        "events": [
                            {
                                "event_id": "$dm-unmentioned",
                                "type": "m.room.message",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 3,
                                "content": {
                                    "msgtype": "m.text",
                                    "body": "direct workflow without mention"
                                },
                                "room_id": "!dm-auto:matrix.test"
                            },
                            {
                                "event_id": "$media-ok",
                                "type": "m.room.message",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 4,
                                "content": {
                                    "msgtype": "m.image",
                                    "body": "diagram.png",
                                    "url": "mxc://matrix.test/media-ok",
                                    "info": {
                                        "mimetype": "image/png",
                                        "size": 512,
                                        "w": 640,
                                        "h": 480
                                    }
                                },
                                "room_id": "!dm-auto:matrix.test"
                            },
                            {
                                "event_id": "$media-large",
                                "type": "m.room.message",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 5,
                                "content": {
                                    "msgtype": "m.file",
                                    "body": "archive.zip",
                                    "url": "mxc://matrix.test/media-large",
                                    "info": {
                                        "mimetype": "application/zip",
                                        "size": 2048
                                    }
                                },
                                "room_id": "!dm-auto:matrix.test"
                            }
                        ]
                    }
                },
                "!ops:matrix.test": {
                    "state": { "events": [] },
                    "timeline": {
                        "events": [
                            {
                                "event_id": "$bot-thread",
                                "type": "m.room.message",
                                "sender": "@bot:matrix.test",
                                "origin_server_ts": 10,
                                "content": {
                                    "msgtype": "m.text",
                                    "body": "bot joined the thread",
                                    "m.relates_to": {
                                        "rel_type": "m.thread",
                                        "event_id": "$support-thread"
                                    }
                                },
                                "room_id": "!ops:matrix.test"
                            },
                            {
                                "event_id": "$thread-followup",
                                "type": "m.room.message",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 11,
                                "content": {
                                    "msgtype": "m.text",
                                    "body": "follow-up without another mention",
                                    "m.relates_to": {
                                        "rel_type": "m.thread",
                                        "event_id": "$support-thread"
                                    }
                                },
                                "room_id": "!ops:matrix.test"
                            },
                            {
                                "event_id": "$approval-ok",
                                "type": "m.reaction",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 12,
                                "content": {
                                    "m.relates_to": {
                                        "rel_type": "m.annotation",
                                        "event_id": "$thread-followup",
                                        "key": "approve"
                                    }
                                },
                                "room_id": "!ops:matrix.test"
                            },
                            {
                                "event_id": "$approval-denied",
                                "type": "m.reaction",
                                "sender": "@mallory:matrix.test",
                                "origin_server_ts": 13,
                                "content": {
                                    "m.relates_to": {
                                        "rel_type": "m.annotation",
                                        "event_id": "$thread-followup",
                                        "key": "approve"
                                    }
                                },
                                "room_id": "!ops:matrix.test"
                            },
                            {
                                "event_id": "$receipt",
                                "type": "m.receipt",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 14,
                                "content": { "$thread-followup": { "m.read": {} } },
                                "room_id": "!ops:matrix.test"
                            },
                            {
                                "event_id": "$redaction",
                                "type": "m.room.redaction",
                                "sender": "@alice:matrix.test",
                                "origin_server_ts": 15,
                                "content": { "redacts": "$thread-followup" },
                                "room_id": "!ops:matrix.test"
                            }
                        ]
                    }
                }
            }
        }
    })
}

fn open_jsonl_log() -> (Arc<Mutex<File>>, std::path::PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis();
    let dir = std::env::temp_dir().join(format!(
        "fcp-matrix-workflow-policy-e2e-{}-{now}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create Matrix workflow e2e log directory");
    let path = dir.join("matrix_workflow_policy_e2e.jsonl");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("open Matrix workflow e2e JSONL log");
    (Arc::new(Mutex::new(file)), path)
}

fn log_step(logs: &Arc<Mutex<File>>, phase: &str, status: &str, details: &Value) {
    let line = json!({
        "phase": phase,
        "status": status,
        "details": details.clone(),
    });
    let mut file = logs.lock().expect("log file lock");
    writeln!(file, "{line}").expect("write JSONL log line");
    drop(file);
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
        .principal("matrix-workflow-loopback")
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

fn sync_request(connector: &MatrixConnector, key: &Ed25519SigningKey) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("matrix-workflow-policy-loopback"),
        connector_id: connector.id().clone(),
        operation: OperationId::from_static(OP_SYNC),
        zone_id: ZoneId::work(),
        input: json!({ "timeout_ms": 1000 }),
        capability_token: capability_token(key, connector.instance_id()),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn json_array<'a>(value: &'a Value, pointer: &str) -> Option<&'a Vec<Value>> {
    value.pointer(pointer).and_then(Value::as_array)
}

fn event_by_id<'a>(events: &'a [Value], event_id: &str) -> Option<&'a Value> {
    events
        .iter()
        .find(|event| event.get("event_id").and_then(Value::as_str) == Some(event_id))
}

#[fcp_async_core::runtime::test]
async fn workflow_policy_loopback_logs_dm_thread_reaction_media_and_shutdown() {
    let (logs, log_path) = open_jsonl_log();
    log_step(
        &logs,
        "log_start",
        "ok",
        &json!({ "path": log_path.display().to_string() }),
    );
    let mut server = WorkflowLoopbackServer::start(&logs);
    let key = Ed25519SigningKey::generate();
    let mut connector = MatrixConnector::new();
    connector
        .configure(json!({
            "homeserver_url": server.uri(),
            "auth": { "mode": "access_token", "access_token": "tok" },
            "inbound_policy": {
                "allowed_users": ["@alice:matrix.test"],
                "bot_user_id": "@bot:matrix.test",
                "require_mention": true,
                "dynamic_direct_message_detection": true,
                "direct_message_member_limit": 2,
                "approval_reaction_keys": ["approve"],
                "media_max_bytes": 1024,
                "encrypted_events": "fail_closed"
            }
        }))
        .await
        .expect("configure Matrix connector");
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
        .expect("handshake Matrix connector");
    log_step(
        &logs,
        "connector_ready",
        "ok",
        &connector
            .doctor()
            .pointer("/details")
            .cloned()
            .unwrap_or(Value::Null),
    );

    let response = connector
        .invoke(sync_request(&connector, &key))
        .await
        .expect("invoke matrix.sync");
    let result = response.result.expect("sync result");
    log_step(&logs, "sync_result", "ok", &result);

    let authorized =
        json_array(&result, "/authorized_message_events").expect("authorized events array");
    let dm_message = event_by_id(authorized, "$dm-unmentioned").expect("dm event");
    assert_eq!(
        dm_message
            .pointer("/delivery_context/dynamic_direct_message")
            .and_then(Value::as_bool),
        Some(true)
    );
    let media_message = event_by_id(authorized, "$media-ok").expect("media event");
    assert_eq!(
        media_message
            .pointer("/media/mxc_uri")
            .and_then(Value::as_str),
        Some("mxc://matrix.test/media-ok")
    );
    assert_eq!(
        media_message
            .pointer("/media/within_size_limit")
            .and_then(Value::as_bool),
        Some(true)
    );
    let thread_message = event_by_id(authorized, "$thread-followup").expect("thread event");
    assert_eq!(
        thread_message
            .pointer("/delivery_context/thread_participated")
            .and_then(Value::as_bool),
        Some(true)
    );

    let reaction = event_by_id(
        json_array(&result, "/reaction_events").expect("reaction events array"),
        "$approval-ok",
    )
    .expect("approval reaction event");
    assert_eq!(
        reaction
            .pointer("/approval/approved")
            .and_then(Value::as_bool),
        Some(true)
    );

    let dropped_reasons = json_array(&result, "/dropped_events")
        .expect("dropped events array")
        .iter()
        .filter_map(|event| event.get("reason").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert!(dropped_reasons.contains(&"media_too_large"));
    assert!(dropped_reasons.contains(&"self_event"));
    assert!(dropped_reasons.contains(&"sender_not_allowed"));
    assert!(dropped_reasons.contains(&"read_receipt_not_delivered"));
    assert!(dropped_reasons.contains(&"redaction_event_not_delivered"));

    assert!(
        json_array(
            &result,
            "/policy_context_updates/dynamic_direct_message_rooms"
        )
        .expect("dynamic DM update array")
        .iter()
        .any(|room| room.as_str() == Some("!dm-auto:matrix.test"))
    );
    assert!(
        json_array(
            &result,
            "/policy_context_updates/thread_participation_roots"
        )
        .expect("thread participation update array")
        .iter()
        .any(|root| root.as_str() == Some("$support-thread"))
    );

    let doctor = connector.doctor();
    log_step(
        &logs,
        "doctor_final",
        "ok",
        &doctor.pointer("/details").cloned().unwrap_or(Value::Null),
    );
    assert!(
        doctor
            .pointer("/sync_tracking/dynamic_direct_message_rooms")
            .and_then(Value::as_array)
            .is_some_and(|rooms| rooms
                .iter()
                .any(|room| room.as_str() == Some("!dm-auto:matrix.test")))
    );
    assert_eq!(server.requests().len(), 1);

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1000,
            drain: true,
            reason: Some("matrix workflow policy loopback e2e complete".into()),
        })
        .await
        .expect("shutdown Matrix connector");
    server.stop();
    log_step(
        &logs,
        "shutdown",
        "ok",
        &json!({ "log_path": log_path.display().to_string() }),
    );
}
