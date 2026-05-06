use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_dingtalk::DingTalkConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId,
    ShutdownRequest, ZoneId,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const OP_STREAM_INGEST: &str = "dingtalk.stream.ingest_message";
const OP_STREAM_REPLY: &str = "dingtalk.stream.reply";
const CAP_MESSAGES_READ: &str = "dingtalk.messages.read";
const CAP_MESSAGES_WRITE: &str = "dingtalk.messages.write";

struct LoopbackServer {
    base_url: String,
    received: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LoopbackServer {
    fn start(expected_posts: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set loopback listener nonblocking");
        let addr = listener.local_addr().expect("loopback listener address");
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_received = Arc::clone(&received);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !thread_stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handle_connection(stream, &thread_received);
                        if thread_received.lock().expect("received lock").len() >= expected_posts {
                            break;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url: format!("http://{addr}"),
            received,
            stop,
            handle: Some(handle),
        }
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.base_url.trim_start_matches("http://"));
        if let Some(handle) = self.handle.take() {
            handle.join().expect("loopback server thread should join");
        }
    }
}

fn handle_connection(mut stream: TcpStream, received: &Arc<Mutex<Vec<Value>>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut data = Vec::new();
    let mut scratch = [0_u8; 4096];
    loop {
        let read = match stream.read(&mut scratch) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(_) => break,
        };
        data.extend_from_slice(&scratch[..read]);
        if request_complete(&data) {
            break;
        }
    }

    let request = String::from_utf8_lossy(&data);
    let first_line = request.lines().next().unwrap_or_default();
    let path = first_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    let body = request
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .unwrap_or(Value::Null);
    received
        .lock()
        .expect("received lock")
        .push(json!({ "path": path, "body": body }));

    let (status, headers, body) = match first_line.split_whitespace().nth(1).unwrap_or("/") {
        "/session-rate-limit" => (
            "HTTP/1.1 429 Too Many Requests\r\n",
            "Retry-After: 1\r\nContent-Type: application/json\r\n",
            json!({"errcode": 88_001, "errmsg": "rate limited"}).to_string(),
        ),
        "/session-timeout" => {
            thread::sleep(Duration::from_millis(700));
            (
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: application/json\r\n",
                json!({"errcode": 0, "errmsg": "late"}).to_string(),
            )
        }
        _ => (
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: application/json\r\n",
            json!({"errcode": 0, "errmsg": "ok"}).to_string(),
        ),
    };
    let response = format!(
        "{status}{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn request_complete(data: &[u8]) -> bool {
    let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&data[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then_some(value)
        })
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(0);
    data.len() >= header_end + 4 + content_length
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &'static str,
    operation: &'static str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn invoke_request(
    id: &'static str,
    operation: &'static str,
    capability: &'static str,
    input: Value,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.dingtalk"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: build_token(signing_key, instance_id, capability, operation),
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

fn stream_event(msg_id: &str, staff_id: &str, text: &str) -> Value {
    json!({
        "msgType": "text",
        "text": { "content": text },
        "senderId": format!("user-{staff_id}"),
        "senderStaffId": staff_id,
        "senderNick": "Alice",
        "conversationId": "conv-1",
        "conversationType": "2",
        "conversationTitle": "Ops Room",
        "chatbotUserId": "bot-1",
        "atUsers": [],
        "createAt": 1_700_000_000_000_i64,
        "msgId": msg_id
    })
}

fn stream_ingest_input(event: Value, is_in_at_list: bool, session_webhook: &str) -> Value {
    let mut input = serde_json::Map::new();
    input.insert("event".into(), event);
    input.insert("is_in_at_list".into(), json!(is_in_at_list));
    input.insert("session_webhook".into(), json!(session_webhook));
    input.insert(
        "session_webhook_expired_time_ms".into(),
        json!(now_ms().saturating_add(120_000)),
    );
    Value::Object(input)
}

fn log_step(logs: &mut Vec<Value>, step: &str, status: &str, details: Value) {
    logs.push(json!({
        "ts_ms": now_ms(),
        "step": step,
        "status": status,
        "details": redact_log_value(details)
    }));
}

fn redact_log_value(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(redact_log_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let redacted = match key.as_str() {
                        "raw" => json!("<omitted>"),
                        "senderId" | "senderStaffId" | "sender_id" | "sender_name"
                        | "conversationId" | "conversation_id" | "conversationTitle"
                        | "instance_id" | "resource_uris" | "stream_key" | "principal"
                        | "display" | "text" | "content" | "title" => json!("<redacted>"),
                        _ => redact_log_value(value),
                    };
                    (key, redacted)
                })
                .collect(),
        ),
        other => other,
    }
}

fn write_jsonl_log(logs: &[Value]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fcp-dingtalk-stream-mode-e2e-{}-{}",
        std::process::id(),
        now_ms()
    ));
    fs::create_dir_all(&dir).expect("create e2e log dir");
    let path = dir.join("dingtalk_stream_e2e.jsonl");
    let mut file = File::create(&path).expect("create e2e log file");
    for entry in logs {
        let line = serde_json::to_string(entry).expect("serialize log entry");
        println!("{line}");
        writeln!(file, "{line}").expect("write log entry");
    }
    path
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

#[fcp_async_core::runtime::test]
async fn stream_mode_loopback_e2e_logs_policy_reply_and_shutdown() {
    let mut loopback = LoopbackServer::start(3);
    let session_ok = format!("{}/session-ok", loopback.base_url);
    let session_rate_limit = format!("{}/session-rate-limit", loopback.base_url);
    let session_timeout = format!("{}/session-timeout", loopback.base_url);
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let mut connector = DingTalkConnector::new();
    let mut logs = Vec::new();

    connector
        .configure(json!({
            "base_url": loopback.base_url.clone(),
            "media_base_url": loopback.base_url.clone(),
            "client_id": "ding-app",
            "client_secret": "secret",
            "request_timeout_ms": 1_000,
            "stream_mode_enabled": true,
            "stream_allowed_users": ["staff-1"],
            "stream_mention_patterns": ["@opsbot"],
            "stream_replay_cache_entries": 16,
            "stream_session_webhook_cache_entries": 4,
            "stream_session_webhook_expiry_safety_ms": 1_000,
            "stream_reply_timeout_ms": 200
        }))
        .await
        .expect("configure stream mode connector");
    log_step(
        &mut logs,
        "configure",
        "ok",
        json!({"stream_mode_enabled": true}),
    );

    let handshake = connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [7_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_MESSAGES_READ),
                CapabilityId::from_static(CAP_MESSAGES_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: Some(instance_id.clone()),
        })
        .await
        .expect("handshake stream mode connector");
    let event_caps = handshake.event_caps.expect("event caps");
    assert!(!event_caps.streaming);
    assert!(event_caps.replay);
    assert_eq!(event_caps.min_buffer_events, 16);
    log_step(
        &mut logs,
        "handshake",
        "ok",
        json!({
            "streaming": event_caps.streaming,
            "replay": event_caps.replay,
            "min_buffer_events": event_caps.min_buffer_events
        }),
    );

    let accepted = connector
        .invoke(invoke_request(
            "dingtalk-stream-accepted",
            OP_STREAM_INGEST,
            CAP_MESSAGES_READ,
            stream_ingest_input(
                stream_event("msg-1", "staff-1", "@opsbot deploy?"),
                true,
                &session_ok,
            ),
            &signing_key,
            &instance_id,
        ))
        .await
        .expect("accepted stream ingest");
    assert!(matches!(accepted.status, InvokeStatus::Ok));
    let accepted_result = accepted.result.expect("accepted result");
    assert_eq!(accepted_result["policy"]["decision"], json!("accepted"));
    assert_eq!(accepted_result["event"]["topic"], json!("dingtalk.message"));
    assert_eq!(
        accepted_result["delivery"]["session_webhook_cached"],
        json!(true)
    );
    log_step(&mut logs, "message", "accepted", accepted_result);

    let duplicate = connector
        .invoke(invoke_request(
            "dingtalk-stream-duplicate",
            OP_STREAM_INGEST,
            CAP_MESSAGES_READ,
            stream_ingest_input(
                stream_event("msg-1", "staff-1", "@opsbot deploy?"),
                true,
                &session_ok,
            ),
            &signing_key,
            &instance_id,
        ))
        .await
        .expect("duplicate stream ingest");
    let duplicate_result = duplicate.result.expect("duplicate result");
    assert_eq!(duplicate_result["policy"]["decision"], json!("duplicate"));
    assert_eq!(duplicate_result["event"], json!(null));
    log_step(&mut logs, "duplicate", "dropped", duplicate_result);

    let disallowed = connector
        .invoke(invoke_request(
            "dingtalk-stream-disallowed",
            OP_STREAM_INGEST,
            CAP_MESSAGES_READ,
            stream_ingest_input(
                stream_event("msg-2", "staff-2", "@opsbot deploy?"),
                true,
                &session_ok,
            ),
            &signing_key,
            &instance_id,
        ))
        .await
        .expect("disallowed stream ingest");
    let disallowed_result = disallowed.result.expect("disallowed result");
    assert_eq!(
        disallowed_result["policy"]["reason"],
        json!("sender_not_allowed")
    );
    log_step(&mut logs, "disallowed_user", "rejected", disallowed_result);

    let missing_mention = connector
        .invoke(invoke_request(
            "dingtalk-stream-missing-mention",
            OP_STREAM_INGEST,
            CAP_MESSAGES_READ,
            stream_ingest_input(
                stream_event("msg-3", "staff-1", "hello"),
                false,
                &session_ok,
            ),
            &signing_key,
            &instance_id,
        ))
        .await
        .expect("missing mention stream ingest");
    let missing_mention_result = missing_mention.result.expect("missing mention result");
    assert_eq!(
        missing_mention_result["policy"]["reason"],
        json!("mention_required")
    );
    log_step(
        &mut logs,
        "missing_mention",
        "rejected",
        missing_mention_result,
    );

    let mut media_event = stream_event("msg-4", "staff-1", "@opsbot see file");
    media_event["content"] = json!({
        "file": {
            "downloadCode": "x".repeat(2_049)
        }
    });
    let media = connector
        .invoke(invoke_request(
            "dingtalk-stream-media-bound",
            OP_STREAM_INGEST,
            CAP_MESSAGES_READ,
            stream_ingest_input(media_event, true, &session_ok),
            &signing_key,
            &instance_id,
        ))
        .await
        .expect("media bound stream ingest");
    let media_result = media.result.expect("media result");
    assert_eq!(
        media_result["policy"]["reason"],
        json!("media_field_too_large")
    );
    log_step(&mut logs, "media_bound", "rejected", media_result);

    let reply = connector
        .invoke(invoke_request(
            "dingtalk-stream-reply",
            OP_STREAM_REPLY,
            CAP_MESSAGES_WRITE,
            json!({
                "chat_id": "conv-1",
                "content": "reply from FCP stream mode loopback"
            }),
            &signing_key,
            &instance_id,
        ))
        .await
        .expect("session webhook reply");
    let reply_result = reply.result.expect("reply result");
    assert_eq!(reply_result["status"], json!("sent"));
    assert_eq!(reply_result["session_webhook_source"], json!("cache"));
    log_step(&mut logs, "reply", "sent", reply_result);

    let rate_limited = connector
        .invoke(invoke_request(
            "dingtalk-stream-reply-rate-limit",
            OP_STREAM_REPLY,
            CAP_MESSAGES_WRITE,
            json!({
                "chat_id": "conv-rate-limit",
                "content": "rate limit check",
                "session_webhook": session_rate_limit
            }),
            &signing_key,
            &instance_id,
        ))
        .await
        .expect_err("rate-limited webhook should error");
    log_step(
        &mut logs,
        "rate_limit",
        "error",
        json!({"error": rate_limited.to_string()}),
    );

    let timed_out = connector
        .invoke(invoke_request(
            "dingtalk-stream-reply-timeout",
            OP_STREAM_REPLY,
            CAP_MESSAGES_WRITE,
            json!({
                "chat_id": "conv-timeout",
                "content": "timeout check",
                "session_webhook": session_timeout
            }),
            &signing_key,
            &instance_id,
        ))
        .await
        .expect_err("timeout webhook should error");
    log_step(
        &mut logs,
        "timeout",
        "error",
        json!({"error": timed_out.to_string()}),
    );

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("stream loopback e2e complete".into()),
        })
        .await
        .expect("shutdown connector");
    loopback.shutdown();
    let received = loopback.received.lock().expect("received lock").clone();
    assert_eq!(received.len(), 3);
    assert!(
        received
            .iter()
            .any(|entry| entry["path"] == json!("/session-ok"))
    );
    assert!(
        received
            .iter()
            .any(|entry| entry["path"] == json!("/session-rate-limit"))
    );
    assert!(
        received
            .iter()
            .any(|entry| entry["path"] == json!("/session-timeout"))
    );
    log_step(
        &mut logs,
        "shutdown",
        "ok",
        json!({
            "loopback_posts": received,
            "connector_owned_websocket": false,
            "reconnect_transport": "host_forwarded_stream_frame_divergence"
        }),
    );

    let log_path = write_jsonl_log(&logs);
    assert!(log_path.exists(), "jsonl log path should exist");
}
