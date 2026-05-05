use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use fcp_nostr::NostrConnector;
use fcp_nostr::client::{NostrClient, NostrKeyMaterial, build_nip04_dm_event, build_profile_event};
use fcp_nostr::types::{
    CAP_EVENTS_READ, DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD, DEFAULT_RELAY_CIRCUIT_RESET_MS,
    EVENT_INBOUND_DM, InboundDmPolicyMode, NIP01_KIND_PROFILE, NIP04_KIND_ENCRYPTED_DM,
    NostrConfig, NostrInboundDmConfig, NostrProfile, OP_PROFILE_IMPORT, OP_PROFILE_PUBLISH,
    encode_public_key_npub, encode_secret_key_nsec, normalize_public_key_input,
};
use fcp_prelude::{
    CapabilityId, FcpConnector, HandshakeRequest, RequestId, SubscribeRequest, UnsubscribeRequest,
    ZoneId,
};
use serde_json::{Value, json};
use sha1::{Digest as Sha1Digest, Sha1};
use uuid::Uuid;

const TEST_SECRET_KEY_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const RECIPIENT_SCALAR_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const SENDER_B_SCALAR_HEX: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const SENDER_C_SCALAR_HEX: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
const SENDER_D_SCALAR_HEX: &str =
    "5555555555555555555555555555555555555555555555555555555555555555";
const SENDER_E_SCALAR_HEX: &str =
    "6666666666666666666666666666666666666666666666666666666666666666";
const TEST_DM_PLAINTEXT: &str = "private loopback DM text";

#[derive(Default)]
struct E2eLog {
    entries: Vec<Value>,
}

impl E2eLog {
    fn record(&mut self, event: &str, detail: impl Into<Value>) {
        let detail = detail.into();
        let entry = json!({
            "test": "nostr_relay_policy_e2e",
            "event": event,
            "detail": detail,
        });
        eprintln!("{entry}");
        self.entries.push(entry);
    }
}

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    fcp_async_core::runtime::block_on_sync(future).expect("test runtime should start")
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    while !request.ends_with(b"\r\n\r\n") {
        let read = stream
            .read(&mut buf)
            .expect("loopback relay should read websocket handshake");
        assert!(read > 0, "client closed before websocket handshake");
        request.extend_from_slice(&buf[..read]);
    }
    String::from_utf8(request).expect("websocket handshake should be UTF-8")
}

fn websocket_accept_value(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(digest.finalize())
}

fn complete_websocket_handshake(stream: &mut TcpStream) {
    let request = read_http_request(stream);
    let key = request
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
        .expect("websocket client should send Sec-WebSocket-Key");
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        websocket_accept_value(key.trim())
    );
    stream
        .write_all(response.as_bytes())
        .expect("websocket handshake response should write");
    stream
        .flush()
        .expect("websocket handshake response should flush");
}

fn read_exact_len(stream: &mut TcpStream, len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_websocket_text_frame(stream: &mut TcpStream) -> io::Result<String> {
    let header = read_exact_len(stream, 2)?;
    let opcode = header[0] & 0x0f;
    if opcode == 0x8 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "client sent websocket close frame",
        ));
    }
    assert_eq!(opcode, 0x1, "client should send a websocket text frame");

    let masked = (header[1] & 0x80) != 0;
    assert!(masked, "client-to-server websocket frames must be masked");
    let mut payload_len = u64::from(header[1] & 0x7f);
    if payload_len == 126 {
        let ext = read_exact_len(stream, 2)?;
        payload_len = u64::from(u16::from_be_bytes([ext[0], ext[1]]));
    } else if payload_len == 127 {
        let ext = read_exact_len(stream, 8)?;
        payload_len = u64::from_be_bytes([
            ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
        ]);
    }
    let payload_len = usize::try_from(payload_len).expect("test websocket payload should fit");
    let mask = read_exact_len(stream, 4)?;
    let mut payload = read_exact_len(stream, payload_len)?;
    for (idx, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[idx % 4];
    }
    String::from_utf8(payload).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_websocket_text_frame(stream: &mut TcpStream, payload: &str) -> io::Result<()> {
    let bytes = payload.as_bytes();
    if bytes.len() > 65_535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("test websocket payload too large: {} bytes", bytes.len()),
        ));
    }

    let mut frame = vec![0x81];
    if bytes.len() <= 125 {
        frame.push(u8::try_from(bytes.len()).expect("short websocket payload length"));
    } else {
        frame.push(126);
        frame.extend_from_slice(
            &u16::try_from(bytes.len())
                .expect("medium websocket payload length")
                .to_be_bytes(),
        );
    }
    frame.extend_from_slice(bytes);
    stream.write_all(&frame)?;
    stream.flush()
}

fn write_websocket_close_frame(stream: &mut TcpStream) {
    stream
        .write_all(&[0x88, 0])
        .expect("websocket close frame should write");
    stream.flush().expect("websocket close frame should flush");
}

fn spawn_publish_ack_relay() -> (String, JoinHandle<Vec<Value>>) {
    spawn_publish_ack_relay_connections(1)
}

fn spawn_publish_ack_relay_connections(
    connection_count: usize,
) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let mut frames = Vec::with_capacity(connection_count);
        for _ in 0..connection_count {
            let (mut stream, _) = listener.accept().expect("publish relay should accept");
            complete_websocket_handshake(&mut stream);
            let frame_text = read_websocket_text_frame(&mut stream).expect("publish frame");
            let frame: Value = serde_json::from_str(&frame_text).expect("publish frame JSON");
            assert_eq!(frame[0], "EVENT");
            let event_id = frame[1]["id"]
                .as_str()
                .expect("publish frame should include signed event id");
            write_websocket_text_frame(&mut stream, &json!(["OK", event_id, true, ""]).to_string())
                .expect("publish OK frame should write");
            write_websocket_close_frame(&mut stream);
            frames.push(frame);
        }
        frames
    });
    (format!("ws://{address}"), handle)
}

fn spawn_publish_reject_relay(message: &'static str) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("reject relay should accept");
        complete_websocket_handshake(&mut stream);
        let frame_text = read_websocket_text_frame(&mut stream).expect("publish frame");
        let frame: Value = serde_json::from_str(&frame_text).expect("publish frame JSON");
        assert_eq!(frame[0], "EVENT");
        let event_id = frame[1]["id"]
            .as_str()
            .expect("reject frame should include signed event id");
        write_websocket_text_frame(
            &mut stream,
            &json!(["OK", event_id, false, message]).to_string(),
        )
        .expect("publish rejection frame should write");
        write_websocket_close_frame(&mut stream);
        vec![frame]
    });
    (format!("ws://{address}"), handle)
}

fn spawn_silent_publish_relay(sleep_for: Duration) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("silent relay should accept");
        complete_websocket_handshake(&mut stream);
        let frame_text = read_websocket_text_frame(&mut stream).expect("publish frame");
        let frame: Value = serde_json::from_str(&frame_text).expect("publish frame JSON");
        assert_eq!(frame[0], "EVENT");
        thread::sleep(sleep_for);
        vec![frame]
    });
    (format!("ws://{address}"), handle)
}

fn spawn_query_relay() -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("query relay should accept");
        complete_websocket_handshake(&mut stream);
        let frame_text = read_websocket_text_frame(&mut stream).expect("REQ frame");
        let frame: Value = serde_json::from_str(&frame_text).expect("REQ frame JSON");
        assert_eq!(frame[0], "REQ");
        let sub_id = frame[1]
            .as_str()
            .expect("REQ should include subscription id");
        let event = json!({
            "id": "relay-event-1",
            "pubkey": "22".repeat(32),
            "created_at": 1,
            "kind": 1,
            "tags": [],
            "content": "hello from loopback",
            "sig": "33".repeat(32),
        });
        write_websocket_text_frame(&mut stream, &json!(["EVENT", sub_id, event]).to_string())
            .expect("EVENT frame should write");
        write_websocket_text_frame(&mut stream, &json!(["EOSE", sub_id]).to_string())
            .expect("EOSE frame should write");
        let _ = read_websocket_text_frame(&mut stream);
        write_websocket_close_frame(&mut stream);
        vec![frame]
    });
    (format!("ws://{address}"), handle)
}

fn spawn_profile_query_relay(event: Value) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("profile query relay should accept");
        complete_websocket_handshake(&mut stream);
        let frame_text = read_websocket_text_frame(&mut stream).expect("profile REQ frame");
        let frame: Value = serde_json::from_str(&frame_text).expect("profile REQ frame JSON");
        assert_eq!(frame[0], "REQ");
        let sub_id = frame[1]
            .as_str()
            .expect("REQ should include subscription id");
        write_websocket_text_frame(&mut stream, &json!(["EVENT", sub_id, event]).to_string())
            .expect("profile EVENT frame should write");
        write_websocket_text_frame(&mut stream, &json!(["EOSE", sub_id]).to_string())
            .expect("profile EOSE frame should write");
        let _ = read_websocket_text_frame(&mut stream);
        write_websocket_close_frame(&mut stream);
        vec![frame]
    });
    (format!("ws://{address}"), handle)
}

fn spawn_inbound_subscription_relay(events: Vec<Value>) -> (String, JoinHandle<Vec<Value>>) {
    spawn_inbound_subscription_relay_connections(vec![events])
}

fn spawn_inbound_subscription_relay_connections(
    connections: Vec<Vec<Value>>,
) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let mut frames = Vec::with_capacity(connections.len().saturating_mul(2));
        for events in connections {
            let (mut stream, _) = listener.accept().expect("subscription relay should accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("subscription relay should set read timeout");
            complete_websocket_handshake(&mut stream);
            let request_text = read_websocket_text_frame(&mut stream).expect("REQ frame");
            let request_frame: Value = serde_json::from_str(&request_text).expect("REQ frame JSON");
            assert_eq!(request_frame[0], "REQ");
            let sub_id = request_frame[1]
                .as_str()
                .expect("REQ should include subscription id")
                .to_string();
            for event in events {
                write_websocket_text_frame(
                    &mut stream,
                    &json!(["EVENT", sub_id, event]).to_string(),
                )
                .expect("EVENT frame should write");
                thread::sleep(Duration::from_millis(50));
            }
            write_websocket_text_frame(&mut stream, &json!(["EOSE", sub_id]).to_string())
                .expect("EOSE frame should write");
            let close_text = read_websocket_text_frame(&mut stream).expect("CLOSE frame");
            let close_frame: Value = serde_json::from_str(&close_text).expect("CLOSE frame JSON");
            assert_eq!(close_frame, json!(["CLOSE", sub_id]));
            write_websocket_close_frame(&mut stream);
            frames.push(request_frame);
            frames.push(close_frame);
        }
        frames
    });
    (format!("ws://{address}"), handle)
}

fn spawn_hanging_subscription_relay(hold_for: Duration) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("hanging subscription relay should accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("hanging relay should set read timeout");
        complete_websocket_handshake(&mut stream);
        let request_text = read_websocket_text_frame(&mut stream).expect("REQ frame");
        let request_frame: Value = serde_json::from_str(&request_text).expect("REQ frame JSON");
        assert_eq!(request_frame[0], "REQ");
        thread::sleep(hold_for);
        let close_observation = match read_websocket_text_frame(&mut stream) {
            Ok(frame_text) => {
                serde_json::from_str(&frame_text).unwrap_or_else(|_| json!(frame_text))
            }
            Err(error) => json!({
                "connection_result": "client_dropped_or_timed_out",
                "error_kind": format!("{:?}", error.kind()),
            }),
        };
        let _ = stream.write_all(&[0x88, 0]);
        vec![request_frame, close_observation]
    });
    (format!("ws://{address}"), handle)
}

fn spawn_closing_publish_relay(connection_count: usize) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let mut frames = Vec::with_capacity(connection_count);
        for _ in 0..connection_count {
            let (mut stream, _) = listener.accept().expect("closing relay should accept");
            complete_websocket_handshake(&mut stream);
            let frame_text = read_websocket_text_frame(&mut stream).expect("publish frame");
            frames.push(serde_json::from_str(&frame_text).expect("publish frame JSON"));
        }
        frames
    });
    (format!("ws://{address}"), handle)
}

fn spawn_recovering_publish_relay(failure_count: usize) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback relay should bind");
    let address = listener
        .local_addr()
        .expect("loopback relay should have a socket address");
    let handle = thread::spawn(move || {
        let mut frames = Vec::with_capacity(failure_count + 1);
        for _ in 0..failure_count {
            let (mut stream, _) = listener.accept().expect("recovering relay should accept");
            complete_websocket_handshake(&mut stream);
            let frame_text = read_websocket_text_frame(&mut stream).expect("publish frame");
            frames.push(serde_json::from_str(&frame_text).expect("publish frame JSON"));
        }

        let (mut stream, _) = listener
            .accept()
            .expect("recovering relay should accept half-open probe");
        complete_websocket_handshake(&mut stream);
        let frame_text = read_websocket_text_frame(&mut stream).expect("recovery publish frame");
        let frame: Value = serde_json::from_str(&frame_text).expect("recovery publish frame JSON");
        assert_eq!(frame[0], "EVENT");
        let event_id = frame[1]["id"]
            .as_str()
            .expect("recovery frame should include signed event id");
        write_websocket_text_frame(&mut stream, &json!(["OK", event_id, true, ""]).to_string())
            .expect("recovery OK frame should write");
        write_websocket_close_frame(&mut stream);
        frames.push(frame);
        frames
    });
    (format!("ws://{address}"), handle)
}

fn local_config(relay_url: String) -> NostrConfig {
    NostrConfig {
        relay_urls: vec![relay_url],
        secret_key_hex: TEST_SECRET_KEY_HEX.into(),
        request_timeout_ms: 500,
        default_query_limit: 25,
        allow_local_relays: true,
        relay_circuit_failure_threshold: DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
        relay_circuit_reset_ms: DEFAULT_RELAY_CIRCUIT_RESET_MS,
        inbound_dm: NostrInboundDmConfig::default(),
    }
}

fn local_config_value(relay_url: &str) -> Value {
    json!({
        "relay_urls": [relay_url],
        "secret_key_hex": TEST_SECRET_KEY_HEX,
        "request_timeout_ms": 500,
        "default_query_limit": 25,
        "allow_local_relays": true,
        "relay_circuit_failure_threshold": DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
        "relay_circuit_reset_ms": DEFAULT_RELAY_CIRCUIT_RESET_MS,
    })
}

fn local_config_value_with_inbound(relay_url: &str, inbound_dm: &NostrInboundDmConfig) -> Value {
    json!({
        "relay_urls": [relay_url],
        "secret_key_hex": TEST_SECRET_KEY_HEX,
        "request_timeout_ms": 500,
        "default_query_limit": 25,
        "allow_local_relays": true,
        "relay_circuit_failure_threshold": DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
        "relay_circuit_reset_ms": DEFAULT_RELAY_CIRCUIT_RESET_MS,
        "inbound_dm": {
            "policy_mode": inbound_dm.policy_mode,
            "allowed_senders": inbound_dm.allowed_senders.clone(),
            "stale_after_secs": inbound_dm.stale_after_secs,
            "future_skew_secs": inbound_dm.future_skew_secs,
            "max_content_bytes": inbound_dm.max_content_bytes,
            "seen_event_capacity": inbound_dm.seen_event_capacity,
            "rate_window_secs": inbound_dm.rate_window_secs,
            "global_rate_limit": inbound_dm.global_rate_limit,
            "per_sender_rate_limit": inbound_dm.per_sender_rate_limit,
        }
    })
}

fn unique_zone_dir(label: &str) -> String {
    let dir = std::env::temp_dir().join(format!("fcp-nostr-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("zone dir should be created for restart proof");
    dir.to_string_lossy().into_owned()
}

fn local_config_with_secret(relay_url: String, secret_key_input: String) -> NostrConfig {
    let mut config = local_config(relay_url);
    config.secret_key_hex = secret_key_input;
    config
}

fn local_multi_relay_config(relay_urls: Vec<String>) -> NostrConfig {
    let mut config = local_config("ws://127.0.0.1:1".into());
    config.relay_urls = relay_urls;
    config
}

fn local_multi_relay_config_with_threshold(
    relay_urls: Vec<String>,
    failure_threshold: u32,
) -> NostrConfig {
    let mut config = local_multi_relay_config(relay_urls);
    config.relay_circuit_failure_threshold = failure_threshold;
    config
}

fn local_recovery_config(relay_url: String) -> NostrConfig {
    let mut config = local_config(relay_url);
    config.relay_circuit_reset_ms = 0;
    config
}

#[test]
fn production_policy_rejects_loopback_without_explicit_harness_opt_in() {
    let mut log = E2eLog::default();
    let config = NostrConfig {
        relay_urls: vec!["ws://127.0.0.1:7777".into()],
        secret_key_hex: TEST_SECRET_KEY_HEX.into(),
        request_timeout_ms: 500,
        default_query_limit: 25,
        allow_local_relays: false,
        relay_circuit_failure_threshold: DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
        relay_circuit_reset_ms: DEFAULT_RELAY_CIRCUIT_RESET_MS,
        inbound_dm: NostrInboundDmConfig::default(),
    };
    let err = NostrClient::new(&config).expect_err("production config must reject loopback relays");
    log.record(
        "production_loopback_rejected",
        json!({
            "error": err.to_string(),
            "allow_local_relays": false,
        }),
    );
    assert!(
        err.to_string().contains("allow_local_relays=true"),
        "error should explain the explicit local harness opt-in"
    );
}

#[test]
fn local_harness_publish_and_query_emit_resilience_jsonl() {
    let mut log = E2eLog::default();

    let (publish_url, publish_server) = spawn_publish_ack_relay();
    log.record("publish_relay_started", json!({ "relay_url": publish_url }));
    let publish_client = NostrClient::new(&local_config(publish_url.clone()))
        .expect("local harness relay config should be accepted");
    let publish_output = block_on(publish_client.publish_note(&json!({ "content": "hello" })))
        .expect("publish should complete against loopback relay");
    let publish_frames = publish_server
        .join()
        .expect("publish relay thread should finish");
    log.record("publish_client_output", publish_output.clone());
    log.record("publish_server_frames", json!(publish_frames));

    assert_eq!(
        publish_output["accepted_relays"][0]["relay"],
        format!("{publish_url}/")
    );
    assert_eq!(
        publish_output["relay_resilience"][0]["circuit_state"],
        "closed"
    );
    assert_eq!(publish_output["relay_resilience"][0]["success_count"], 1);

    let (query_url, query_server) = spawn_query_relay();
    log.record("query_relay_started", json!({ "relay_url": query_url }));
    let query_client = NostrClient::new(&local_config(query_url.clone()))
        .expect("local harness relay config should be accepted");
    let query_output = block_on(query_client.query_events(&json!({ "limit": 1 })))
        .expect("query should complete against loopback relay");
    let query_frames = query_server
        .join()
        .expect("query relay thread should finish");
    log.record("query_client_output", query_output.clone());
    log.record("query_server_frames", json!(query_frames));

    assert_eq!(query_output["results"][0]["relay"], format!("{query_url}/"));
    assert_eq!(
        query_output["results"][0]["events"][0]["id"],
        "relay-event-1"
    );
    assert_eq!(query_output["relay_resilience"][0]["success_count"], 1);
    assert!(
        log.entries.len() >= 6,
        "e2e should emit detailed JSONL-style progress and result records"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn profile_publish_import_loopback_logs_jsonl_and_preserves_note_boundary() {
    let mut log = E2eLog::default();

    let invalid_profile = json!({
        "profile": {
            "name": "unsafe",
            "picture": "http://127.0.0.1/avatar.png"
        }
    });
    let invalid_client = NostrClient::new(&local_config("ws://127.0.0.1:9".into()))
        .expect("local harness relay config should be accepted");
    let invalid_error = block_on(invalid_client.publish_profile(&invalid_profile, None))
        .expect_err("invalid profile URL must be rejected before publish");
    log.record(
        "profile_invalid_url_rejected",
        json!({
            "operation": OP_PROFILE_PUBLISH,
            "profile_field_set": ["name", "picture"],
            "relay": Value::Null,
            "event_kind": NIP01_KIND_PROFILE,
            "event_id": Value::Null,
            "created_at": Value::Null,
            "persisted": false,
            "import_source": Value::Null,
            "result": invalid_error.to_string(),
            "elapsed_ms": 0,
            "redaction_status": "no_secret_material",
        }),
    );

    let (ok_url, ok_server) = spawn_publish_ack_relay();
    let (reject_url, reject_server) = spawn_publish_reject_relay("blocked by relay policy");
    let partial_client = NostrClient::new(&local_multi_relay_config(vec![
        ok_url.clone(),
        reject_url.clone(),
    ]))
    .expect("local profile publish config should be accepted");
    let publish_started = Instant::now();
    let publish_output = block_on(partial_client.publish_profile(
        &json!({
            "profile": {
                "name": "loopback",
                "display_name": "Loopback Profile",
                "about": "profile proof",
                "picture": "https://example.com/avatar.png",
                "website": "https://example.com",
                "nip05": "loopback@example.com",
                "lud16": "loopback@getalby.com"
            }
        }),
        None,
    ))
    .expect("profile publish should complete against loopback relays");
    let ok_frames = ok_server.join().expect("OK profile relay should finish");
    let reject_frames = reject_server
        .join()
        .expect("reject profile relay should finish");
    log.record(
        "profile_publish_partial_result",
        json!({
            "operation": OP_PROFILE_PUBLISH,
            "profile_field_set": ["name", "display_name", "about", "picture", "website", "nip05", "lud16"],
            "relay": [ok_url, reject_url],
            "event_kind": publish_output["event_kind"],
            "event_id": publish_output["event"]["id"],
            "created_at": publish_output["event"]["created_at"],
            "persisted": publish_output["persist_recommended"],
            "import_source": Value::Null,
            "result": {
                "accepted": publish_output["accepted_relays"].as_array().map_or(0, Vec::len),
                "rejected": publish_output["rejected_relays"].as_array().map_or(0, Vec::len),
            },
            "elapsed_ms": elapsed_ms(publish_started),
            "redaction_status": "no_secret_material",
        }),
    );
    assert_eq!(publish_output["event_kind"], NIP01_KIND_PROFILE);
    assert!(publish_output["persist_recommended"].as_bool().unwrap());
    assert_eq!(
        publish_output["accepted_relays"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        publish_output["rejected_relays"].as_array().unwrap().len(),
        1
    );
    assert_eq!(ok_frames[0][1]["kind"], NIP01_KIND_PROFILE);
    assert_eq!(reject_frames[0][1]["kind"], NIP01_KIND_PROFILE);

    let last_created = publish_output["event"]["created_at"]
        .as_u64()
        .expect("profile publish should expose created_at");
    let (monotonic_url, monotonic_server) = spawn_publish_ack_relay();
    let monotonic_client = NostrClient::new(&local_config(monotonic_url.clone()))
        .expect("local monotonic profile config should be accepted");
    let monotonic_output = block_on(monotonic_client.publish_profile(
        &json!({"profile": {"name": "monotonic"}}),
        Some(last_created + 60),
    ))
    .expect("monotonic publish should complete");
    let monotonic_frames = monotonic_server
        .join()
        .expect("monotonic profile relay should finish");
    log.record(
        "profile_publish_monotonic_after_state_reload",
        json!({
            "operation": OP_PROFILE_PUBLISH,
            "profile_field_set": ["name"],
            "relay": monotonic_url,
            "event_kind": monotonic_output["event_kind"],
            "event_id": monotonic_output["event"]["id"],
            "created_at": monotonic_output["event"]["created_at"],
            "persisted": monotonic_output["persist_recommended"],
            "import_source": "last_published_at",
            "result": "created_at_gt_last",
            "elapsed_ms": 0,
            "redaction_status": "no_secret_material",
        }),
    );
    assert_eq!(monotonic_frames[0][1]["created_at"], last_created + 61);

    let (all_fail_url, all_fail_server) = spawn_publish_reject_relay("profile rejected");
    let all_fail_client = NostrClient::new(&local_config(all_fail_url.clone()))
        .expect("local all-fail profile config should be accepted");
    let all_fail_output =
        block_on(all_fail_client.publish_profile(&json!({"profile": {"name": "allfail"}}), None))
            .expect("all relay failure should return per-relay diagnostics");
    let _ = all_fail_server
        .join()
        .expect("all-fail profile relay should finish");
    log.record(
        "profile_publish_all_relay_failure",
        json!({
            "operation": OP_PROFILE_PUBLISH,
            "profile_field_set": ["name"],
            "relay": all_fail_url,
            "event_kind": all_fail_output["event_kind"],
            "event_id": all_fail_output["event"]["id"],
            "created_at": all_fail_output["event"]["created_at"],
            "persisted": all_fail_output["persist_recommended"],
            "import_source": Value::Null,
            "result": "no_relay_acceptance",
            "elapsed_ms": 0,
            "redaction_status": "no_secret_material",
        }),
    );
    assert!(!all_fail_output["persist_recommended"].as_bool().unwrap());

    let profile_key = NostrKeyMaterial::from_secret_key_input(TEST_SECRET_KEY_HEX).unwrap();
    let profile_event = build_profile_event(
        profile_key.secret_key(),
        profile_key.public_key_hex(),
        &NostrProfile {
            name: Some("imported".into()),
            picture: Some("https://example.com/imported.png".into()),
            ..NostrProfile::default()
        },
        None,
    )
    .expect("profile event should build");
    let (import_url, import_server) = spawn_profile_query_relay(profile_event);
    let import_client = NostrClient::new(&local_config(import_url.clone()))
        .expect("local profile import config should be accepted");
    let import_started = Instant::now();
    let import_output = block_on(import_client.import_profile(&json!({})))
        .expect("profile import should query loopback relay");
    let import_frames = import_server
        .join()
        .expect("profile import relay should finish");
    log.record(
        "profile_import_latest",
        json!({
            "operation": OP_PROFILE_IMPORT,
            "profile_field_set": ["name", "picture"],
            "relay": import_url,
            "event_kind": import_output["event"]["kind"],
            "event_id": import_output["event"]["id"],
            "created_at": import_output["event"]["created_at"],
            "persisted": false,
            "import_source": import_output["source_relay"],
            "result": import_output["ok"],
            "elapsed_ms": elapsed_ms(import_started),
            "redaction_status": "no_secret_material",
        }),
    );
    assert!(import_output["ok"].as_bool().unwrap());
    assert_eq!(import_output["profile"]["name"], "imported");
    assert_eq!(import_frames[0][2]["kinds"], json!([NIP01_KIND_PROFILE]));
    assert!(
        log.entries.len() >= 5,
        "profile e2e must emit detailed JSONL-style progress and result records"
    );
}

#[fcp_async_core::runtime::test]
async fn inbound_dm_subscription_loopback_logs_filter_handoff_cancel_and_redaction() {
    let mut log = E2eLog::default();
    let accepted_plaintext = "synthetic inbound subscription plaintext";
    let rejected_plaintext = "synthetic wrong target plaintext";
    let accepted_event = inbound_dm_event_for_connector(accepted_plaintext);
    let rejected_event = inbound_dm_event_for_wrong_target(rejected_plaintext);
    let connector_pubkey = connector_public_key_hex();
    let (relay_url, server) =
        spawn_inbound_subscription_relay(vec![accepted_event.clone(), rejected_event.clone()]);
    log.record(
        "inbound_subscription_relay_started",
        json!({
            "relay": relay_url,
            "event_kind": NIP04_KIND_ENCRYPTED_DM,
            "target_pubkey": connector_pubkey,
        }),
    );

    let mut connector = NostrConnector::new();
    connector
        .configure(local_config_value(&relay_url))
        .await
        .expect("connector should configure for local relay");
    let handshake = connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [8_u8; 32],
            nonce: [7_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake should succeed");
    let event_caps = handshake.event_caps.expect("event caps should be present");
    assert!(event_caps.streaming);
    assert!(!event_caps.replay);

    let response = connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("inbound-dm-subscription"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: Some("123".into()),
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("inbound DM subscribe should be accepted");
    assert_eq!(
        response.result.confirmed_topics,
        vec![EVENT_INBOUND_DM.to_string()]
    );
    assert!(!response.result.replay_supported);
    assert!(response.result.buffer.is_none());

    for _ in 0..100 {
        let diagnostics = connector.subscription_diagnostics();
        let saw_shutdown = diagnostics.iter().any(|entry| {
            entry["stage"] == "shutdown" && entry["shutdown_result"].as_str().is_some()
        });
        if saw_shutdown && !connector.subscription_events().is_empty() {
            break;
        }
        fcp_async_core::time::sleep(Duration::from_millis(10)).await;
    }

    let relay_frames = server
        .join()
        .expect("subscription relay thread should finish");
    log.record("inbound_subscription_relay_frames", json!(relay_frames));

    let request_frame = &relay_frames[0];
    assert_eq!(request_frame[0], "REQ");
    assert_eq!(request_frame[1], "inbound-dm-subscription");
    assert_eq!(
        request_frame[2],
        json!({
            "kinds": [NIP04_KIND_ENCRYPTED_DM],
            "#p": [connector_pubkey],
            "since": 123
        })
    );
    assert_eq!(relay_frames[1], json!(["CLOSE", "inbound-dm-subscription"]));

    let events = connector.subscription_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].topic, EVENT_INBOUND_DM);
    assert_eq!(events[0].cursor, accepted_event["id"].as_str().unwrap());
    assert_eq!(
        events[0].stream_key.as_deref(),
        accepted_event["pubkey"].as_str()
    );
    assert_eq!(events[0].data.payload["plaintext"], accepted_plaintext);

    let diagnostics = connector.subscription_diagnostics();
    log.record("inbound_subscription_diagnostics", json!(diagnostics));
    assert!(diagnostics.iter().any(|entry| {
        entry["stage"] == "subscribe_ack" && entry["subscribe_result"] == "req_sent"
    }));
    assert!(diagnostics.iter().any(|entry| {
        entry["stage"] == "event_receive" && entry["core_decision"] == "accepted"
    }));
    assert!(diagnostics.iter().any(|entry| {
        entry["stage"] == "event_receive"
            && entry["core_decision"] == "rejected"
            && entry["rejection_reason"] == "wrong_target"
    }));

    connector
        .unsubscribe(UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("inbound-dm-unsubscribe"),
            topics: vec![EVENT_INBOUND_DM.into()],
            capability_token: None,
        })
        .await
        .expect("unsubscribe should be idempotent after relay EOSE");
    assert_eq!(connector.active_subscription_count(), 0);
    connector
        .shutdown(fcp_prelude::ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 100,
            drain: true,
            reason: Some("test complete".into()),
        })
        .await
        .expect("shutdown should cleanly clear subscriptions");

    let serialized_diagnostics =
        serde_json::to_string(&connector.subscription_diagnostics()).unwrap();
    assert!(!serialized_diagnostics.contains(TEST_SECRET_KEY_HEX));
    assert!(!serialized_diagnostics.contains(RECIPIENT_SCALAR_HEX));
    assert!(!serialized_diagnostics.contains(accepted_plaintext));
    assert!(!serialized_diagnostics.contains(rejected_plaintext));
    assert!(
        log.entries.len() >= 3,
        "e2e should log relay start, relay frames, and structured subscription diagnostics"
    );
}

#[fcp_async_core::runtime::test]
async fn inbound_dm_subscription_restart_replays_cursor_and_state_without_secret_leaks() {
    let mut log = E2eLog::default();
    let zone_dir = unique_zone_dir("restart-replay");
    let first_plaintext = "restart replay original plaintext";
    let second_plaintext = "restart replay new plaintext";
    let first_event = inbound_dm_event_for_connector(first_plaintext);
    let second_event = inbound_dm_event_for_connector(second_plaintext);
    let first_created_at = first_event["created_at"]
        .as_i64()
        .expect("first event should have created_at");
    let connector_pubkey = connector_public_key_hex();

    let (first_relay_url, first_server) =
        spawn_inbound_subscription_relay(vec![first_event.clone()]);
    let mut first_connector = NostrConnector::new();
    first_connector
        .configure(local_config_value(&first_relay_url))
        .await
        .expect("first connector should configure");
    first_connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: Some(zone_dir.clone()),
            host_public_key: [8_u8; 32],
            nonce: [7_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("first handshake should prepare durable inbound state");
    first_connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("restart-first"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("first subscribe should be accepted");
    for _ in 0..100 {
        if !first_connector.subscription_events().is_empty()
            && first_connector
                .subscription_diagnostics()
                .iter()
                .any(|entry| entry["stage"] == "shutdown")
        {
            break;
        }
        fcp_async_core::time::sleep(Duration::from_millis(10)).await;
    }
    let first_frames = first_server.join().expect("first relay should finish");
    log.record("restart_first_relay_frames", json!(first_frames));
    assert_eq!(first_connector.subscription_events().len(), 1);
    assert!(
        first_connector
            .subscription_diagnostics()
            .iter()
            .any(|entry| {
                entry["stage"] == "event_receive"
                    && entry["core_decision"] == "accepted"
                    && entry["persistence_result"] == "state_persisted"
            })
    );

    let (second_relay_url, second_server) =
        spawn_inbound_subscription_relay(vec![first_event.clone(), second_event.clone()]);
    let mut restarted_connector = NostrConnector::new();
    restarted_connector
        .configure(local_config_value(&second_relay_url))
        .await
        .expect("restarted connector should configure");
    restarted_connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: Some(zone_dir.clone()),
            host_public_key: [8_u8; 32],
            nonce: [6_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("restart handshake should reload inbound state");
    restarted_connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("restart-second"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("second subscribe should be accepted");
    for _ in 0..100 {
        if !restarted_connector.subscription_events().is_empty()
            && restarted_connector
                .subscription_diagnostics()
                .iter()
                .any(|entry| entry["stage"] == "shutdown")
        {
            break;
        }
        fcp_async_core::time::sleep(Duration::from_millis(10)).await;
    }
    let second_frames = second_server.join().expect("second relay should finish");
    log.record("restart_second_relay_frames", json!(second_frames));
    assert_eq!(second_frames[0][0], "REQ");
    assert_eq!(
        second_frames[0][2],
        json!({
            "kinds": [NIP04_KIND_ENCRYPTED_DM],
            "#p": [connector_pubkey],
            "since": first_created_at,
        })
    );

    let restarted_events = restarted_connector.subscription_events();
    assert_eq!(restarted_events.len(), 1);
    assert_eq!(
        restarted_events[0].data.payload["plaintext"],
        second_plaintext
    );
    let diagnostics = restarted_connector.subscription_diagnostics();
    log.record("restart_second_diagnostics", json!(diagnostics));
    assert!(diagnostics.iter().any(|entry| {
        entry["stage"] == "state_prepare"
            && entry["state_load_result"] == "state_loaded"
            && entry["restart_generation"] == 1
            && entry["effective_since"] == first_created_at
    }));
    assert!(diagnostics.iter().any(|entry| {
        entry["stage"] == "event_receive"
            && entry["core_decision"] == "rejected"
            && entry["rejection_reason"] == "duplicate_event"
            && entry["duplicate_source"] == "recent_event_id"
            && entry["restart_generation"] == 1
    }));
    assert!(diagnostics.iter().any(|entry| {
        entry["stage"] == "event_receive"
            && entry["core_decision"] == "accepted"
            && entry["cursor_before"] == first_created_at
            && entry["persistence_result"] == "state_persisted"
    }));

    let state_path = std::path::Path::new(&zone_dir).join("nostr_inbound_dm_state.json");
    let persisted_state =
        std::fs::read_to_string(&state_path).expect("durable inbound state should exist");
    log.record(
        "restart_persisted_state_summary",
        json!({
            "state_path": state_path.display().to_string(),
            "contains_first_event": persisted_state.contains(first_event["id"].as_str().unwrap()),
            "contains_second_event": persisted_state.contains(second_event["id"].as_str().unwrap()),
        }),
    );
    assert!(persisted_state.contains(first_event["id"].as_str().unwrap()));
    assert!(persisted_state.contains(second_event["id"].as_str().unwrap()));
    assert!(!persisted_state.contains(TEST_SECRET_KEY_HEX));
    assert!(!persisted_state.contains(RECIPIENT_SCALAR_HEX));
    assert!(!persisted_state.contains(first_plaintext));
    assert!(!persisted_state.contains(second_plaintext));
    assert!(
        log.entries.len() >= 4,
        "restart e2e should log relay frames, diagnostics, and persisted-state summary"
    );
}

#[fcp_async_core::runtime::test]
#[allow(clippy::too_many_lines)]
async fn inbound_dm_full_loopback_e2e_logs_reply_policy_rate_replay_and_lifecycle() {
    let mut log = E2eLog::default();
    let zone_dir = unique_zone_dir("full-proof");
    let sender_a = sender_public_key_hex(RECIPIENT_SCALAR_HEX);
    let sender_b = sender_public_key_hex(SENDER_B_SCALAR_HEX);
    let sender_d = sender_public_key_hex(SENDER_D_SCALAR_HEX);
    let sender_e = sender_public_key_hex(SENDER_E_SCALAR_HEX);
    let inbound_dm = NostrInboundDmConfig {
        policy_mode: InboundDmPolicyMode::Allowlist,
        allowed_senders: vec![
            sender_a.clone(),
            sender_b.clone(),
            sender_d.clone(),
            sender_e.clone(),
        ],
        stale_after_secs: 7 * 24 * 60 * 60,
        future_skew_secs: 5 * 60,
        max_content_bytes: 8 * 1024,
        seen_event_capacity: 16,
        rate_window_secs: 60,
        global_rate_limit: 3,
        per_sender_rate_limit: 1,
    };

    let accepted_plaintext = "full proof accepted synthetic fixture";
    let sender_rate_plaintext = "full proof sender-rate synthetic fixture";
    let blocked_plaintext = "full proof blocked synthetic fixture";
    let wrong_target_plaintext = "full proof wrong-target synthetic fixture";
    let invalid_signature_plaintext = "full proof invalid-signature synthetic fixture";
    let accepted_b_plaintext = "full proof second sender synthetic fixture";
    let accepted_d_plaintext = "full proof restart accepted synthetic fixture";
    let global_rate_plaintext = "full proof global-rate synthetic fixture";
    let reply_plaintext = "full proof synthetic reply fixture";

    let accepted_event = inbound_dm_event_from_sender(RECIPIENT_SCALAR_HEX, accepted_plaintext);
    let sender_rate_event =
        inbound_dm_event_from_sender(RECIPIENT_SCALAR_HEX, sender_rate_plaintext);
    let blocked_event = inbound_dm_event_from_sender(SENDER_C_SCALAR_HEX, blocked_plaintext);
    let wrong_target_event =
        inbound_dm_event_from_sender_to_self(SENDER_B_SCALAR_HEX, wrong_target_plaintext);
    let mut invalid_signature_event =
        inbound_dm_event_from_sender(SENDER_D_SCALAR_HEX, invalid_signature_plaintext);
    invalid_signature_event["sig"] = json!("00".repeat(64));
    let accepted_b_event = inbound_dm_event_from_sender(SENDER_B_SCALAR_HEX, accepted_b_plaintext);
    let accepted_d_event = inbound_dm_event_from_sender(SENDER_D_SCALAR_HEX, accepted_d_plaintext);
    let global_rate_event =
        inbound_dm_event_from_sender(SENDER_E_SCALAR_HEX, global_rate_plaintext);
    let accepted_event_id = accepted_event["id"]
        .as_str()
        .expect("accepted event should include id")
        .to_string();

    let (relay_url, subscription_server) = spawn_inbound_subscription_relay_connections(vec![
        vec![
            accepted_event.clone(),
            invalid_signature_event,
            wrong_target_event,
            blocked_event,
            sender_rate_event,
            accepted_b_event,
        ],
        vec![accepted_event.clone()],
        vec![accepted_event.clone()],
        vec![accepted_d_event],
        vec![global_rate_event],
    ]);
    log.record(
        "full_proof_subscription_relay_started",
        json!({
            "relay": relay_url,
            "test_step": "relay_start",
            "allowed_sender_count": inbound_dm.allowed_senders.len(),
            "global_rate_limit": inbound_dm.global_rate_limit,
            "per_sender_rate_limit": inbound_dm.per_sender_rate_limit,
        }),
    );

    let mut connector = NostrConnector::new();
    connector
        .configure(local_config_value_with_inbound(&relay_url, &inbound_dm))
        .await
        .expect("connector should configure with inbound policy and rate limits");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: Some(zone_dir.clone()),
            host_public_key: [8_u8; 32],
            nonce: [7_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake should prepare durable inbound state");
    connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("full-proof-initial"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("initial full-proof subscribe should be accepted");
    wait_for_subscription_shutdown(&connector, "full-proof-initial", 2).await;
    connector
        .unsubscribe(UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("full-proof-unsubscribe-after-eose"),
            topics: vec![EVENT_INBOUND_DM.into()],
            capability_token: None,
        })
        .await
        .expect("unsubscribe after EOSE should clear tracked task");
    assert_eq!(connector.active_subscription_count(), 0);

    connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("full-proof-reconnect"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("reconnect subscribe should be accepted");
    wait_for_subscription_shutdown(&connector, "full-proof-reconnect", 2).await;
    connector
        .unsubscribe(UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("full-proof-unsubscribe-after-reconnect"),
            topics: vec![EVENT_INBOUND_DM.into()],
            capability_token: None,
        })
        .await
        .expect("unsubscribe after reconnect should clear tracked task");
    connector
        .shutdown(fcp_prelude::ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 100,
            drain: true,
            reason: Some("restart proof handoff".into()),
        })
        .await
        .expect("first connector should shutdown cleanly");

    let mut restarted_connector = NostrConnector::new();
    restarted_connector
        .configure(local_config_value_with_inbound(&relay_url, &inbound_dm))
        .await
        .expect("restarted connector should configure");
    restarted_connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: Some(zone_dir.clone()),
            host_public_key: [8_u8; 32],
            nonce: [6_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("restart handshake should reload inbound state");
    restarted_connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("full-proof-restart-duplicate"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("restart duplicate subscribe should be accepted");
    wait_for_subscription_shutdown(&restarted_connector, "full-proof-restart-duplicate", 0).await;
    restarted_connector
        .unsubscribe(UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("full-proof-unsubscribe-after-restart-duplicate"),
            topics: vec![EVENT_INBOUND_DM.into()],
            capability_token: None,
        })
        .await
        .expect("unsubscribe after restart duplicate should clear tracked task");
    restarted_connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("full-proof-restart-accept"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("restart accept subscribe should be accepted");
    wait_for_subscription_shutdown(&restarted_connector, "full-proof-restart-accept", 1).await;
    restarted_connector
        .unsubscribe(UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("full-proof-unsubscribe-after-restart-accept"),
            topics: vec![EVENT_INBOUND_DM.into()],
            capability_token: None,
        })
        .await
        .expect("unsubscribe after restart accept should clear tracked task");
    restarted_connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("full-proof-restart-global-rate"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("restart global-rate subscribe should be accepted");
    wait_for_subscription_shutdown(&restarted_connector, "full-proof-restart-global-rate", 1).await;
    restarted_connector
        .shutdown(fcp_prelude::ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 100,
            drain: true,
            reason: Some("full proof complete".into()),
        })
        .await
        .expect("restarted connector should shutdown cleanly");

    let subscription_frames = subscription_server
        .join()
        .expect("subscription relay should finish all proof connections");
    log.record(
        "full_proof_subscription_frames",
        json!({
            "test_step": "subscription_frame_summary",
            "frame_count": subscription_frames.len(),
            "request_ids": [
                subscription_frames[0][1].clone(),
                subscription_frames[2][1].clone(),
                subscription_frames[4][1].clone(),
                subscription_frames[6][1].clone(),
                subscription_frames[8][1].clone()
            ],
            "close_ids": [
                subscription_frames[1][1].clone(),
                subscription_frames[3][1].clone(),
                subscription_frames[5][1].clone(),
                subscription_frames[7][1].clone(),
                subscription_frames[9][1].clone()
            ],
        }),
    );
    assert_eq!(subscription_frames.len(), 10);
    assert_eq!(subscription_frames[0][0], "REQ");
    assert_eq!(
        subscription_frames[1],
        json!(["CLOSE", "full-proof-initial"])
    );
    assert_eq!(subscription_frames[2][0], "REQ");
    assert_eq!(subscription_frames[2][1], "full-proof-reconnect");
    assert_eq!(
        subscription_frames[3],
        json!(["CLOSE", "full-proof-reconnect"])
    );
    assert_eq!(subscription_frames[4][0], "REQ");
    assert_eq!(subscription_frames[4][1], "full-proof-restart-duplicate");
    assert_eq!(
        subscription_frames[5],
        json!(["CLOSE", "full-proof-restart-duplicate"])
    );
    assert_eq!(subscription_frames[6][0], "REQ");
    assert_eq!(subscription_frames[6][1], "full-proof-restart-accept");
    assert_eq!(
        subscription_frames[7],
        json!(["CLOSE", "full-proof-restart-accept"])
    );
    assert_eq!(subscription_frames[8][0], "REQ");
    assert_eq!(subscription_frames[8][1], "full-proof-restart-global-rate");
    assert_eq!(
        subscription_frames[9],
        json!(["CLOSE", "full-proof-restart-global-rate"])
    );

    let initial_diagnostics = connector.subscription_diagnostics();
    let restart_diagnostics = restarted_connector.subscription_diagnostics();
    log.record(
        "full_proof_initial_diagnostics",
        json!({
            "test_step": "initial_and_reconnect_diagnostics",
            "diagnostics": initial_diagnostics,
        }),
    );
    log.record(
        "full_proof_restart_diagnostics",
        json!({
            "test_step": "restart_diagnostics",
            "diagnostics": restart_diagnostics,
        }),
    );
    let initial_diagnostics = connector.subscription_diagnostics();
    let restart_diagnostics = restarted_connector.subscription_diagnostics();
    assert_eq!(connector.subscription_events().len(), 2);
    assert_eq!(restarted_connector.subscription_events().len(), 1);
    for (reason, scope) in [
        ("invalid_signature", None),
        ("wrong_target", None),
        ("policy_sender_blocked", None),
        ("sender_rate_limited", Some("sender")),
        ("duplicate_event", None),
    ] {
        assert!(
            initial_diagnostics.iter().any(|entry| {
                entry["stage"] == "event_receive"
                    && entry["rejection_reason"] == reason
                    && scope.is_none_or(|expected| entry["rate_limit_scope"] == expected)
            }),
            "initial/reconnect diagnostics should include rejection reason {reason}"
        );
    }
    assert!(restart_diagnostics.iter().any(|entry| {
        entry["stage"] == "state_prepare"
            && entry["state_load_result"] == "state_loaded"
            && entry["restart_generation"] == 1
    }));
    assert!(restart_diagnostics.iter().any(|entry| {
        entry["stage"] == "event_receive"
            && entry["rejection_reason"] == "duplicate_event"
            && entry["duplicate_source"] == "recent_event_id"
            && entry["restart_generation"] == 1
    }));
    assert!(restart_diagnostics.iter().any(|entry| {
        entry["stage"] == "event_receive"
            && entry["core_decision"] == "accepted"
            && entry["sender"] == sender_d
    }));
    assert!(restart_diagnostics.iter().any(|entry| {
        entry["stage"] == "event_receive"
            && entry["rejection_reason"] == "global_rate_limited"
            && entry["rate_limit_scope"] == "global"
            && entry["retry_after_ms"].as_u64().is_some()
    }));

    let (reply_url, reply_server) = spawn_publish_ack_relay();
    let reply_client =
        NostrClient::new(&local_config(reply_url.clone())).expect("reply client should configure");
    let reply_start = Instant::now();
    let reply_output = reply_client
        .send_dm(&json!({
            "recipient": sender_a.clone(),
            "plaintext": reply_plaintext,
            "reply_to_event_id": accepted_event_id.clone(),
        }))
        .await
        .expect("reply DM should publish through production send path");
    let reply_frames = reply_server
        .join()
        .expect("reply relay thread should finish");
    assert_eq!(reply_frames.len(), 1);
    assert_dm_reply_event_frame(&reply_frames[0], &sender_a, &accepted_event_id);
    log.record(
        "full_proof_reply_send",
        json!({
            "test_step": "reply_send",
            "reply_result": dm_acceptance_status(&reply_output),
            "event_kind": reply_output["event_kind"],
            "recipient": sender_a,
            "reply_to_event_id": accepted_event_id,
            "elapsed_ms": elapsed_ms(reply_start),
        }),
    );
    reply_client.shutdown();

    let (unsubscribe_url, unsubscribe_server) =
        spawn_hanging_subscription_relay(Duration::from_millis(100));
    let mut unsubscribe_connector = NostrConnector::new();
    unsubscribe_connector
        .configure(local_config_value(&unsubscribe_url))
        .await
        .expect("unsubscribe connector should configure");
    unsubscribe_connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [8_u8; 32],
            nonce: [5_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("unsubscribe handshake should succeed");
    unsubscribe_connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("full-proof-active-unsubscribe"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("active unsubscribe subscribe should be accepted");
    fcp_async_core::time::sleep(Duration::from_millis(20)).await;
    unsubscribe_connector
        .unsubscribe(UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("full-proof-active-unsubscribe-request"),
            topics: vec![EVENT_INBOUND_DM.into()],
            capability_token: None,
        })
        .await
        .expect("active unsubscribe should abort subscription task");
    let unsubscribe_frames = unsubscribe_server
        .join()
        .expect("hanging unsubscribe relay should finish");
    log.record(
        "full_proof_active_unsubscribe",
        json!({
            "test_step": "active_unsubscribe",
            "relay_frame_count": unsubscribe_frames.len(),
            "diagnostics": unsubscribe_connector.subscription_diagnostics(),
        }),
    );
    assert!(
        unsubscribe_connector
            .subscription_diagnostics()
            .iter()
            .any(|entry| {
                entry["stage"] == "unsubscribe"
                    && entry["unsubscribe_result"] == "aborted"
                    && entry["cancellation_reason"] == "unsubscribe"
            })
    );

    let (shutdown_url, shutdown_server) =
        spawn_hanging_subscription_relay(Duration::from_millis(100));
    let mut shutdown_connector = NostrConnector::new();
    shutdown_connector
        .configure(local_config_value(&shutdown_url))
        .await
        .expect("shutdown connector should configure");
    shutdown_connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [8_u8; 32],
            nonce: [4_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("shutdown handshake should succeed");
    shutdown_connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("full-proof-active-shutdown"),
            topics: vec![EVENT_INBOUND_DM.into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(25),
            window_size: Some(16),
            capability_token: None,
        })
        .await
        .expect("active shutdown subscribe should be accepted");
    fcp_async_core::time::sleep(Duration::from_millis(20)).await;
    shutdown_connector
        .shutdown(fcp_prelude::ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 100,
            drain: false,
            reason: Some("active shutdown proof".into()),
        })
        .await
        .expect("active shutdown should abort subscription task");
    let shutdown_frames = shutdown_server
        .join()
        .expect("hanging shutdown relay should finish");
    log.record(
        "full_proof_active_shutdown",
        json!({
            "test_step": "active_shutdown",
            "relay_frame_count": shutdown_frames.len(),
            "diagnostics": shutdown_connector.subscription_diagnostics(),
        }),
    );
    assert!(
        shutdown_connector
            .subscription_diagnostics()
            .iter()
            .any(|entry| {
                entry["stage"] == "cancellation"
                    && entry["cancellation_reason"] == "shutdown"
                    && entry["shutdown_result"] == "task_abort_requested"
            })
    );

    let serialized_log =
        serde_json::to_string(&log.entries).expect("full proof log should serialize");
    for forbidden in [
        TEST_SECRET_KEY_HEX,
        RECIPIENT_SCALAR_HEX,
        SENDER_B_SCALAR_HEX,
        SENDER_C_SCALAR_HEX,
        SENDER_D_SCALAR_HEX,
        SENDER_E_SCALAR_HEX,
        accepted_plaintext,
        sender_rate_plaintext,
        blocked_plaintext,
        wrong_target_plaintext,
        invalid_signature_plaintext,
        accepted_b_plaintext,
        accepted_d_plaintext,
        global_rate_plaintext,
        reply_plaintext,
    ] {
        assert!(
            !serialized_log.contains(forbidden),
            "full proof transcript leaked forbidden fixture value: {forbidden}"
        );
    }
    assert!(
        log.entries.len() >= 7,
        "full e2e proof should emit a detailed JSONL-style transcript"
    );
}

struct IdentityPublishCase {
    step_name: &'static str,
    input_format_class: &'static str,
    secret_key_input: String,
    content: &'static str,
}

struct IdentityLogStep<'a> {
    step_name: &'static str,
    input_format_class: &'static str,
    normalized_identity: Option<&'a str>,
    operation: &'static str,
    expected_result: &'static str,
    actual_result: &'static str,
    elapsed_ms: u64,
    extra: Value,
}

fn log_identity_step(log: &mut E2eLog, step: IdentityLogStep<'_>) {
    let mut detail = json!({
        "step_name": step.step_name,
        "input_format_class": step.input_format_class,
        "normalized_identity": step.normalized_identity,
        "operation": step.operation,
        "expected_result": step.expected_result,
        "actual_result": step.actual_result,
        "elapsed_ms": step.elapsed_ms,
    });
    if let (Some(detail), Value::Object(extra)) = (detail.as_object_mut(), step.extra) {
        detail.extend(extra);
    }
    log.record("identity_normalization_step", detail);
}

fn publish_acceptance_status(output: &Value) -> &'static str {
    if output["accepted_relays"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        "accepted"
    } else {
        "not_accepted"
    }
}

fn configure_and_publish_identity(
    log: &mut E2eLog,
    relay_url: String,
    server: JoinHandle<Vec<Value>>,
    case: IdentityPublishCase,
) -> (NostrClient, String) {
    let start = Instant::now();
    let client = NostrClient::new(&local_config_with_secret(relay_url, case.secret_key_input))
        .expect("identity config should be accepted");
    let publish = block_on(client.publish_note(&json!({ "content": case.content })))
        .expect("identity-configured client should publish");
    let frames = server
        .join()
        .expect("identity publish relay thread should finish");
    let normalized_identity = client.public_key_hex().to_string();
    log_identity_step(
        log,
        IdentityLogStep {
            step_name: case.step_name,
            input_format_class: case.input_format_class,
            normalized_identity: Some(&normalized_identity),
            operation: "nostr.notes.publish",
            expected_result: "accepted",
            actual_result: publish_acceptance_status(&publish),
            elapsed_ms: elapsed_ms(start),
            extra: json!({ "server_frame_count": frames.len() }),
        },
    );
    (client, normalized_identity)
}

fn log_target_normalization(log: &mut E2eLog, normalized_identity: &str, npub: &str) {
    for (input_format_class, target_input) in [
        ("raw_hex_pubkey", normalized_identity.to_string()),
        ("nip19_npub", npub.to_string()),
        ("nostr_npub", format!("nostr:{npub}")),
    ] {
        let start = Instant::now();
        let normalized_target =
            normalize_public_key_input(&target_input).expect("target should normalize");
        assert_eq!(
            normalized_target.canonical_public_key_hex(),
            normalized_identity
        );
        log_identity_step(
            log,
            IdentityLogStep {
                step_name: "outbound-target-normalization",
                input_format_class,
                normalized_identity: Some(normalized_target.canonical_public_key_hex()),
                operation: "normalize_public_key_input",
                expected_result: "canonical_hex",
                actual_result: "canonical_hex",
                elapsed_ms: elapsed_ms(start),
                extra: json!({}),
            },
        );
    }
}

fn log_bad_identity_inputs(log: &mut E2eLog, nsec: &str, npub: String) {
    let start = Instant::now();
    let bad_key_error = NostrClient::new(&local_config_with_secret(
        "wss://relay.example.com".into(),
        npub,
    ))
    .expect_err("npub must not configure as a secret key");
    log_identity_step(
        log,
        IdentityLogStep {
            step_name: "bad-key-failure",
            input_format_class: "wrong_nip19_prefix",
            normalized_identity: None,
            operation: "NostrClient::new",
            expected_result: "rejected",
            actual_result: "rejected",
            elapsed_ms: elapsed_ms(start),
            extra: json!({ "error_class": bad_key_error.error_code() }),
        },
    );

    let start = Instant::now();
    let bad_target_error =
        normalize_public_key_input(nsec).expect_err("nsec must not normalize as a public key");
    log_identity_step(
        log,
        IdentityLogStep {
            step_name: "bad-target-failure",
            input_format_class: "wrong_nip19_prefix",
            normalized_identity: None,
            operation: "normalize_public_key_input",
            expected_result: "rejected",
            actual_result: "rejected",
            elapsed_ms: elapsed_ms(start),
            extra: json!({ "error_class": bad_target_error.error_code() }),
        },
    );
}

fn log_identity_shutdown(log: &mut E2eLog, normalized_identity: &str, clients: &[&NostrClient]) {
    let start = Instant::now();
    for client in clients {
        client.shutdown();
    }
    log_identity_step(
        log,
        IdentityLogStep {
            step_name: "shutdown",
            input_format_class: "configured_clients",
            normalized_identity: Some(normalized_identity),
            operation: "NostrClient::shutdown",
            expected_result: "completed",
            actual_result: "completed",
            elapsed_ms: elapsed_ms(start),
            extra: json!({ "client_count": clients.len() }),
        },
    );
}

struct DmLogStep<'a> {
    step: &'static str,
    recipient_format: &'static str,
    normalized_recipient: Option<&'a str>,
    event_kind: Option<u64>,
    relay: Option<&'a str>,
    result: &'static str,
    retryable: Option<bool>,
    elapsed_ms: u64,
    extra: Value,
}

fn log_dm_step(log: &mut E2eLog, step: DmLogStep<'_>) {
    let mut detail = json!({
        "step": step.step,
        "recipient_format": step.recipient_format,
        "normalized_recipient": step.normalized_recipient,
        "event_kind": step.event_kind,
        "relay": step.relay,
        "result": step.result,
        "retryable": step.retryable,
        "elapsed_ms": step.elapsed_ms,
    });
    if let (Some(detail), Value::Object(extra)) = (detail.as_object_mut(), step.extra) {
        detail.extend(extra);
    }
    log.record("dm_send_step", detail);
}

fn recipient_public_key_hex() -> String {
    NostrClient::new(&local_config_with_secret(
        "wss://relay.example.com".into(),
        RECIPIENT_SCALAR_HEX.into(),
    ))
    .expect("recipient key fixture should configure")
    .public_key_hex()
    .to_string()
}

fn connector_public_key_hex() -> String {
    NostrClient::new(&local_config("wss://relay.example.com".into()))
        .expect("connector key fixture should configure")
        .public_key_hex()
        .to_string()
}

fn sender_public_key_hex(secret_key_hex: &str) -> String {
    NostrKeyMaterial::from_secret_key_input(secret_key_hex)
        .expect("sender key fixture should configure")
        .public_key_hex()
        .to_string()
}

fn inbound_dm_event_from_sender(secret_key_hex: &str, plaintext: &str) -> Value {
    let sender = NostrKeyMaterial::from_secret_key_input(secret_key_hex)
        .expect("sender key fixture should configure");
    build_nip04_dm_event(
        sender.secret_key(),
        sender.public_key_hex(),
        &connector_public_key_hex(),
        plaintext,
        None,
    )
    .expect("inbound DM event should build")
}

fn inbound_dm_event_from_sender_to_self(secret_key_hex: &str, plaintext: &str) -> Value {
    let sender = NostrKeyMaterial::from_secret_key_input(secret_key_hex)
        .expect("sender key fixture should configure");
    build_nip04_dm_event(
        sender.secret_key(),
        sender.public_key_hex(),
        sender.public_key_hex(),
        plaintext,
        None,
    )
    .expect("wrong-target inbound DM event should build")
}

fn inbound_dm_event_for_connector(plaintext: &str) -> Value {
    inbound_dm_event_from_sender(RECIPIENT_SCALAR_HEX, plaintext)
}

fn inbound_dm_event_for_wrong_target(plaintext: &str) -> Value {
    inbound_dm_event_from_sender_to_self(RECIPIENT_SCALAR_HEX, plaintext)
}

async fn wait_for_subscription_shutdown(
    connector: &NostrConnector,
    stream_id: &str,
    min_events: usize,
) {
    let mut saw_shutdown = false;
    for _ in 0..150 {
        saw_shutdown = connector
            .subscription_diagnostics()
            .iter()
            .any(|entry| entry["stream_id"] == stream_id && entry["stage"] == "shutdown");
        if saw_shutdown && connector.subscription_events().len() >= min_events {
            return;
        }
        fcp_async_core::time::sleep(Duration::from_millis(10)).await;
    }
    let event_count = connector.subscription_events().len();
    let diagnostics = serde_json::to_string(&connector.subscription_diagnostics())
        .unwrap_or_else(|error| format!("diagnostic serialization failed: {error}"));
    assert!(
        saw_shutdown && event_count >= min_events,
        "subscription did not reach shutdown with {min_events} accepted event(s); events={event_count}, diagnostics={diagnostics}"
    );
}

fn assert_dm_reply_event_frame(frame: &Value, normalized_recipient: &str, reply_to_event_id: &str) {
    assert_eq!(frame[0], "EVENT");
    let event = &frame[1];
    assert_eq!(event["kind"], NIP04_KIND_ENCRYPTED_DM);
    let tags = event["tags"]
        .as_array()
        .expect("DM reply event should include tags");
    assert!(
        tags.iter()
            .any(|tag| tag == &json!(["p", normalized_recipient]))
    );
    assert!(
        tags.iter()
            .any(|tag| tag == &json!(["e", reply_to_event_id]))
    );
    let content = event["content"]
        .as_str()
        .expect("DM relay event should include encrypted content");
    assert!(content.contains("?iv="));
    assert!(!content.contains(TEST_DM_PLAINTEXT));
}

fn dm_acceptance_status(output: &Value) -> &'static str {
    if output["accepted_relays"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        "accepted"
    } else if output["rejected_relays"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        "rejected"
    } else {
        "not_delivered"
    }
}

fn assert_dm_event_frame(frame: &Value, normalized_recipient: &str) {
    assert_eq!(frame[0], "EVENT");
    let event = &frame[1];
    assert_eq!(event["kind"], NIP04_KIND_ENCRYPTED_DM);
    assert_eq!(event["tags"], json!([["p", normalized_recipient]]));
    let content = event["content"]
        .as_str()
        .expect("DM relay event should include encrypted content");
    assert!(content.contains("?iv="));
    assert!(!content.contains(TEST_DM_PLAINTEXT));
}

#[test]
#[allow(clippy::too_many_lines)]
fn outbound_dm_loopback_e2e_logs_success_failures_circuit_partial_and_shutdown() {
    let mut log = E2eLog::default();
    let normalized_recipient = recipient_public_key_hex();
    let recipient_npub =
        encode_public_key_npub(&normalized_recipient).expect("recipient npub should encode");

    let (success_url, success_server) = spawn_publish_ack_relay();
    let success_relay = format!("{success_url}/");
    let success_client =
        NostrClient::new(&local_config(success_url)).expect("success client should configure");
    let start = Instant::now();
    let success = block_on(success_client.send_dm(&json!({
        "recipient": recipient_npub,
        "plaintext": TEST_DM_PLAINTEXT
    })))
    .expect("DM publish should complete against loopback relay");
    let success_frames = success_server
        .join()
        .expect("success relay thread should finish");
    assert_eq!(success_frames.len(), 1);
    assert_dm_event_frame(&success_frames[0], &normalized_recipient);
    assert_eq!(success["event_kind"], NIP04_KIND_ENCRYPTED_DM);
    assert_eq!(success["recipient_pubkey_hex"], normalized_recipient);
    assert!(success.get("event").is_none());
    assert!(success.get("content").is_none());
    log_dm_step(
        &mut log,
        DmLogStep {
            step: "successful-encrypted-dm-publish",
            recipient_format: "nip19_npub",
            normalized_recipient: Some(&normalized_recipient),
            event_kind: Some(NIP04_KIND_ENCRYPTED_DM),
            relay: Some(&success_relay),
            result: dm_acceptance_status(&success),
            retryable: Some(false),
            elapsed_ms: elapsed_ms(start),
            extra: json!({
                "event_id": success["event_id"],
                "accepted_count": success["accepted_relays"].as_array().map_or(0, Vec::len),
                "rejected_count": success["rejected_relays"].as_array().map_or(0, Vec::len),
            }),
        },
    );

    let start = Instant::now();
    let invalid_recipient = block_on(success_client.send_dm(&json!({
        "recipient": "not-a-pubkey",
        "plaintext": TEST_DM_PLAINTEXT
    })))
    .expect_err("invalid recipient should fail before relay fan-out");
    log_dm_step(
        &mut log,
        DmLogStep {
            step: "invalid-recipient",
            recipient_format: "invalid",
            normalized_recipient: None,
            event_kind: None,
            relay: None,
            result: "rejected",
            retryable: Some(false),
            elapsed_ms: elapsed_ms(start),
            extra: json!({ "error_class": invalid_recipient.error_code() }),
        },
    );

    let (reject_url, reject_server) = spawn_publish_reject_relay("blocked: policy");
    let reject_relay = format!("{reject_url}/");
    let reject_client =
        NostrClient::new(&local_config(reject_url)).expect("reject client should configure");
    let start = Instant::now();
    let rejected = block_on(reject_client.send_dm(&json!({
        "target": normalized_recipient.clone(),
        "content": TEST_DM_PLAINTEXT
    })))
    .expect("relay rejection should return structured diagnostics");
    let reject_frames = reject_server
        .join()
        .expect("reject relay thread should finish");
    assert_dm_event_frame(&reject_frames[0], &normalized_recipient);
    log_dm_step(
        &mut log,
        DmLogStep {
            step: "relay-rejection",
            recipient_format: "raw_hex_pubkey",
            normalized_recipient: Some(&normalized_recipient),
            event_kind: Some(NIP04_KIND_ENCRYPTED_DM),
            relay: Some(&reject_relay),
            result: dm_acceptance_status(&rejected),
            retryable: rejected["rejected_relays"][0]["retryable"].as_bool(),
            elapsed_ms: elapsed_ms(start),
            extra: json!({ "error_class": "relay_rejected" }),
        },
    );

    let (timeout_url, timeout_server) = spawn_silent_publish_relay(Duration::from_millis(150));
    let timeout_relay = format!("{timeout_url}/");
    let mut timeout_config = local_config(timeout_url);
    timeout_config.request_timeout_ms = 50;
    let timeout_client =
        NostrClient::new(&timeout_config).expect("timeout client should configure");
    let start = Instant::now();
    let timed_out = block_on(timeout_client.send_dm(&json!({
        "recipient_pubkey": format!("nostr:{}", encode_public_key_npub(&normalized_recipient).unwrap()),
        "plaintext": TEST_DM_PLAINTEXT
    })))
    .expect("relay timeout should return structured diagnostics");
    let timeout_frames = timeout_server
        .join()
        .expect("timeout relay thread should finish");
    assert_dm_event_frame(&timeout_frames[0], &normalized_recipient);
    log_dm_step(
        &mut log,
        DmLogStep {
            step: "relay-timeout",
            recipient_format: "nostr_npub",
            normalized_recipient: Some(&normalized_recipient),
            event_kind: Some(NIP04_KIND_ENCRYPTED_DM),
            relay: Some(&timeout_relay),
            result: dm_acceptance_status(&timed_out),
            retryable: timed_out["rejected_relays"][0]["retryable"].as_bool(),
            elapsed_ms: elapsed_ms(start),
            extra: json!({ "error_class": "timeout" }),
        },
    );

    let (closing_url, closing_server) = spawn_closing_publish_relay(1);
    let (partial_ack_url, partial_ack_server) = spawn_publish_ack_relay_connections(2);
    let partial_ack_relay = format!("{partial_ack_url}/");
    let partial_client = NostrClient::new(&local_multi_relay_config_with_threshold(
        vec![closing_url.clone(), partial_ack_url],
        1,
    ))
    .expect("partial client should configure");
    let start = Instant::now();
    let partial = block_on(partial_client.send_dm(&json!({
        "recipient": normalized_recipient.clone(),
        "plaintext": TEST_DM_PLAINTEXT
    })))
    .expect("partial multi-relay send should return structured diagnostics");
    assert_eq!(partial["accepted_relays"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(partial["rejected_relays"].as_array().map_or(0, Vec::len), 1);
    log_dm_step(
        &mut log,
        DmLogStep {
            step: "multi-relay-partial-success",
            recipient_format: "raw_hex_pubkey",
            normalized_recipient: Some(&normalized_recipient),
            event_kind: Some(NIP04_KIND_ENCRYPTED_DM),
            relay: Some(&partial_ack_relay),
            result: "partial_success",
            retryable: partial["rejected_relays"][0]["retryable"].as_bool(),
            elapsed_ms: elapsed_ms(start),
            extra: json!({
                "accepted_count": partial["accepted_relays"].as_array().map_or(0, Vec::len),
                "rejected_count": partial["rejected_relays"].as_array().map_or(0, Vec::len),
            }),
        },
    );

    let start = Instant::now();
    let skipped = block_on(partial_client.send_dm(&json!({
        "recipient": normalized_recipient.clone(),
        "plaintext": TEST_DM_PLAINTEXT
    })))
    .expect("open circuit should skip failed relay and continue other relays");
    assert_eq!(skipped["accepted_relays"].as_array().map_or(0, Vec::len), 1);
    assert!(
        skipped["rejected_relays"]
            .as_array()
            .unwrap()
            .iter()
            .any(|relay| relay["error"] == "relay circuit breaker open")
    );
    let skipped_relay = format!("{closing_url}/");
    log_dm_step(
        &mut log,
        DmLogStep {
            step: "circuit-open-relay-skipped",
            recipient_format: "raw_hex_pubkey",
            normalized_recipient: Some(&normalized_recipient),
            event_kind: Some(NIP04_KIND_ENCRYPTED_DM),
            relay: Some(&skipped_relay),
            result: "skipped",
            retryable: Some(true),
            elapsed_ms: elapsed_ms(start),
            extra: json!({
                "accepted_count": skipped["accepted_relays"].as_array().map_or(0, Vec::len),
                "rejected_count": skipped["rejected_relays"].as_array().map_or(0, Vec::len),
            }),
        },
    );

    let closing_frames = closing_server
        .join()
        .expect("closing relay thread should finish");
    let partial_frames = partial_ack_server
        .join()
        .expect("partial ack relay thread should finish");
    assert_dm_event_frame(&closing_frames[0], &normalized_recipient);
    assert_eq!(partial_frames.len(), 2);
    for frame in &partial_frames {
        assert_dm_event_frame(frame, &normalized_recipient);
    }

    let start = Instant::now();
    for client in [
        &success_client,
        &reject_client,
        &timeout_client,
        &partial_client,
    ] {
        client.shutdown();
    }
    log_dm_step(
        &mut log,
        DmLogStep {
            step: "shutdown",
            recipient_format: "configured_clients",
            normalized_recipient: Some(&normalized_recipient),
            event_kind: None,
            relay: None,
            result: "completed",
            retryable: Some(false),
            elapsed_ms: elapsed_ms(start),
            extra: json!({ "client_count": 4 }),
        },
    );

    let serialized_log = serde_json::to_string(&log.entries).expect("e2e log should serialize");
    assert!(!serialized_log.contains(TEST_SECRET_KEY_HEX));
    assert!(!serialized_log.contains(RECIPIENT_SCALAR_HEX));
    assert!(!serialized_log.contains(TEST_DM_PLAINTEXT));
    assert!(
        !serde_json::to_string(&success)
            .unwrap()
            .contains(TEST_DM_PLAINTEXT)
    );
    assert!(
        log.entries.len() >= 7,
        "e2e should log success, failures, partial delivery, circuit skip, and shutdown"
    );
}

#[test]
fn identity_normalization_loopback_e2e_logs_all_setup_and_error_paths() {
    let mut log = E2eLog::default();
    let nsec = encode_secret_key_nsec(TEST_SECRET_KEY_HEX).expect("test nsec should encode");

    let (hex_url, hex_server) = spawn_publish_ack_relay();
    let (hex_client, normalized_identity) = configure_and_publish_identity(
        &mut log,
        hex_url,
        hex_server,
        IdentityPublishCase {
            step_name: "configure-from-hex",
            input_format_class: "raw_hex_secret",
            secret_key_input: TEST_SECRET_KEY_HEX.into(),
            content: "from hex",
        },
    );

    let (nsec_url, nsec_server) = spawn_publish_ack_relay();
    let (nsec_client, nsec_identity) = configure_and_publish_identity(
        &mut log,
        nsec_url,
        nsec_server,
        IdentityPublishCase {
            step_name: "configure-from-nsec",
            input_format_class: "nip19_nsec",
            secret_key_input: nsec.clone(),
            content: "from nsec",
        },
    );
    assert_eq!(nsec_identity, normalized_identity);

    let npub = encode_public_key_npub(&normalized_identity).expect("test npub should encode");
    log_target_normalization(&mut log, &normalized_identity, &npub);
    log_bad_identity_inputs(&mut log, &nsec, npub);
    log_identity_shutdown(&mut log, &normalized_identity, &[&hex_client, &nsec_client]);

    let serialized_log = serde_json::to_string(&log.entries).expect("e2e log should serialize");
    assert!(!serialized_log.contains(TEST_SECRET_KEY_HEX));
    assert!(!serialized_log.contains(&nsec));
    assert!(
        log.entries.len() >= 8,
        "e2e should log configure, target normalization, failure, and shutdown steps"
    );
}

#[test]
fn repeated_loopback_failures_open_circuit_and_skip_next_attempt() {
    let mut log = E2eLog::default();
    let (relay_url, server) = spawn_closing_publish_relay(5);
    log.record("closing_relay_started", json!({ "relay_url": relay_url }));
    let client = NostrClient::new(&local_config(relay_url)).expect("local harness config accepted");

    for attempt in 1..=5 {
        let output =
            block_on(client.publish_note(&json!({ "content": format!("attempt {attempt}") })))
                .expect("publish should return structured per-relay rejection");
        log.record(
            "publish_failure_recorded",
            json!({
                "attempt": attempt,
                "output": output,
            }),
        );
    }
    let accepted_frames = server.join().expect("closing relay thread should finish");
    log.record("closing_relay_frames", json!(accepted_frames));

    let skipped = block_on(client.publish_note(&json!({ "content": "skipped by circuit" })))
        .expect("open circuit should return structured skip output");
    log.record("publish_skipped_by_circuit", skipped.clone());

    assert_eq!(
        skipped["rejected_relays"][0]["error"],
        "relay circuit breaker open"
    );
    assert_eq!(skipped["relay_resilience"][0]["circuit_state"], "open");
    assert_eq!(skipped["relay_resilience"][0]["failure_count"], 5);
    assert_eq!(skipped["relay_resilience"][0]["skipped_count"], 1);
}

#[test]
fn opened_circuit_half_open_probe_recovers_against_same_loopback_relay() {
    let mut log = E2eLog::default();
    let (relay_url, server) = spawn_recovering_publish_relay(5);
    let normalized_relay = format!("{relay_url}/");
    log.record(
        "recovering_relay_started",
        json!({ "relay_url": relay_url }),
    );
    let client =
        NostrClient::new(&local_recovery_config(relay_url)).expect("local harness config accepted");

    for attempt in 1..=5 {
        let output = block_on(
            client.publish_note(&json!({ "content": format!("recovery attempt {attempt}") })),
        )
        .expect("publish should record pre-recovery failure");
        log.record(
            "recovery_failure_recorded",
            json!({
                "operation": "nostr.notes.publish",
                "attempt": attempt,
                "normalized_relay": normalized_relay,
                "circuit_state": output["relay_resilience"][0]["circuit_state"],
                "retryable": output["rejected_relays"][0]["retryable"],
                "result": "failure",
            }),
        );
    }

    let recovered = block_on(client.publish_note(&json!({ "content": "half-open recovery" })))
        .expect("half-open publish should recover");
    let frames = server
        .join()
        .expect("recovering relay thread should finish");
    log.record("recovery_relay_frames", json!(frames));
    log.record(
        "recovery_attempt_summary",
        json!({
            "operation": "nostr.notes.publish",
            "attempt": 6,
            "normalized_relay": normalized_relay,
            "circuit_state": recovered["relay_resilience"][0]["circuit_state"],
            "latency_ms": recovered["relay_resilience"][0]["average_latency_ms"],
            "retryable": false,
            "result": "success",
            "shutdown_confirmation": true,
        }),
    );

    assert_eq!(recovered["accepted_relays"][0]["relay"], normalized_relay);
    assert_eq!(recovered["relay_resilience"][0]["circuit_state"], "closed");
    assert_eq!(recovered["relay_resilience"][0]["success_count"], 1);
    assert_eq!(recovered["relay_resilience"][0]["failure_count"], 5);
}
