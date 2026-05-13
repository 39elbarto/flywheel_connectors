#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use fcp_prelude::FcpError;
use fcp_zalo::ZaloConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const ACCESS_TOKEN: &str = "local-token";

struct RecordedRequest {
    label: &'static str,
    request_line: String,
    body: String,
}

struct LoopbackResponse {
    label: &'static str,
    status: u16,
    body: &'static str,
}

impl LoopbackResponse {
    const fn json(label: &'static str, status: u16, body: &'static str) -> Self {
        Self {
            label,
            status,
            body,
        }
    }
}

fn spawn_loopback_server(
    responses: Vec<LoopbackResponse>,
) -> (String, Receiver<RecordedRequest>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
    let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
    let (tx, rx) = mpsc::channel();
    let join = thread::spawn(move || {
        for response in responses {
            let (mut stream, _peer) = listener.accept().expect("accept loopback request");
            let (request_line, body) = read_http_request(&mut stream);
            tx.send(RecordedRequest {
                label: response.label,
                request_line,
                body,
            })
            .expect("record request");

            let header = format!(
                "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.status,
                response.body.len()
            );
            stream
                .write_all(header.as_bytes())
                .expect("write response header");
            stream
                .write_all(response.body.as_bytes())
                .expect("write response body");
        }
    });
    (base_url, rx, join)
}

fn read_http_request(stream: &mut TcpStream) -> (String, String) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read request");
        assert!(read > 0, "request stream ended before headers");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };

    let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buffer.len().saturating_sub(body_start) < content_length {
        let read = stream.read(&mut chunk).expect("read body");
        assert!(read > 0, "request stream ended before body complete");
        buffer.extend_from_slice(&chunk[..read]);
    }

    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let body =
        String::from_utf8_lossy(&buffer[body_start..body_start + content_length]).to_string();
    (request_line, body)
}

async fn configured_connector(base_url: &str) -> ZaloConnector {
    let mut connector = ZaloConnector::new();
    connector
        .handle_configure(json!({
            "access_token": ACCESS_TOKEN,
            "base_url": base_url,
            "request_timeout_ms": 1_000,
            "webhook_verify_challenge": "local-secret",
            "webhook_path": "/zalo/inbound",
            "allowed_sender_ids": ["sender-1"],
            "allowed_chat_ids": ["chat-1"],
            "rate_limit_window_ms": 60_000,
            "rate_limit_max": 100,
            "replay_cache_entries": 32
        }))
        .await
        .expect("configure should accept loopback base URL");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should complete");
    connector
}

fn recv_request(
    requests: &Receiver<RecordedRequest>,
    expected_label: &'static str,
) -> RecordedRequest {
    let request = requests
        .recv_timeout(Duration::from_secs(1))
        .expect("loopback request should be recorded");
    assert_eq!(request.label, expected_label);
    request
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_loopback_covers_bot_api_request_paths_and_errors() {
    let (base_url, requests, join) = spawn_loopback_server(vec![
        LoopbackResponse::json(
            "send_message",
            200,
            r#"{"ok":true,"result":{"message_id":"msg-local-1"}}"#,
        ),
        LoopbackResponse::json(
            "poll_updates",
            200,
            r#"{"ok":true,"result":[{"update_id":80,"message":{"message_id":"msg-80","from":{"id":"sender-1"},"chat":{"id":"chat-1","type":"private"},"text":"hello from poll"}}]}"#,
        ),
        LoopbackResponse::json(
            "auth_failure",
            200,
            r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
        ),
    ]);
    let connector = configured_connector(&base_url).await;

    let sent = connector
        .handle_invoke(json!({
            "operation_id": "zalo.messages.send",
            "input": { "recipient_id": "chat-1", "message": "hello local" }
        }))
        .await
        .expect("sendMessage should succeed against loopback");
    assert_eq!(sent["result"]["message_id"], "msg-local-1");
    let send_request = recv_request(&requests, "send_message");
    assert_eq!(
        send_request.request_line,
        "POST /botlocal-token/sendMessage HTTP/1.1"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&send_request.body).expect("send body JSON"),
        json!({ "chat_id": "chat-1", "text": "hello local" })
    );

    let updates = connector
        .handle_invoke(json!({
            "operation_id": "zalo.updates.poll",
            "input": { "offset": 70, "timeout_seconds": 0 }
        }))
        .await
        .expect("polling response should normalize authorized events");
    assert_eq!(updates["events"][0]["topic"], "zalo.message.text");
    assert_eq!(updates["events"][0]["policy_reason"], "sender_allowed");
    assert_eq!(updates["cursor"]["next_offset"], json!(81));
    let poll_request = recv_request(&requests, "poll_updates");
    assert_eq!(
        poll_request.request_line,
        "POST /botlocal-token/getUpdates HTTP/1.1"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&poll_request.body).expect("poll body JSON"),
        json!({ "timeout": "0", "offset": 70 })
    );

    let auth_failure = connector
        .handle_invoke(json!({ "operation_id": "zalo.self.get_me" }))
        .await
        .expect_err("provider auth failure should map to external error");
    assert!(matches!(
        auth_failure,
        FcpError::External {
            status_code: Some(401),
            retryable: false,
            ..
        }
    ));
    let auth_request = recv_request(&requests, "auth_failure");
    assert_eq!(
        auth_request.request_line,
        "POST /botlocal-token/getMe HTTP/1.1"
    );

    join.join().expect("loopback server should exit");
}

#[test]
fn local_non_mock_suite_class_is_declared() {
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
}
