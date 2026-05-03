//! Slack connector integration tests (flywheel_connectors-i1b.6).
//!
//! Deterministic integration tests using wiremock plus structured HTTP fakes
//! to exercise the Slack Web API transport more realistically.
//! No real API calls. Covers:
//! - Messages (post, reply, history, search)
//! - Channels (list, set topic)
//! - Users (get info)
//! - Files (upload, download/info)
//! - Reactions (add)
//! - Error taxonomy (`not_authed`/`channel_not_found`/`ratelimited` -> `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]

use asupersync::Cx;
use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::websocket::{
    CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
};
use chrono::{Duration, Utc};
use fcp_async_core::channel::oneshot;
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use std::collections::HashMap;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::thread;
use std::time::Duration as StdDuration;
use url::form_urlencoded;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_slack::client::SlackClient;
use fcp_slack::connector::SlackConnector;

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> fcp_core::CapabilityToken {
    generate_valid_token_for_operation(signing_key, cap, cap)
}

fn generate_valid_token_for_operation(
    signing_key: &Ed25519SigningKey,
    cap: &str,
    operation: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .constraints_cbor(&cbor)
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut SlackConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

async fn setup_configure(connector: &mut SlackConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "token": "xoxb-test-token-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard Slack message response.
fn slack_message(text: &str, ts: &str) -> serde_json::Value {
    json!({
        "type": "message",
        "user": "U01234567",
        "text": text,
        "ts": ts
    })
}

/// Standard Slack channel response.
fn slack_channel(id: &str, name: &str) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "is_channel": true,
        "is_group": false,
        "is_im": false,
        "is_archived": false,
        "is_private": false,
        "num_members": 42
    })
}

#[derive(Clone, Debug)]
struct StructuredHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct StructuredHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl StructuredHttpResponse {
    fn json(status: u16, body: serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_string().into_bytes(),
        }
    }
}

struct StructuredFakeHttpServer {
    base_url: String,
    requests: Arc<Mutex<Vec<StructuredHttpRequest>>>,
    _join: thread::JoinHandle<()>,
}

impl StructuredFakeHttpServer {
    fn spawn<F>(expected_requests: usize, responder: F) -> Self
    where
        F: Fn(usize, &StructuredHttpRequest) -> StructuredHttpResponse + Send + Sync + 'static,
    {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind fake http server");
        let addr = listener.local_addr().expect("fake http server addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let responder = Arc::new(responder);

        let join = thread::spawn(move || {
            for idx in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept fake http connection");
                let request = read_structured_http_request(&mut stream);
                let response = responder(idx, &request);
                requests_for_thread
                    .lock()
                    .expect("lock fake http requests")
                    .push(request);
                write_structured_http_response(&mut stream, response);
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            requests,
            _join: join,
        }
    }

    fn url(&self) -> &str {
        &self.base_url
    }

    fn requests(&self) -> Vec<StructuredHttpRequest> {
        self.requests
            .lock()
            .expect("lock fake http requests")
            .clone()
    }
}

fn read_structured_http_request(stream: &mut std::net::TcpStream) -> StructuredHttpRequest {
    let mut buffer = Vec::new();
    let mut temp = [0u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut temp).expect("read fake http request");
        assert!(read > 0, "unexpected EOF while reading fake http request");
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let header_text = std::str::from_utf8(&buffer[..header_end]).expect("request headers utf8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .expect("request method")
        .to_string();
    let path = request_line_parts.next().expect("request path").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').expect("header separator");
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut temp).expect("read fake http body");
        assert!(read > 0, "unexpected EOF while reading fake http body");
        body.extend_from_slice(&temp[..read]);
    }
    body.truncate(content_length);

    StructuredHttpRequest {
        method,
        path,
        headers,
        body,
    }
}

fn write_structured_http_response(
    stream: &mut std::net::TcpStream,
    response: StructuredHttpResponse,
) {
    let reason = match response.status {
        200 => "OK",
        429 => "Too Many Requests",
        _ => "OK",
    };
    let mut raw = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.body.len()
    );
    for (name, value) in response.headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str("\r\n");
    stream
        .write_all(raw.as_bytes())
        .expect("write fake http response headers");
    stream
        .write_all(&response.body)
        .expect("write fake http response body");
}

type TestServerWebSocket = ServerWebSocket<TcpStream>;

async fn read_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    const MAX_HEADERS: usize = 16 * 1024;

    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 256];

    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before websocket handshake completed",
            ));
        }

        buf.extend_from_slice(&temp[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake headers too large",
            ));
        }
    }
}

async fn accept_test_websocket(mut stream: TcpStream) -> TestServerWebSocket {
    let request = read_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    WebSocketAcceptor::new()
        .accept(&Cx::for_testing(), &request, stream)
        .await
        .expect("accept websocket")
}

async fn send_json_frame(ws: &mut TestServerWebSocket, value: serde_json::Value, context: &str) {
    ws.send(&Cx::for_testing(), ServerWsMessage::text(value.to_string()))
        .await
        .expect(context);
}

async fn recv_text_frame(ws: &mut TestServerWebSocket, context: &str) -> Option<String> {
    match ws.recv(&Cx::for_testing()).await {
        Ok(Some(ServerWsMessage::Text(text))) => Some(text),
        Ok(Some(other)) => panic!("expected text frame for {context}, got {other:?}"),
        Ok(None) => None,
        Err(err) => panic!("{context}: {err}"),
    }
}

async fn close_test_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws.close(&Cx::for_testing(), CloseReason::normal()).await;
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn post_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.post_message.happy_path");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer xoxb-test-token-xyz")
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack post body json");
        assert_eq!(body["channel"], "C01234567");
        assert_eq!(body["text"], "Hello from FCP!");
        StructuredHttpResponse::json(
            200,
            json!({
                "ok": true,
                "channel": "C01234567",
                "ts": "1234567890.123456",
                "message": slack_message("Hello from FCP!", "1234567890.123456")
            }),
        )
    });

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "Hello from FCP!" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["message"]["text"], "Hello from FCP!");
    assert_eq!(result["message"]["ts"], "1234567890.123456");
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn reply_thread_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.reply_thread.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.654321",
            "message": {
                "type": "message",
                "user": "U01234567",
                "text": "Thread reply",
                "ts": "1234567890.654321",
                "thread_ts": "1234567890.123456"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "Thread reply",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["message"]["text"], "Thread reply");
    assert_eq!(result["message"]["thread_ts"], "1234567890.123456");
}

#[fcp_async_core::runtime::test]
async fn get_channel_history_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.channel_history.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": [
                slack_message("First message", "1234567890.111111"),
                slack_message("Second message", "1234567890.222222")
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C01234567", "limit": 10 },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["text"], "First message");
    assert_eq!(messages[1]["text"], "Second message");
}

#[fcp_async_core::runtime::test]
async fn search_messages_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.search_messages.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search.messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": {
                "total": 1,
                "matches": [slack_message("deployment update", "1234567890.333333")]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.search_messages"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.search_messages");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.search_messages",
            "input": { "query": "deployment in:#general" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["total"], 1);
}

#[fcp_async_core::runtime::test]
async fn list_channels_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.list_channels.happy_path");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "GET");
        let (path, query) = request
            .path
            .split_once('?')
            .expect("list_channels should include query params");
        assert_eq!(path, "/conversations.list");
        let query_params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            query_params.get("types").map(String::as_str),
            Some("public_channel")
        );
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer xoxb-test-token-xyz")
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert!(
            request.headers.get("content-type").is_none(),
            "GET list_channels should not send a content-type header"
        );
        StructuredHttpResponse::json(
            200,
            json!({
                "ok": true,
                "channels": [
                    slack_channel("C01234567", "general"),
                    slack_channel("C07654321", "random")
                ]
            }),
        )
    });

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.list_channels"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let token = generate_valid_token(&key, "slack.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": { "types": "public_channel" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let channels = result["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 2);
    assert_eq!(channels[0]["name"], "general");
    assert_eq!(channels[1]["name"], "random");
}

#[fcp_async_core::runtime::test]
async fn get_user_info_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.get_user_info.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "user": {
                "id": "U01234567",
                "name": "testuser",
                "real_name": "Test User",
                "is_bot": false,
                "is_admin": false,
                "deleted": false,
                "profile": {
                    "display_name": "testuser",
                    "email": "test@example.com"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_user_info"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.get_user_info");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_user_info",
            "input": { "user": "U01234567" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["user"]["name"], "testuser");
    assert_eq!(result["user"]["id"], "U01234567");
}

#[fcp_async_core::runtime::test]
async fn upload_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.upload_file.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/files.upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F01234567",
                "name": "output.log",
                "title": "output.log",
                "mimetype": "text/plain",
                "filetype": "text",
                "size": 42
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content_object_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "resolved_content": "log data here",
                "filename": "output.log"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["file"]["id"], "F01234567");
    assert_eq!(result["file"]["name"], "output.log");
    assert_eq!(
        result["source_object_id"],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(
        result["file_object_id"].as_str().unwrap().len(),
        64,
        "file_object_id should be a hex ObjectId"
    );
}

#[fcp_async_core::runtime::test]
async fn download_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.download_file.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F01234567",
                "name": "report.pdf",
                "title": "Q4 Report",
                "mimetype": "application/pdf",
                "filetype": "pdf",
                "size": 102_400,
                "url_private": "https://files.slack.com/files-pri/T01234-F01234567/report.pdf",
                "url_private_download": "https://files.slack.com/files-pri/T01234-F01234567/download/report.pdf"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.files.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token_for_operation(&key, "slack.files.read", "slack.download_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.download_file",
            "input": { "file_id": "F01234567" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["file"]["id"], "F01234567");
    assert_eq!(result["file"]["name"], "report.pdf");
    assert!(result["file"]["url_private_download"].is_null());
    assert!(result["file"]["url_private"].is_null());
    assert_eq!(
        result["content_object_id"].as_str().unwrap().len(),
        64,
        "content_object_id should be a hex ObjectId"
    );
}

#[fcp_async_core::runtime::test]
async fn add_reaction_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.add_reaction.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/reactions.add"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": {
                "channel": "C01234567",
                "timestamp": "1234567890.123456",
                "name": "thumbsup"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["ok"], true);
}

#[fcp_async_core::runtime::test]
async fn set_channel_topic_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.set_channel_topic.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "topic": "Sprint 42 - Deployment day"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": {
                "channel": "C01234567",
                "topic": "Sprint 42 - Deployment day"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["topic"], "Sprint 42 - Deployment day");
}

// ============================================================================
// Receipt verification (side-effecting operations)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn post_message_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.post_message");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.123456",
            "message": slack_message("Hello!", "1234567890.123456")
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "Hello!" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.post_message");
    assert_eq!(receipt["effect"], "message_created");
    assert_eq!(receipt["resource"], "channel:C01234567");
    assert_eq!(receipt["timestamp"], "1234567890.123456");
}

#[fcp_async_core::runtime::test]
async fn reply_thread_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.reply_thread");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.654321",
            "message": {
                "type": "message",
                "user": "U01234567",
                "text": "Thread reply",
                "ts": "1234567890.654321",
                "thread_ts": "1234567890.111111"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "Thread reply",
                "thread_ts": "1234567890.111111"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.reply_thread");
    assert_eq!(receipt["effect"], "thread_reply_created");
    assert!(receipt["resource"].as_str().unwrap().contains("thread:"));
}

#[fcp_async_core::runtime::test]
async fn upload_file_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.upload_file");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/files.upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F09876543",
                "name": "data.csv",
                "title": "data.csv",
                "mimetype": "text/csv",
                "filetype": "csv",
                "size": 100
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content_object_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_content": "a,b,c",
                "filename": "data.csv"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.upload_file");
    assert_eq!(receipt["effect"], "file_uploaded");
    assert!(
        receipt["resource"]
            .as_str()
            .unwrap()
            .starts_with("file_object:")
    );
}

#[fcp_async_core::runtime::test]
async fn add_reaction_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.add_reaction");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/reactions.add"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": {
                "channel": "C01234567",
                "timestamp": "1234567890.123456",
                "name": "thumbsup"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.add_reaction");
    assert_eq!(receipt["effect"], "reaction_added");
    assert!(receipt["resource"].as_str().unwrap().contains("message:"));
}

#[fcp_async_core::runtime::test]
async fn set_channel_topic_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.set_channel_topic");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "topic": "New topic"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": { "channel": "C01234567", "topic": "New topic" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.set_channel_topic");
    assert_eq!(receipt["effect"], "topic_updated");
    assert_eq!(receipt["resource"], "channel:C01234567");
}

// ============================================================================
// Read operations should NOT emit receipts
// ============================================================================

#[fcp_async_core::runtime::test]
async fn read_operations_have_no_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.read_no_receipt");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channels": [slack_channel("C01234567", "general")]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.list_channels"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert!(result.get("receipt").is_none());
}

// ============================================================================
// Error taxonomy tests (Slack API errors come as 200 OK with ok:false)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn error_not_authed_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.not_authed");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer bad-token")
        );
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack error body json");
        assert_eq!(body["channel"], "C01234567");
        assert_eq!(body["text"], "hello");
        StructuredHttpResponse::json(
            200,
            json!({
                "ok": false,
                "error": "not_authed"
            }),
        )
    });

    let client = SlackClient::new("bad-token")
        .unwrap()
        .with_base_url(fake_server.url())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_invalid_auth_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.invalid_auth");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "invalid_auth"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_token_revoked_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.token_revoked");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "token_revoked"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("revoked-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.list_channels(None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_channel_not_found_maps_to_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.channel_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "channel_not_found"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_channel_history("C_NONEXIST", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "Expected ResourceNotFound, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_user_not_found_maps_to_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.user_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "user_not_found"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_user_info("U_NONEXIST").await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "Expected ResourceNotFound, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_ratelimited_api_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.ratelimited_api");
    let mock_server = MockServer::start().await;

    // Slack API-level ratelimited error (200 OK with ok:false)
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "ratelimited"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "test", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_http_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.http_429");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/conversations.list");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer valid-token")
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        StructuredHttpResponse {
            status: 429,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("retry-after".into(), "30".into()),
            ],
            body: json!({"ok": false, "error": "ratelimited"})
                .to_string()
                .into_bytes(),
        }
    });

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(fake_server.url())
        .with_retry_config(0, 10, 100);

    let result = client.list_channels(None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_missing_scope_maps_to_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.missing_scope");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "missing_scope"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::CapabilityDenied { .. }),
        "Expected CapabilityDenied, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_not_in_channel_maps_to_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.not_in_channel");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_in_channel"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::CapabilityDenied { .. }),
        "Expected CapabilityDenied, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_retryable_classification() {
    use fcp_slack::error::SlackError;

    // API transient errors should be retryable
    let transient = SlackError::Api {
        error: "internal_error".into(),
        code: None,
        ok: false,
    };
    assert!(transient.is_retryable());

    let timeout = SlackError::Api {
        error: "request_timeout".into(),
        code: None,
        ok: false,
    };
    assert!(timeout.is_retryable());

    let unavailable = SlackError::Api {
        error: "service_unavailable".into(),
        code: None,
        ok: false,
    };
    assert!(unavailable.is_retryable());

    // Non-transient errors should NOT be retryable
    let not_authed = SlackError::Api {
        error: "not_authed".into(),
        code: None,
        ok: false,
    };
    assert!(!not_authed.is_retryable());

    let chan_not_found = SlackError::Api {
        error: "channel_not_found".into(),
        code: None,
        ok: false,
    };
    assert!(!chan_not_found.is_retryable());

    // RateLimited is always retryable
    let rate = SlackError::RateLimited {
        retry_after_secs: 30,
    };
    assert!(rate.is_retryable());
}

// ============================================================================
// Invoke-level error tests (401/403/429 through handle_invoke)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_401_not_authed() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.401_not_authed");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_authed"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_401_invalid_auth() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.401_invalid_auth");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "invalid_auth"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C01234567" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_missing_scope() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_missing_scope");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "missing_scope"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_not_in_channel() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_not_in_channel");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_in_channel"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_restricted_action() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_restricted_action");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "restricted_action"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": { "channel": "C01234567", "topic": "new topic" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_429_rate_limited_api() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.429_api");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "ratelimited"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.resource_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "channel_not_found"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C_INVALID" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::ResourceNotFound { .. }
        ),
        "Expected ResourceNotFound"
    );
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::runtime::test]
async fn fcp2_invoke_requires_handshake() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.no_handshake");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    // No handshake → NotConfigured (no verifier set)
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": { "raw": vec![0u8; 32] }
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn fcp2_invoke_requires_capability_token() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.missing_token");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" }
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("capability_token"));
        }
        e => panic!("Expected InvalidRequest about capability_token, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn fcp2_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.wrong_cap");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    // Handshake grants only slack.read
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Token is for slack.read, but we invoke slack.post_message
    let token = generate_valid_token(&key, "slack.read");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn fcp2_unknown_operation_rejected() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.unknown_op");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.nonexistent"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::OperationNotGranted { .. }
        ),
        "Expected OperationNotGranted"
    );
}

#[fcp_async_core::runtime::test]
async fn fcp2_missing_operation_field() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.missing_op");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_invoke(json!({
            "input": {},
            "capability_token": { "raw": vec![0u8; 32] }
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("operation"));
        }
        e => panic!("Expected InvalidRequest about operation, got: {e:?}"),
    }
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.health_before");
    let connector = SlackConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.health_after");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_returns_accepted() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.handshake");
    let mut connector = SlackConnector::new();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": vec![0u8; 32],
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["slack.read", "slack.write"]
        }))
        .await
        .unwrap();

    assert_eq!(result["status"], "accepted");
    assert!(result["session_id"].as_str().is_some());
    let grants = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(grants.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.introspect");
    let connector = SlackConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 10);

    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
    for expected in &[
        "slack.post_message",
        "slack.reply_thread",
        "slack.get_channel_history",
        "slack.search_messages",
        "slack.list_channels",
        "slack.get_user_info",
        "slack.upload_file",
        "slack.download_file",
        "slack.add_reaction",
        "slack.set_channel_topic",
    ] {
        assert!(op_ids.contains(expected), "Missing op: {expected}");
    }
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.shutdown");
    let mut connector = SlackConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Socket Mode streaming tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn socket_mode_subscribe_emits_event_envelope_and_ack() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.event_and_ack");
    let mock_server = MockServer::start().await;
    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build async-core runtime");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let ws_url = format!(
        "ws://{}",
        listener.local_addr().expect("listener local addr")
    );

    let (ack_tx, ack_rx) = oneshot::channel::<Option<String>>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let mut ws_stream = accept_test_websocket(tcp_stream).await;

        send_json_frame(
            &mut ws_stream,
            json!({ "type": "hello" }),
            "send hello frame",
        )
        .await;
        send_json_frame(
            &mut ws_stream,
            json!({
                "envelope_id": "envelope-1",
                "type": "events_api",
                "payload": {
                    "event_id": "Ev01",
                    "team_id": "T_TEAM_1",
                    "event": {
                        "type": "message",
                        "user": "U_EVT_1",
                        "channel": "C_EVT_1",
                        "text": "hello from socket mode",
                        "ts": "1700000000.000001"
                    }
                }
            }),
            "send events_api frame",
        )
        .await;

        let ack_payload = recv_text_frame(&mut ws_stream, "ack frame").await;
        let _ = ack_tx.send(ack_payload);

        close_test_websocket(&mut ws_stream).await;
    });

    Mock::given(method("POST"))
        .and(path("/apps.connections.open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "url": ws_url
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "token": "xoxb-test-token-xyz",
            "app_token": "xapp-test-token-xyz",
            "base_url": mock_server.uri()
        }))
        .await
        .expect("configure");

    let mut event_rx = connector.subscribe_events();
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.message.new"]
        })))
        .expect("subscribe should succeed");
    assert_eq!(subscribe_result["connection_status"], "started");

    let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
        .await
        .expect("timeout waiting for socket mode event")
        .expect("broadcast receive")
        .expect("event payload");

    assert_eq!(event.topic, "slack.message.new");
    assert_eq!(event.cursor, "Ev01");
    assert_eq!(event.data.principal.kind, "slack_user");
    assert_eq!(event.data.principal.id, "U_EVT_1");
    assert_eq!(event.data.principal.trust, fcp_core::TrustLevel::Untrusted);
    assert_eq!(event.data.zone_id, fcp_core::ZoneId::community());
    assert_eq!(
        event.data.payload["event"]["text"].as_str(),
        Some("hello from socket mode")
    );

    let ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), ack_rx)
        .await
        .expect("timeout waiting for socket ack")
        .expect("ack channel should complete")
        .expect("ack payload missing");
    let ack_value: serde_json::Value =
        serde_json::from_str(&ack_json).expect("ack should be valid json");
    assert_eq!(ack_value["envelope_id"], "envelope-1");

    runtime
        .block_on(connector.handle_shutdown(json!({})))
        .expect("shutdown should succeed");

    fcp_async_core::time::timeout(StdDuration::from_secs(3), ws_task)
        .await
        .expect("timeout waiting for ws task")
        .expect("ws task join");
}

#[fcp_async_core::runtime::test]
async fn socket_mode_subscribe_reuses_single_connection() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.singleton_connection");
    let mock_server = MockServer::start().await;
    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build async-core runtime");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let ws_url = format!(
        "ws://{}",
        listener.local_addr().expect("listener local addr")
    );

    let (stop_ws_tx, mut stop_ws_rx) = fcp_async_core::channel::watch::channel(false);
    let (connected_tx, connected_rx) = oneshot::channel::<()>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let accepted = fcp_async_core::select! {
            accept_result = listener.accept() => Some(accept_result.expect("accept websocket client")),
            _ = stop_ws_rx.changed() => None,
        };
        let Some((tcp_stream, _)) = accepted else {
            return;
        };
        let mut ws_stream = accept_test_websocket(tcp_stream).await;
        let _ = connected_tx.send(());

        send_json_frame(
            &mut ws_stream,
            json!({ "type": "hello" }),
            "send hello frame",
        )
        .await;

        fcp_async_core::select! {
            _ = stop_ws_rx.changed() => {},
            () = async {
                loop {
                    match ws_stream.recv(&Cx::for_testing()).await {
                        Ok(Some(ServerWsMessage::Close(_)) | None) | Err(_) => break,
                        _ => {}
                    }
                }
            } => {}
        }

        close_test_websocket(&mut ws_stream).await;
    });

    Mock::given(method("POST"))
        .and(path("/apps.connections.open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "url": ws_url
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "token": "xoxb-test-token-xyz",
            "app_token": "xapp-test-token-xyz",
            "base_url": mock_server.uri()
        }))
        .await
        .expect("configure");

    let first = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.message.new"]
        })))
        .expect("first subscribe should succeed");
    assert_eq!(first["connection_status"], "started");
    fcp_async_core::time::timeout(StdDuration::from_secs(3), connected_rx)
        .await
        .expect("timeout waiting for socket connection")
        .expect("socket connection signal should complete");

    let second = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.message.new", "slack.reaction.added"]
        })))
        .expect("second subscribe should succeed");
    assert_eq!(second["connection_status"], "already_running");

    let health = connector.handle_health().await.expect("health");
    assert_eq!(health["streaming"]["socket_mode_running"], true);

    runtime
        .block_on(connector.handle_shutdown(json!({})))
        .expect("shutdown should succeed");

    let _ = stop_ws_tx.send(true);
    fcp_async_core::time::timeout(StdDuration::from_secs(3), ws_task)
        .await
        .expect("timeout waiting for ws task")
        .expect("ws task join");

    mock_server.verify().await;
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn validate_post_message_missing_channel() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_channel");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "text": "hello" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("channel"));
        }
        e => panic!("Expected InvalidRequest about channel, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_post_message_missing_text() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_text");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("text"));
        }
        e => panic!("Expected InvalidRequest about text, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_reply_thread_missing_thread_ts() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_thread_ts");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": { "channel": "C01234567", "text": "reply" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("thread_ts"));
        }
        e => panic!("Expected InvalidRequest about thread_ts, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_add_reaction_missing_name() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_name");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": { "channel": "C01234567", "timestamp": "1234567890.123456" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("name"));
        }
        e => panic!("Expected InvalidRequest about name, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_configure_missing_token() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_token");
    let mut connector = SlackConnector::new();
    let result = connector.handle_configure(json!({})).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("token"));
        }
        e => panic!("Expected InvalidRequest about token, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_upload_file_missing_channels() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_channels");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "content_object_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "resolved_content": "data"
            },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("channels"));
        }
        e => panic!("Expected InvalidRequest about channels, got: {e:?}"),
    }
}

// ============================================================================
// Regression: ok=true envelope with missing payload returns a terminal
// `SlackError::Api` instead of panicking. See flywheel_connectors-g37n0.
// ============================================================================

/// A partial success envelope (`{"ok": true}` with no `message`/`channel`/…)
/// must surface as a recoverable `SlackError::Api { ok: true, .. }` mapped
/// through to `FcpError::External`, not a process abort.
#[fcp_async_core::runtime::test]
async fn ok_true_with_missing_payload_is_mapped_to_api_error_not_panic() {
    let _ctx = AsyncTestContext::for_scenario("slack.ok_true_missing_payload");
    let mock_server = MockServer::start().await;

    // Server claims success but returns no `message` / `channel` /
    // `ts` fields. Previously the client called
    // `.expect("ok response has data")` on the flattened payload and
    // panicked; after the fix we expect a terminal SlackError::Api.
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("xoxb-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    let err = result.expect_err("ok=true without payload must not succeed");

    match &err {
        fcp_slack::error::SlackError::Api { error, ok, code: _ } => {
            assert!(
                *ok,
                "error must mark ok=true so callers can distinguish partial \
                 success envelope from classic ok=false api errors"
            );
            assert!(
                error.contains("chat.postMessage"),
                "error message must name the Slack method for debuggability, \
                 got: {error}"
            );
            assert!(
                error.contains("ok=true"),
                "error message must explicitly mention ok=true so operators \
                 can grep for partial-envelope incidents, got: {error}"
            );
        }
        other => panic!(
            "Expected SlackError::Api for ok=true with missing payload, \
             got: {other:?}"
        ),
    }

    // Also confirm the SDK error mapping preserves the context.
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::External { .. }),
        "ok=true partial envelope should map to External (non-panicking) \
         FcpError, got: {fcp_err:?}"
    );
}
