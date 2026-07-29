#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration as StdDuration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_feishu::connector::FeishuConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const APP_ID: &str = "cli_test_app";
const APP_SECRET: &str = "cli_test_secret";
const TENANT_TOKEN: &str = "tenant-token-123";
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const OP_CHATS_LIST: &str = "feishu.chats.list";

#[derive(Debug)]
struct RecordedRequest {
    label: &'static str,
    request_line: String,
    headers: String,
    body: String,
}

struct HttpResponseSpec {
    label: &'static str,
    status: u16,
    body: &'static str,
}

impl HttpResponseSpec {
    const fn json(label: &'static str, status: u16, body: &'static str) -> Self {
        Self {
            label,
            status,
            body,
        }
    }
}

fn spawn_loopback_server(
    responses: Vec<HttpResponseSpec>,
) -> (String, Receiver<RecordedRequest>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind Feishu loopback server");
    let address = listener.local_addr().expect("read Feishu loopback address");
    let (sender, receiver) = mpsc::channel();

    let handle = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("accept Feishu loopback request");
            let (request_line, headers, body) = read_http_request(&mut stream);
            sender
                .send(RecordedRequest {
                    label: response.label,
                    request_line,
                    headers,
                    body,
                })
                .expect("record Feishu loopback request");
            write_http_response(&mut stream, &response);
        }
    });

    (format!("http://{address}"), receiver, handle)
}

fn read_http_request(stream: &mut TcpStream) -> (String, String, String) {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set Feishu loopback read timeout");

    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let headers_end = loop {
        let count = stream.read(&mut chunk).expect("read Feishu HTTP request");
        assert_ne!(count, 0, "connection closed before HTTP headers arrived");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = find_headers_end(&bytes) {
            break end;
        }
    };

    let headers = String::from_utf8(bytes[..headers_end].to_vec()).expect("headers are UTF-8");
    let request_line = headers
        .lines()
        .next()
        .expect("request line present")
        .to_owned();
    let expected_body_len = content_length(&headers);
    let mut body_bytes = bytes[(headers_end + 4)..].to_vec();
    while body_bytes.len() < expected_body_len {
        let count = stream
            .read(&mut chunk)
            .expect("read Feishu HTTP request body");
        assert_ne!(count, 0, "connection closed before request body arrived");
        body_bytes.extend_from_slice(&chunk[..count]);
    }
    body_bytes.truncate(expected_body_len);
    let body = String::from_utf8(body_bytes).expect("body is UTF-8");

    (request_line, headers, body)
}

fn find_headers_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content-length"))
        })
        .unwrap_or(0)
}

fn write_http_response(stream: &mut TcpStream, response: &HttpResponseSpec) {
    let body = response.body.as_bytes();
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        status_reason(response.status),
        body.len()
    )
    .expect("write Feishu HTTP response headers");
    stream
        .write_all(body)
        .expect("write Feishu HTTP response body");
    stream.flush().expect("flush Feishu HTTP response");
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        429 => "Too Many Requests",
        _ => "Unknown",
    }
}

fn recv_request(receiver: &Receiver<RecordedRequest>, label: &'static str) -> RecordedRequest {
    let request = receiver
        .recv_timeout(StdDuration::from_secs(5))
        .expect("Feishu loopback request recorded");
    assert_eq!(request.label, label);
    request
}

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("feishu.messages.write"),
            CapabilityId::from_static("feishu.chats.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn test_constraints_cbor() -> Vec<u8> {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize capability constraints");
    cbor
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(op))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&test_constraints_cbor())
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn capability_for_operation(op: &str) -> &'static str {
    match op {
        OP_MESSAGES_SEND => "feishu.messages.write",
        OP_CHATS_LIST => "feishu.chats.read",
        _ => panic!("unsupported Feishu operation in local acceptance harness: {op}"),
    }
}

fn invoke_req(op: &'static str, input: Value, capability_token: CapabilityToken) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("feishu-local-{op}")),
        connector_id: ConnectorId::from_static("fcp.feishu"),
        operation: OperationId::from_static(op),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

async fn setup_connector(base_url: &str) -> (FeishuConnector, Ed25519SigningKey) {
    let mut connector = FeishuConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": base_url,
            "app_id": APP_ID,
            "app_secret": APP_SECRET,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 1_000
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn feishu_loopback_covers_auth_send_and_chat_list() {
    let (base_url, requests, server) = spawn_loopback_server(vec![
        HttpResponseSpec::json(
            "auth",
            200,
            r#"{"code":0,"msg":"success","tenant_access_token":"tenant-token-123","expire":7200}"#,
        ),
        HttpResponseSpec::json(
            "send",
            200,
            r#"{"code":0,"msg":"success","data":{"message_id":"om_local_1","msg_type":"text"}}"#,
        ),
        HttpResponseSpec::json(
            "chats",
            200,
            r#"{"code":0,"msg":"success","data":{"items":[{"chat_id":"oc_chat_1","name":"Platform Team"},{"chat_id":"oc_chat_2","name":"Ops"}],"page_token":"page-2","has_more":true}}"#,
        ),
    ]);
    let (connector, signing_key) = setup_connector(&base_url).await;

    let send_response = connector
        .invoke(invoke_req(
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_123456",
                "receive_id_type": "open_id",
                "msg_type": "text",
                "content": "{\"text\":\"hello from raw Feishu loopback\"}"
            }),
            generate_valid_token(&signing_key, OP_MESSAGES_SEND, connector.instance_id()),
        ))
        .await
        .unwrap();
    assert_eq!(send_response.status, InvokeStatus::Ok);
    let send_result = send_response.result.expect("send result");
    assert_eq!(send_result["message_id"], "om_local_1");
    assert_eq!(send_result["msg_type"], "text");
    assert_eq!(send_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(send_result["coordination"][1]["outcome"], "granted");
    assert_eq!(send_result["coordination"][2]["event"], "send_executed");
    let coordination_text = serde_json::to_string(&send_result["coordination"]).unwrap();
    assert!(!coordination_text.contains("ou_123456"));
    assert!(!coordination_text.contains("hello from raw Feishu loopback"));

    let auth_request = recv_request(&requests, "auth");
    assert_eq!(
        auth_request.request_line,
        "POST /open-apis/auth/v3/tenant_access_token/internal HTTP/1.1"
    );
    let auth_body: Value = serde_json::from_str(&auth_request.body).unwrap();
    assert_eq!(auth_body["app_id"], APP_ID);
    assert_eq!(auth_body["app_secret"], APP_SECRET);

    let send_request = recv_request(&requests, "send");
    assert_eq!(
        send_request.request_line,
        "POST /open-apis/im/v1/messages?receive_id_type=open_id HTTP/1.1"
    );
    let expected_auth = format!("authorization: bearer {TENANT_TOKEN}");
    assert!(
        send_request
            .headers
            .to_ascii_lowercase()
            .contains(&expected_auth)
    );
    let send_body: Value = serde_json::from_str(&send_request.body).unwrap();
    assert_eq!(send_body["receive_id"], "ou_123456");
    assert_eq!(send_body["msg_type"], "text");
    assert_eq!(
        send_body["content"],
        r#"{"text":"hello from raw Feishu loopback"}"#
    );

    let chats_response = connector
        .invoke(invoke_req(
            OP_CHATS_LIST,
            json!({
                "page_token": "page-1",
                "page_size": 50
            }),
            generate_valid_token(&signing_key, OP_CHATS_LIST, connector.instance_id()),
        ))
        .await
        .unwrap();
    assert_eq!(chats_response.status, InvokeStatus::Ok);
    let chats_result = chats_response.result.expect("chat list result");
    assert_eq!(chats_result["items"].as_array().unwrap().len(), 2);
    assert_eq!(chats_result["page_token"], "page-2");
    assert_eq!(chats_result["has_more"], true);

    let chats_request = recv_request(&requests, "chats");
    assert_eq!(
        chats_request.request_line,
        "GET /open-apis/im/v1/chats?page_token=page-1&page_size=50 HTTP/1.1"
    );
    assert!(
        chats_request
            .headers
            .to_ascii_lowercase()
            .contains(&expected_auth)
    );
    assert!(chats_request.body.is_empty());

    server.join().expect("Feishu loopback server joins cleanly");
}

#[test]
fn acceptance_suite_class_is_declared() {
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
}
