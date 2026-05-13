#![forbid(unsafe_code)]
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
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_wecom::{WeComConnector, types::DEFAULT_TIMEOUT_MS};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const OP_SEND_TEXT: &str = "wecom.messages.send_text";
const OP_GET_USER: &str = "wecom.users.get";

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
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind WeCom loopback server");
    let address = listener.local_addr().expect("read WeCom loopback address");
    let (sender, receiver) = mpsc::channel();

    let handle = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("accept WeCom loopback request");
            let (request_line, headers, body) = read_http_request(&mut stream);
            sender
                .send(RecordedRequest {
                    label: response.label,
                    request_line,
                    headers,
                    body,
                })
                .expect("record WeCom loopback request");
            write_http_response(&mut stream, &response);
        }
    });

    (format!("http://{address}"), receiver, handle)
}

fn read_http_request(stream: &mut TcpStream) -> (String, String, String) {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set WeCom loopback read timeout");

    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let headers_end = loop {
        let count = stream.read(&mut chunk).expect("read WeCom HTTP request");
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
            .expect("read WeCom HTTP request body");
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
    .expect("write WeCom HTTP response headers");
    stream
        .write_all(body)
        .expect("write WeCom HTTP response body");
    stream.flush().expect("flush WeCom HTTP response");
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
        .expect("WeCom loopback request recorded");
    assert_eq!(request.label, label);
    request
}

fn handshake_request(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [31_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("wecom.messages.write"),
            CapabilityId::from_static("wecom.users.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
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

fn capability_token(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&test_constraints_cbor())
        .expect("test constraints cbor should be valid")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

fn capability_for_operation(operation: &str) -> &'static str {
    match operation {
        OP_SEND_TEXT => "wecom.messages.write",
        OP_GET_USER => "wecom.users.read",
        _ => panic!("unsupported WeCom operation in local acceptance harness: {operation}"),
    }
}

fn invoke_request(
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("wecom-local-{operation}")),
        connector_id: ConnectorId::from_static("fcp.wecom"),
        operation: OperationId::from_static(operation),
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
        approval_tokens: Vec::new(),
    }
}

async fn configured_connector(base_url: &str) -> (WeComConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = WeComConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .configure(json!({
            "base_url": base_url,
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
            "request_timeout_ms": DEFAULT_TIMEOUT_MS,
            "chat_coordination": { "backend": "in_memory" }
        }))
        .await
        .expect("configure WeCom connector");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake WeCom connector");
    (connector, signing_key, instance_id)
}

#[fcp_async_core::runtime::test]
async fn wecom_loopback_covers_token_send_and_user_lookup() {
    let (base_url, requests, server) = spawn_loopback_server(vec![
        HttpResponseSpec::json(
            "token",
            200,
            r#"{"errcode":0,"errmsg":"ok","access_token":"token-123","expires_in":7200}"#,
        ),
        HttpResponseSpec::json(
            "send_text",
            200,
            r#"{"errcode":0,"errmsg":"ok","msgid":"mid-local-1"}"#,
        ),
        HttpResponseSpec::json(
            "user",
            200,
            r#"{"errcode":0,"errmsg":"ok","userid":"zhangsan","name":"Zhang San"}"#,
        ),
    ]);
    let (connector, signing_key, instance_id) = configured_connector(&base_url).await;

    let send_response = connector
        .invoke(invoke_request(
            OP_SEND_TEXT,
            json!({
                "touser": "zhangsan",
                "content": "hello from raw WeCom loopback"
            }),
            capability_token(&signing_key, OP_SEND_TEXT, &instance_id),
        ))
        .await
        .unwrap();
    assert_eq!(send_response.status, InvokeStatus::Ok);
    let send_result = send_response.result.expect("send text result");
    assert_eq!(send_result["msgid"], "mid-local-1");
    assert_eq!(send_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(send_result["coordination"][1]["outcome"], "granted");
    assert_eq!(send_result["coordination"][2]["event"], "send_executed");
    assert!(
        !serde_json::to_string(&send_result["coordination"])
            .unwrap()
            .contains("zhangsan")
    );

    let token_request = recv_request(&requests, "token");
    assert_eq!(
        token_request.request_line,
        "GET /cgi-bin/gettoken?corpid=corp&corpsecret=secret HTTP/1.1"
    );
    assert!(token_request.body.is_empty());

    let send_request = recv_request(&requests, "send_text");
    assert_eq!(
        send_request.request_line,
        "POST /cgi-bin/message/send?access_token=token-123 HTTP/1.1"
    );
    assert!(
        send_request
            .headers
            .to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    let send_body: Value = serde_json::from_str(&send_request.body).unwrap();
    assert_eq!(send_body["touser"], "zhangsan");
    assert_eq!(send_body["agentid"], json!(1_000_002_u64));
    assert_eq!(send_body["msgtype"], "text");
    assert_eq!(
        send_body["text"]["content"],
        "hello from raw WeCom loopback"
    );

    let user_response = connector
        .invoke(invoke_request(
            OP_GET_USER,
            json!({ "userid": "zhangsan" }),
            capability_token(&signing_key, OP_GET_USER, &instance_id),
        ))
        .await
        .unwrap();
    assert_eq!(user_response.status, InvokeStatus::Ok);
    let user_result = user_response.result.expect("user lookup result");
    assert_eq!(user_result["userid"], "zhangsan");
    assert_eq!(user_result["name"], "Zhang San");

    let user_request = recv_request(&requests, "user");
    assert_eq!(
        user_request.request_line,
        "GET /cgi-bin/user/get?access_token=token-123&userid=zhangsan HTTP/1.1"
    );
    assert!(user_request.body.is_empty());

    server.join().expect("WeCom loopback server joins cleanly");
}

#[test]
fn acceptance_suite_class_is_declared() {
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
}
