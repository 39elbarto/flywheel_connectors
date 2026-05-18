//! Local loopback acceptance coverage for the Microsoft 365 connector.

#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_microsoft365::connector::M365Connector;
use fcp_prelude::CapabilityConstraints;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const OP_MAIL_LIST: &str = "m365.mail.list_messages";
const OP_MAIL_SEND: &str = "m365.mail.send_message";

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

#[derive(Debug)]
struct RecordedRequest {
    request_line: String,
    headers: String,
    body: Option<Value>,
}

struct LoopbackGraph {
    base_url: String,
    join: JoinHandle<Vec<RecordedRequest>>,
}

impl LoopbackGraph {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("bind Microsoft365 loopback listener");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("read Microsoft365 loopback address")
        );

        let join = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener
                        .accept()
                        .expect("accept Microsoft365 connector request");
                    handle_request(stream, response)
                })
                .collect()
        });

        Self { base_url, join }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(self) -> Vec<RecordedRequest> {
        self.join
            .join()
            .expect("Microsoft365 loopback thread should finish")
    }
}

fn handle_request(mut stream: TcpStream, response: HttpResponse) -> RecordedRequest {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set Microsoft365 loopback read timeout");

    let request = read_complete_request(&mut stream);
    let body_bytes = response.body.as_bytes();
    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        body_bytes.len(),
        response.body
    )
    .expect("write Microsoft365 loopback response");

    request
}

fn read_complete_request(stream: &mut TcpStream) -> RecordedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut header_end = None;
    let mut expected_len = None;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("read Microsoft365 loopback request");
        assert_ne!(
            read, 0,
            "connection closed before Microsoft365 request completed"
        );
        bytes.extend_from_slice(&buffer[..read]);
        assert!(
            bytes.len() <= 64 * 1024,
            "Microsoft365 loopback request should stay bounded"
        );

        if header_end.is_none() {
            if let Some(end) = find_header_end(&bytes) {
                let headers = String::from_utf8(bytes[..end].to_vec())
                    .expect("Microsoft365 request headers should be UTF-8");
                let content_length = content_length(&headers);
                header_end = Some(end);
                expected_len = Some(end + b"\r\n\r\n".len() + content_length);
            }
        }

        if let (Some(end), Some(total_len)) = (header_end, expected_len) {
            if bytes.len() >= total_len {
                let headers = String::from_utf8(bytes[..end].to_vec())
                    .expect("Microsoft365 request headers should be UTF-8");
                let request_line = headers
                    .lines()
                    .next()
                    .expect("request line should be present")
                    .to_owned();
                let body_start = end + b"\r\n\r\n".len();
                let body_slice = &bytes[body_start..total_len];
                let body = if body_slice.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(body_slice)
                            .expect("Microsoft365 request body should be JSON"),
                    )
                };
                return RecordedRequest {
                    request_line,
                    headers,
                    body,
                };
            }
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content-length"))
        })
        .unwrap_or(0)
}

fn header_equals(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn make_jwt_token(scopes: &[&str]) -> String {
    let header = BASE64_URL.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = json!({
        "scp": scopes.join(" "),
        "roles": [],
    });
    let payload = BASE64_URL.encode(serde_json::to_vec(&payload).expect("serialize JWT payload"));
    format!("{header}.{payload}.signature")
}

async fn setup_handshake(connector: &mut M365Connector) -> (Ed25519SigningKey, String) {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let zone_dir = unique_zone_dir();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir,
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": [
                "m365.mail.read",
                "m365.mail.send",
            ]
        }))
        .await
        .expect("Microsoft365 handshake should succeed");

    (signing_key, connector.instance_id().to_string())
}

fn unique_zone_dir() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!("fcp-m365-local-non-mock-{nanos}"));
    path.to_string_lossy().into_owned()
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &'static str,
    capability: &'static str,
) -> fcp_core::CapabilityToken {
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
        .principal("user:m365-local-non-mock")
        .operations(&[op])
        .issuer("node:m365-local-non-mock")
        .validity(now, now + Duration::hours(1))
        .target_instance(instance_id)
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");

    fcp_core::CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_mail_read_and_send_use_graph_loopback_boundary() {
    let graph = LoopbackGraph::start(vec![
        HttpResponse {
            status: "200 OK",
            body: r#"{"value":[{"id":"msg-local-1","subject":"Loopback Acceptance","isRead":false}]}"#,
        },
        HttpResponse {
            status: "202 Accepted",
            body: "",
        },
    ]);
    let fixture_jwt = make_jwt_token(&["Mail.Read", "Mail.Send"]);
    let expected_authorization = format!("Bearer {fixture_jwt}");

    let mut connector = M365Connector::new();
    connector
        .handle_configure(json!({
            "access_token": fixture_jwt,
            "allow_test_api_url": true,
            "api_url": graph.base_url(),
            "required_permissions": ["Mail.Read", "Mail.Send"],
        }))
        .await
        .expect("configure Microsoft365 connector");
    let (signing_key, instance_id) = setup_handshake(&mut connector).await;

    let messages = connector
        .handle_invoke(json!({
            "operation": OP_MAIL_LIST,
            "input": { "user_id": "me" },
            "capability_token": generate_valid_token(
                &signing_key,
                &instance_id,
                OP_MAIL_LIST,
                "m365.mail.read"
            ),
        }))
        .await
        .expect("list messages through loopback Graph boundary");
    assert_eq!(messages["messages"][0]["id"], "msg-local-1");
    assert_eq!(messages["messages"][0]["subject"], "Loopback Acceptance");

    let send_result = connector
        .handle_invoke(json!({
            "operation": OP_MAIL_SEND,
            "input": {
                "user_id": "me",
                "message": {
                    "subject": "Loopback Send",
                    "body": { "contentType": "Text", "content": "redacted fixture body" },
                    "toRecipients": [
                        { "emailAddress": { "address": "recipient@example.invalid" } }
                    ]
                }
            },
            "capability_token": generate_valid_token(
                &signing_key,
                &instance_id,
                OP_MAIL_SEND,
                "m365.mail.send"
            ),
        }))
        .await
        .expect("send message through loopback Graph boundary");
    assert_eq!(send_result["status"], "sent");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown Microsoft365 connector");

    let requests = graph.join();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].request_line, "GET /me/messages? HTTP/1.1");
    assert!(header_equals(
        &requests[0].headers,
        "authorization",
        &expected_authorization
    ));
    assert!(header_equals(
        &requests[0].headers,
        "user-agent",
        "fcp-microsoft365/0.1.0"
    ));
    assert_eq!(requests[1].request_line, "POST /me/sendMail HTTP/1.1");
    assert!(header_equals(
        &requests[1].headers,
        "authorization",
        &expected_authorization
    ));
    assert_eq!(
        requests[1].body.as_ref().expect("send body present")["message"]["subject"],
        "Loopback Send"
    );

    let artifact = json!({
        "connector": "microsoft365",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-angoc.16.5",
        "command": "cargo test -p fcp-microsoft365 --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "sandbox_required",
        "request_response_boundaries": [
            { "method": "GET", "path": "/me/messages" },
            { "method": "POST", "path": "/me/sendMail" }
        ],
        "auth_gate": {
            "mode": "bearer_token",
            "authorization_header_verified": true,
            "required_permissions": ["Mail.Read", "Mail.Send"]
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
