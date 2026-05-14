//! Local loopback acceptance coverage for the FCP Matrix connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_matrix::MatrixConnector;
use fcp_sdk::prelude::*;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.43";
const ACCESS_SECRET: &str = "local_matrix_acceptance_secret";
const CAP_READ: &str = "matrix.read";
const CAP_WRITE: &str = "matrix.write";
const OP_JOINED_ROOMS: &str = "matrix.joined_rooms";
const OP_SEND_MESSAGE: &str = "matrix.send_message";
const OP_GET_MESSAGES: &str = "matrix.get_messages";
const ROOM_ID: &str = "!room:matrix.example";
const ENCODED_ROOM_ID: &str = "%21room%3Amatrix.example";

const JOINED_ROOMS_RESPONSE_BODY: &str = r#"{
  "joined_rooms": [
    "!room:matrix.example",
    "!alerts:matrix.example"
  ]
}"#;

const MESSAGES_RESPONSE_BODY: &str = r#"{
  "chunk": [
    {
      "event_id": "$event1",
      "type": "m.room.message",
      "room_id": "!room:matrix.example",
      "sender": "@alice:matrix.example",
      "origin_server_ts": 1700000000000,
      "content": {
        "msgtype": "m.text",
        "body": "loopback hello"
      }
    }
  ],
  "end": "end-token"
}"#;

const SEND_MESSAGE_RESPONSE_BODY: &str = r#"{
  "event_id": "$local-send"
}"#;

const RATE_LIMIT_BODY: &str = r#"{
  "errcode": "M_LIMIT_EXCEEDED",
  "error": "Too many requests"
}"#;

#[derive(Debug, Clone, Copy)]
struct ResponseSpec {
    status: u16,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            headers: &[],
            body,
        }
    }

    const fn with_headers(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
    ) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Matrix loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<RequestObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_message(&mut stream);
    let header_end = find_header_end(&raw).expect("request contains header terminator");
    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();
    let body = String::from_utf8_lossy(&raw[header_end + 4..]).to_string();

    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        status_reason(response.status),
        response.body.len()
    )
    .expect("write response headers");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write extra response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");

    RequestObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let total_len = header_end + 4 + content_length(&headers);
            while request.len() < total_len {
                let bytes_read = stream
                    .read(&mut buffer)
                    .expect("read connector request body");
                assert!(bytes_read > 0, "connector body should not close early");
                request.extend_from_slice(&buffer[..bytes_read]);
                assert!(request.len() < 16384, "request body should stay bounded");
            }
            request.truncate(total_len);
            return request;
        }

        assert!(request.len() < 16384, "request headers should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("content-length is usize")
            })
        })
        .unwrap_or(0)
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        429 => "Too Many Requests",
        _ => "Status",
    }
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((actual_name, actual_value)) = line.split_once(':') else {
            return false;
        };
        actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == expected_value
    })
}

fn request_path(request_line: &str) -> &str {
    request_line.split_whitespace().nth(1).unwrap_or_default()
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability_id: &str,
) -> CapabilityToken {
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(1);
    let signed_capability = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id("z:work")
        .principal("matrix-local-acceptance")
        .issuer("node:loopback")
        .validity(now, expires)
        .target_instance(instance_id.as_str())
        .operations(&[OP_JOINED_ROOMS, OP_GET_MESSAGES, OP_SEND_MESSAGE])
        .try_constraints_cbor(&cbor)
        .expect("valid constraints")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(signed_capability)
}

async fn setup_connector(base_url: &str) -> (MatrixConnector, Ed25519SigningKey) {
    let key = Ed25519SigningKey::generate();
    let mut connector = MatrixConnector::new();
    connector
        .configure(json!({
            "homeserver_url": base_url,
            "auth": {
                "mode": "access_token",
                "access_token": ACCESS_SECRET
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
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake connector");
    (connector, key)
}

fn invoke_request(
    connector: &MatrixConnector,
    key: &Ed25519SigningKey,
    operation: &'static str,
    capability_id: &str,
    input: Value,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("matrix-local-{operation}")),
        connector_id: connector.id().clone(),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: capability_token(key, connector.instance_id(), capability_id),
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

async fn shutdown_connector(connector: &mut MatrixConnector) {
    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1000,
            drain: false,
            reason: Some("local_non_mock acceptance complete".into()),
        })
        .await
        .expect("shutdown connector");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_read_paths_cross_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, JOINED_ROOMS_RESPONSE_BODY),
        ResponseSpec::json(200, MESSAGES_RESPONSE_BODY),
    ]);
    let (mut connector, key) = setup_connector(fixture.base_url()).await;

    let joined_response = connector
        .invoke(invoke_request(
            &connector,
            &key,
            OP_JOINED_ROOMS,
            CAP_READ,
            json!({}),
        ))
        .await
        .expect("joined rooms through loopback");
    let joined_result = joined_response.result.expect("joined rooms result");
    assert_eq!(
        joined_result["rooms"][0].as_str(),
        Some("!room:matrix.example")
    );

    let messages_response = connector
        .invoke(invoke_request(
            &connector,
            &key,
            OP_GET_MESSAGES,
            CAP_READ,
            json!({
                "room_id": ROOM_ID,
                "from": "s123",
                "limit": 2
            }),
        ))
        .await
        .expect("get messages through loopback");
    let messages_result = messages_response.result.expect("messages result");
    assert_eq!(messages_result["end"].as_str(), Some("end-token"));
    assert_eq!(
        messages_result["messages"][0]["content"]["body"].as_str(),
        Some("loopback hello")
    );

    shutdown_connector(&mut connector).await;
    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].request_line,
        "GET /_matrix/client/v3/joined_rooms HTTP/1.1"
    );
    assert_eq!(
        request_path(&observations[1].request_line),
        format!("/_matrix/client/v3/rooms/{ENCODED_ROOM_ID}/messages?dir=b&limit=2&from=s123")
    );
    for observation in &observations {
        assert!(has_header(
            &observation.headers,
            "authorization",
            &format!("Bearer {ACCESS_SECRET}")
        ));
    }

    let artifact = json!({
        "connector": "matrix",
        "connector_id": "fcp.matrix",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-matrix --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operations": [OP_JOINED_ROOMS, OP_GET_MESSAGES],
        "request_response_boundary": {
            "methods": ["GET"],
            "paths": [
                "/_matrix/client/v3/joined_rooms",
                format!("/_matrix/client/v3/rooms/{ENCODED_ROOM_ID}/messages?dir=b&limit=2&from=s123")
            ],
            "path_encoding_verified": true,
            "query_encoding_verified": true
        },
        "auth_gate": {
            "mode": "bearer_header",
            "authorization_header_verified": true,
            "upstream_credentials_used": false
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_send_message_puts_json_body_to_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json(200, SEND_MESSAGE_RESPONSE_BODY)]);
    let (mut connector, key) = setup_connector(fixture.base_url()).await;

    let response = connector
        .invoke(invoke_request(
            &connector,
            &key,
            OP_SEND_MESSAGE,
            CAP_WRITE,
            json!({
                "room_id": ROOM_ID,
                "body": "ship Matrix local acceptance",
                "msgtype": "m.notice"
            }),
        ))
        .await
        .expect("send message through loopback");
    let result = response.result.expect("send result");
    assert_eq!(result["event_id"].as_str(), Some("$local-send"));

    shutdown_connector(&mut connector).await;
    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    let path = request_path(&observations[0].request_line);
    assert!(
        path.starts_with(&format!(
            "/_matrix/client/v3/rooms/{ENCODED_ROOM_ID}/send/m.room.message/"
        )),
        "unexpected Matrix send path: {path}"
    );
    assert_eq!(
        observations[0].request_line.split_whitespace().next(),
        Some("PUT")
    );
    assert!(has_header(
        &observations[0].headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));
    assert!(observations[0].headers.iter().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("content-type") && value.trim().starts_with("application/json")
    }));
    let body: Value = serde_json::from_str(&observations[0].body).expect("request JSON body");
    assert_eq!(body["msgtype"].as_str(), Some("m.notice"));
    assert_eq!(body["body"].as_str(), Some("ship Matrix local acceptance"));

    let artifact = json!({
        "connector": "matrix",
        "connector_id": "fcp.matrix",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-matrix --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_SEND_MESSAGE,
        "request_response_boundary": {
            "method": "PUT",
            "path_prefix": format!("/_matrix/client/v3/rooms/{ENCODED_ROOM_ID}/send/m.room.message/"),
            "path_encoding_verified": true,
            "json_body_verified": true
        },
        "auth_gate": {
            "mode": "bearer_header",
            "authorization_header_verified": true,
            "upstream_credentials_used": false
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_metadata() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::with_headers(
        429,
        &[("retry-after", "9")],
        RATE_LIMIT_BODY,
    )]);
    let (mut connector, key) = setup_connector(fixture.base_url()).await;

    let error = connector
        .invoke(invoke_request(
            &connector,
            &key,
            OP_JOINED_ROOMS,
            CAP_READ,
            json!({}),
        ))
        .await
        .expect_err("rate limit response should map to FCP rate limit error");
    shutdown_connector(&mut connector).await;
    let observations = fixture.join();

    match error {
        FcpError::RateLimited {
            retry_after_ms,
            violation,
        } => {
            assert_eq!(retry_after_ms, 9000);
            assert!(violation.is_none());
        }
        other => panic!("unexpected provider error mapping: {other:?}"),
    }
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].request_line,
        "GET /_matrix/client/v3/joined_rooms HTTP/1.1"
    );
    assert!(has_header(
        &observations[0].headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));

    let artifact = json!({
        "connector": "matrix",
        "connector_id": "fcp.matrix",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-matrix --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http_rate_limit",
        "provider_class": "local_sufficient",
        "operation": OP_JOINED_ROOMS,
        "request_response_boundary": {
            "method": "GET",
            "path": "/_matrix/client/v3/joined_rooms",
            "status": 429,
            "retry_after_ms": 9000
        },
        "auth_gate": {
            "mode": "bearer_header",
            "authorization_header_verified": true,
            "upstream_credentials_used": false
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
