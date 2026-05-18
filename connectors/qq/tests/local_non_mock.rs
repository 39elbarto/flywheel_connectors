//! Local loopback acceptance coverage for the QQ connector.

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
    time::Duration as StdDuration,
};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId,
    ShutdownRequest, ZoneId,
};
use fcp_qq::QqConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const OP_SEND_CHANNEL: &str = "qq.messages.send_channel";
const OP_HEALTH: &str = "qq.health";
const CAP_MESSAGES_WRITE: &str = "qq.messages.write";
const CAP_HEALTH_READ: &str = "qq.health.read";
const ACCESS_MATERIAL: &str = "qq-local-access-material";
const EXPIRED_ACCESS_MATERIAL: &str = "qq-local-expired-material";
const FRESH_ACCESS_MATERIAL: &str = "qq-local-fresh-material";

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

struct LoopbackQq {
    base_url: String,
    join: JoinHandle<Vec<RecordedRequest>>,
}

impl LoopbackQq {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind QQ loopback listener");
        let base_url = format!(
            "http://{}",
            listener.local_addr().expect("read QQ loopback address")
        );

        let join = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept QQ connector request");
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
        self.join.join().expect("QQ loopback thread should finish")
    }
}

fn handle_request(mut stream: TcpStream, response: HttpResponse) -> RecordedRequest {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set QQ loopback read timeout");

    let request = read_complete_request(&mut stream);
    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        response.body.len(),
        response.body
    )
    .expect("write QQ loopback response");
    request
}

fn read_complete_request(stream: &mut TcpStream) -> RecordedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut header_end = None;
    let mut expected_len = None;

    loop {
        let read = stream.read(&mut buffer).expect("read QQ loopback request");
        assert_ne!(read, 0, "connection closed before QQ request completed");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 64 * 1024, "QQ request should stay bounded");

        if header_end.is_none() {
            if let Some(end) = find_header_end(&bytes) {
                let headers =
                    String::from_utf8(bytes[..end].to_vec()).expect("QQ headers should be UTF-8");
                let content_length = content_length(&headers);
                header_end = Some(end);
                expected_len = Some(end + b"\r\n\r\n".len() + content_length);
            }
        }

        if let (Some(end), Some(total_len)) = (header_end, expected_len) {
            if bytes.len() >= total_len {
                let headers =
                    String::from_utf8(bytes[..end].to_vec()).expect("QQ headers should be UTF-8");
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
                    Some(serde_json::from_slice(body_slice).expect("QQ body should be JSON"))
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

fn handshake_request(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [9_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_MESSAGES_WRITE),
            CapabilityId::from_static(CAP_HEALTH_READ),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
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
        .principal("user:qq-local-non-mock")
        .operations(&[operation])
        .issuer("node:qq-local-non-mock")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn channel_send_request(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("qq-local-non-mock"),
        connector_id: ConnectorId::from_static("fcp.qq"),
        operation: OperationId::from_static(OP_SEND_CHANNEL),
        zone_id: ZoneId::work(),
        input: json!({
            "channel_id": "channel-local-1",
            "content": "hello from QQ local acceptance"
        }),
        capability_token: build_token(
            signing_key,
            instance_id,
            CAP_MESSAGES_WRITE,
            OP_SEND_CHANNEL,
        ),
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

fn health_request(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("qq-local-health-refresh"),
        connector_id: ConnectorId::from_static("fcp.qq"),
        operation: OperationId::from_static(OP_HEALTH),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: build_token(signing_key, instance_id, CAP_HEALTH_READ, OP_HEALTH),
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

#[fcp_async_core::runtime::test]
async fn local_non_mock_channel_send_uses_token_and_api_loopback_boundaries() {
    let qq = LoopbackQq::start(vec![
        HttpResponse {
            status: "200 OK",
            body: r#"{"access_token":"qq-local-access-material","expires_in":7200}"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"id":"msg-local-1","timestamp":"2026-05-18T00:00:00Z"}"#,
        },
    ]);
    let app_credential = "local-credential";
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    let mut connector = QqConnector::new();
    connector
        .configure(json!({
            "base_url": qq.base_url(),
            "token_base_url": qq.base_url(),
            "app_id": "qq-local-app",
            "client_secret": app_credential,
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure QQ connector");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake QQ connector");

    let response = connector
        .invoke(channel_send_request(&signing_key, &instance_id))
        .await
        .expect("send QQ channel message through loopback fixture");
    assert!(matches!(response.status, InvokeStatus::Ok));
    let result = response.result.expect("QQ send result should be present");
    assert_eq!(result["id"], "msg-local-1");

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("qq-local-non-mock-complete".into()),
        })
        .await
        .expect("shutdown QQ connector");

    let requests = qq.join();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].request_line,
        "POST /app/getAppAccessToken HTTP/1.1"
    );
    assert_eq!(
        requests[0].body.as_ref().expect("token body present")["appId"],
        "qq-local-app"
    );
    assert_eq!(
        requests[0].body.as_ref().expect("token body present")["clientSecret"],
        app_credential
    );
    assert_eq!(
        requests[1].request_line,
        "POST /channels/channel-local-1/messages HTTP/1.1"
    );
    assert!(header_equals(
        &requests[1].headers,
        "authorization",
        &format!("QQBot {ACCESS_MATERIAL}")
    ));
    assert_eq!(
        requests[1].body.as_ref().expect("send body present")["content"],
        "hello from QQ local acceptance"
    );

    let artifact = json!({
        "connector": "qq",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-angoc.16.5",
        "command": "cargo test -p fcp-qq --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundaries": [
            { "method": "POST", "path": "/app/getAppAccessToken" },
            { "method": "POST", "path": "/channels/channel-local-1/messages" }
        ],
        "auth_gate": {
            "mode": "qqbot_access_token",
            "authorization_header_verified": true,
            "token_cache_path": "memory_only"
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_health_refreshes_expired_access_token_once() {
    let qq = LoopbackQq::start(vec![
        HttpResponse {
            status: "200 OK",
            body: r#"{"access_token":"qq-local-expired-material","expires_in":7200}"#,
        },
        HttpResponse {
            status: "401 Unauthorized",
            body: r#"{"message":"expired access material"}"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"access_token":"qq-local-fresh-material","expires_in":7200}"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"url":"wss://gateway.qq.example/ws"}"#,
        },
    ]);
    let app_credential = "refresh-credential";
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    let mut connector = QqConnector::new();
    connector
        .configure(json!({
            "base_url": qq.base_url(),
            "token_base_url": qq.base_url(),
            "app_id": "qq-refresh-app",
            "client_secret": app_credential,
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure QQ connector");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake QQ connector");

    let response = connector
        .invoke(health_request(&signing_key, &instance_id))
        .await
        .expect("run QQ health through loopback fixture");
    assert!(matches!(response.status, InvokeStatus::Ok));
    let result = response.result.expect("QQ health result should be present");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["gateway"], "wss://gateway.qq.example/ws");

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("qq-local-health-refresh-complete".into()),
        })
        .await
        .expect("shutdown QQ connector");

    let requests = qq.join();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[0].request_line,
        "POST /app/getAppAccessToken HTTP/1.1"
    );
    assert_eq!(
        requests[0].body.as_ref().expect("token body present")["clientSecret"],
        app_credential
    );
    assert_eq!(requests[1].request_line, "GET /gateway HTTP/1.1");
    assert!(header_equals(
        &requests[1].headers,
        "authorization",
        &format!("QQBot {EXPIRED_ACCESS_MATERIAL}")
    ));
    assert_eq!(
        requests[2].request_line,
        "POST /app/getAppAccessToken HTTP/1.1"
    );
    assert_eq!(requests[3].request_line, "GET /gateway HTTP/1.1");
    assert!(header_equals(
        &requests[3].headers,
        "authorization",
        &format!("QQBot {FRESH_ACCESS_MATERIAL}")
    ));

    let artifact = json!({
        "connector": "qq",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-6n7.12.3",
        "command": "cargo test -p fcp-qq --test local_non_mock local_non_mock_health_refreshes_expired_access_token_once -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundaries": [
            { "method": "POST", "path": "/app/getAppAccessToken", "purpose": "initial_access_token" },
            { "method": "GET", "path": "/gateway", "purpose": "expired_token_probe" },
            { "method": "POST", "path": "/app/getAppAccessToken", "purpose": "refresh_after_unauthorized" },
            { "method": "GET", "path": "/gateway", "purpose": "fresh_token_probe" }
        ],
        "auth_gate": {
            "mode": "qqbot_access_token",
            "authorization_header_verified": true,
            "refresh_after_unauthorized_verified": true,
            "refresh_attempts": 1,
            "token_cache_path": "memory_only"
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
