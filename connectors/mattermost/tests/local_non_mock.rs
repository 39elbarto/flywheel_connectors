//! Local loopback acceptance coverage for the `Mattermost` connector.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_mattermost::MattermostConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityToken, InstanceId, InvokeRequest, InvokeStatus, OperationId,
    RequestId, ZoneId,
};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};

const OP_CREATE_POST: &str = "mattermost.create_post";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const ACCESS_TOKEN: &str = "mattermost_local_acceptance_token";
const CHANNEL_ID: &str = "channel_local_non_mock";
const ROOT_ID: &str = "root_local_non_mock";
const MESSAGE_TEXT: &str = "local non-mock Mattermost reply body";
const RESPONSE_BODY: &str = r#"{
  "id": "post_local_non_mock_reply",
  "channel_id": "channel_local_non_mock",
  "user_id": "user_local_non_mock",
  "message": "provider response body must stay out of evidence",
  "root_id": "root_local_non_mock",
  "create_at": 1775000001,
  "update_at": 1775000001
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: Vec<String>,
    body: Vec<u8>,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream)
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let mut raw = read_http_headers(&mut stream);
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("request should contain HTTP header terminator");
    let headers_len = header_end + 4;
    let header_text = String::from_utf8_lossy(&raw[..headers_len]).into_owned();
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();
    let content_length = header_value(&headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .expect("Mattermost JSON request should include content-length");
    let already_read_body = raw.len().saturating_sub(headers_len);
    if already_read_body < content_length {
        let remaining = content_length - already_read_body;
        let mut body_tail = vec![0_u8; remaining];
        stream
            .read_exact(&mut body_tail)
            .expect("read connector request body");
        raw.extend_from_slice(&body_tail);
    }
    let body = raw[headers_len..headers_len + content_length].to_vec();

    write!(
        stream,
        "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    }
}

fn header_value(headers: &[String], name: &str) -> Option<String> {
    headers.iter().find_map(|header| {
        let (header_name, value) = header.split_once(':')?;
        header_name
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

fn requested_instance_handshake_params(signing_key: &Ed25519SigningKey) -> (Value, InstanceId) {
    let requested_instance = InstanceId::new();
    let params = json!({
        "protocol_version": "1.0.0",
        "zone": "z:work",
        "host_public_key": signing_key.verifying_key().to_bytes().to_vec(),
        "nonce": vec![0_u8; 32],
        "capabilities_requested": ["mattermost.write"],
        "requested_instance_id": requested_instance.as_ref()
    });
    (params, requested_instance)
}

fn signed_capability_for_instance(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_owned()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("test constraints should serialize");

    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("agent:mattermost-local-non-mock")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(instance_id.as_ref())
        .try_constraints_cbor(&constraints_cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .expect("test capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn invoke_request(
    connector: &MattermostConnector,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_owned(),
        id: RequestId::new("req_mattermost_local_non_mock"),
        connector_id: connector.id().clone(),
        operation: OperationId::new(OP_CREATE_POST).expect("valid Mattermost operation id"),
        zone_id: ZoneId::work(),
        input: json!({
            "channel_id": CHANNEL_ID,
            "message": MESSAGE_TEXT,
            "root_id": ROOT_ID
        }),
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

fn hashed_id(kind: &str, raw: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(kind.as_bytes());
    hasher.update(b":");
    hasher.update(raw.as_bytes());
    let mut digest_hex = hex::encode(hasher.finalize());
    digest_hex.truncate(16);
    format!("{kind}:{digest_hex}")
}

fn git_revision() -> String {
    std::env::var("FCP_TEST_GIT_REVISION")
        .or_else(|_| std::env::var("GIT_REVISION"))
        .unwrap_or_else(|_| "worktree".to_owned())
}

fn assert_redaction_safe(serialized: &str) {
    for forbidden in [
        ACCESS_TOKEN,
        CHANNEL_ID,
        ROOT_ID,
        MESSAGE_TEXT,
        "provider response body",
        "user_local_non_mock",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "sensitive test value leaked in evidence: {forbidden}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn loopback_create_post_uses_public_mattermost_request_boundary() {
    let fixture = LoopbackFixture::start();
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = MattermostConnector::new();
    connector
        .handle_configure(json!({
            "base_url": fixture.base_url(),
            "token": ACCESS_TOKEN,
            "request_timeout_ms": 5_000,
            "chat_coordination": {
                "backend": "in_memory",
                "fail_open": false,
                "dm_mode": "treat_as_thread"
            }
        }))
        .await
        .expect("configure connector");
    let (handshake, requested_instance) = requested_instance_handshake_params(&signing_key);
    connector
        .handle_handshake(handshake)
        .expect("handshake connector");

    let started = Instant::now();
    let response = connector
        .invoke(invoke_request(
            &connector,
            signed_capability_for_instance(
                &signing_key,
                "mattermost.write",
                OP_CREATE_POST,
                &requested_instance,
            ),
        ))
        .await
        .expect("create_post should pass through the raw loopback fixture");
    let latency_ms = started.elapsed().as_millis();
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response
        .result
        .expect("successful Mattermost invoke should include a result");
    assert_eq!(result["id"], "post_local_non_mock_reply");
    assert_eq!(result["root_id"], ROOT_ID);
    assert!(
        result["coordination"]
            .as_array()
            .is_some_and(|records| !records.is_empty()),
        "create_post should include chat coordination audit records"
    );

    assert_eq!(observation.request_line, "POST /api/v4/posts HTTP/1.1");
    assert_eq!(
        header_value(&observation.headers, "authorization").as_deref(),
        Some("Bearer mattermost_local_acceptance_token")
    );
    assert!(
        header_value(&observation.headers, "content-type")
            .as_deref()
            .is_some_and(|value| value.starts_with("application/json"))
    );
    let request_body: Value =
        serde_json::from_slice(&observation.body).expect("connector request body should be JSON");
    assert_eq!(request_body["channel_id"], CHANNEL_ID);
    assert_eq!(request_body["root_id"], ROOT_ID);
    assert_eq!(request_body["message"], MESSAGE_TEXT);

    let artifact = json!({
        "connector": "mattermost",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.7.1",
        "command": "cargo test -p fcp-mattermost --test local_non_mock -- --nocapture",
        "git_revision": git_revision(),
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "operation_id": OP_CREATE_POST,
        "connector_archetype": "bidirectional",
        "bidirectional_boundary": {
            "kind": "threaded_channel_send",
            "request_method": "POST",
            "request_path": "/api/v4/posts",
            "response_status": 201,
            "channel_id_hash": hashed_id("channel", CHANNEL_ID),
            "thread_id_hash": hashed_id("thread", ROOT_ID),
            "message_body_redacted": true
        },
        "auth_gate": {
            "mode": "synthetic_bearer_token",
            "credentials_used": false,
            "authorization_header_observed": true
        },
        "capability_gate": {
            "operation": OP_CREATE_POST,
            "capability": "mattermost.write",
            "target_instance": requested_instance.as_ref(),
            "status": "granted"
        },
        "chat_coordination": {
            "backend": "in_memory",
            "dm_mode": "treat_as_thread",
            "audit_records": result["coordination"].as_array().map_or(0, Vec::len)
        },
        "latency_ms": latency_ms,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    let serialized = artifact.to_string();
    assert_redaction_safe(&serialized);
    println!("{serialized}");
}
