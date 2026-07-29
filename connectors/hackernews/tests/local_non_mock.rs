//! Local loopback acceptance coverage for the `Hacker News` connector.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_hackernews::HackerNewsConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::json;

const OP_TOP_STORIES: &str = "hackernews.top_stories";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const RESPONSE_BODY: &str = "[101,102,103]";

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: Vec<String>,
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
            base_url: format!("http://{address}/v0"),
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
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_headers(&mut stream);
    let request = String::from_utf8_lossy(&raw);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers,
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
        assert!(request.len() < 8192, "request should stay bounded");
    }
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [41_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static("hackernews.read")],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    operation_id: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id("hackernews.read")
        .zone_id("z:work")
        .principal("user:local-acceptance")
        .operations(&[operation_id])
        .issuer("node:local-acceptance")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints cbor should be valid")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn invoke_request(capability_token: CapabilityToken) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("hackernews-local-non-mock-1"),
        connector_id: ConnectorId::from_static("fcp.hackernews"),
        operation: OperationId::from_static(OP_TOP_STORIES),
        zone_id: ZoneId::work(),
        input: json!({ "limit": 2 }),
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

#[fcp_async_core::runtime::test]
async fn loopback_top_stories_uses_public_firebase_boundary() {
    let fixture = LoopbackFixture::start();
    let mut connector = HackerNewsConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": fixture.base_url(),
            "request_timeout_ms": 5_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure connector");
    connector
        .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake connector");

    let token = capability_token(&signing_key, OP_TOP_STORIES, connector.instance_id());
    let response = connector
        .invoke(invoke_request(token))
        .await
        .expect("top stories through loopback fixture");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(observation.request_line, "GET /v0/topstories.json HTTP/1.1");
    assert!(
        observation
            .headers
            .iter()
            .any(|line| line.to_ascii_lowercase().starts_with("host: 127.0.0.1:"))
    );
    assert!(
        observation
            .headers
            .iter()
            .all(|line| !line.to_ascii_lowercase().starts_with("authorization:"))
    );
    assert_eq!(response.status, InvokeStatus::Ok);
    assert_eq!(response.result, Some(json!([101, 102])));

    let artifact = json!({
        "connector": "hackernews",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.6",
        "command": "cargo test -p fcp-hackernews --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "GET",
            "path": "/v0/topstories.json",
            "input_fields": ["limit"]
        },
        "auth_gate": {
            "mode": "capability_token_only",
            "upstream_credentials_used": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
