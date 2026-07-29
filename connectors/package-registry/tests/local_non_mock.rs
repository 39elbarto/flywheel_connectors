//! Local loopback acceptance coverage for the FCP Package Registry connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_package_registry::connector::PackageRegistryConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::json;

const EXPECTED_PATH: &str = "/api/v1/crates?q=serde&per_page=1&page=1";
const RESPONSE_BODY: &str = r#"{
  "crates": [
    {
      "name": "serde",
      "description": "fixture serialization framework",
      "max_version": "1.0.228",
      "downloads": 123456,
      "recent_downloads": 789
    }
  ],
  "meta": { "total": 1 }
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    user_agent_seen: bool,
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

    let mut buffer = [0_u8; 4096];
    let bytes_read = stream.read(&mut buffer).expect("read connector request");
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let user_agent_seen = request
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("user-agent:"));

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        user_agent_seen,
    }
}

fn handshake_req(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static("registry.search")],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn capability_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id("registry.search")
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&["registry.search"])
        .target_instance(instance_id.as_str())
        .issuer("node:local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn loopback_crates_search_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let mut connector = PackageRegistryConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .configure(json!({
            "provider": "crates_io",
            "base_url": fixture.base_url(),
            "request_timeout_ms": 1_000,
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
        .handshake(handshake_req(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake connector");

    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("package-registry-local-non-mock"),
            connector_id: ConnectorId::from_static("fcp.package-registry"),
            operation: OperationId::from_static("registry.search"),
            zone_id: ZoneId::work(),
            input: json!({"query": "serde", "limit": 1, "page": 1}),
            capability_token: capability_token(&signing_key, &instance_id),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        })
        .await
        .expect("search packages through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.user_agent_seen);
    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["results"][0]["name"], "serde");
    assert_eq!(result["results"][0]["latest_version"], "1.0.228");

    let artifact = json!({
        "connector": "package-registry",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": "registry.search",
        "method": "GET",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "user_agent_seen": observation.user_agent_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
