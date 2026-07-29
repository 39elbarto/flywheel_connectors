//! Local loopback acceptance coverage for the FCP Airtable connector.

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
use fcp_airtable::connector::AirtableConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, HandshakeRequest, InstanceId, ZoneId,
};
use serde_json::json;

const OP_LIST_BASES: &str = "airtable.list_bases";
const EXPECTED_PATH: &str = "/v0/meta/bases?offset=itrNEXT";
const ACCESS_TOKEN: &str = "pat_local_airtable_token";
const RESPONSE_BODY: &str = r#"{
  "bases": [
    {
      "id": "appLocalAcceptance",
      "name": "Local Acceptance Base",
      "permissionLevel": "create"
    }
  ],
  "offset": "itrDONE"
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
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
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        if bytes_read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    }

    let request = String::from_utf8_lossy(&request);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let authorization_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case(&format!("authorization: Bearer {ACCESS_TOKEN}")));
    let user_agent_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("user-agent: fcp-airtable/0.1.0"));

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        user_agent_seen,
    }
}

fn handshake_req(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "1.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [37_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static("airtable.read")],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn capability_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id("airtable.read")
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:local-non-mock")
        .operations(&[OP_LIST_BASES])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (AirtableConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .handle_configure(json!({
            "token": ACCESS_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(
            serde_json::to_value(handshake_req(
                signing_key.verifying_key().to_bytes(),
                &instance_id,
            ))
            .expect("serialize handshake request"),
        )
        .await
        .expect("handshake connector");

    (connector, signing_key, instance_id)
}

#[fcp_async_core::runtime::test]
async fn loopback_list_bases_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_LIST_BASES,
            "input": {
                "offset": "itrNEXT"
            },
            "capability_token": capability_token(&signing_key, &instance_id)
        }))
        .await
        .expect("list Airtable bases through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.user_agent_seen);
    assert_eq!(result["bases"][0]["id"], "appLocalAcceptance");
    assert_eq!(result["bases"][0]["name"], "Local Acceptance Base");
    assert_eq!(result["offset"], "itrDONE");

    let artifact = json!({
        "connector": "airtable",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": OP_LIST_BASES,
        "method": "GET",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "user_agent_seen": observation.user_agent_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
