//! Local loopback acceptance coverage for the FCP Bitbucket connector.

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
use fcp_bitbucket::connector::BitbucketConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpResult};
use serde_json::{Value, json};

const EXPECTED_PATH: &str = "/repositories/test-workspace/fixture-repo";
const RESPONSE_BODY: &str = r#"{
  "uuid": "{repo-fixture}",
  "full_name": "test-workspace/fixture-repo",
  "name": "fixture-repo",
  "is_private": true,
  "language": "rust"
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
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
    let authorization_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer test-bitbucket-token"));

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
    }
}

struct TestConnector {
    connector: BitbucketConnector,
    signing_key: Ed25519SigningKey,
    instance_id: String,
}

impl TestConnector {
    async fn invoke(&self, mut params: Value) -> FcpResult<Value> {
        self.attach_capability_token(&mut params);
        self.connector.handle_invoke(params).await
    }

    fn attach_capability_token(&self, params: &mut Value) {
        let Some(object) = params.as_object_mut() else {
            return;
        };
        if object.contains_key("capability_token") {
            return;
        }
        object.insert(
            "capability_token".into(),
            serde_json::to_value(capability_token(&self.signing_key, &self.instance_id)).unwrap(),
        );
    }
}

fn capability_token(signing_key: &Ed25519SigningKey, instance_id: &str) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id("bitbucket.repositories.read")
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&["bitbucket.repositories.get"])
        .issuer("node:local-non-mock")
        .target_instance(instance_id)
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

fn handshake_params(signing_key: &Ed25519SigningKey) -> Value {
    let verifying_key = signing_key.verifying_key();
    json!({
        "session_id": "local-non-mock",
        "zone": "z:work",
        "host_public_key": verifying_key.to_bytes()
    })
}

async fn setup_connector(base_url: &str) -> TestConnector {
    let mut connector = BitbucketConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "test-bitbucket-token",
            "base_url": base_url
        }))
        .await
        .expect("configure connector");
    let signing_key = Ed25519SigningKey::generate();
    let handshake = connector
        .handle_handshake(handshake_params(&signing_key))
        .await
        .expect("handshake connector");
    let instance_id = handshake["instance_id"].as_str().unwrap().to_string();
    TestConnector {
        connector,
        signing_key,
        instance_id,
    }
}

#[fcp_async_core::runtime::test]
async fn loopback_repository_get_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let connector = setup_connector(fixture.base_url()).await;

    let result = connector
        .invoke(json!({
            "operation_id": "bitbucket.repositories.get",
            "input": {
                "workspace": "test-workspace",
                "repo_slug": "fixture-repo"
            }
        }))
        .await
        .expect("get repository through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert_eq!(result["repository"]["name"], "fixture-repo");
    assert_eq!(result["repository"]["language"], "rust");

    let artifact = json!({
        "connector": "bitbucket",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": "bitbucket.repositories.get",
        "method": "GET",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
