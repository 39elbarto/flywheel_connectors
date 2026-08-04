//! Local loopback acceptance coverage for the Google Forms connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_forms::connector::FormsConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpError, HandshakeRequest, InstanceId,
    ZoneId,
};
use serde_json::{Value, json};

const LOOPBACK_AUTH_VALUE: &str = "local-loopback-auth-value";
const OP_GET_FORM: &str = "forms.get";
const READ_CAPABILITY: &str = "forms.read";
const WRITE_CAPABILITY: &str = "form.structure.write";
const FORM_ID: &str = "form_test_123";
const EXPECTED_PATH: &str = "/v1/forms/form_test_123?";

const SUCCESS_RESPONSE: &str = r#"{
  "formId": "form_test_123",
  "revisionId": "rev-1",
  "info": {"title": "Private local fixture"},
  "settings": {"quizSettings": {"isQuiz": false}},
  "items": [{"itemId":"item-1","title":"Local item","textItem":{}}]
}"#;

const UNAUTHORIZED_RESPONSE: &str = r#"{
  "error": {
    "code": 401,
    "message": "provider-private-message",
    "status": "UNAUTHENTICATED"
  }
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    accept_seen: bool,
    user_agent_seen: bool,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start(response_status: &'static str, response_body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream, response_status, response_body)
        });

        Self {
            base_url: format!("http://{address}/v1"),
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

fn handle_request(
    mut stream: TcpStream,
    response_status: &str,
    response_body: &str,
) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_headers(&mut stream);
    let headers = String::from_utf8_lossy(&request);
    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let authorization_seen = header_seen(
        &headers,
        "authorization",
        &format!("Bearer {LOOPBACK_AUTH_VALUE}"),
    );
    let accept_seen = header_value_contains(&headers, "accept", "application/json");
    let user_agent_seen = header_value_contains(&headers, "user-agent", "fcp-google-forms/0.1.0");

    write!(
        stream,
        "HTTP/1.1 {response_status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        accept_seen,
        user_agent_seen,
    }
}

fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector should send request headers");
        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    }
}

fn header_seen(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn header_value_contains(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name)
            && value
                .to_ascii_lowercase()
                .contains(&expected_value.to_ascii_lowercase())
    })
}

fn assert_get_request_boundary(request_line: &str) {
    let mut parts = request_line.split_whitespace();
    assert_eq!(parts.next(), Some("GET"));
    let target = parts.next().expect("request target should be present");
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    assert_eq!(parts.next(), None);

    assert_eq!(target, EXPECTED_PATH);
}

fn handshake_req(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "1.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [31_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(READ_CAPABILITY)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!("google-forms:form:{FORM_ID}")],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:local-non-mock")
        .operations(&[OP_GET_FORM])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (FormsConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = FormsConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .handle_configure(json!({
            "access_token": LOOPBACK_AUTH_VALUE,
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

fn get_input() -> Value {
    json!({ "form_id": FORM_ID })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_get_form_uses_forms_request_boundary() {
    let fixture = LoopbackFixture::start("200 OK", SUCCESS_RESPONSE);
    let (mut connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_GET_FORM,
            "input": get_input(),
            "capability_token": capability_token(&signing_key, &instance_id, READ_CAPABILITY)
        }))
        .await
        .expect("get form through connector");
    let observation = fixture.join();

    assert_get_request_boundary(&observation.request_line);
    assert!(observation.authorization_seen);
    assert!(observation.accept_seen);
    assert!(observation.user_agent_seen);
    assert_eq!(result["form"]["metadata"]["form_id"], FORM_ID);
    assert_eq!(result["form"]["metadata"]["title"], "Private local fixture");
    assert_eq!(result["form"]["metadata"]["revision_id"], "rev-1");
    assert_eq!(result["form"]["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(result["form"]["items_complete"], true);
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-forms",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "bd-2oc.14",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_GET_FORM,
        "method": "GET",
        "endpoint_shape": "/v1/forms/{form_id}",
        "request_target_verified": true,
        "form_id_redacted": true,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen
        },
        "headers": {
            "accept_json_seen": observation.accept_seen,
            "user_agent_seen": observation.user_agent_seen
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_error_does_not_leak_auth_material() {
    let fixture = LoopbackFixture::start("401 Unauthorized", UNAUTHORIZED_RESPONSE);
    let (mut connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_GET_FORM,
            "input": get_input(),
            "capability_token": capability_token(&signing_key, &instance_id, READ_CAPABILITY)
        }))
        .await
        .expect_err("401 should map to unauthorized");
    let observation = fixture.join();

    assert!(observation.authorization_seen);
    assert!(matches!(error, FcpError::Unauthorized { .. }));
    assert!(!error.to_string().contains(LOOPBACK_AUTH_VALUE));
    assert!(!error.to_string().contains("provider-private-message"));

    let artifact = json!({
        "connector": "google-forms",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "bd-2oc.14",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_GET_FORM,
        "error_mapping": "unauthorized",
        "authorization_header_verified": observation.authorization_seen,
        "auth_material_leaked": false,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_wrong_capability_fails_before_loopback_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let base_url = format!(
        "http://{}/v1",
        listener.local_addr().expect("read listener address")
    );
    let (mut connector, signing_key, instance_id) = setup_connector(&base_url).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_GET_FORM,
            "input": get_input(),
            "capability_token": capability_token(&signing_key, &instance_id, WRITE_CAPABILITY)
        }))
        .await
        .expect_err("write capability should not authorize form reads");

    assert!(matches!(
        error,
        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
    ));
    let accept_error = listener
        .accept()
        .expect_err("capability denial should happen before loopback egress");
    assert_eq!(accept_error.kind(), io::ErrorKind::WouldBlock);

    let artifact = json!({
        "connector": "google-forms",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "bd-2oc.14",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_GET_FORM,
        "denial": "wrong_capability",
        "loopback_egress_attempted": false,
        "result": "passed"
    });
    println!("{artifact}");
}
