//! Local loopback acceptance coverage for the GLM connector.

#![allow(
    clippy::future_not_send,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_glm::{
    DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, GlmConnector,
    connector::{test_handshake_request, test_invoke_request},
};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, InstanceId,
};
use serde_json::{Value, json};

const CONNECTOR: &str = "glm";
const PACKAGE: &str = "fcp-glm";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.28";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_KEY: &str = "local_glm_api_key";

const OP_CHAT: &str = "glm.chat.completions";
const OP_EMBEDDINGS: &str = "glm.embeddings.create";

const CAP_CHAT: &str = "glm.chat";
const CAP_EMBEDDINGS: &str = "glm.embeddings";

const CHAT_RESPONSE: &str = r#"{
  "id": "chatcmpl-glm-local",
  "object": "chat.completion",
  "created": 1,
  "model": "glm-5.1",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "loopback GLM response"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 4,
    "completion_tokens": 3,
    "total_tokens": 7
  }
}"#;

const EMBEDDINGS_RESPONSE: &str = r#"{
  "object": "list",
  "model": "embedding-3",
  "data": [
    {
      "index": 0,
      "object": "embedding",
      "embedding": [0.125, 0.25, 0.5]
    }
  ],
  "usage": {
    "prompt_tokens": 2,
    "total_tokens": 2
  }
}"#;

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: HeaderObservations,
    body: Option<Value>,
}

#[derive(Debug)]
struct HeaderObservations {
    authorization: HeaderPresence,
    accept_json: HeaderPresence,
    content_type_json: HeaderPresence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderPresence {
    Seen,
    Missing,
}

impl HeaderPresence {
    const fn from_found(found: bool) -> Self {
        if found { Self::Seen } else { Self::Missing }
    }

    fn assert_seen(self, name: &str) {
        assert_eq!(self, Self::Seen, "expected {name} header");
    }
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<Vec<FixtureObservation>>>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, *response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}/api/paas/v4"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<FixtureObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: HttpResponse) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let request = read_complete_request(&mut stream);
    let header_end = find_header_end(&request).expect("request contains complete headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body_start = header_end + b"\r\n\r\n".len();
    let body = (body_start < request.len())
        .then(|| serde_json::from_slice(&request[body_start..]).expect("request body is JSON"));
    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let header_observations = HeaderObservations {
        authorization: HeaderPresence::from_found(header_equals(
            &headers,
            "authorization",
            &format!("Bearer {API_KEY}"),
        )),
        accept_json: HeaderPresence::from_found(header_contains(
            &headers,
            "accept",
            "application/json",
        )),
        content_type_json: HeaderPresence::from_found(header_contains(
            &headers,
            "content-type",
            "application/json",
        )),
    };

    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        response.body.len(),
        response.body
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers: header_observations,
        body,
    }
}

fn read_complete_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector closed before request completed");
        request.extend_from_slice(&buffer[..bytes_read]);
        assert!(request.len() < 64 * 1024, "request should stay bounded");

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = parse_content_length(&headers).unwrap_or(0);
            let expected_len = header_end + b"\r\n\r\n".len() + content_length;
            if request.len() >= expected_len {
                request.truncate(expected_len);
                return request;
            }
        }
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Option<usize> {
    header_value(headers, "content-length")?.parse().ok()
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}:");
    headers.lines().find_map(|line| {
        let (actual_name, value) = line.split_once(':')?;
        actual_name
            .eq_ignore_ascii_case(prefix.trim_end_matches(':'))
            .then(|| value.trim())
    })
}

fn header_equals(headers: &str, name: &str, expected: &str) -> bool {
    header_value(headers, name).is_some_and(|value| value == expected)
}

fn header_contains(headers: &str, name: &str, needle: &str) -> bool {
    header_value(headers, name)
        .map(str::to_ascii_lowercase)
        .is_some_and(|value| value.contains(&needle.to_ascii_lowercase()))
}

async fn configured_connector(
    base_url: &str,
    capabilities: &[&'static str],
) -> (GlmConnector, Ed25519SigningKey) {
    let mut connector = GlmConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "base_url": base_url,
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure should succeed");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let caps = capabilities
        .iter()
        .map(|cap| CapabilityId::from_static(cap))
        .collect();
    connector
        .handle_handshake(
            serde_json::to_value(test_handshake_request(caps, verifying_key.to_bytes()))
                .expect("handshake request serializes"),
        )
        .await
        .expect("handshake should succeed");

    (connector, signing_key)
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &GlmConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_grant,
        }))
        .await
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_chat_completions_posts_body_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: CHAT_RESPONSE,
    }]);
    let (connector, signing_key) = configured_connector(server.base_url(), &[CAP_CHAT]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello loopback GLM"}],
            "max_tokens": 8,
            "temperature": 0.25
        }),
    )
    .await
    .expect("chat invoke should succeed");

    assert_eq!(result["id"], "chatcmpl-glm-local");
    assert_eq!(result["model"], DEFAULT_MODEL);
    assert_eq!(result["content"], "loopback GLM response");
    assert_eq!(result["finish_reason"], "stop");
    assert_eq!(result["usage"]["total_tokens"], 7);
    assert!(
        !result.to_string().contains(API_KEY),
        "response must not leak API key"
    );

    let observations = server.join();
    let observation = observations.first().expect("one chat request observed");
    assert_eq!(
        observation.request_line,
        "POST /api/paas/v4/chat/completions HTTP/1.1"
    );
    observation
        .headers
        .authorization
        .assert_seen("authorization");
    observation.headers.accept_json.assert_seen("accept");
    observation
        .headers
        .content_type_json
        .assert_seen("content-type");
    let body = observation
        .body
        .as_ref()
        .expect("chat request has JSON body");
    assert_eq!(body["model"], DEFAULT_MODEL);
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "hello loopback GLM");
    assert_eq!(body["stream"], false);
    assert_eq!(body["max_tokens"], 8);
    assert_eq!(body["temperature"], 0.25);

    println!(
        "{}",
        json!({
            "connector": CONNECTOR,
            "package": PACKAGE,
            "bead": BEAD_ID,
            "suite_class": ACCEPTANCE_SUITE_CLASS,
            "operation": OP_CHAT,
            "fixture": "raw_tcp_listener",
            "egress": "loopback_only",
            "auth": "bearer_observed_redacted",
            "request_path": "/api/paas/v4/chat/completions",
            "cleanup": "listener_joined"
        })
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_embeddings_posts_body_and_maps_vector() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: EMBEDDINGS_RESPONSE,
    }]);
    let (connector, signing_key) = configured_connector(server.base_url(), &[CAP_EMBEDDINGS]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({
            "input": "embedding fixture text",
            "dimensions": 3
        }),
    )
    .await
    .expect("embeddings invoke should succeed");

    assert_eq!(result["model"], DEFAULT_EMBEDDING_MODEL);
    assert_eq!(result["usage"]["total_tokens"], 2);
    assert_eq!(result["data"][0]["embedding"][0], 0.125);
    assert!(
        !result.to_string().contains(API_KEY),
        "embedding response must not leak API key"
    );

    let observations = server.join();
    let observation = observations
        .first()
        .expect("one embeddings request observed");
    assert_eq!(
        observation.request_line,
        "POST /api/paas/v4/embeddings HTTP/1.1"
    );
    observation
        .headers
        .authorization
        .assert_seen("authorization");
    observation.headers.accept_json.assert_seen("accept");
    observation
        .headers
        .content_type_json
        .assert_seen("content-type");
    let body = observation
        .body
        .as_ref()
        .expect("embeddings request has JSON body");
    assert_eq!(body["model"], DEFAULT_EMBEDDING_MODEL);
    assert_eq!(body["input"], "embedding fixture text");
    assert_eq!(body["dimensions"], 3);

    println!(
        "{}",
        json!({
            "connector": CONNECTOR,
            "package": PACKAGE,
            "bead": BEAD_ID,
            "suite_class": ACCEPTANCE_SUITE_CLASS,
            "operation": OP_EMBEDDINGS,
            "fixture": "raw_tcp_listener",
            "egress": "loopback_only",
            "auth": "bearer_observed_redacted",
            "request_path": "/api/paas/v4/embeddings",
            "cleanup": "listener_joined"
        })
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_wrong_capability_fails_before_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused listener");
    listener
        .set_nonblocking(true)
        .expect("make listener nonblocking");
    let base_url = format!(
        "http://{}/api/paas/v4",
        listener.local_addr().expect("read listener address")
    );
    let (connector, signing_key) = configured_connector(&base_url, &[CAP_EMBEDDINGS]).await;
    let capability_grant = valid_token(
        &signing_key,
        connector.instance_id(),
        CAP_EMBEDDINGS,
        OP_EMBEDDINGS,
    );

    let error = match connector
        .invoke(test_invoke_request(
            "glm-wrong-capability",
            OP_CHAT,
            json!({"messages": [{"role": "user", "content": "must not egress"}]}),
            capability_grant,
        ))
        .await
    {
        Err(error) => error,
        Ok(response) => response
            .error
            .expect("wrong capability returns invoke error"),
    };

    assert!(
        matches!(
            error,
            FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
        ),
        "unexpected error for wrong capability: {error:?}"
    );
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Ok(_) => panic!("capability denial must happen before any network egress"),
        Err(error) => panic!("unexpected listener error: {error}"),
    }

    println!(
        "{}",
        json!({
            "connector": CONNECTOR,
            "package": PACKAGE,
            "bead": BEAD_ID,
            "suite_class": ACCEPTANCE_SUITE_CLASS,
            "operation": OP_CHAT,
            "fixture": "raw_tcp_listener_nonblocking",
            "egress": "none",
            "authz": "wrong_capability_denied_before_socket_accept",
            "cleanup": "listener_dropped"
        })
    );
}
