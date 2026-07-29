//! Local loopback acceptance coverage for the FCP NVIDIA NIM connector.

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

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_nvidia_nim::client::{DEFAULT_MODEL, USER_AGENT};
use fcp_nvidia_nim::connector::{CONNECTOR_ID, test_handshake_request};
use fcp_prelude::{CapabilityConstraints, CapabilityId, CapabilityToken, FcpError};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.45";
const ACCESS_SECRET: &str = "local_nvidia_nim_acceptance_secret";
const OP_CHAT: &str = "nvidia_nim.chat.completions";
const OP_MODELS: &str = "nvidia_nim.models.list";
const CAP_CHAT: &str = "nvidia_nim.chat";
const CAP_MODELS: &str = "nvidia_nim.models.read";

const CHAT_RESPONSE_BODY: &str = r#"{
  "id": "chatcmpl-local-nim",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "meta/llama-3.1-8b-instruct",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "local boundary accepted"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 3,
    "completion_tokens": 4,
    "total_tokens": 7
  }
}"#;

const MODELS_RESPONSE_BODY: &str = r#"{
  "object": "list",
  "data": [
    {
      "id": "meta/llama-3.1-8b-instruct",
      "object": "model",
      "created": 1693721698,
      "owned_by": "nvidia"
    }
  ]
}"#;

const RATE_LIMIT_BODY: &str = r#"{
  "error": {
    "type": "rate_limit_error",
    "message": "Too many local requests"
  }
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind NVIDIA NIM listener");
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
            base_url: format!("http://{address}/v1"),
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
    instance_id: &fcp_prelude::InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let now = Utc::now();
    let signed_capability = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:owner")
        .principal("nvidia-nim-local-acceptance")
        .issuer("node:loopback")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(instance_id.as_str())
        .operations(&[operation])
        .try_constraints_cbor(&cbor)
        .expect("valid constraints")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(signed_capability)
}

async fn setup_connector(
    base_url: &str,
    capabilities: Vec<CapabilityId>,
) -> (fcp_nvidia_nim::NvidiaNimConnector, Ed25519SigningKey) {
    let mut connector = fcp_nvidia_nim::NvidiaNimConnector::new();
    connector
        .handle_configure(json!({
            "deployment_mode": "self_hosted",
            "base_url": base_url,
            "api_key": ACCESS_SECRET,
            "request_timeout_ms": 5000
        }))
        .await
        .expect("configure connector");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(
            serde_json::to_value(test_handshake_request(
                capabilities,
                signing_key.verifying_key().to_bytes(),
            ))
            .expect("serialize handshake request"),
        )
        .await
        .expect("handshake connector");
    (connector, signing_key)
}

async fn invoke(
    connector: &fcp_nvidia_nim::NvidiaNimConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    capability: &str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_token(
                signing_key,
                connector.instance_id(),
                capability,
                operation
            )
        }))
        .await
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_chat_and_models_cross_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, CHAT_RESPONSE_BODY),
        ResponseSpec::json(200, MODELS_RESPONSE_BODY),
    ]);
    let (mut connector, signing_key) = setup_connector(
        fixture.base_url(),
        vec![
            CapabilityId::from_static(CAP_CHAT),
            CapabilityId::from_static(CAP_MODELS),
        ],
    )
    .await;

    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "local private prompt"}],
            "provider_extensions": {"fixture_case": "local-chat"}
        }),
    )
    .await
    .expect("chat completion through loopback");
    assert_eq!(chat["content"].as_str(), Some("local boundary accepted"));
    assert_eq!(chat["model"].as_str(), Some(DEFAULT_MODEL));

    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("model list through loopback");
    assert_eq!(models["data"][0]["id"].as_str(), Some(DEFAULT_MODEL));
    assert_eq!(models["base_url_class"].as_str(), Some("loopback"));

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].request_line,
        "POST /v1/chat/completions HTTP/1.1"
    );
    assert_eq!(observations[1].request_line, "GET /v1/models HTTP/1.1");

    let chat_body: Value = serde_json::from_str(&observations[0].body).expect("chat JSON body");
    assert_eq!(chat_body["model"].as_str(), Some(DEFAULT_MODEL));
    assert_eq!(chat_body["stream"].as_bool(), Some(false));
    assert_eq!(
        chat_body["messages"][0]["content"].as_str(),
        Some("local private prompt")
    );
    assert_eq!(chat_body["fixture_case"].as_str(), Some("local-chat"));

    for observation in &observations {
        assert!(has_header(
            &observation.headers,
            "authorization",
            &format!("Bearer {ACCESS_SECRET}")
        ));
        assert!(has_header(&observation.headers, "user-agent", USER_AGENT));
        assert!(has_header(
            &observation.headers,
            "accept",
            "application/json"
        ));
    }

    let artifact = json!({
        "connector": "nvidia-nim",
        "connector_id": CONNECTOR_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-nvidia-nim --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operations": [OP_CHAT, OP_MODELS],
        "request_response_boundary": {
            "methods": ["POST", "GET"],
            "paths": ["/v1/chat/completions", "/v1/models"],
            "json_body_verified": true,
            "model_list_verified": true
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
        &[("retry-after", "2")],
        RATE_LIMIT_BODY,
    )]);
    let (mut connector, signing_key) = setup_connector(
        fixture.base_url(),
        vec![CapabilityId::from_static(CAP_CHAT)],
    )
    .await;

    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "rate limited prompt"}]
        }),
    )
    .await
    .expect_err("rate limit response should map to FCP rate limit error");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let observations = fixture.join();
    let error_text = error.to_string();

    match error {
        FcpError::RateLimited {
            retry_after_ms,
            violation,
        } => {
            assert_eq!(retry_after_ms, 2000);
            assert!(violation.is_none());
        }
        other => panic!("unexpected provider error mapping: {other:?}"),
    }
    assert_eq!(observations.len(), 1);
    assert_eq!(
        request_path(&observations[0].request_line),
        "/v1/chat/completions"
    );
    assert!(has_header(
        &observations[0].headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));
    assert!(!error_text.contains(ACCESS_SECRET));
    assert!(!error_text.contains("rate limited prompt"));

    let artifact = json!({
        "connector": "nvidia-nim",
        "connector_id": CONNECTOR_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-nvidia-nim --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http_rate_limit",
        "provider_class": "local_sufficient",
        "operation": OP_CHAT,
        "request_response_boundary": {
            "method": "POST",
            "path": "/v1/chat/completions",
            "status": 429,
            "retry_after_ms": 2000
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
