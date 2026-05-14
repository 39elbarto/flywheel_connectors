//! Local loopback acceptance coverage for the FCP Microsoft Foundry connector.

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
use fcp_microsoft_foundry::MicrosoftFoundryConnector;
use fcp_microsoft_foundry::client::USER_AGENT;
use fcp_microsoft_foundry::connector::test_handshake_request;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, InstanceId,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.48";
const ACCESS_SECRET: &str = "local_foundry_acceptance_secret";
const DEFAULT_MODEL: &str = "prod-gpt4o";
const OP_CHAT: &str = "microsoft_foundry.chat.completions";
const OP_MODELS: &str = "microsoft_foundry.deployments.list";
const CAP_CHAT: &str = "microsoft_foundry.chat";
const CAP_MODELS: &str = "microsoft_foundry.deployments.read";

const CHAT_RESPONSE_BODY: &str = r#"{
  "id": "chatcmpl-foundry-local",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "prod-gpt4o",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "local foundry accepted"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 2,
    "completion_tokens": 3,
    "total_tokens": 5
  }
}"#;

const MODELS_RESPONSE_BODY: &str = r#"{
  "object": "list",
  "data": [
    {
      "id": "prod-gpt4o",
      "object": "model",
      "created": 1700000000,
      "owned_by": "azure"
    }
  ]
}"#;

const RATE_LIMIT_BODY: &str = r#"{
  "error": {
    "type": "rate_limit_error",
    "message": "slow down"
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Microsoft Foundry listener");
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
            base_url: format!("http://{address}/openai/v1"),
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

fn assert_header(headers: &[String], name: &str, expected_value: &str) {
    assert!(
        has_header(headers, name, expected_value),
        "expected header {name}: {expected_value}, got {headers:?}"
    );
}

fn assert_required_headers(observation: &RequestObservation) {
    assert_header(&observation.headers, "api-key", ACCESS_SECRET);
    assert_header(&observation.headers, "accept", "application/json");
    assert_header(&observation.headers, "content-type", "application/json");
    assert_header(&observation.headers, "user-agent", USER_AGENT);
}

fn request_path(request_line: &str) -> &str {
    request_line.split_whitespace().nth(1).unwrap_or_default()
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
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
        .zone_id("z:work")
        .principal("microsoft-foundry-local-acceptance")
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

async fn setup_connector(base_url: &str) -> (MicrosoftFoundryConnector, Ed25519SigningKey) {
    let mut connector = MicrosoftFoundryConnector::new();
    connector
        .handle_configure(json!({
            "api_key": ACCESS_SECRET,
            "base_url": base_url,
            "default_model": DEFAULT_MODEL,
            "request_timeout_ms": 5000,
            "model_cache_ttl_seconds": 1
        }))
        .await
        .expect("configure connector");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(test_handshake_request(
            vec![
                CapabilityId::from_static(CAP_CHAT),
                CapabilityId::from_static(CAP_MODELS),
            ],
            signing_key.verifying_key().to_bytes(),
        ))
        .await
        .expect("handshake connector");
    (connector, signing_key)
}

async fn invoke(
    connector: &MicrosoftFoundryConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    capability: &str,
    input: &Value,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_token(
                signing_key,
                connector.instance_id(),
                capability,
                operation,
            ),
        }))
        .await
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_chat_and_deployment_list_cross_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, CHAT_RESPONSE_BODY),
        ResponseSpec::json(200, MODELS_RESPONSE_BODY),
    ]);
    let (connector, signing_key) = setup_connector(fixture.base_url()).await;

    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        &json!({
            "messages": [
                {"role": "user", "content": "local foundry prompt"}
            ]
        }),
    )
    .await
    .expect("chat invoke should succeed");
    assert_eq!(chat["id"], "chatcmpl-foundry-local");
    assert_eq!(chat["model"], DEFAULT_MODEL);
    assert_eq!(chat["content"], "local foundry accepted");
    assert_eq!(chat["finish_reason"], "stop");
    assert_eq!(chat["choice_count"], 1);

    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, &json!({}))
        .await
        .expect("models should succeed");
    assert_eq!(models["data"][0]["id"], DEFAULT_MODEL);

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);

    let chat_request = &observations[0];
    assert_eq!(
        chat_request.request_line,
        "POST /openai/v1/chat/completions HTTP/1.1"
    );
    assert_required_headers(chat_request);
    let chat_body: Value = serde_json::from_str(&chat_request.body).expect("chat body is JSON");
    assert_eq!(chat_body["model"], DEFAULT_MODEL);
    assert_eq!(chat_body["stream"], false);
    assert_eq!(chat_body["messages"][0]["content"], "local foundry prompt");
    assert!(!chat_request.body.contains(ACCESS_SECRET));

    let models_request = &observations[1];
    assert_eq!(
        models_request.request_line,
        "GET /openai/v1/models HTTP/1.1"
    );
    assert_required_headers(models_request);
    assert!(models_request.body.is_empty());

    let evidence = json!({
        "suite": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "connector": "microsoft-foundry",
        "operations": [OP_CHAT, OP_MODELS],
        "request_paths": [
            request_path(&chat_request.request_line),
            request_path(&models_request.request_line),
        ],
        "capability_token_verified": true,
        "required_headers_verified": ["api-key", "accept", "content-type", "user-agent"],
        "chat_id": chat["id"],
        "deployment_id": models["data"][0]["id"],
    });
    let evidence_text = evidence.to_string();
    assert!(!evidence_text.contains(ACCESS_SECRET));
    assert!(!evidence_text.contains("local foundry prompt"));
    println!("{evidence}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_metadata() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::with_headers(
        429,
        &[("retry-after", "2")],
        RATE_LIMIT_BODY,
    )]);
    let (connector, signing_key) = setup_connector(fixture.base_url()).await;

    let limited = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        &json!({"messages": [{"role": "user", "content": "limited"}]}),
    )
    .await
    .expect_err("rate limit should fail");
    let limited_debug = format!("{limited:?}");
    assert!(!limited_debug.contains(ACCESS_SECRET));
    let retry_after_ms = match limited {
        FcpError::RateLimited {
            retry_after_ms,
            violation,
        } => {
            assert!(violation.is_none());
            retry_after_ms
        }
        other => panic!("expected rate limit, got {other:?}"),
    };
    assert_eq!(retry_after_ms, 2_000);

    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    let request = &observations[0];
    assert_eq!(
        request.request_line,
        "POST /openai/v1/chat/completions HTTP/1.1"
    );
    assert_required_headers(request);

    let evidence = json!({
        "suite": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "connector": "microsoft-foundry",
        "operation": OP_CHAT,
        "request_path": request_path(&request.request_line),
        "error_class": "rate_limited",
        "retry_after_ms": retry_after_ms,
        "secret_redaction_checked": true,
    });
    let evidence_text = evidence.to_string();
    assert!(!evidence_text.contains(ACCESS_SECRET));
    assert!(!evidence_text.contains("slow down"));
    println!("{evidence}");
}
