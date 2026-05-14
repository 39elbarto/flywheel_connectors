use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_perplexity_search::PerplexitySearchConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

const API_KEY: &str = "pplx-local-non-mock-key";
const OP_QUERY: &str = "perplexity-search.query";
const OP_SEARCH: &str = "perplexity-search.search";
const CAP_QUERY: &str = "perplexity-search.query";
const CAP_SEARCH: &str = "perplexity-search.search";

struct CapturedRequest {
    head: String,
    body: Value,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(status: &'static str, extra_headers: &[(&str, &str)], body: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its local address")
        );
        let (request_tx, received) = mpsc::channel();
        let mut extra_headers_text = String::new();
        for &(name, value) in extra_headers {
            write!(&mut extra_headers_text, "{name}: {value}\r\n")
                .expect("loopback headers should format into a string");
        }

        let join = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .expect("loopback listener should accept one request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("loopback stream should set a read timeout");

            let request = read_complete_request(&mut stream);
            request_tx
                .send(request)
                .expect("captured request should be delivered to the test");

            let response = format!(
                "HTTP/1.1 {status}\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 {extra_headers_text}\r\n\
                 {body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("loopback response should be writable");
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn finish(self) -> CapturedRequest {
        let request = self
            .received
            .recv_timeout(Duration::from_secs(5))
            .expect("loopback server should capture one request");
        self.join
            .join()
            .expect("loopback server thread should finish cleanly");
        request
    }
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        assert!(count > 0, "client closed before request was complete");
        bytes.extend_from_slice(&buffer[..count]);

        let Some(body_start) = body_start_offset(&bytes) else {
            continue;
        };
        let head = String::from_utf8_lossy(&bytes[..body_start]).into_owned();
        let content_length = content_length(&head);
        if bytes.len() >= body_start + content_length {
            let body_end = body_start + content_length;
            let body = serde_json::from_slice(&bytes[body_start..body_end])
                .expect("loopback request body should be JSON");
            return CapturedRequest { head, body };
        }
    }
}

fn body_start_offset(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|header_end| header_end + 4)
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .expect("loopback request should include content-length")
}

fn header_value<'a>(head: &'a str, wanted: &str) -> &'a str {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case(wanted) {
                Some(value.trim())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("missing expected header {wanted}"))
}

fn signing_key_and_pub() -> (Ed25519SigningKey, [u8; 32]) {
    let signing_key = Ed25519SigningKey::generate();
    let public_key = signing_key.verifying_key().to_bytes();
    (signing_key, public_key)
}

fn handshake_request(
    host_public_key: [u8; 32],
    requested_instance_id: InstanceId,
    capability: &'static str,
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [29_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(capability)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(requested_instance_id),
    }
}

fn operation_capability(
    signing_key: &Ed25519SigningKey,
    target_instance: &InstanceId,
    capability: &'static str,
    operation: &'static str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(target_instance.as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

async fn configured_connector(
    base_url: &str,
    capability: &'static str,
) -> (PerplexitySearchConnector, Ed25519SigningKey, InstanceId) {
    let (signing_key, public_key) = signing_key_and_pub();
    let requested_instance_id = InstanceId::new();
    let mut connector = PerplexitySearchConnector::new();
    connector
        .configure(json!({
            "api_key": API_KEY,
            "base_url": base_url,
            "request_timeout_ms": 5_000,
            "retry": { "max_retries": 0 }
        }))
        .await
        .expect("Perplexity connector should configure against loopback");
    connector
        .handshake(handshake_request(
            public_key,
            requested_instance_id.clone(),
            capability,
        ))
        .await
        .expect("Perplexity connector should handshake after configuration");
    (connector, signing_key, requested_instance_id)
}

fn invoke_request(
    id: &'static str,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.perplexity-search"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
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

#[fcp_async_core::runtime::test]
async fn local_non_mock_query_posts_chat_body_and_returns_answer() {
    let server = LoopbackServer::start(
        "200 OK",
        &[],
        r#"{"id":"chatcmpl-local-1","model":"sonar","object":"chat.completion","created":1778715000,"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"Rust emphasizes memory safety without a garbage collector."},"delta":null}],"usage":{"prompt_tokens":9,"completion_tokens":11,"total_tokens":20},"citations":["https://www.rust-lang.org/"]}"#,
    );
    let (connector, signing_key, instance_id) =
        configured_connector(&server.base_url, CAP_QUERY).await;

    let token = operation_capability(&signing_key, &instance_id, CAP_QUERY, OP_QUERY);
    let response = connector
        .invoke(invoke_request(
            "perplexity-local-query",
            OP_QUERY,
            json!({
                "query": "What makes Rust useful for infrastructure?",
                "system_prompt": "Answer tersely.",
                "temperature": 0.2,
                "max_tokens": 128,
                "search_domain_filter": ["rust-lang.org"],
                "return_related_questions": true,
                "freshness": "week"
            }),
            token,
        ))
        .await
        .expect("loopback chat-completions query should succeed");
    let captured = server.finish();
    let output = response
        .result
        .expect("successful invoke should include output");

    assert!(captured.head.starts_with("POST /chat/completions HTTP/1.1"));
    assert_eq!(
        header_value(&captured.head, "authorization"),
        "Bearer pplx-local-non-mock-key"
    );
    assert_eq!(header_value(&captured.head, "accept"), "application/json");
    assert_eq!(captured.body["model"], json!("sonar"));
    assert_eq!(captured.body["stream"], json!(false));
    assert_eq!(captured.body["messages"][0]["role"], json!("system"));
    assert_eq!(
        captured.body["messages"][0]["content"],
        json!("Answer tersely.")
    );
    assert_eq!(
        captured.body["messages"][1]["content"],
        json!("What makes Rust useful for infrastructure?")
    );
    assert_eq!(captured.body["max_tokens"], json!(128));
    assert_eq!(
        captured.body["search_domain_filter"],
        json!(["rust-lang.org"])
    );
    assert_eq!(captured.body["return_related_questions"], json!(true));
    assert_eq!(captured.body["search_recency_filter"], json!("week"));
    assert_eq!(
        output["answer"],
        json!("Rust emphasizes memory safety without a garbage collector.")
    );
    assert_eq!(output["citations"], json!(["https://www.rust-lang.org/"]));
    assert_eq!(output["usage"]["total_tokens"], json!(20));
    assert_eq!(output["external_content"]["untrusted"], json!(true));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_native_search_posts_filters_and_wraps_results() {
    let server = LoopbackServer::start(
        "200 OK",
        &[],
        r#"{"results":[{"title":"Rust Async","url":"https://www.rust-lang.org/learn","snippet":"Async Rust resources.","date":"2026-05-03"}]}"#,
    );
    let (connector, signing_key, instance_id) =
        configured_connector(&server.base_url, CAP_SEARCH).await;

    let token = operation_capability(&signing_key, &instance_id, CAP_SEARCH, OP_SEARCH);
    let response = connector
        .invoke(invoke_request(
            "perplexity-local-native-search",
            OP_SEARCH,
            json!({
                "query": "rust async runtimes",
                "count": 2,
                "country": "US",
                "language": "en",
                "domain_filter": ["rust-lang.org"],
                "date_after": "2026-05-01",
                "date_before": "2026-05-10",
                "max_tokens": 1000,
                "max_tokens_per_page": 250
            }),
            token,
        ))
        .await
        .expect("loopback native search should succeed");
    let captured = server.finish();
    let output = response
        .result
        .expect("successful invoke should include output");

    assert!(captured.head.starts_with("POST /search HTTP/1.1"));
    assert_eq!(
        header_value(&captured.head, "authorization"),
        "Bearer pplx-local-non-mock-key"
    );
    assert_eq!(captured.body["query"], json!("rust async runtimes"));
    assert_eq!(captured.body["max_results"], json!(2));
    assert_eq!(captured.body["country"], json!("US"));
    assert_eq!(captured.body["search_language_filter"], json!(["en"]));
    assert_eq!(
        captured.body["search_domain_filter"],
        json!(["rust-lang.org"])
    );
    assert_eq!(captured.body["search_after_date"], json!("5/1/2026"));
    assert_eq!(captured.body["search_before_date"], json!("5/10/2026"));
    assert_eq!(captured.body["max_tokens_per_page"], json!(250));
    assert_eq!(output["provider"], json!("perplexity"));
    assert_eq!(output["count"], json!(1));
    assert_eq!(
        output["results"][0]["url"],
        json!("https://www.rust-lang.org/learn")
    );
    assert_eq!(
        output["results"][0]["site_name"],
        json!("www.rust-lang.org")
    );
    assert!(
        output["results"][0]["title"]
            .as_str()
            .expect("title should be string")
            .contains("<untrusted-web-search>")
    );
    assert_eq!(output["external_content"]["wrapped"], json!(true));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_query_maps_provider_auth_denial() {
    let server = LoopbackServer::start(
        "401 Unauthorized",
        &[],
        r#"{"error":{"message":"Invalid API Key","type":"authentication_error","code":401}}"#,
    );
    let (connector, signing_key, instance_id) =
        configured_connector(&server.base_url, CAP_QUERY).await;

    let token = operation_capability(&signing_key, &instance_id, CAP_QUERY, OP_QUERY);
    let error = connector
        .invoke(invoke_request(
            "perplexity-local-auth-denial",
            OP_QUERY,
            json!({ "query": "will be denied" }),
            token,
        ))
        .await
        .expect_err("401 loopback response should deny authentication");
    let captured = server.finish();

    assert!(captured.head.starts_with("POST /chat/completions HTTP/1.1"));
    assert_eq!(
        captured.body["messages"][0]["content"],
        json!("will be denied")
    );
    match error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 2001);
            assert!(message.contains("HTTP 401"));
        }
        other => panic!("expected unauthorized error, got {other:?}"),
    }
}
