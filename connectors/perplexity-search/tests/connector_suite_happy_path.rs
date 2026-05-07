use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_perplexity_search::PerplexitySearchConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

const OP_SEARCH: &str = "perplexity-search.query";
const OP_NATIVE_SEARCH: &str = "perplexity-search.search";
const CAP_SEARCH: &str = "perplexity-search.query";
const CAP_NATIVE_SEARCH: &str = "perplexity-search.search";

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
        nonce: [17u8; 32],
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
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .target_instance(target_instance.as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn search_capability(
    signing_key: &Ed25519SigningKey,
    target_instance: &InstanceId,
) -> CapabilityToken {
    operation_capability(signing_key, target_instance, CAP_SEARCH, OP_SEARCH)
}

fn native_search_capability(
    signing_key: &Ed25519SigningKey,
    target_instance: &InstanceId,
) -> CapabilityToken {
    operation_capability(
        signing_key,
        target_instance,
        CAP_NATIVE_SEARCH,
        OP_NATIVE_SEARCH,
    )
}

fn invoke_for_operation(
    id: &'static str,
    operation: &'static str,
    input: serde_json::Value,
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

fn search_invoke(id: &'static str, capability_token: CapabilityToken) -> InvokeRequest {
    invoke_for_operation(
        id,
        OP_SEARCH,
        json!({
            "query": "What is Rust?",
            "temperature": 0.5
        }),
        capability_token,
    )
}

fn native_search_invoke(id: &'static str, capability_token: CapabilityToken) -> InvokeRequest {
    invoke_for_operation(
        id,
        OP_NATIVE_SEARCH,
        json!({
            "query": "rust async runtimes",
            "count": 2,
            "country": "US",
            "language": "en",
            "domain_filter": ["rust-lang.org"],
            "date_after": "2026-05-01",
            "max_tokens": 1000,
            "max_tokens_per_page": 250
        }),
        capability_token,
    )
}

fn search_suite(server: &MockServer) -> ConnectorSuite {
    let (signing_key, public_key) = signing_key_and_pub();
    let requested_instance_id = InstanceId::new();
    ConnectorSuite {
        test_name: "perplexity_search_connector_suite_happy_path".into(),
        config: json!({
            "api_key": "pplx-test-key",
            "base_url": server.uri()
        }),
        handshake: handshake_request(public_key, requested_instance_id.clone(), CAP_SEARCH),
        invoke: Some(search_invoke(
            "perplexity-search-suite",
            search_capability(&signing_key, &requested_instance_id),
        )),
        invoke_expectations: InvokeExpectations::default(),
    }
}

fn native_search_suite(server: &MockServer) -> ConnectorSuite {
    let (signing_key, public_key) = signing_key_and_pub();
    let requested_instance_id = InstanceId::new();
    ConnectorSuite {
        test_name: "perplexity_native_search_connector_suite_happy_path".into(),
        config: json!({
            "api_key": "pplx-test-key",
            "base_url": server.uri()
        }),
        handshake: handshake_request(public_key, requested_instance_id.clone(), CAP_NATIVE_SEARCH),
        invoke: Some(native_search_invoke(
            "perplexity-native-search-suite",
            native_search_capability(&signing_key, &requested_instance_id),
        )),
        invoke_expectations: InvokeExpectations::default(),
    }
}

#[fcp_async_core::runtime::test]
async fn connector_suite_search_happy_path_uses_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer pplx-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-suite-123",
            "model": "sonar",
            "object": "chat.completion",
            "created": 1_700_000_000u64,
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": "Rust is a systems programming language focused on safety and performance."
                },
                "delta": null
            }],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 15,
                "total_tokens": 27
            },
            "citations": [
                "https://www.rust-lang.org/",
                "https://doc.rust-lang.org/book/"
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = PerplexitySearchConnector::new();
    let mut runner = E2eRunner::new("fcp-perplexity-search");
    let report = runner
        .run_connector_suite(&mut connector, search_suite(&server))
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector suite should pass: {report:#?}");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}

#[fcp_async_core::runtime::test]
async fn connector_suite_native_search_happy_path_uses_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/search"))
        .and(header("authorization", "Bearer pplx-test-key"))
        .and(body_json(json!({
            "query": "rust async runtimes",
            "max_results": 2,
            "country": "US",
            "search_domain_filter": ["rust-lang.org"],
            "search_language_filter": ["en"],
            "search_after_date": "5/1/2026",
            "max_tokens": 1000,
            "max_tokens_per_page": 250
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Rust",
                "url": "https://www.rust-lang.org/",
                "snippet": "Rust is a language empowering everyone to build reliable software.",
                "date": "2026-05-02"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = PerplexitySearchConnector::new();
    let mut runner = E2eRunner::new("fcp-perplexity-search");
    let report = runner
        .run_connector_suite(&mut connector, native_search_suite(&server))
        .await
        .expect("native connector suite run");

    assert!(
        report.passed,
        "native connector suite should pass: {report:#?}"
    );
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
