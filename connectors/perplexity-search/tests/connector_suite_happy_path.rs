use chrono::{Duration, Utc};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_perplexity_search::PerplexitySearchConnector;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const OP_SEARCH: &str = "perplexity-search.query";
const CAP_SEARCH: &str = "perplexity-search.query";

fn signing_key_and_pub() -> (Ed25519SigningKey, [u8; 32]) {
    let signing_key = Ed25519SigningKey::generate();
    let public_key = signing_key.verifying_key().to_bytes();
    (signing_key, public_key)
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_SEARCH)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn search_capability(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_SEARCH)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_SEARCH])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn search_invoke(id: &'static str, capability_token: CapabilityToken) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.perplexity-search"),
        operation: OperationId::from_static(OP_SEARCH),
        zone_id: ZoneId::work(),
        input: json!({
            "query": "What is Rust?",
            "temperature": 0.5
        }),
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

fn suite(server: &MockServer) -> ConnectorSuite {
    let (signing_key, public_key) = signing_key_and_pub();
    ConnectorSuite {
        test_name: "perplexity_search_connector_suite_happy_path".into(),
        config: json!({
            "api_key": "pplx-test-key",
            "base_url": server.uri()
        }),
        handshake: handshake_request(public_key),
        invoke: Some(search_invoke(
            "perplexity-search-suite",
            search_capability(&signing_key),
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
        .run_connector_suite(&mut connector, suite(&server))
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
