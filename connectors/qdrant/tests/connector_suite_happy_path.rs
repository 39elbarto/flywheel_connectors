use chrono::{Duration, Utc};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_qdrant::connector::QdrantConnector;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const OP_LIST_COLLECTIONS: &str = "qdrant.list_collections";
const CAP_COLLECTIONS_READ: &str = "qdrant.collections.read";

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [9u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_COLLECTIONS_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_COLLECTIONS_READ)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_LIST_COLLECTIONS])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_lists_collections() {
    let qdrant_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .and(header("api-key", "test-qdrant-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "collections": [
                    { "name": "embeddings" },
                    { "name": "documents" }
                ]
            },
            "status": "ok",
            "time": 0.001
        })))
        .expect(1)
        .mount(&qdrant_server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let invoke = InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("qdrant-connector-suite"),
        connector_id: ConnectorId::from_static("qdrant"),
        operation: OperationId::from_static(OP_LIST_COLLECTIONS),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: build_token(&signing_key),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    };

    let suite = ConnectorSuite {
        test_name: "qdrant_list_collections_happy_path".to_string(),
        config: json!({
            "cluster_url": qdrant_server.uri(),
            "api_key": "test-qdrant-key"
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = QdrantConnector::new();
    let mut runner = E2eRunner::new("fcp-qdrant");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    for entry in &report.logs {
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
    }

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
