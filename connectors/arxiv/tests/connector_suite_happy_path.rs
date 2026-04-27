use chrono::{Duration, Utc};
use fcp_arxiv::connector::ArxivConnector;
use fcp_core::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path_regex},
};

const OP_SEARCH_PAPERS: &str = "arxiv.search_papers";
const CAP_SEARCH: &str = "arxiv.search";

struct ArxivSuiteAdapter {
    connector: ArxivConnector,
    id: ConnectorId,
}

impl ArxivSuiteAdapter {
    fn new() -> Self {
        Self {
            connector: ArxivConnector::new(),
            id: ConnectorId::from_static("fcp.arxiv"),
        }
    }
}

fcp_core::impl_fcp_sealed!(ArxivSuiteAdapter);

#[fcp_core::async_trait]
impl FcpConnector for ArxivSuiteAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        self.connector
            .handle_handshake(json!({ "session_id": "arxiv-connector-suite" }))
            .await?;

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: "sha256:arxiv-connector-suite".into(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => match payload.get("status").and_then(serde_json::Value::as_str) {
                Some("healthy") => HealthSnapshot::ready(),
                Some(other) => HealthSnapshot::degraded(format!("arxiv_status:{other}")),
                None => HealthSnapshot::error("arxiv_status:missing"),
            },
            Err(error) => HealthSnapshot::error(error.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static(OP_SEARCH_PAPERS),
                summary: "Search arxiv papers through the connector".into(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": { "type": "string" },
                        "max_results": { "type": "integer" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "papers": { "type": "array" },
                        "total_results": { "type": "integer" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_SEARCH),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Search arxiv using the connector-local API surface.".into(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"query":"attention", "max_results":1}"#.into()],
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id;
        let operation_id = req.operation.as_str().to_string();
        let payload = json!({
            "operation_id": operation_id,
            "input": req.input,
        });
        let value = self.connector.handle_invoke(payload).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request_id = req.id;
        let operation_id = req.operation.as_str().to_string();
        let value = self
            .connector
            .handle_simulate(json!({ "operation_id": operation_id }))
            .await?;
        if value
            .get("allowed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            Ok(SimulateResponse::allowed(request_id))
        } else {
            Ok(SimulateResponse::denied(
                request_id,
                "operation is not supported",
                "FCP-3010",
            ))
        }
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn sample_atom_feed() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<opensearch:totalResults>1</opensearch:totalResults>
<entry>
<id>http://arxiv.org/abs/1706.03762v7</id>
<title>Attention Is All You Need</title>
<summary>The dominant sequence transduction models.</summary>
<author><name>Ashish Vaswani</name></author>
<published>2017-06-12T17:57:34Z</published>
<updated>2023-08-02T01:04:45Z</updated>
<arxiv:primary_category term="cs.CL" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.CL"/>
</entry>
</feed>"#
        .to_string()
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [13u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_SEARCH)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_SEARCH)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_SEARCH_PAPERS])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_searches_localhost_arxiv() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let invoke = InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("arxiv-connector-suite"),
        connector_id: ConnectorId::from_static("fcp.arxiv"),
        operation: OperationId::from_static(OP_SEARCH_PAPERS),
        zone_id: ZoneId::work(),
        input: json!({ "query": "attention", "max_results": 1 }),
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
        test_name: "arxiv_search_papers_happy_path".into(),
        config: json!({
            "arxiv_base_url": server.uri(),
            "scholar_base_url": server.uri(),
            "rate_limit_rps": 3.0
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = ArxivSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-arxiv");
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
