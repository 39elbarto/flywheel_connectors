//! E2E arXiv connector compliance tests.
//!
//! Exercises the arXiv connector through the shared E2E harness:
//! - Default deny via capability mismatch on monitor operations
//! - Network guard allow/deny checks via manifest constraints
//! - Monitor checkpoint behavior remaining bound to a single zone
//! - Structured JSON evidence logs
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features arxiv --test arxiv_compliance_e2e`

#![cfg(feature = "arxiv")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_arxiv::connector::ArxivConnector;
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus,
    OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{
    ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations, validate_log_entry_value,
};
use fcp_manifest::ConnectorManifest;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path_regex},
};

struct ArxivConnectorAdapter {
    connector: ArxivConnector,
    id: ConnectorId,
    instance_id: InstanceId,
    verifier: Option<CapabilityVerifier>,
}

impl ArxivConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: ArxivConnector::new(),
            id: ConnectorId::from_static("arxiv"),
            instance_id: InstanceId::new(),
            verifier: None,
        }
    }
}

fcp_core::impl_fcp_sealed!(ArxivConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for ArxivConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        self.connector
            .handle_handshake(json!({
                "session_id": "arxiv-e2e-session",
            }))
            .await?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.instance_id.clone(),
        ));

        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: req
                .capabilities_requested
                .iter()
                .cloned()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
            session_id: SessionId::new(),
            manifest_hash: "sha256:arxiv-e2e".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "degraded" => HealthSnapshot::degraded("not_handshaken"),
                    "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("arxiv_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<SelfCheckReport> {
        let value = self.connector.handle_self_check().await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize arXiv self_check: {err}"),
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.verifier = None;
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("arxiv-monitor-suite"),
                summary: "arxiv-monitor-suite".to_string(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("z:work"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: String::new(),
                    common_mistakes: Vec::new(),
                    examples: Vec::new(),
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "arXiv verifier not initialized; handshake required".into(),
        })?;
        let required_capability = required_capability(req.operation.as_str())?;
        verifier.verify(
            req.capability_token.clone(),
            &required_capability,
            &req.operation,
            &[],
        )?;

        let request_id = req.id.clone();
        let value = self
            .connector
            .handle_invoke(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "arXiv verifier not initialized; handshake required".into(),
        })?;
        let required_capability = required_capability(req.operation.as_str())?;
        verifier.verify(
            req.capability_token.clone(),
            &required_capability,
            &req.operation,
            &[],
        )?;

        let value = self
            .connector
            .handle_simulate(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;

        Ok(SimulateResponse {
            r#type: "simulate_response".to_string(),
            id: req.id,
            would_succeed: value
                .get("allowed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            failure_reason: value
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .filter(|_| {
                    !value
                        .get("allowed")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                })
                .map(str::to_string),
            denial_code: None,
            missing_capabilities: Vec::new(),
            estimated_cost: None,
            availability: None,
            response_metadata: None,
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn required_capability(operation: &str) -> fcp_core::FcpResult<CapabilityId> {
    let capability = match operation {
        "arxiv.search_papers" | "arxiv.search_semantic" => "arxiv.search",
        "arxiv.get_paper" | "arxiv.get_full_text" | "arxiv.download_pdf" => "arxiv.read",
        "arxiv.get_citations" | "arxiv.get_references" | "arxiv.extract_references" => {
            "arxiv.citations"
        }
        "arxiv.get_author" => "arxiv.authors",
        "arxiv.list_categories" | "arxiv.get_new_papers" => "arxiv.categories",
        "arxiv.monitor_category" | "arxiv.monitor_query" => "arxiv.monitor",
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };

    capability
        .parse::<CapabilityId>()
        .map_err(|err| FcpError::Internal {
            message: format!("invalid capability id mapping for {operation}: {err}"),
        })
}

fn arxiv_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/arxiv/manifest.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn arxiv_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/arxiv/manifest.toml"))
        .expect("arXiv manifest TOML")
}

fn arxiv_config(base_url: &str) -> serde_json::Value {
    json!({
        "arxiv_base_url": base_url,
        "scholar_base_url": base_url,
        "scholar_api_key": "test-scholar-key",
    })
}

fn handshake_request(
    zone: ZoneId,
    host_public_key: [u8; 32],
    capabilities: &[&str],
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone,
        zone_dir: None,
        host_public_key,
        nonce: [23_u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|capability| {
                capability
                    .parse::<CapabilityId>()
                    .expect("capability id parse")
            })
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    zone_id: &str,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("serialize test constraints");
    let token = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone_id)
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .constraints_cbor(&constraints_cbor)
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(token)
}

fn invoke_request(
    request_id: &'static str,
    zone_id: ZoneId,
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from(request_id),
        connector_id: ConnectorId::from_static("arxiv"),
        operation: OperationId::from_static(operation),
        zone_id,
        input,
        capability_token: token,
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

fn sample_atom_feed() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<opensearch:totalResults>2</opensearch:totalResults>
<entry>
<id>http://arxiv.org/abs/1706.03762v7</id>
<title>Attention Is All You Need</title>
<summary>The dominant sequence transduction models are based on complex recurrent or convolutional neural networks.</summary>
<author><name>Ashish Vaswani</name></author>
<author><name>Noam Shazeer</name></author>
<published>2017-06-12T17:57:34Z</published>
<updated>2023-08-02T01:04:45Z</updated>
<arxiv:primary_category term="cs.CL" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.CL"/>
<category term="cs.LG"/>
<link href="http://arxiv.org/pdf/1706.03762v7" rel="related" type="application/pdf"/>
</entry>
<entry>
<id>http://arxiv.org/abs/2301.08745v1</id>
<title>Another Paper</title>
<summary>This is another paper abstract.</summary>
<author><name>Alice Smith</name></author>
<published>2023-01-20T00:00:00Z</published>
<updated>2023-01-20T00:00:00Z</updated>
<arxiv:primary_category term="cs.AI" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.AI"/>
</entry>
</feed>"#
}

fn operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_name: &str,
) -> &'a toml::value::Table {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .expect("operation network_constraints")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    operation_network_constraints(manifest, operation_name)
        .get("host_allow")
        .and_then(toml::Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .expect("operation host_allow")
}

fn host_allowed(host: &str, host_allow: &[String]) -> bool {
    fcp_sandbox::host_matches_allow_list(host, host_allow)
}

fn assert_report_logs_validate(report: &fcp_e2e::E2eReport) {
    let jsonl = report.to_json_lines();
    assert!(
        !jsonl.trim().is_empty(),
        "report should emit JSONL evidence"
    );
    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("jsonl line should parse");
        validate_log_entry_value(&value).expect("jsonl line should satisfy E2E schema");
    }
}

fn assert_common_network_constraints(manifest: &toml::Value, operation_name: &str) {
    let constraints = operation_network_constraints(manifest, operation_name);
    assert_eq!(
        constraints
            .get("deny_localhost")
            .and_then(toml::Value::as_bool),
        Some(true),
        "operation {operation_name} must deny localhost"
    );
    assert_eq!(
        constraints
            .get("deny_private_ranges")
            .and_then(toml::Value::as_bool),
        Some(true),
        "operation {operation_name} must deny private ranges"
    );
    assert_eq!(
        constraints
            .get("require_sni")
            .and_then(toml::Value::as_bool),
        Some(true),
        "operation {operation_name} must require SNI"
    );
}

#[fcp_async_core::runtime::test]
async fn arxiv_default_deny_compliance_suite_passes_and_emits_reasoned_logs() {
    let mock = MockServer::start().await;

    let mut connector = ArxivConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        ZoneId::work(),
        signing_key.verifying_key().to_bytes(),
        &["arxiv.monitor"],
    );
    let token = build_token(&signing_key, "z:work", "arxiv.read", &["arxiv.get_paper"]);
    let invoke = invoke_request(
        "arxiv-default-deny",
        ZoneId::work(),
        "arxiv.monitor_category",
        json!({ "categories": ["cs.AI"] }),
        token,
    );

    let dynamic = DynamicSuite {
        config: arxiv_config(&mock.uri()),
        handshake,
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new("arxiv_default_deny", arxiv_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-arxiv");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(
        report.passed,
        "default deny compliance should pass: {report:#?}"
    );
    assert_report_logs_validate(&report);

    // Compliance suite produces a single "verify" log entry with dynamic findings
    let verify_entry = report
        .logs
        .iter()
        .find(|entry| entry.phase == "verify")
        .expect("verify log entry");
    assert!(
        !verify_entry.correlation_id.is_empty(),
        "verify log entry should include correlation_id"
    );
    // Dynamic findings should include the invoke denial check
    let dynamic = verify_entry
        .context
        .get("dynamic")
        .expect("dynamic context");
    assert_eq!(
        dynamic.get("passed").and_then(serde_json::Value::as_bool),
        Some(true),
        "dynamic checks should pass for default deny"
    );
}

#[fcp_async_core::runtime::test]
async fn arxiv_monitor_category_connector_suite_passes_and_emits_schema_valid_logs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .mount(&server)
        .await;

    let mut connector = ArxivConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        ZoneId::work(),
        signing_key.verifying_key().to_bytes(),
        &["arxiv.monitor"],
    );
    let token = build_token(
        &signing_key,
        "z:work",
        "arxiv.monitor",
        &["arxiv.monitor_category"],
    );
    let invoke = invoke_request(
        "arxiv-monitor-suite",
        ZoneId::work(),
        "arxiv.monitor_category",
        json!({
            "categories": ["cs.AI"],
            "since_ts": "2010-01-01T00:00:00Z",
        }),
        token,
    );

    let suite = ConnectorSuite {
        test_name: "arxiv_monitor_category".to_string(),
        config: arxiv_config(&server.uri()),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-arxiv");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "monitor suite should pass");
    assert_report_logs_validate(&report);

    let invoke_entry = report
        .logs
        .iter()
        .find(|entry| entry.context.get("operation") == Some(&json!("invoke")))
        .expect("invoke log entry");
    assert_eq!(invoke_entry.result, "pass");
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
    assert!(
        !invoke_entry.correlation_id.is_empty(),
        "invoke log entry should include correlation_id"
    );
}

#[fcp_async_core::runtime::test]
async fn arxiv_monitor_checkpointing_stays_single_zone_bound() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .mount(&server)
        .await;

    let mut connector = ArxivConnectorAdapter::new();
    connector
        .configure(arxiv_config(&server.uri()))
        .await
        .expect("configure arXiv connector");

    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(
            ZoneId::work(),
            signing_key.verifying_key().to_bytes(),
            &["arxiv.monitor"],
        ))
        .await
        .expect("handshake arXiv connector");

    let success = connector
        .invoke(invoke_request(
            "arxiv-monitor-zone-ok",
            ZoneId::work(),
            "arxiv.monitor_category",
            json!({
                "categories": ["cs.AI"],
                "since_ts": "2010-01-01T00:00:00Z",
            }),
            build_token(
                &signing_key,
                "z:work",
                "arxiv.monitor",
                &["arxiv.monitor_category"],
            ),
        ))
        .await
        .expect("same-zone monitor invoke should succeed");

    assert_eq!(success.status, InvokeStatus::Ok);
    let result = success.result.expect("monitor result payload");
    assert_eq!(result["papers"].as_array().map(Vec::len), Some(2));
    assert_eq!(result["cursor_ts"], json!("2023-08-02T01:04:45Z"));

    let err = connector
        .invoke(invoke_request(
            "arxiv-monitor-zone-mismatch",
            ZoneId::work(),
            "arxiv.monitor_category",
            json!({
                "categories": ["cs.AI"],
                "since_ts": "2010-01-01T00:00:00Z",
            }),
            build_token(
                &signing_key,
                "z:private",
                "arxiv.monitor",
                &["arxiv.monitor_category"],
            ),
        ))
        .await
        .expect_err("cross-zone monitor invoke should be rejected");

    assert!(
        matches!(err, FcpError::ZoneViolation { .. }),
        "expected zone violation for cross-zone monitor invoke, got: {err:?}"
    );
}

#[test]
fn arxiv_manifest_network_guard_allows_arxiv_hosts_and_scoped_scholar_hosts() {
    let manifest = arxiv_manifest_toml();

    let arxiv_only_operations = [
        "arxiv.download_pdf",
        "arxiv.extract_references",
        "arxiv.get_full_text",
        "arxiv.get_new_papers",
        "arxiv.get_paper",
        "arxiv.list_categories",
        "arxiv.monitor_category",
        "arxiv.monitor_query",
        "arxiv.search_papers",
    ];
    let scholar_backed_operations = [
        "arxiv.get_author",
        "arxiv.get_citations",
        "arxiv.get_references",
        "arxiv.search_semantic",
    ];

    let arxiv_hosts = vec!["export.arxiv.org".to_string(), "arxiv.org".to_string()];
    for operation_name in arxiv_only_operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, arxiv_hosts,
            "operation {operation_name} should be limited to arXiv API/PDF hosts"
        );
        assert!(host_allowed("export.arxiv.org", &host_allow));
        assert!(host_allowed("arxiv.org", &host_allow));
        assert!(!host_allowed("api.semanticscholar.org", &host_allow));
        assert!(!host_allowed("localhost", &host_allow));
        assert!(!host_allowed("127.0.0.1", &host_allow));
        assert!(!host_allowed("example.com", &host_allow));
        assert_common_network_constraints(&manifest, operation_name);
    }

    let scholar_hosts = vec![
        "export.arxiv.org".to_string(),
        "arxiv.org".to_string(),
        "api.semanticscholar.org".to_string(),
    ];
    for operation_name in scholar_backed_operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, scholar_hosts,
            "operation {operation_name} should only extend the arXiv allowlist with Semantic Scholar"
        );
        assert!(host_allowed("export.arxiv.org", &host_allow));
        assert!(host_allowed("arxiv.org", &host_allow));
        assert!(host_allowed("api.semanticscholar.org", &host_allow));
        assert!(!host_allowed("evil.api.semanticscholar.org", &host_allow));
        assert!(!host_allowed("localhost", &host_allow));
        assert!(!host_allowed("example.com", &host_allow));
        assert_common_network_constraints(&manifest, operation_name);
    }

    let state = manifest
        .get("connector")
        .and_then(toml::Value::as_table)
        .and_then(|connector| connector.get("state"))
        .and_then(toml::Value::as_table)
        .expect("connector.state table");
    assert_eq!(
        state.get("model").and_then(toml::Value::as_str),
        Some("singleton_writer"),
        "monitor cursor checkpointing must stay fenced behind singleton_writer state"
    );
}
