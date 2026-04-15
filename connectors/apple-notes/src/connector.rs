//! `Apple Notes` connector implementation.

use std::time::Instant;

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::AppleNotesClient;
use crate::types::AppleNotesConfig;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "apple_notes.read";
const CAP_WRITE: &str = "apple_notes.write";
const OP_HEALTH: &str = "apple_notes.health";
const OP_LIST_NOTES: &str = "apple_notes.list_notes";
const OP_SEARCH_NOTES: &str = "apple_notes.search_notes";
const OP_GET_NOTE: &str = "apple_notes.get_note";
const OP_CREATE_NOTE: &str = "apple_notes.create_note";

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    passed: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn new(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().all(|check| !check.critical || check.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
pub struct AppleNotesConnector {
    base: BaseConnector,
    config: Option<AppleNotesConfig>,
    client: Option<AppleNotesClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl AppleNotesConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.apple-notes")),
            config: None,
            client: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        DoctorResult::new(vec![
            DoctorCheck {
                name: "platform".into(),
                passed: std::env::consts::OS == "macos",
                message: format!("Detected OS: {}", std::env::consts::OS),
                critical: true,
            },
            DoctorCheck {
                name: "configured".into(),
                passed: self.client.is_some(),
                message: if self.client.is_some() {
                    "Configuration loaded".into()
                } else {
                    "Connector is not configured".into()
                },
                critical: true,
            },
        ])
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report Apple Notes health".into(),
                description: Some("Report platform support and connector configuration.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before note operations on a new host.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_NOTES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_LIST_NOTES),
                summary: "List note summaries".into(),
                description: Some("List note summaries, optionally scoped to a folder.".into()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "folder": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to browse notes before reading a specific note.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{\"folder\":\"Inbox\"}".into()],
                    related: vec![CapabilityId::from_static(OP_GET_NOTE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEARCH_NOTES),
                summary: "Search note summaries".into(),
                description: Some("Search notes by substring match over title/body.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to locate notes by keyword before reading them.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{\"query\":\"deploy\"}".into()],
                    related: vec![CapabilityId::from_static(OP_GET_NOTE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_GET_NOTE),
                summary: "Get one note".into(),
                description: Some("Fetch one note by note identifier.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["note_id"],
                    "properties": {
                        "note_id": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this after obtaining a note identifier from list/search."
                        .into(),
                    common_mistakes: vec![],
                    examples: vec!["{\"note_id\":\"x-coredata://...\"}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_NOTES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_CREATE_NOTE),
                summary: "Create a note".into(),
                description: Some("Create a new note in the default or requested folder.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["title", "body"],
                    "properties": {
                        "title": { "type": "string" },
                        "body": { "type": "string" },
                        "folder": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this to create a new note in Apple Notes.".into(),
                    common_mistakes: vec![
                        "Apple Notes automation requires Automation permission on macOS.".into(),
                    ],
                    examples: vec![
                        "{\"title\":\"Deploy checklist\",\"body\":\"- verify logs\"}".into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_LIST_NOTES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
        ]
    }

    fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let required_cap = match req.operation.as_str() {
            OP_HEALTH | OP_LIST_NOTES | OP_SEARCH_NOTES | OP_GET_NOTE => {
                CapabilityId::from_static(CAP_READ)
            }
            OP_CREATE_NOTE => CapabilityId::from_static(CAP_WRITE),
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(req.capability_token, &required_cap, &req.operation, &[])?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_HEALTH => json!({
                "status": "ok",
                "platform": std::env::consts::OS,
                "manifest_hash": Self::manifest_hash(),
            }),
            OP_LIST_NOTES => {
                let folder = req.input.get("folder").and_then(|value| value.as_str());
                client
                    .list_notes(folder)
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_SEARCH_NOTES => {
                let query = req
                    .input
                    .get("query")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing query".into(),
                    })?;
                client
                    .search_notes(query)
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_GET_NOTE => {
                let note_id = req
                    .input
                    .get("note_id")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing note_id".into(),
                    })?;
                client
                    .get_note(note_id)
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_CREATE_NOTE => {
                let title = req
                    .input
                    .get("title")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing title".into(),
                    })?;
                let body = req
                    .input
                    .get("body")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing body".into(),
                    })?;
                let folder = req.input.get("folder").and_then(|value| value.as_str());
                client
                    .create_note(title, body, folder)
                    .map_err(|error| error.to_fcp_error())?
            }
            _ => unreachable!(),
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for AppleNotesConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(AppleNotesConnector);

#[async_trait]
impl FcpConnector for AppleNotesConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = AppleNotesConfig::from_value(config)?;
        let client =
            AppleNotesClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(req.capabilities_requested),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.client.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.client.is_some(),
            "platform": std::env::consts::OS,
            "manifest_hash": Self::manifest_hash(),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.client.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        }
        if std::env::consts::OS != "macos" {
            return Ok(SelfCheckReport::failed(
                "unsupported_platform",
                "Apple Notes connector requires macOS",
            ));
        }
        Ok(SelfCheckReport {
            details: Some(json!({
                "platform": std::env::consts::OS,
                "automation_permission_hint": "Grant Automation access to Notes.app if prompted",
            })),
            ..SelfCheckReport::ok()
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.config = None;
        self.client = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req);
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.client.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) = verifier.verify(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_HEALTH | OP_LIST_NOTES | OP_SEARCH_NOTES | OP_GET_NOTE => {
            Ok(CapabilityId::from_static(CAP_READ))
        }
        OP_CREATE_NOTE => Ok(CapabilityId::from_static(CAP_WRITE)),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| matches!(capability.as_str(), CAP_READ | CAP_WRITE))
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_core::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

    use super::*;

    fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::private(),
            zone_dir: None,
            host_public_key,
            nonce: [32u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn test_constraints_cbor() -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        cbor
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:private")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .constraints_cbor(&test_constraints_cbor())
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    #[test]
    fn operations_catalog_contains_expected_entries() {
        let operations = AppleNotesConnector::operations_info();
        assert_eq!(operations.len(), 5);
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_CREATE_NOTE)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_status() {
        let mut connector = AppleNotesConnector::new();
        connector
            .configure(json!({}))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");
        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("notes-health"),
                connector_id: ConnectorId::from_static("fcp.apple-notes"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::private(),
                input: json!({}),
                capability_token: capability_token(&signing_key, CAP_READ, OP_HEALTH),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("health should succeed");
        assert_eq!(response.result.expect("result")["status"], "ok");
    }
}
