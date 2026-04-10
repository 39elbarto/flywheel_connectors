//! Outlook connector implementation.

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

use crate::client::OutlookClient;
use crate::types::OutlookConfig;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "outlook.read";
const CAP_SEND: &str = "outlook.send";
const CAP_CALENDAR: &str = "outlook.calendar";
const OP_LIST_MESSAGES: &str = "outlook.list_messages";
const OP_GET_MESSAGE: &str = "outlook.get_message";
const OP_SEARCH_MESSAGES: &str = "outlook.search_messages";
const OP_SEND_MESSAGE: &str = "outlook.send_message";
const OP_LIST_EVENTS: &str = "outlook.list_events";
const OP_CREATE_EVENT: &str = "outlook.create_event";
const OP_LIST_FOLDERS: &str = "outlook.list_folders";

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn new(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().all(|c| !c.critical || c.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
pub struct OutlookConnector {
    base: BaseConnector,
    config: Option<OutlookConfig>,
    client: Option<OutlookClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl OutlookConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.outlook")),
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
        let mut checks = vec![DoctorCheck {
            name: "configured".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                "Configuration loaded".into()
            } else {
                "Connector not configured".into()
            },
            critical: true,
        }];
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "graph_host".into(),
                passed: true,
                message: config.graph_host.clone(),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "access_token".into(),
                passed: !config.access_token.trim().is_empty(),
                message: "token present (redacted)".into(),
                critical: true,
            });
        }
        DoctorResult::new(checks)
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_LIST_MESSAGES),
                summary: "List recent email messages from a folder".into(),
                description: Some("List emails from the user's inbox or a specified folder via Microsoft Graph API.".into()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "folder_id": { "type": "string" },
                        "top": { "type": "integer", "minimum": 1, "maximum": 100 }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use to list recent emails in the user's inbox or a specific folder.".into(),
                    common_mistakes: vec!["Forgetting to specify folder_id defaults to Inbox".into()],
                    examples: vec!["{}".into(), "{\"folder_id\":\"Drafts\",\"top\":10}".into()],
                    related: vec![CapabilityId::from_static(OP_GET_MESSAGE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_GET_MESSAGE),
                summary: "Get a single email message by ID".into(),
                description: Some("Retrieve the full content of a specific email.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["message_id"],
                    "properties": { "message_id": { "type": "string" } }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use to retrieve the full content of a specific email.".into(),
                    common_mistakes: vec!["Use message ID, not display name".into()],
                    examples: vec!["{\"message_id\":\"AAMk...\"}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_MESSAGES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEARCH_MESSAGES),
                summary: "Search email messages by query".into(),
                description: Some("Search emails with a keyword query across subjects, bodies, and senders.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": { "type": "string" },
                        "top": { "type": "integer", "minimum": 1, "maximum": 100 }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use to search emails with a keyword query.".into(),
                    common_mistakes: vec!["Query must be a non-empty string".into()],
                    examples: vec!["{\"query\":\"invoice\",\"top\":10}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_MESSAGES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEND_MESSAGE),
                summary: "Send a new email message".into(),
                description: Some("Send an email from the configured Outlook account.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["to", "subject", "body"],
                    "properties": {
                        "to": { "type": "array", "items": { "type": "string" } },
                        "cc": { "type": "array", "items": { "type": "string" } },
                        "subject": { "type": "string" },
                        "body": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_SEND),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use to send an email from the configured Outlook account.".into(),
                    common_mistakes: vec!["At least one recipient required".into()],
                    examples: vec!["{\"to\":[\"user@example.com\"],\"subject\":\"Hi\",\"body\":\"Hello\"}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_MESSAGES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_LIST_EVENTS),
                summary: "List calendar events".into(),
                description: Some("List upcoming calendar events from the user's default calendar.".into()),
                input_schema: json!({
                    "type": "object",
                    "properties": { "top": { "type": "integer", "minimum": 1, "maximum": 100 } }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_CALENDAR),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use to list upcoming calendar events.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into(), "{\"top\":5}".into()],
                    related: vec![CapabilityId::from_static(OP_CREATE_EVENT)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_CREATE_EVENT),
                summary: "Create a new calendar event".into(),
                description: Some("Create a new event in the user's Outlook calendar.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["subject", "start", "end"],
                    "properties": {
                        "subject": { "type": "string" },
                        "start": { "type": "string" },
                        "end": { "type": "string" },
                        "body": { "type": "string" },
                        "location": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_CALENDAR),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use to create a new calendar event.".into(),
                    common_mistakes: vec!["subject, start, and end are required".into()],
                    examples: vec!["{\"subject\":\"Meeting\",\"start\":\"2026-04-01T10:00:00\",\"end\":\"2026-04-01T11:00:00\"}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_EVENTS)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_LIST_FOLDERS),
                summary: "List mail folders".into(),
                description: Some("Discover available mail folders.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use to discover available mail folders.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_MESSAGES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
        ]
    }

    fn parse_top(input: &serde_json::Value) -> FcpResult<Option<u32>> {
        let Some(value) = input.get("top") else {
            return Ok(None);
        };
        let top = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "top must be a positive integer".into(),
        })?;
        let top = u32::try_from(top).map_err(|_| FcpError::InvalidRequest {
            code: 1005,
            message: "top is out of range for u32".into(),
        })?;
        if top == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "top must be at least 1".into(),
            });
        }
        Ok(Some(top))
    }

    fn parse_string_array(
        input: &serde_json::Value,
        field: &str,
        required: bool,
    ) -> FcpResult<Vec<String>> {
        let Some(value) = input.get(field) else {
            return if required {
                Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing {field}"),
                })
            } else {
                Ok(Vec::new())
            };
        };
        let values = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an array of non-empty strings"),
        })?;
        if required && values.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{field} must contain at least one recipient"),
            });
        }

        values
            .iter()
            .map(|value| {
                let text = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("{field} must contain only strings"),
                })?;
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("{field} must not contain empty recipients"),
                    });
                }
                Ok(trimmed.to_string())
            })
            .collect()
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let cap = required_capability(req.operation.as_str())?;
        verifier.verify(req.capability_token, &cap, &req.operation, &[])?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let output = match req.operation.as_str() {
            OP_LIST_MESSAGES => {
                let folder_id = req.input.get("folder_id").and_then(|v| v.as_str());
                let top = Self::parse_top(&req.input)?;
                client
                    .list_messages(folder_id, top)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_GET_MESSAGE => {
                let message_id = req
                    .input
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing message_id".into(),
                    })?;
                client
                    .get_message(message_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_SEARCH_MESSAGES => {
                let query = req
                    .input
                    .get("query")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing query".into(),
                    })?;
                let top = Self::parse_top(&req.input)?;
                client
                    .search_messages(query, top)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_SEND_MESSAGE => {
                let to = Self::parse_string_array(&req.input, "to", true)?;
                let cc = Self::parse_string_array(&req.input, "cc", false)?;
                let subject = req
                    .input
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing subject".into(),
                    })?;
                let body = req
                    .input
                    .get("body")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing body".into(),
                    })?;
                client
                    .send_message(&to, subject, body, &cc)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_LIST_EVENTS => {
                let top = Self::parse_top(&req.input)?;
                client
                    .list_events(top)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_CREATE_EVENT => {
                let subject = req
                    .input
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing subject".into(),
                    })?;
                let start = req
                    .input
                    .get("start")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing start".into(),
                    })?;
                let end = req
                    .input
                    .get("end")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing end".into(),
                    })?;
                let body = req.input.get("body").and_then(|v| v.as_str());
                let location = req.input.get("location").and_then(|v| v.as_str());
                client
                    .create_event(subject, start, end, body, location)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_LIST_FOLDERS => client.list_folders().await.map_err(|e| e.to_fcp_error())?,
            _ => unreachable!(),
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for OutlookConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_LIST_MESSAGES | OP_GET_MESSAGE | OP_SEARCH_MESSAGES | OP_LIST_FOLDERS => {
            Ok(CapabilityId::from_static(CAP_READ))
        }
        OP_SEND_MESSAGE => Ok(CapabilityId::from_static(CAP_SEND)),
        OP_LIST_EVENTS | OP_CREATE_EVENT => Ok(CapabilityId::from_static(CAP_CALENDAR)),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|c| matches!(c.as_str(), CAP_READ | CAP_SEND | CAP_CALENDAR))
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

#[async_trait]
impl FcpConnector for OutlookConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = OutlookConfig::from_value(config)?;
        let client = OutlookClient::from_config(&config).map_err(|e| e.to_fcp_error())?;
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
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector not configured",
            ));
        };
        let details = client.health().await.map_err(|e| e.to_fcp_error())?;
        Ok(SelfCheckReport {
            details: Some(details),
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
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let cap = match required_capability(req.operation.as_str()) {
            Ok(c) => c,
            Err(e) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    e.to_string(),
                    e.error_code(),
                ));
            }
        };
        if self.client.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Not handshaken",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(e) = verifier.verify(req.capability_token, &cap, &req.operation, &[]) {
            let mut response = SimulateResponse::denied(req.id, e.to_string(), e.error_code());
            if e.error_code() == "FCP-3001" {
                response = response.with_missing_capabilities(vec![cap.as_str().to_string()]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::FcpConnector;

    #[test]
    fn connector_id_is_correct() {
        let connector = OutlookConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.outlook");
    }

    #[test]
    fn default_creates_same_as_new() {
        let c1 = OutlookConnector::new();
        let c2 = OutlookConnector::default();
        assert_eq!(c1.id().as_str(), c2.id().as_str());
    }

    #[test]
    fn operations_catalog_has_seven_ops() {
        let ops = OutlookConnector::operations_info();
        assert_eq!(ops.len(), 7);
    }

    #[test]
    fn all_operations_present() {
        let ops = OutlookConnector::operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        assert!(ids.contains(&OP_LIST_MESSAGES));
        assert!(ids.contains(&OP_GET_MESSAGE));
        assert!(ids.contains(&OP_SEARCH_MESSAGES));
        assert!(ids.contains(&OP_SEND_MESSAGE));
        assert!(ids.contains(&OP_LIST_EVENTS));
        assert!(ids.contains(&OP_CREATE_EVENT));
        assert!(ids.contains(&OP_LIST_FOLDERS));
    }

    #[test]
    fn send_message_is_risky() {
        let ops = OutlookConnector::operations_info();
        let send = ops
            .iter()
            .find(|o| o.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn create_event_is_risky() {
        let ops = OutlookConnector::operations_info();
        let event = ops
            .iter()
            .find(|o| o.id.as_str() == OP_CREATE_EVENT)
            .unwrap();
        assert_eq!(event.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = OutlookConnector::operations_info();
        for op_id in [
            OP_LIST_MESSAGES,
            OP_GET_MESSAGE,
            OP_SEARCH_MESSAGES,
            OP_LIST_FOLDERS,
        ] {
            let op = ops.iter().find(|o| o.id.as_str() == op_id).unwrap();
            assert_eq!(op.safety_tier, SafetyTier::Safe, "{op_id} should be Safe");
        }
    }

    #[test]
    fn operations_have_nonempty_summaries() {
        for op in OutlookConnector::operations_info() {
            assert!(!op.summary.is_empty(), "{} has empty summary", op.id);
        }
    }

    #[test]
    fn operations_have_descriptions() {
        for op in OutlookConnector::operations_info() {
            assert!(op.description.is_some(), "{} missing description", op.id);
        }
    }

    #[test]
    fn operations_have_ai_hints() {
        for op in OutlookConnector::operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{} empty hints", op.id);
        }
    }

    #[test]
    fn introspect_returns_all_operations() {
        let connector = OutlookConnector::new();
        assert_eq!(connector.introspect().operations.len(), 7);
    }

    #[test]
    fn introspect_reports_no_streaming() {
        let connector = OutlookConnector::new();
        let caps = connector.introspect().event_caps.unwrap();
        assert!(!caps.streaming);
    }

    #[test]
    fn doctor_before_configure_fails() {
        let connector = OutlookConnector::new();
        assert!(!connector.doctor().passed);
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let h1 = OutlookConnector::manifest_hash();
        let h2 = OutlookConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn required_capability_read_ops() {
        assert_eq!(
            required_capability(OP_LIST_MESSAGES).unwrap().as_str(),
            CAP_READ
        );
        assert_eq!(
            required_capability(OP_GET_MESSAGE).unwrap().as_str(),
            CAP_READ
        );
        assert_eq!(
            required_capability(OP_SEARCH_MESSAGES).unwrap().as_str(),
            CAP_READ
        );
        assert_eq!(
            required_capability(OP_LIST_FOLDERS).unwrap().as_str(),
            CAP_READ
        );
    }

    #[test]
    fn required_capability_send() {
        assert_eq!(
            required_capability(OP_SEND_MESSAGE).unwrap().as_str(),
            CAP_SEND
        );
    }

    #[test]
    fn required_capability_calendar() {
        assert_eq!(
            required_capability(OP_LIST_EVENTS).unwrap().as_str(),
            CAP_CALENDAR
        );
        assert_eq!(
            required_capability(OP_CREATE_EVENT).unwrap().as_str(),
            CAP_CALENDAR
        );
    }

    #[test]
    fn required_capability_unknown() {
        assert!(required_capability("outlook.unknown").is_err());
    }

    #[test]
    fn parse_top_rejects_non_numeric_values() {
        let err = OutlookConnector::parse_top(&json!({ "top": "ten" }))
            .expect_err("non-numeric top should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn parse_top_rejects_zero() {
        let err =
            OutlookConnector::parse_top(&json!({ "top": 0 })).expect_err("zero top should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn parse_string_array_rejects_non_string_values() {
        let err = OutlookConnector::parse_string_array(
            &json!({ "to": ["a@example.com", 5] }),
            "to",
            true,
        )
        .expect_err("mixed recipient types should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn parse_string_array_rejects_blank_required_recipients() {
        let err = OutlookConnector::parse_string_array(&json!({ "to": ["   "] }), "to", true)
            .expect_err("blank recipient should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn granted_capabilities_filters_valid() {
        let grants = granted_capabilities(vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static("bogus"),
            CapabilityId::from_static(CAP_SEND),
        ]);
        assert_eq!(grants.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn health_before_configure_is_degraded() {
        let connector = OutlookConnector::new();
        let snapshot = connector.health().await;
        assert!(matches!(
            snapshot.status,
            fcp_core::HealthState::Degraded { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_valid_config() {
        let mut connector = OutlookConnector::new();
        let result = connector
            .configure(json!({ "access_token": "test-token" }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_empty_token() {
        let mut connector = OutlookConnector::new();
        let result = connector.configure(json!({ "access_token": "  " })).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_after_configure_is_ready() {
        let mut connector = OutlookConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        let snapshot = connector.health().await;
        assert!(matches!(snapshot.status, fcp_core::HealthState::Ready));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_before_configure_is_degraded() {
        let connector = OutlookConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
    }
}
