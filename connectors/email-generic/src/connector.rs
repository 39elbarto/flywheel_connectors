//! Generic email connector implementation.

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

use crate::client::EmailGenericClient;
use crate::types::EmailGenericConfig;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "email_generic.read";
const CAP_WRITE: &str = "email_generic.write";
const OP_HEALTH: &str = "email_generic.health";
const OP_LIST_MAILBOXES: &str = "email_generic.list_mailboxes";
const OP_SEARCH_MESSAGES: &str = "email_generic.search_messages";
const OP_SEND_MESSAGE: &str = "email_generic.send_message";

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
pub struct EmailGenericConnector {
    base: BaseConnector,
    config: Option<EmailGenericConfig>,
    client: Option<EmailGenericClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl EmailGenericConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.email-generic")),
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
                "Connector is not configured".into()
            },
            critical: true,
        }];
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "imap_host".into(),
                passed: true,
                message: config.imap.host.clone(),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "smtp_host".into(),
                passed: true,
                message: config.smtp.host.clone(),
                critical: false,
            });
        }
        DoctorResult::new(checks)
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report generic email connector health".into(),
                description: Some("Check basic IMAP reachability and configuration.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to validate account connectivity before searching or sending.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_MAILBOXES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_LIST_MAILBOXES),
                summary: "List IMAP mailboxes".into(),
                description: Some("List available IMAP mailboxes.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before searching a mailbox.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_SEARCH_MESSAGES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEARCH_MESSAGES),
                summary: "Search IMAP messages".into(),
                description: Some("Search a mailbox and return matching UIDs.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["mailbox", "query"],
                    "properties": {
                        "mailbox": { "type": "string" },
                        "query": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to search mailbox content and return matching UIDs.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{\"mailbox\":\"INBOX\",\"query\":\"deploy\"}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_MAILBOXES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEND_MESSAGE),
                summary: "Send an email".into(),
                description: Some("Send an email through SMTP.".into()),
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
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this to send an email from the configured account.".into(),
                    common_mistakes: vec!["At least one recipient is required.".into()],
                    examples: vec![
                        "{\"to\":[\"ops@example.com\"],\"subject\":\"Deploy status\",\"body\":\"Green\"}"
                            .into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_HEALTH)],
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
            OP_HEALTH | OP_LIST_MAILBOXES | OP_SEARCH_MESSAGES => {
                CapabilityId::from_static(CAP_READ)
            }
            OP_SEND_MESSAGE => CapabilityId::from_static(CAP_WRITE),
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_HEALTH => json!({
                "status": "ok",
                "imap_host": config.imap.host,
                "smtp_host": config.smtp.host,
                "manifest_hash": Self::manifest_hash(),
            }),
            OP_LIST_MAILBOXES => client
                .list_mailboxes()
                .map_err(|error| error.to_fcp_error())?,
            OP_SEARCH_MESSAGES => {
                let mailbox = req
                    .input
                    .get("mailbox")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing mailbox".into(),
                    })?;
                let query = req
                    .input
                    .get("query")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing query".into(),
                    })?;
                client
                    .search_messages(mailbox, query)
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_SEND_MESSAGE => {
                let to = req
                    .input
                    .get("to")
                    .and_then(|value| value.as_array())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing to".into(),
                    })?
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect::<Vec<_>>();
                let cc = req
                    .input
                    .get("cc")
                    .and_then(|value| value.as_array())
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let subject = req
                    .input
                    .get("subject")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing subject".into(),
                    })?;
                let body = req
                    .input
                    .get("body")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing body".into(),
                    })?;
                client
                    .send_message(&to, subject, body, &cc)
                    .map_err(|error| error.to_fcp_error())?
            }
            _ => unreachable!(),
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for EmailGenericConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for EmailGenericConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = EmailGenericConfig::from_value(config)?;
        let client =
            EmailGenericClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
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
            "manifest_hash": Self::manifest_hash(),
            "imap_host": self.config.as_ref().map(|config| config.imap.host.clone()),
            "smtp_host": self.config.as_ref().map(|config| config.smtp.host.clone()),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let details = client.health().map_err(|error| error.to_fcp_error())?;
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
        if let Err(error) = verifier.verify(&req.capability_token, &capability, &req.operation, &[])
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
        OP_HEALTH | OP_LIST_MAILBOXES | OP_SEARCH_MESSAGES => {
            Ok(CapabilityId::from_static(CAP_READ))
        }
        OP_SEND_MESSAGE => Ok(CapabilityId::from_static(CAP_WRITE)),
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
    use fcp_core::{CapabilityToken, RequestId, ZoneId};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

    use super::*;

    fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::private(),
            zone_dir: None,
            host_public_key,
            nonce: [44u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
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
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    #[test]
    fn connector_id_is_correct() {
        let connector = EmailGenericConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.email-generic");
    }

    #[test]
    fn default_creates_same_as_new() {
        let c1 = EmailGenericConnector::new();
        let c2 = EmailGenericConnector::default();
        assert_eq!(c1.id().as_str(), c2.id().as_str());
    }

    #[test]
    fn operations_catalog_contains_expected_entries() {
        let operations = EmailGenericConnector::operations_info();
        assert_eq!(operations.len(), 4);
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_SEND_MESSAGE)
        );
    }

    #[test]
    fn operations_catalog_contains_all_four_ops() {
        let ops = EmailGenericConnector::operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        assert!(ids.contains(&OP_HEALTH));
        assert!(ids.contains(&OP_LIST_MAILBOXES));
        assert!(ids.contains(&OP_SEARCH_MESSAGES));
        assert!(ids.contains(&OP_SEND_MESSAGE));
    }

    #[test]
    fn send_message_is_risky() {
        let ops = EmailGenericConnector::operations_info();
        let send = ops
            .iter()
            .find(|o| o.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = EmailGenericConnector::operations_info();
        for op_id in [OP_HEALTH, OP_LIST_MAILBOXES, OP_SEARCH_MESSAGES] {
            let op = ops.iter().find(|o| o.id.as_str() == op_id).unwrap();
            assert_eq!(op.safety_tier, SafetyTier::Safe, "{op_id} should be Safe");
            assert_eq!(
                op.idempotency,
                IdempotencyClass::Strict,
                "{op_id} should be Strict"
            );
        }
    }

    #[test]
    fn read_operations_use_read_capability() {
        let ops = EmailGenericConnector::operations_info();
        for op_id in [OP_HEALTH, OP_LIST_MAILBOXES, OP_SEARCH_MESSAGES] {
            let op = ops.iter().find(|o| o.id.as_str() == op_id).unwrap();
            assert_eq!(op.capability.as_str(), CAP_READ);
        }
    }

    #[test]
    fn send_uses_write_capability() {
        let ops = EmailGenericConnector::operations_info();
        let send = ops
            .iter()
            .find(|o| o.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.capability.as_str(), CAP_WRITE);
    }

    #[test]
    fn operations_have_nonempty_summaries() {
        for op in EmailGenericConnector::operations_info() {
            assert!(!op.summary.is_empty(), "{} has empty summary", op.id);
        }
    }

    #[test]
    fn operations_have_descriptions() {
        for op in EmailGenericConnector::operations_info() {
            assert!(op.description.is_some(), "{} missing description", op.id);
        }
    }

    #[test]
    fn operations_have_ai_hints() {
        for op in EmailGenericConnector::operations_info() {
            assert!(
                !op.ai_hints.when_to_use.is_empty(),
                "{} has empty when_to_use hint",
                op.id
            );
        }
    }

    #[test]
    fn operations_have_examples() {
        for op in EmailGenericConnector::operations_info() {
            assert!(
                !op.ai_hints.examples.is_empty(),
                "{} has no examples",
                op.id
            );
        }
    }

    #[test]
    fn introspect_returns_all_operations() {
        let connector = EmailGenericConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 4);
    }

    #[test]
    fn introspect_reports_no_streaming() {
        let connector = EmailGenericConnector::new();
        let intro = connector.introspect();
        let caps = intro.event_caps.expect("should have event_caps");
        assert!(!caps.streaming);
        assert!(!caps.replay);
    }

    #[test]
    fn doctor_before_configure_fails() {
        let connector = EmailGenericConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
    }

    #[test]
    fn doctor_checks_are_nonempty() {
        let connector = EmailGenericConnector::new();
        let result = connector.doctor();
        assert!(!result.checks.is_empty());
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let h1 = EmailGenericConnector::manifest_hash();
        let h2 = EmailGenericConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn required_capability_read_ops() {
        assert_eq!(required_capability(OP_HEALTH).unwrap().as_str(), CAP_READ);
        assert_eq!(
            required_capability(OP_LIST_MAILBOXES).unwrap().as_str(),
            CAP_READ
        );
        assert_eq!(
            required_capability(OP_SEARCH_MESSAGES).unwrap().as_str(),
            CAP_READ
        );
    }

    #[test]
    fn required_capability_write_ops() {
        assert_eq!(
            required_capability(OP_SEND_MESSAGE).unwrap().as_str(),
            CAP_WRITE
        );
    }

    #[test]
    fn required_capability_unknown_op() {
        assert!(required_capability("email_generic.unknown").is_err());
    }

    #[test]
    fn granted_capabilities_filters_valid() {
        let grants = granted_capabilities(vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static("bogus.cap"),
            CapabilityId::from_static(CAP_WRITE),
        ]);
        assert_eq!(grants.len(), 2);
    }

    #[test]
    fn granted_capabilities_rejects_all_bogus() {
        let grants = granted_capabilities(vec![CapabilityId::from_static("bogus.cap")]);
        assert!(grants.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn health_before_configure_is_degraded() {
        let connector = EmailGenericConnector::new();
        let snapshot = connector.health().await;
        assert!(
            matches!(snapshot.status, fcp_core::HealthState::Degraded { .. }),
            "should be degraded before configure"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_valid_config() {
        let mut connector = EmailGenericConnector::new();
        let result = connector
            .configure(json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_config() {
        let mut connector = EmailGenericConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_after_configure_is_ready() {
        let mut connector = EmailGenericConnector::new();
        connector
            .configure(json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
            }))
            .await
            .unwrap();
        let snapshot = connector.health().await;
        assert!(matches!(snapshot.status, fcp_core::HealthState::Ready));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_before_configure_returns_degraded() {
        let connector = EmailGenericConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn subscribe_returns_not_supported() {
        let connector = EmailGenericConnector::new();
        let result = connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("sub"),
                topics: vec![],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: None,
            })
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut connector = EmailGenericConnector::new();
        connector
            .configure(json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
            }))
            .await
            .unwrap();
        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .unwrap();
        let snapshot = connector.health().await;
        assert!(matches!(
            snapshot.status,
            fcp_core::HealthState::Degraded { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_status() {
        let mut connector = EmailGenericConnector::new();
        connector
            .configure(json!({
                "imap": {
                    "host": "imap.example.com",
                    "username": "user@example.com",
                    "password": "secret"
                },
                "smtp": {
                    "host": "smtp.example.com",
                    "username": "user@example.com",
                    "password": "secret",
                    "from_address": "user@example.com"
                }
            }))
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
                id: RequestId::new("email-health"),
                connector_id: ConnectorId::from_static("fcp.email-generic"),
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
