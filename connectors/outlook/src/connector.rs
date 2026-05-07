//! Outlook connector implementation.

use std::time::Instant;

use async_trait::async_trait;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
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
const OPERATION_ORDER: [&str; 7] = [
    OP_LIST_MESSAGES,
    OP_GET_MESSAGE,
    OP_SEARCH_MESSAGES,
    OP_SEND_MESSAGE,
    OP_LIST_EVENTS,
    OP_CREATE_EVENT,
    OP_LIST_FOLDERS,
];

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

    /// Returns the operation catalog derived from the embedded manifest.
    ///
    /// # Panics
    ///
    /// Panics if the embedded manifest cannot be parsed before interface-hash
    /// validation. That indicates a checked-in connector manifest is
    /// structurally invalid and should fail tests before release.
    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        let manifest = ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
            .expect("embedded Outlook manifest should parse before hash validation");
        let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
        operations.sort_by(|(left, _), (right, _)| {
            let left_index = operation_order(left);
            let right_index = operation_order(right);
            left_index.cmp(&right_index).then_with(|| left.cmp(right))
        });
        operations
            .into_iter()
            .map(|(id, operation)| operation_info_from_manifest(id, operation))
            .collect()
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
        verifier.verify_bound(req.capability_token, &cap, &req.operation, &[])?;
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
            other => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {other}"),
                });
            }
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for OutlookConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(usize::MAX)
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

fn operation_info_from_manifest(
    id: String,
    operation: fcp_manifest::OperationSection,
) -> OperationInfo {
    let description = operation.description;
    OperationInfo {
        id: OperationId::new(id).expect("manifest operation id should be canonical"),
        summary: description.clone(),
        description: Some(description),
        input_schema: operation.input_schema,
        output_schema: operation.output_schema,
        capability: operation.capability,
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints,
        rate_limit: operation.rate_limit.map(|rate_limit| rate_limit.0),
        requires_approval: approval_mode_from_manifest(operation.requires_approval),
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

fcp_core::impl_fcp_sealed!(OutlookConnector);

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
        if let Err(e) = verifier.verify_bound(req.capability_token, &cap, &req.operation, &[]) {
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
    use fcp_prelude::{FcpConnector, IdempotencyClass, SafetyTier};
    use jsonschema::Validator;
    use serde_json::{Value, json};

    fn outlook_manifest_unchecked() -> ConnectorManifest {
        ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
            .expect("Outlook manifest should parse before hash validation")
    }

    fn operation_input_schema<'a>(
        manifest: &'a ConnectorManifest,
        operation_id: &str,
    ) -> &'a Value {
        &manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should be declared")
            .input_schema
    }

    fn operation_output_schema<'a>(
        manifest: &'a ConnectorManifest,
        operation_id: &str,
    ) -> &'a Value {
        &manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should be declared")
            .output_schema
    }

    fn validator_for(schema: &Value) -> Validator {
        Validator::new(schema).expect("manifest operation schema should compile")
    }

    fn assert_schema_accepts(schema: &Value, payload: &Value) {
        let validator = validator_for(schema);
        let errors: Vec<_> = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "schema should accept {payload}; errors: {errors:?}"
        );
    }

    fn assert_schema_rejects(schema: &Value, payload: &Value) {
        let validator = validator_for(schema);
        assert!(
            validator.iter_errors(payload).next().is_some(),
            "schema should reject {payload}"
        );
    }

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
    fn graph_subscription_ingress_stays_in_microsoft365_connector() {
        let ops = OutlookConnector::operations_info();
        let ids: Vec<&str> = ops.iter().map(|op| op.id.as_str()).collect();
        assert!(!ids.contains(&"m365.notifications.ingest"));
        assert!(!ids.contains(&"m365.subscriptions.create"));
        assert!(!ids.contains(&"outlook.notifications.ingest"));
        assert!(!ids.contains(&"outlook.subscriptions.create"));
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
    fn manifest_declares_valid_outlook_operations_metadata() {
        let unchecked = outlook_manifest_unchecked();
        let expected_hash = unchecked
            .compute_interface_hash()
            .expect("interface hash should compute");
        assert_eq!(
            unchecked.manifest.interface_hash.to_string(),
            expected_hash.to_string(),
            "update connectors/outlook/manifest.toml interface_hash to {expected_hash}"
        );

        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        assert_eq!(manifest.connector.id.as_str(), "fcp.outlook");
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());
        assert_eq!(
            manifest
                .capabilities
                .optional
                .iter()
                .map(CapabilityId::as_str)
                .collect::<Vec<_>>(),
            vec![CAP_READ, CAP_SEND, CAP_CALENDAR]
        );

        let list_messages = manifest
            .provides
            .operations
            .get(OP_LIST_MESSAGES)
            .expect("list messages operation should be declared");
        assert_eq!(list_messages.capability.as_str(), CAP_READ);
        assert_eq!(json!(list_messages.risk_level), json!("low"));
        assert_eq!(json!(list_messages.safety_tier), json!("safe"));
        assert_eq!(json!(list_messages.idempotency), json!("strict"));
        assert_eq!(
            list_messages.input_schema["properties"]["top"]["maximum"],
            json!(100)
        );

        let send_message = manifest
            .provides
            .operations
            .get(OP_SEND_MESSAGE)
            .expect("send operation should be declared");
        assert_eq!(send_message.capability.as_str(), CAP_SEND);
        assert_eq!(json!(send_message.risk_level), json!("medium"));
        assert_eq!(json!(send_message.safety_tier), json!("risky"));
        assert_eq!(json!(send_message.idempotency), json!("none"));
        assert_eq!(
            send_message.input_schema["required"],
            json!(["to", "subject", "body"])
        );

        let create_event = manifest
            .provides
            .operations
            .get(OP_CREATE_EVENT)
            .expect("create event operation should be declared");
        assert_eq!(create_event.capability.as_str(), CAP_CALENDAR);
        assert_eq!(json!(create_event.safety_tier), json!("risky"));
        assert_eq!(
            create_event.input_schema["required"],
            json!(["subject", "start", "end"])
        );

        for operation_id in OPERATION_ORDER {
            let operation = manifest
                .provides
                .operations
                .get(operation_id)
                .expect("operation should be declared");
            assert!(!operation.ai_hints.when_to_use.trim().is_empty());
            assert!(!operation.ai_hints.common_mistakes.is_empty());
            let network = operation
                .network_constraints
                .as_ref()
                .expect("operation should declare network constraints");
            assert_eq!(
                network.host_allow,
                vec![
                    "graph.microsoft.com".to_string(),
                    "graph.microsoft.us".to_string()
                ]
            );
            assert_eq!(network.port_allow, vec![443]);
            assert!(network.deny_localhost);
            assert!(network.deny_private_ranges);
            assert!(network.deny_tailnet_ranges);
            assert!(network.require_sni);
            assert!(network.deny_ip_literals);
            assert_eq!(network.max_redirects, 0);
            assert_eq!(network.total_timeout_ms, 15_000);
        }
    }

    #[test]
    fn introspection_uses_manifest_operation_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        let connector = OutlookConnector::new();
        let introspection = connector.introspect();
        assert_eq!(
            introspection.operations.len(),
            manifest.provides.operations.len()
        );

        for (operation, expected_id) in introspection.operations.iter().zip(OPERATION_ORDER) {
            let manifest_operation = manifest
                .provides
                .operations
                .get(expected_id)
                .expect("operation should be declared");
            assert_eq!(operation.id.as_str(), expected_id);
            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(operation.capability, manifest_operation.capability);
            assert_eq!(operation.risk_level, manifest_operation.risk_level);
            assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
            assert_eq!(operation.idempotency, manifest_operation.idempotency);
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
            assert_eq!(
                operation.ai_hints.when_to_use,
                manifest_operation.ai_hints.when_to_use
            );
            assert_eq!(
                operation
                    .rate_limit
                    .as_ref()
                    .map(|rate| (rate.max, rate.per_ms)),
                manifest_operation
                    .rate_limit
                    .as_ref()
                    .map(|rate| (rate.0.max, rate.0.per_ms))
            );
        }
    }

    #[test]
    fn manifest_input_schemas_validate_happy_boundary_and_permissive_runtime_payloads() {
        let manifest = outlook_manifest_unchecked();
        assert_schema_accepts(
            operation_input_schema(&manifest, OP_LIST_MESSAGES),
            &json!({ "folder_id": "Drafts", "top": 100 }),
        );
        assert_schema_accepts(
            operation_input_schema(&manifest, OP_GET_MESSAGE),
            &json!({ "message_id": "AAMkExampleMessageId", "trace_context": "ignored-by-runtime" }),
        );
        assert_schema_accepts(
            operation_input_schema(&manifest, OP_SEARCH_MESSAGES),
            &json!({ "query": "invoice", "top": 1 }),
        );
        assert_schema_accepts(
            operation_input_schema(&manifest, OP_SEND_MESSAGE),
            &json!({
                "to": ["recipient@example.com"],
                "cc": ["copy@example.com"],
                "subject": "",
                "body": "",
                "client_note": "ignored-by-runtime"
            }),
        );
        assert_schema_accepts(
            operation_input_schema(&manifest, OP_LIST_EVENTS),
            &json!({ "top": 100 }),
        );
        assert_schema_accepts(
            operation_input_schema(&manifest, OP_CREATE_EVENT),
            &json!({
                "subject": "Meeting",
                "start": "2026-04-01T10:00:00-04:00",
                "end": "2026-04-01T11:00:00-04:00",
                "body": "Agenda",
                "location": "Conference Room"
            }),
        );
        assert_schema_accepts(
            operation_input_schema(&manifest, OP_LIST_FOLDERS),
            &json!({ "trace_context": "ignored-by-runtime" }),
        );
    }

    #[test]
    fn manifest_input_schemas_reject_missing_and_malformed_core_fields() {
        let manifest = outlook_manifest_unchecked();
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_LIST_MESSAGES),
            &json!({ "top": 0 }),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_LIST_MESSAGES),
            &json!({ "top": 101 }),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_GET_MESSAGE),
            &json!({}),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_GET_MESSAGE),
            &json!({ "message_id": 5 }),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_SEARCH_MESSAGES),
            &json!({ "query": "" }),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_SEARCH_MESSAGES),
            &json!({ "query": "invoice", "top": "ten" }),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_SEND_MESSAGE),
            &json!({ "to": [], "subject": "Hello", "body": "World" }),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_SEND_MESSAGE),
            &json!({ "to": ["recipient@example.com"], "body": "World" }),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_CREATE_EVENT),
            &json!({ "subject": "", "start": "2026-04-01T10:00:00Z", "end": "2026-04-01T11:00:00Z" }),
        );
        assert_schema_rejects(
            operation_input_schema(&manifest, OP_CREATE_EVENT),
            &json!({ "subject": "Meeting", "start": "2026-04-01T10:00:00Z" }),
        );
    }

    #[test]
    fn manifest_output_schemas_validate_success_shapes_and_error_boundaries() {
        let manifest = outlook_manifest_unchecked();
        for operation_id in [
            OP_LIST_MESSAGES,
            OP_SEARCH_MESSAGES,
            OP_LIST_EVENTS,
            OP_LIST_FOLDERS,
        ] {
            assert_schema_accepts(
                operation_output_schema(&manifest, operation_id),
                &json!({ "value": [], "@odata.context": "redacted-in-tests" }),
            );
            assert_schema_rejects(
                operation_output_schema(&manifest, operation_id),
                &json!({ "value": "not-an-array" }),
            );
        }
        assert_schema_accepts(
            operation_output_schema(&manifest, OP_GET_MESSAGE),
            &json!({
                "id": "AAMkExampleMessageId",
                "subject": "Subject",
                "body": { "contentType": "Text", "content": "Redacted fixture body" }
            }),
        );
        assert_schema_accepts(
            operation_output_schema(&manifest, OP_SEND_MESSAGE),
            &json!({ "status": "ok" }),
        );
        assert_schema_rejects(
            operation_output_schema(&manifest, OP_SEND_MESSAGE),
            &json!({ "status": "queued" }),
        );
        assert_schema_accepts(
            operation_output_schema(&manifest, OP_CREATE_EVENT),
            &json!({ "id": "event-id", "subject": "Meeting" }),
        );
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
