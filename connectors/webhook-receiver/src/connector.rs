//! FCP Webhook Receiver Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::DateTime;
use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::WebhookStore, error::WebhookReceiverError};

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP Webhook Receiver Connector.
pub struct WebhookReceiverConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    store: WebhookStore,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl WebhookReceiverConnector {
    /// Create a new Webhook Receiver connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "webhook-receiver",
            ))),
            configured: false,
            store: WebhookStore::new(),
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for WebhookReceiverConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookReceiverConnector {
    /// Handle the `configure` method.
    ///
    /// The webhook receiver is a local meta-connector so configuration is
    /// minimal. No external API credentials are needed.
    pub async fn handle_configure(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Configuring Webhook Receiver connector");
        self.configured = true;
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if !self.configured {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.webhook-receiver",
            "connector_version": "0.1.0",
            "capabilities": [
                "webhook.endpoints.read",
                "webhook.endpoints.write",
                "webhook.events.read"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let handshaken = self.session_id.is_some();

        let status = if self.configured && handshaken {
            "healthy"
        } else if self.configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": self.configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "endpoints": self.store.endpoint_count(),
            "events": self.store.total_event_count(),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.configured,
            message: if self.configured {
                None
            } else {
                Some("Not configured — call configure first".into())
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "store_initialized".into(),
            passed: true,
            message: None,
            critical: true,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.webhook-receiver",
            "version": "0.1.0",
            "status": if self.configured { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.webhook-receiver",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let result = match operation {
            "webhook.endpoints.create" => self.invoke_endpoints_create(&input),
            "webhook.endpoints.delete" => self.invoke_endpoints_delete(&input),
            "webhook.endpoints.list" => self.invoke_endpoints_list(),
            "webhook.events.recent" => self.invoke_events_recent(&input),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Webhook Receiver connector shutting down");
        self.store.clear();
        self.configured = false;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        self.session_id = None;
        Ok(json!({}))
    }

    // -- Operation implementations --

    fn invoke_endpoints_create(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let path = require_str(input, "path")?;
        let signing_secret = require_str(input, "signing_secret")?;

        let allowed_sources = input
            .get("allowed_sources")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let endpoint = self.store.create_endpoint(
            path.to_string(),
            signing_secret.to_string(),
            allowed_sources,
        )?;

        Ok(json!({
            "endpoint_id": endpoint.endpoint_id,
            "url": endpoint.url,
        }))
    }

    fn invoke_endpoints_delete(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoint_id = require_str(input, "endpoint_id")?;
        self.store.delete_endpoint(endpoint_id)?;
        Ok(json!({}))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn invoke_endpoints_list(&self) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoints = self.store.list_endpoints();
        let endpoints_json: Vec<serde_json::Value> = endpoints
            .iter()
            .map(|ep| {
                json!({
                    "endpoint_id": ep.endpoint_id,
                    "path": ep.path,
                    "url": ep.url,
                    "active": ep.active,
                    "created_at": ep.created_at.to_rfc3339(),
                    "event_count": ep.event_count,
                })
            })
            .collect();

        Ok(json!({ "endpoints": endpoints_json }))
    }

    fn invoke_events_recent(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoint_id = input.get("endpoint_id").and_then(serde_json::Value::as_str);

        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as usize);

        let since_ts = input
            .get("since_ts")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        let events = self.store.get_recent_events(endpoint_id, limit, since_ts)?;

        let events_json: Vec<serde_json::Value> = events
            .iter()
            .map(|evt| {
                json!({
                    "event_id": evt.event_id,
                    "endpoint_id": evt.endpoint_id,
                    "received_at": evt.received_at.to_rfc3339(),
                    "payload": evt.payload,
                    "signature_valid": evt.signature_valid,
                })
            })
            .collect();

        Ok(json!({ "events": events_json }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, WebhookReceiverError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: format!("Missing required field: {field}"),
        })
}

/// Build a single [`OperationInfo`].
#[allow(clippy::too_many_arguments)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "webhook.endpoints.create",
            "Register a new webhook endpoint",
            json!({
                "type": "object",
                "required": ["path", "signing_secret"],
                "properties": {
                    "path": { "type": "string", "description": "URL path to listen on" },
                    "signing_secret": { "type": "string", "description": "HMAC secret for signature validation" },
                    "allowed_sources": { "type": "array", "description": "IP CIDR ranges allowed to send webhooks" }
                }
            }),
            json!({
                "type": "object",
                "required": ["endpoint_id", "url"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "url": { "type": "string" }
                }
            }),
            "webhook.endpoints.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Register a new webhook endpoint.".into(),
                common_mistakes: vec![
                    "Not setting a signing secret — payloads won't be verified.".into(),
                ],
                examples: vec![
                    r#"{"path": "/hooks/github", "signing_secret": "whsec_abc123"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("webhook.endpoints.list"),
                    CapabilityId::from_static("webhook.endpoints.delete"),
                ],
            },
        ),
        op_info(
            "webhook.endpoints.delete",
            "Remove a webhook endpoint",
            json!({
                "type": "object",
                "required": ["endpoint_id"],
                "properties": {
                    "endpoint_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "webhook.endpoints.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use:
                    "Remove a webhook endpoint. Incoming webhooks to this path will be rejected."
                        .into(),
                common_mistakes: vec![],
                examples: vec![r#"{"endpoint_id": "ep_abc123"}"#.into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.list")],
            },
        ),
        op_info(
            "webhook.endpoints.list",
            "List registered webhook endpoints",
            json!({
                "type": "object",
                "required": [],
                "properties": {}
            }),
            json!({
                "type": "object",
                "required": ["endpoints"],
                "properties": {
                    "endpoints": { "type": "array" }
                }
            }),
            "webhook.endpoints.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List configured webhook endpoints.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.create")],
            },
        ),
        op_info(
            "webhook.events.recent",
            "Get recent webhook events",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "limit": { "type": "integer", "maximum": 100 },
                    "since_ts": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["events"],
                "properties": {
                    "events": { "type": "array" }
                }
            }),
            "webhook.events.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get recent webhook events received on an endpoint.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"endpoint_id": "ep_abc123", "limit": 20}"#.into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.list")],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_str_present() {
        let input = json!({"path": "/hooks/github"});
        assert_eq!(require_str(&input, "path").unwrap(), "/hooks/github");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"path": 42});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"path": null});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn operations_info_has_4_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 4);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_ref().is_empty(), "missing id");
            assert!(!op.summary.is_empty(), "missing summary");
            assert!(!op.capability.as_ref().is_empty(), "missing capability");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let ops = operations_info();
        for op in &ops {
            // RiskLevel is a typed enum, always valid by construction
            let _ = op.risk_level;
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            // SafetyTier is a typed enum, always valid by construction
            let _ = op.safety_tier;
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".read") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "read op {} should be safe",
                    op.id.as_ref()
                );
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "read op {} should be low risk",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"webhook.endpoints.create"));
        assert!(ids.contains(&"webhook.endpoints.delete"));
        assert!(ids.contains(&"webhook.endpoints.list"));
        assert!(ids.contains(&"webhook.events.recent"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            // IdempotencyClass is a typed enum, always present by construction
            let _ = op.idempotency;
        }
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = WebhookReceiverConnector::default();
        assert!(!c.configured);
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_state() {
        let c = WebhookReceiverConnector::new();
        assert!(!c.configured);
        assert!(c.session_id.is_none());
        assert_eq!(c.store.endpoint_count(), 0);
        assert_eq!(c.store.total_event_count(), 0);
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"path": true});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"path": ["a", "b"]});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn operations_write_ops_are_not_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".write") {
                assert_ne!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "write op {} should not be safe",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"path": {"nested": "val"}});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"path": ""});
        // Empty string is still a valid string
        assert_eq!(require_str(&input, "path").unwrap(), "");
    }

    #[test]
    fn operations_endpoints_create_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.create")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.write");
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn operations_endpoints_delete_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.delete")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.write");
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
    }

    #[test]
    fn operations_endpoints_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.list")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.read");
    }

    #[test]
    fn operations_events_recent_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.events.recent")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.events.read");
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail a".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail b".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn doctor_check_serializes_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("error detail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "error detail");
    }

    #[test]
    fn doctor_check_skips_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(v.get("message").is_none());
    }

    #[test]
    fn doctor_status_serialize_lowercase() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize_lowercase() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        #[allow(clippy::redundant_clone)]
        let cloned = r.clone();
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("msg".into()),
            critical: true,
        };
        #[allow(clippy::redundant_clone)]
        let cloned = check.clone();
        assert_eq!(cloned.name, "test");
        assert!(!cloned.passed);
        assert_eq!(cloned.message, Some("msg".into()));
        assert!(cloned.critical);
    }

    #[test]
    fn doctor_result_deserialize_roundtrip() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ]);
        let s = serde_json::to_string(&r).unwrap();
        let r2: DoctorResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r2.status, DoctorStatus::Degraded);
        assert_eq!(r2.checks.len(), 2);
    }
}
