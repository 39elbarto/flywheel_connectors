//! FCP MCP Bridge Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{McpAuth, McpClient},
    error::McpBridgeError,
};

/// Parsed and validated MCP Bridge connector configuration.
#[derive(Debug, Clone)]
struct McpBridgeConfig {
    mcp_url: String,
    auth: McpAuth,
}

impl McpBridgeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let mcp_url = params
            .get("mcp_url")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty mcp_url in configuration".into(),
            })?
            .to_string();

        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        Ok(Self {
            mcp_url,
            auth: McpAuth { api_key },
        })
    }
}

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

/// FCP MCP Bridge Connector.
pub struct McpBridgeConnector {
    base: Arc<BaseConnector>,
    config: Option<McpBridgeConfig>,
    client: Option<Arc<McpClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl McpBridgeConnector {
    /// Create a new MCP Bridge connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("mcp-bridge"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for McpBridgeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl McpBridgeConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = McpBridgeConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), mcp_url = %config.mcp_url, "Configuring MCP Bridge connector");

        let client =
            McpClient::new(config.auth.clone(), &config.mcp_url).map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
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
            "connector_id": "fcp.mcp-bridge",
            "connector_version": "0.1.0",
            "capabilities": [
                "mcp.tools.read",
                "mcp.tools.write",
                "mcp.resources.read",
                "mcp.prompts.read"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();

        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured - call configure first".into())
            } else {
                None
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("MCP client not initialized".into())
            } else {
                None
            },
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
            "connector_id": "fcp.mcp-bridge",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.mcp-bridge",
            "version": "0.1.0",
            "operations": operations_info(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params
            .get("input")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "mcp.tools.list" => self.invoke_tools_list(client).await,
            "mcp.tools.call" => self.invoke_tools_call(client, &input).await,
            "mcp.resources.list" => self.invoke_resources_list(client).await,
            "mcp.resources.read" => self.invoke_resources_read(client, &input).await,
            "mcp.prompts.list" => self.invoke_prompts_list(client).await,
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

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });

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
        info!("MCP Bridge connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_tools_list(
        &self,
        client: &McpClient,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.tools_list().await?;
        Ok(data)
    }

    async fn invoke_tools_call(
        &self,
        client: &McpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let name = require_str(input, "name")?;
        let arguments = input
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if !arguments.is_object() && !arguments.is_null() {
            return Err(McpBridgeError::McpError {
                code: -32602,
                message: "arguments must be an object".into(),
            });
        }
        let args = if arguments.is_null() {
            json!({})
        } else {
            arguments
        };
        let data = client.tools_call(name, &args).await?;
        Ok(data)
    }

    async fn invoke_resources_list(
        &self,
        client: &McpClient,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.resources_list().await?;
        Ok(data)
    }

    async fn invoke_resources_read(
        &self,
        client: &McpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let uri = require_str(input, "uri")?;
        let data = client.resources_read(uri).await?;
        Ok(data)
    }

    async fn invoke_prompts_list(
        &self,
        client: &McpClient,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.prompts_list().await?;
        Ok(data)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, McpBridgeError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| McpBridgeError::McpError {
            code: -32602,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "mcp.tools.list",
            "summary": "List available tools from the MCP server",
            "capability": "mcp.tools.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "mcp.tools.call",
            "summary": "Call a tool on the MCP server",
            "capability": "mcp.tools.write",
            "risk_level": "high",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "mcp.resources.list",
            "summary": "List available resources from the MCP server",
            "capability": "mcp.resources.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "mcp.resources.read",
            "summary": "Read a resource by URI from the MCP server",
            "capability": "mcp.resources.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "mcp.prompts.list",
            "summary": "List available prompts from the MCP server",
            "capability": "mcp.prompts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_valid_params() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000");
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_with_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "sk-test-key",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000");
        assert_eq!(config.auth.api_key, Some("sk-test-key".into()));
    }

    #[test]
    fn config_rejects_missing_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = McpBridgeConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_mcp_url() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "  http://localhost:3000  ",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000");
    }

    #[test]
    fn config_ignores_empty_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "",
        }))
        .unwrap();
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_ignores_whitespace_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "   ",
        }))
        .unwrap();
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_trims_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "  sk-key  ",
        }))
        .unwrap();
        assert_eq!(config.auth.api_key, Some("sk-key".into()));
    }

    #[test]
    fn require_str_present() {
        let input = json!({"name": "read_file"});
        assert_eq!(require_str(&input, "name").unwrap(), "read_file");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"name": 42});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"name": null});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"name": true});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"name": ["a", "b"]});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 5);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"mcp.tools.list"));
        assert!(ids.contains(&"mcp.tools.call"));
        assert!(ids.contains(&"mcp.resources.list"));
        assert!(ids.contains(&"mcp.resources.read"));
        assert!(ids.contains(&"mcp.prompts.list"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_tools_call_is_risky() {
        let ops = operations_info();
        let call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.call")
            .unwrap();
        assert_eq!(call_op["safety_tier"], "risky");
        assert_eq!(call_op["risk_level"], "high");
    }

    #[test]
    fn operations_tools_list_capability() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.list")
            .unwrap();
        assert_eq!(list_op["capability"], "mcp.tools.read");
    }

    #[test]
    fn operations_tools_call_has_no_idempotency() {
        let ops = operations_info();
        let call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.call")
            .unwrap();
        assert_eq!(call_op["idempotency"], "none");
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
    fn connector_default() {
        let c = McpBridgeConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = McpBridgeConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = McpBridgeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip_healthy() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_roundtrip_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_serde_roundtrip_unhealthy() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg.contains("Degraded"));
    }

    #[test]
    fn doctor_result_deserializes() {
        let v = json!({
            "status": "unhealthy",
            "checks": [
                {"name": "config", "passed": false, "message": "fail", "critical": true}
            ]
        });
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn doctor_check_deserializes() {
        let v = json!({"name": "test", "passed": true, "critical": false});
        let c: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c.name, "test");
        assert!(c.passed);
        assert!(c.message.is_none());
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = DoctorCheck::clone(&c);
        assert_eq!(cloned.name, "cfg");
        assert_eq!(cloned.message, Some("ok".into()));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = DoctorResult::clone(&r);
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"name": ""});
        assert_eq!(require_str(&input, "name").unwrap(), "");
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"name": {"nested": true}});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_resources_read_capability() {
        let ops = operations_info();
        let r_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.resources.read")
            .unwrap();
        assert_eq!(r_op["capability"], "mcp.resources.read");
    }

    #[test]
    fn operations_prompts_list_capability() {
        let ops = operations_info();
        let p_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.prompts.list")
            .unwrap();
        assert_eq!(p_op["capability"], "mcp.prompts.read");
    }

    #[test]
    fn doctor_check_serializes_without_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_serializes_with_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
    }

    #[test]
    fn config_rejects_boolean_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({ "mcp_url": true }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_array_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({ "mcp_url": [1, 2, 3] }));
        assert!(result.is_err());
    }
}
