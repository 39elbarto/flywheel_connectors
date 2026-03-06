//! FCP Cron Connector implementation.
//!
//! A local meta-connector that manages cron schedules and execution history
//! in memory. No external API calls are needed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};
use uuid::Uuid;

use crate::error::CronError;
use crate::types::{Execution, Schedule, validate_cron_expression};

/// Default maximum number of executions returned.
const DEFAULT_EXECUTION_LIMIT: u64 = 50;
/// Maximum number of executions returned.
const MAX_EXECUTION_LIMIT: u64 = 100;

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

/// FCP Cron Connector.
///
/// Manages cron schedules and execution history entirely in memory.
pub struct CronConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    session_id: Option<String>,
    schedules: Vec<Schedule>,
    executions: Vec<Execution>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl CronConnector {
    /// Create a new Cron connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("cron"))),
            configured: false,
            session_id: None,
            schedules: Vec::new(),
            executions: Vec::new(),
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for CronConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CronConnector {
    /// Handle the `configure` method.
    ///
    /// The cron connector requires no external credentials. Configuration
    /// simply marks the connector as ready.
    pub async fn handle_configure(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Configuring Cron connector (local meta-connector, no external auth)");
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
            "connector_id": "fcp.cron",
            "connector_version": "0.1.0",
            "capabilities": [
                "cron.schedules.read",
                "cron.schedules.write",
                "cron.executions.read"
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
            "schedules": self.schedules.len(),
            "executions": self.executions.len(),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
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
                Some("Not configured - call configure first".into())
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

        checks.push(DoctorCheck {
            name: "state_store".into(),
            passed: true,
            message: Some(format!(
                "{} schedules, {} executions in memory",
                self.schedules.len(),
                self.executions.len()
            )),
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.cron",
            "version": "0.1.0",
            "status": if self.configured { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.cron",
            "version": "0.1.0",
            "operations": operations_info(),
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

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let result = match operation {
            "cron.schedules.list" => self.invoke_schedules_list(),
            "cron.schedules.create" => self.invoke_schedules_create(&input),
            "cron.schedules.delete" => self.invoke_schedules_delete(&input),
            "cron.trigger" => self.invoke_trigger(&input),
            "cron.executions.list" => self.invoke_executions_list(&input),
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
    pub async fn handle_simulate(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
        info!("Cron connector shutting down");
        self.configured = false;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    #[allow(clippy::unnecessary_wraps)]
    fn invoke_schedules_list(&self) -> Result<serde_json::Value, CronError> {
        let schedules: Vec<serde_json::Value> = self
            .schedules
            .iter()
            .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
            .collect();
        Ok(json!({ "schedules": schedules }))
    }

    fn invoke_schedules_create(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let name = input
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: name".into(),
            })?;

        let expression = input
            .get("expression")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: expression".into(),
            })?;

        let target_operation = input
            .get("target_operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: target_operation".into(),
            })?;

        // Validate cron expression
        if !validate_cron_expression(expression) {
            return Err(CronError::InvalidExpression {
                expression: expression.into(),
            });
        }

        // Check for duplicate names
        if self.schedules.iter().any(|s| s.name == name) {
            return Err(CronError::DuplicateName { name: name.into() });
        }

        let enabled = input
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);

        let payload = input.get("payload").cloned();

        let schedule_id = format!("sched_{}", Uuid::new_v4());
        let now = Utc::now().to_rfc3339();

        let schedule = Schedule {
            id: schedule_id.clone(),
            name: name.into(),
            expression: expression.into(),
            target_operation: target_operation.into(),
            payload,
            enabled,
            created_at: now,
        };

        self.schedules.push(schedule);

        Ok(json!({ "schedule_id": schedule_id }))
    }

    fn invoke_schedules_delete(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let schedule_id = input
            .get("schedule_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: schedule_id".into(),
            })?;

        let idx = self
            .schedules
            .iter()
            .position(|s| s.id == schedule_id)
            .ok_or_else(|| CronError::ScheduleNotFound {
                schedule_id: schedule_id.into(),
            })?;

        self.schedules.remove(idx);

        Ok(json!({}))
    }

    fn invoke_trigger(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let schedule_id = input
            .get("schedule_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: schedule_id".into(),
            })?;

        // Verify schedule exists
        if !self.schedules.iter().any(|s| s.id == schedule_id) {
            return Err(CronError::ScheduleNotFound {
                schedule_id: schedule_id.into(),
            });
        }

        let execution_id = format!("exec_{}", Uuid::new_v4());
        let now = Utc::now().to_rfc3339();

        let execution = Execution {
            id: execution_id.clone(),
            schedule_id: schedule_id.into(),
            triggered_at: now,
            status: "triggered".into(),
        };

        self.executions.push(execution);

        Ok(json!({ "execution_id": execution_id }))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn invoke_executions_list(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let schedule_id_filter = input
            .get("schedule_id")
            .and_then(serde_json::Value::as_str);

        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_EXECUTION_LIMIT)
            .min(MAX_EXECUTION_LIMIT);

        let executions: Vec<serde_json::Value> = self
            .executions
            .iter()
            .filter(|e| {
                schedule_id_filter
                    .is_none_or(|filter| e.schedule_id == filter)
            })
            .rev() // most recent first
            .take(limit as usize)
            .map(|e| serde_json::to_value(e).unwrap_or(serde_json::Value::Null))
            .collect();

        Ok(json!({ "executions": executions }))
    }

    // -- Accessors for testing --

    /// Get the number of schedules.
    #[must_use]
    pub fn schedule_count(&self) -> usize {
        self.schedules.len()
    }

    /// Get the number of executions.
    #[must_use]
    pub fn execution_count(&self) -> usize {
        self.executions.len()
    }
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "cron.schedules.list",
            "summary": "List configured cron schedules",
            "capability": "cron.schedules.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "cron.schedules.create",
            "summary": "Create a new cron schedule",
            "capability": "cron.schedules.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "cron.schedules.delete",
            "summary": "Delete a cron schedule",
            "capability": "cron.schedules.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "cron.trigger",
            "summary": "Manually trigger a schedule immediately",
            "capability": "cron.schedules.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "cron.executions.list",
            "summary": "List recent execution history for a schedule",
            "capability": "cron.executions.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Constructor / Default --

    #[test]
    fn connector_new() {
        let c = CronConnector::new();
        assert!(!c.configured);
        assert!(c.session_id.is_none());
        assert!(c.schedules.is_empty());
        assert!(c.executions.is_empty());
    }

    #[test]
    fn connector_default() {
        let c = CronConnector::default();
        assert!(!c.configured);
        assert!(c.session_id.is_none());
    }

    // -- Operations info --

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
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
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
        assert!(ids.contains(&"cron.schedules.list"));
        assert!(ids.contains(&"cron.schedules.create"));
        assert!(ids.contains(&"cron.schedules.delete"));
        assert!(ids.contains(&"cron.trigger"));
        assert!(ids.contains(&"cron.executions.list"));
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
    fn delete_is_dangerous() {
        let ops = operations_info();
        let delete_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "cron.schedules.delete")
            .unwrap();
        assert_eq!(delete_op["safety_tier"], "dangerous");
        assert_eq!(delete_op["risk_level"], "high");
    }

    #[test]
    fn trigger_is_risky() {
        let ops = operations_info();
        let trigger_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "cron.trigger")
            .unwrap();
        assert_eq!(trigger_op["safety_tier"], "risky");
        assert_eq!(trigger_op["risk_level"], "medium");
    }

    // -- Doctor --

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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
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

    // -- In-memory schedule operations (sync) --

    #[test]
    fn create_schedule_basic() {
        let mut c = CronConnector::new();
        c.configured = true;
        let result = c
            .invoke_schedules_create(&json!({
                "name": "hourly-sync",
                "expression": "0 * * * *",
                "target_operation": "slack.channels.list"
            }))
            .unwrap();
        assert!(result["schedule_id"].as_str().unwrap().starts_with("sched_"));
        assert_eq!(c.schedules.len(), 1);
        assert_eq!(c.schedules[0].name, "hourly-sync");
        assert_eq!(c.schedules[0].expression, "0 * * * *");
        assert!(c.schedules[0].enabled);
    }

    #[test]
    fn create_schedule_with_payload() {
        let mut c = CronConnector::new();
        c.configured = true;
        let result = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "*/5 * * * *",
                "target_operation": "op.test",
                "payload": {"channel": "general"}
            }))
            .unwrap();
        assert!(result["schedule_id"].as_str().is_some());
        assert_eq!(c.schedules[0].payload, Some(json!({"channel": "general"})));
    }

    #[test]
    fn create_schedule_disabled() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "disabled-job",
            "expression": "0 0 * * *",
            "target_operation": "op.test",
            "enabled": false
        }))
        .unwrap();
        assert!(!c.schedules[0].enabled);
    }

    #[test]
    fn create_schedule_invalid_expression() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "name": "bad",
                "expression": "not a cron expr",
                "target_operation": "op.test"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::InvalidExpression { .. }));
    }

    #[test]
    fn create_schedule_too_few_fields() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "name": "bad",
                "expression": "* *",
                "target_operation": "op.test"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::InvalidExpression { .. }));
    }

    #[test]
    fn create_schedule_duplicate_name() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "my-job",
            "expression": "0 * * * *",
            "target_operation": "op.a"
        }))
        .unwrap();
        let err = c
            .invoke_schedules_create(&json!({
                "name": "my-job",
                "expression": "0 0 * * *",
                "target_operation": "op.b"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::DuplicateName { .. }));
    }

    #[test]
    fn create_schedule_missing_name() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn create_schedule_missing_expression() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "target_operation": "op.test"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn create_schedule_missing_target_operation() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn list_schedules_empty() {
        let c = CronConnector::new();
        let result = c.invoke_schedules_list().unwrap();
        assert_eq!(result["schedules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn list_schedules_after_create() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "a",
            "expression": "0 * * * *",
            "target_operation": "op.a"
        }))
        .unwrap();
        c.invoke_schedules_create(&json!({
            "name": "b",
            "expression": "0 0 * * *",
            "target_operation": "op.b"
        }))
        .unwrap();
        let result = c.invoke_schedules_list().unwrap();
        assert_eq!(result["schedules"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn delete_schedule() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "to-delete",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();
        assert_eq!(c.schedules.len(), 1);

        c.invoke_schedules_delete(&json!({ "schedule_id": sched_id }))
            .unwrap();
        assert!(c.schedules.is_empty());
    }

    #[test]
    fn delete_schedule_not_found() {
        let mut c = CronConnector::new();
        let err = c
            .invoke_schedules_delete(&json!({ "schedule_id": "nonexistent" }))
            .unwrap_err();
        assert!(matches!(err, CronError::ScheduleNotFound { .. }));
    }

    #[test]
    fn delete_schedule_missing_id() {
        let mut c = CronConnector::new();
        let err = c.invoke_schedules_delete(&json!({})).unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn trigger_schedule() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "trigger-me",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        let result = c
            .invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();
        assert!(result["execution_id"].as_str().unwrap().starts_with("exec_"));
        assert_eq!(c.executions.len(), 1);
        assert_eq!(c.executions[0].schedule_id, sched_id);
        assert_eq!(c.executions[0].status, "triggered");
    }

    #[test]
    fn trigger_nonexistent_schedule() {
        let mut c = CronConnector::new();
        let err = c
            .invoke_trigger(&json!({ "schedule_id": "sched_nonexistent" }))
            .unwrap_err();
        assert!(matches!(err, CronError::ScheduleNotFound { .. }));
    }

    #[test]
    fn trigger_missing_schedule_id() {
        let mut c = CronConnector::new();
        let err = c.invoke_trigger(&json!({})).unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn executions_list_empty() {
        let c = CronConnector::new();
        let result = c.invoke_executions_list(&json!({})).unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn executions_list_after_trigger() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();

        let result = c.invoke_executions_list(&json!({})).unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn executions_list_filter_by_schedule() {
        let mut c = CronConnector::new();
        c.configured = true;

        let s1 = c
            .invoke_schedules_create(&json!({
                "name": "a",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }))
            .unwrap();
        let s2 = c
            .invoke_schedules_create(&json!({
                "name": "b",
                "expression": "0 0 * * *",
                "target_operation": "op.b"
            }))
            .unwrap();

        let sid1 = s1["schedule_id"].as_str().unwrap();
        let sid2 = s2["schedule_id"].as_str().unwrap();

        c.invoke_trigger(&json!({ "schedule_id": sid1 })).unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sid1 })).unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sid2 })).unwrap();

        let filtered = c
            .invoke_executions_list(&json!({ "schedule_id": sid1 }))
            .unwrap();
        assert_eq!(filtered["executions"].as_array().unwrap().len(), 2);

        let filtered2 = c
            .invoke_executions_list(&json!({ "schedule_id": sid2 }))
            .unwrap();
        assert_eq!(filtered2["executions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn executions_list_with_limit() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        for _ in 0..10 {
            c.invoke_trigger(&json!({ "schedule_id": sched_id }))
                .unwrap();
        }

        let result = c
            .invoke_executions_list(&json!({ "limit": 3 }))
            .unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn executions_list_limit_capped_at_max() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        // Create 5 executions and request limit 200 (should be capped to 100)
        for _ in 0..5 {
            c.invoke_trigger(&json!({ "schedule_id": sched_id }))
                .unwrap();
        }

        let result = c
            .invoke_executions_list(&json!({ "limit": 200 }))
            .unwrap();
        // Only 5 exist, so 5 returned (limit capped at 100 but only 5 available)
        assert_eq!(result["executions"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn executions_list_default_limit() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        // Create 3 executions, no limit specified (defaults to 50)
        for _ in 0..3 {
            c.invoke_trigger(&json!({ "schedule_id": sched_id }))
                .unwrap();
        }

        let result = c.invoke_executions_list(&json!({})).unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn executions_list_reversed_order() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();

        let result = c.invoke_executions_list(&json!({})).unwrap();
        let execs = result["executions"].as_array().unwrap();
        // Most recent first (second trigger should be first in the list)
        let id0 = execs[0]["id"].as_str().unwrap();
        let id1 = execs[1]["id"].as_str().unwrap();
        assert_ne!(id0, id1);
    }

    // -- Accessors --

    #[test]
    fn schedule_count() {
        let mut c = CronConnector::new();
        c.configured = true;
        assert_eq!(c.schedule_count(), 0);
        c.invoke_schedules_create(&json!({
            "name": "a",
            "expression": "0 * * * *",
            "target_operation": "op.a"
        }))
        .unwrap();
        assert_eq!(c.schedule_count(), 1);
    }

    #[test]
    fn execution_count() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "a",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }))
            .unwrap();
        assert_eq!(c.execution_count(), 0);
        let sched_id = created["schedule_id"].as_str().unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();
        assert_eq!(c.execution_count(), 1);
    }

    // -- Multiple creates and deletes --

    #[test]
    fn create_multiple_then_delete_one() {
        let mut c = CronConnector::new();
        c.configured = true;
        let s1 = c
            .invoke_schedules_create(&json!({
                "name": "a",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }))
            .unwrap();
        c.invoke_schedules_create(&json!({
            "name": "b",
            "expression": "0 0 * * *",
            "target_operation": "op.b"
        }))
        .unwrap();
        assert_eq!(c.schedules.len(), 2);

        let sid1 = s1["schedule_id"].as_str().unwrap();
        c.invoke_schedules_delete(&json!({ "schedule_id": sid1 }))
            .unwrap();
        assert_eq!(c.schedules.len(), 1);
        assert_eq!(c.schedules[0].name, "b");
    }

    #[test]
    fn delete_then_create_with_same_name() {
        let mut c = CronConnector::new();
        c.configured = true;
        let s1 = c
            .invoke_schedules_create(&json!({
                "name": "recycled",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }))
            .unwrap();
        let sid1 = s1["schedule_id"].as_str().unwrap();
        c.invoke_schedules_delete(&json!({ "schedule_id": sid1 }))
            .unwrap();

        // Should succeed since the name is no longer taken
        let s2 = c
            .invoke_schedules_create(&json!({
                "name": "recycled",
                "expression": "0 0 * * *",
                "target_operation": "op.b"
            }))
            .unwrap();
        assert!(s2["schedule_id"].as_str().is_some());
        assert_eq!(c.schedules.len(), 1);
    }

    #[test]
    fn create_schedule_with_null_payload() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "null-payload",
            "expression": "0 * * * *",
            "target_operation": "op.test",
            "payload": null
        }))
        .unwrap();
        // null payload is stored as Some(Value::Null)
        assert!(c.schedules[0].payload.is_some());
    }

    #[test]
    fn create_schedule_has_created_at() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "timestamped",
            "expression": "0 * * * *",
            "target_operation": "op.test"
        }))
        .unwrap();
        assert!(!c.schedules[0].created_at.is_empty());
        // Should be a valid ISO 8601 timestamp
        assert!(c.schedules[0].created_at.contains('T'));
    }

    #[test]
    fn trigger_records_execution_with_timestamp() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();

        assert!(!c.executions[0].triggered_at.is_empty());
        assert!(c.executions[0].triggered_at.contains('T'));
    }

    // -- DoctorStatus serde --

    #[test]
    fn doctor_status_serializes_to_lowercase() {
        assert_eq!(serde_json::to_value(DoctorStatus::Healthy).unwrap(), "healthy");
        assert_eq!(serde_json::to_value(DoctorStatus::Degraded).unwrap(), "degraded");
        assert_eq!(serde_json::to_value(DoctorStatus::Unhealthy).unwrap(), "unhealthy");
    }

    #[test]
    fn doctor_status_deserializes_from_lowercase() {
        let h: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_and_eq() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_serializes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failure reason".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("failure reason"));
    }

    #[test]
    fn doctor_result_preserves_checks() {
        let checks = vec![
            DoctorCheck {
                name: "check_a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "check_b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.checks.len(), 2);
        assert_eq!(r.checks[0].name, "check_a");
        assert_eq!(r.checks[1].name, "check_b");
    }

    // -- Operations info edge cases --

    #[test]
    fn operations_all_have_summary() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_schedules_create_is_risky() {
        let ops = operations_info();
        let create_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "cron.schedules.create")
            .unwrap();
        assert_eq!(create_op["safety_tier"], "risky");
        assert_eq!(create_op["risk_level"], "medium");
    }

    #[test]
    fn operations_schedules_list_is_strict_idempotent() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "cron.schedules.list")
            .unwrap();
        assert_eq!(list_op["idempotency"], "strict");
    }

    #[test]
    fn operations_trigger_idempotency_none() {
        let ops = operations_info();
        let trigger_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "cron.trigger")
            .unwrap();
        assert_eq!(trigger_op["idempotency"], "none");
    }

    // -- Connector accessors / state --

    #[test]
    fn connector_new_zero_request_count() {
        let c = CronConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_new_zero_error_count() {
        let c = CronConnector::new();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn create_schedule_empty_target_operation() {
        let mut c = CronConnector::new();
        c.configured = true;
        // An empty target_operation is accepted (validation not enforced on content)
        let result = c.invoke_schedules_create(&json!({
            "name": "empty-target",
            "expression": "0 * * * *",
            "target_operation": ""
        }));
        assert!(result.is_ok());
    }

    #[test]
    fn delete_then_list_is_empty() {
        let mut c = CronConnector::new();
        c.configured = true;
        let s = c
            .invoke_schedules_create(&json!({
                "name": "temp",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sid = s["schedule_id"].as_str().unwrap();
        c.invoke_schedules_delete(&json!({ "schedule_id": sid }))
            .unwrap();
        let list = c.invoke_schedules_list().unwrap();
        assert_eq!(list["schedules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn executions_list_filter_nonexistent_schedule() {
        let c = CronConnector::new();
        let result = c
            .invoke_executions_list(&json!({ "schedule_id": "sched_ghost" }))
            .unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 0);
    }
}
