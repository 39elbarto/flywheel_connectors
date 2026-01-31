//! Doctor report service for mesh health and connector self-checks.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fcp_core::{ConnectorId, SelfCheckReport, SelfCheckStatus, ZoneId};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use crate::{ConnectorRegistry, HostError, HostResult};

/// Doctor report request payload.
#[derive(Debug, Clone, Deserialize)]
pub struct DoctorRequest {
    /// Zone to diagnose.
    pub zone_id: String,

    /// Connector IDs to self-check.
    #[serde(default)]
    pub connectors: Vec<String>,

    /// Whether to run connector self-checks.
    #[serde(default)]
    pub self_check: bool,
}

/// Connector self-check entry in the report.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectorSelfCheck {
    /// Connector identifier.
    pub connector_id: String,

    /// Self-check report from connector.
    pub report: SelfCheckReport,
}

/// Overall status of the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OverallStatus {
    /// Zone is healthy and all checks pass.
    Ok,
    /// Zone has warnings but operations can proceed.
    Warn,
    /// Zone has critical failures; Risky/Dangerous operations should fail.
    Fail,
}

/// Freshness level for heads/checkpoints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessLevel {
    /// Data is fresh and up-to-date.
    #[default]
    Fresh,
    /// Data is stale but operations allowed in degraded mode.
    Stale,
    /// Data is too stale; operations must fail.
    TooStale,
    /// Data is missing/unavailable.
    Missing,
}

/// Checkpoint freshness status.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CheckpointStatus {
    /// Freshness level.
    pub freshness: FreshnessLevel,
}

/// Revocation head freshness status.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RevocationStatus {
    /// Freshness level.
    pub freshness: FreshnessLevel,
}

/// Audit head freshness status.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditStatus {
    /// Freshness level.
    pub freshness: FreshnessLevel,
}

/// Transport policy status.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TransportPolicyStatus {
    /// Whether LAN transport is allowed.
    pub allow_lan: bool,
    /// Whether DERP relay transport is allowed.
    pub allow_derp: bool,
    /// Whether Funnel ingress is allowed.
    pub allow_funnel: bool,
}

/// Store coverage status for key roots.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StoreCoverageStatus {
    /// Overall store health.
    pub store_healthy: bool,
}

/// Degraded mode status.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DegradedModeStatus {
    /// Whether the system is in degraded mode.
    pub is_degraded: bool,
}

/// Individual check result.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// Check name.
    pub name: String,
    /// Check status.
    pub status: CheckStatus,
    /// Check severity.
    pub severity: CheckSeverity,
    /// Human-readable message.
    pub message: String,
}

/// Check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

/// Check severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverity {
    Info,
    Warning,
    Critical,
}

/// Complete doctor report including zone health and freshness status.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,

    /// Zone being diagnosed.
    pub zone_id: String,

    /// Overall status summary.
    pub overall_status: OverallStatus,

    /// Checkpoint freshness status.
    pub checkpoint: CheckpointStatus,

    /// Revocation head freshness status.
    pub revocation: RevocationStatus,

    /// Audit head freshness status.
    pub audit: AuditStatus,

    /// Transport policy settings.
    pub transport_policy: TransportPolicyStatus,

    /// Store coverage summary for key roots.
    pub store_coverage: StoreCoverageStatus,

    /// Degraded mode status and reasons.
    pub degraded_mode: DegradedModeStatus,

    /// Individual check results.
    pub checks: Vec<CheckResult>,

    /// Connector self-check results (when requested).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connector_self_checks: Vec<ConnectorSelfCheck>,
}

impl DoctorReport {
    /// Schema version constant (aligned with fcp-cli).
    pub const SCHEMA_VERSION: &'static str = "1.1.0";

    fn baseline(zone_id: &str) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            zone_id: zone_id.to_string(),
            overall_status: OverallStatus::Ok,
            checkpoint: CheckpointStatus::default(),
            revocation: RevocationStatus::default(),
            audit: AuditStatus::default(),
            transport_policy: TransportPolicyStatus {
                allow_lan: true,
                allow_derp: false,
                allow_funnel: false,
            },
            store_coverage: StoreCoverageStatus {
                store_healthy: true,
            },
            degraded_mode: DegradedModeStatus::default(),
            checks: Vec::new(),
            connector_self_checks: Vec::new(),
        }
    }

    fn with_self_checks(mut self, checks: Vec<ConnectorSelfCheck>) -> Self {
        self.overall_status = overall_status_from_self_checks(&checks);
        self.connector_self_checks = checks;
        self
    }
}

const DEFAULT_SELF_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Doctor report service built on top of a connector registry.
#[derive(Clone)]
pub struct DoctorService<R> {
    registry: Arc<R>,
    self_check_timeout: Duration,
}

impl<R> DoctorService<R>
where
    R: ConnectorRegistry,
{
    /// Create a new doctor service.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(registry: Arc<R>) -> Self {
        Self {
            registry,
            self_check_timeout: DEFAULT_SELF_CHECK_TIMEOUT,
        }
    }

    /// Create a doctor service with a custom self-check timeout.
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_timeout(registry: Arc<R>, self_check_timeout: Duration) -> Self {
        Self {
            registry,
            self_check_timeout,
        }
    }

    /// Build a doctor report for the given request.
    ///
    /// # Errors
    /// Returns a `HostError` when inputs are invalid or connectors are missing.
    pub async fn handle(&self, request: DoctorRequest) -> HostResult<DoctorReport> {
        let _zone: ZoneId = request.zone_id.parse().map_err(|err| {
            HostError::InvalidFilter(format!("invalid zone_id '{}': {err}", request.zone_id))
        })?;

        let mut self_checks = Vec::new();
        if request.self_check {
            for connector in request.connectors {
                let connector_id: ConnectorId = connector.parse().map_err(|err| {
                    HostError::InvalidFilter(format!("invalid connector id '{connector}': {err}"))
                })?;
                let report = match timeout(
                    self.self_check_timeout,
                    self.registry.self_check(&connector_id),
                )
                .await
                {
                    Ok(Some(report)) => report,
                    Ok(None) => {
                        return Err(HostError::ConnectorNotFound(connector_id.to_string()));
                    }
                    Err(_) => SelfCheckReport::failed(
                        "self_check_timeout",
                        format!(
                            "self_check exceeded {}ms",
                            self.self_check_timeout.as_millis()
                        ),
                    ),
                };
                self_checks.push(ConnectorSelfCheck {
                    connector_id: connector_id.to_string(),
                    report,
                });
            }
        }

        Ok(DoctorReport::baseline(&request.zone_id).with_self_checks(self_checks))
    }
}

fn overall_status_from_self_checks(checks: &[ConnectorSelfCheck]) -> OverallStatus {
    if checks
        .iter()
        .any(|check| check.report.status == SelfCheckStatus::Failed)
    {
        return OverallStatus::Fail;
    }

    if checks
        .iter()
        .any(|check| check.report.status == SelfCheckStatus::Degraded)
    {
        return OverallStatus::Warn;
    }

    OverallStatus::Ok
}
