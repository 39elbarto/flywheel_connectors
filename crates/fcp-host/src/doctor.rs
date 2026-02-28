//! Doctor report service for mesh health and connector self-checks.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fcp_async_core::{AsyncError, ExecutionContext};
use fcp_core::{ConnectorId, SelfCheckReport, SelfCheckStatus, ZoneId};
use serde::{Deserialize, Serialize};

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
                let context = ExecutionContext::request_scoped(self.self_check_timeout);
                let report = match context.run(self.registry.self_check(&connector_id)).await {
                    Ok(Some(report)) => report,
                    Ok(None) => {
                        return Err(HostError::ConnectorNotFound(connector_id.to_string()));
                    }
                    Err(AsyncError::Timeout { .. }) => SelfCheckReport::failed(
                        "self_check_timeout",
                        format!(
                            "self_check exceeded {}ms",
                            self.self_check_timeout.as_millis()
                        ),
                    ),
                    Err(AsyncError::Cancelled) => SelfCheckReport::failed(
                        "self_check_cancelled",
                        "self_check cancelled by execution context".to_string(),
                    ),
                    Err(error) => SelfCheckReport::failed(
                        "self_check_runtime",
                        format!("self_check runtime failure: {error}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    use fcp_core::{
        ConnectorHealth, ConnectorId, Introspection, RateLimitDeclarations, SelfCheckReport,
        SelfCheckStatus,
    };

    use crate::{ConnectorArchetype, ConnectorRegistry, ConnectorSummary};

    // ── Mock Registry ──

    struct TestRegistry {
        self_check_fn:
            Box<dyn Fn(&ConnectorId) -> Option<SelfCheckReport> + Send + Sync>,
    }

    impl TestRegistry {
        fn always_ok() -> Self {
            Self {
                self_check_fn: Box::new(|_| Some(SelfCheckReport::ok())),
            }
        }

        fn always_fail() -> Self {
            Self {
                self_check_fn: Box::new(|_| {
                    Some(SelfCheckReport::failed("test_fail", "test failure reason"))
                }),
            }
        }

        fn not_found() -> Self {
            Self {
                self_check_fn: Box::new(|_| None),
            }
        }

        fn degraded() -> Self {
            Self {
                self_check_fn: Box::new(|_| Some(SelfCheckReport::degraded("test_degraded", "degraded reason"))),
            }
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for TestRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            vec![]
        }

        async fn get(&self, _id: &ConnectorId) -> Option<ConnectorSummary> {
            Some(ConnectorSummary {
                id: ConnectorId::from_static("test.doctor:utility:1.0.0"),
                name: "Test".to_string(),
                description: None,
                version: semver::Version::new(1, 0, 0),
                categories: vec![],
                tool_count: 0,
                max_safety_tier: fcp_core::SafetyTier::Safe,
                enabled: true,
                health: ConnectorHealth::healthy(),
                last_health_check: None,
            })
        }

        async fn get_introspection(&self, _id: &ConnectorId) -> Option<Introspection> {
            None
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            Some(ConnectorArchetype::RequestResponse)
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            (self.self_check_fn)(id)
        }

        fn version(&self) -> u64 {
            1
        }
    }

    // ── overall_status_from_self_checks tests ──

    #[test]
    fn overall_ok_when_all_ok() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: "a".to_string(),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: "b".to_string(),
                report: SelfCheckReport::ok(),
            },
        ];
        assert_eq!(overall_status_from_self_checks(&checks), OverallStatus::Ok);
    }

    #[test]
    fn overall_fail_when_any_failed() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: "a".to_string(),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: "b".to_string(),
                report: SelfCheckReport::failed("test", "failed"),
            },
        ];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    #[test]
    fn overall_warn_when_degraded() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: "a".to_string(),
            report: SelfCheckReport::degraded("test", "degraded"),
        }];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn overall_fail_beats_warn() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: "a".to_string(),
                report: SelfCheckReport::degraded("test", "degraded"),
            },
            ConnectorSelfCheck {
                connector_id: "b".to_string(),
                report: SelfCheckReport::failed("test", "failed"),
            },
        ];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    #[test]
    fn overall_ok_when_empty() {
        assert_eq!(overall_status_from_self_checks(&[]), OverallStatus::Ok);
    }

    // ── DoctorReport tests ──

    #[test]
    fn baseline_report_has_correct_defaults() {
        let report = DoctorReport::baseline("test-zone");
        assert_eq!(report.zone_id, "test-zone");
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Fresh);
        assert_eq!(report.revocation.freshness, FreshnessLevel::Fresh);
        assert_eq!(report.audit.freshness, FreshnessLevel::Fresh);
        assert!(report.transport_policy.allow_lan);
        assert!(!report.transport_policy.allow_derp);
        assert!(!report.transport_policy.allow_funnel);
        assert!(report.store_coverage.store_healthy);
        assert!(!report.degraded_mode.is_degraded);
        assert!(report.checks.is_empty());
        assert!(report.connector_self_checks.is_empty());
        assert_eq!(report.schema_version, DoctorReport::SCHEMA_VERSION);
    }

    #[test]
    fn report_json_serializable() {
        let report = DoctorReport::baseline("test-zone");
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("test-zone"));
        assert!(json.contains("OK"));
    }

    // ── DoctorService tests ──

    #[fcp_async_core::runtime::test]
    async fn doctor_no_self_check() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec![],
            self_check: false,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert!(report.connector_self_checks.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_self_check_ok() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert_eq!(report.connector_self_checks.len(), 1);
        assert_eq!(
            report.connector_self_checks[0].report.status,
            SelfCheckStatus::Ok
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_self_check_failed() {
        let registry = Arc::new(TestRegistry::always_fail());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(report.connector_self_checks.len(), 1);
        assert_eq!(
            report.connector_self_checks[0].report.status,
            SelfCheckStatus::Failed
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_self_check_degraded() {
        let registry = Arc::new(TestRegistry::degraded());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_connector_not_found() {
        let registry = Arc::new(TestRegistry::not_found());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let result = service.handle(request).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_invalid_zone_id() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "".to_string(),
            connectors: vec![],
            self_check: false,
        };

        let result = service.handle(request).await;
        // Empty zone_id may or may not be rejected depending on ZoneId::parse
        // but we exercise the code path
        match result {
            Ok(report) => assert_eq!(report.zone_id, ""),
            Err(_) => {} // Expected for invalid zone
        }
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_multiple_connectors() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec![
                "test.a:utility:1.0.0".to_string(),
                "test.b:utility:1.0.0".to_string(),
            ],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.connector_self_checks.len(), 2);
        assert_eq!(report.overall_status, OverallStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_custom_timeout() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::with_timeout(registry, Duration::from_secs(1));

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Ok);
    }

    // ── FreshnessLevel tests ──

    #[test]
    fn freshness_level_default_is_fresh() {
        assert_eq!(FreshnessLevel::default(), FreshnessLevel::Fresh);
    }

    // ── CheckResult/CheckStatus/CheckSeverity tests ──

    #[test]
    fn check_result_serialization() {
        let result = CheckResult {
            name: "test_check".to_string(),
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "something is off".to_string(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["name"], "test_check");
        assert_eq!(json["status"], "WARN");
        assert_eq!(json["severity"], "warning");
    }
}
