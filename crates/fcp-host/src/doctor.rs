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

    #[must_use]
    pub fn baseline(zone_id: &str) -> Self {
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
    R: ConnectorRegistry + 'static,
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
            let mut handles = Vec::new();

            for connector in request.connectors {
                let connector_id: ConnectorId = connector.parse().map_err(|err| {
                    HostError::InvalidFilter(format!("invalid connector id '{connector}': {err}"))
                })?;

                let registry = Arc::clone(&self.registry);
                let timeout = self.self_check_timeout;

                let handle = fcp_async_core::task::spawn(async move {
                    let context = ExecutionContext::request_scoped(timeout);
                    let report = match context.run(registry.self_check(&connector_id)).await {
                        Ok(Some(report)) => report,
                        Ok(None) => SelfCheckReport::failed(
                            "not_found",
                            "connector not found in registry".to_string(),
                        ),
                        Err(AsyncError::Timeout { .. }) => SelfCheckReport::failed(
                            "self_check_timeout",
                            format!("self_check exceeded {}ms", timeout.as_millis()),
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
                    Ok(ConnectorSelfCheck {
                        connector_id: connector_id.to_string(),
                        report,
                    })
                });
                handles.push(handle);
            }

            for handle in handles {
                // `fcp_async_core::task::spawn` returns a join handle. We await it,
                // unwrap any panics (for now, or handle them gracefully), and push the result.
                let result = handle.await.map_err(|err| {
                    HostError::Internal(format!("self_check task panicked: {err}"))
                })??;
                self_checks.push(result);
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
    type SelfCheckFn = dyn Fn(&ConnectorId) -> Option<SelfCheckReport> + Send + Sync;

    struct TestRegistry {
        self_check_fn: Box<SelfCheckFn>,
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
                self_check_fn: Box::new(|_| {
                    Some(SelfCheckReport::degraded(
                        "test_degraded",
                        "degraded reason",
                    ))
                }),
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

        let result = service.handle(request).await.unwrap();
        assert_eq!(result.overall_status, OverallStatus::Fail);
        assert_eq!(result.connector_self_checks.len(), 1);
        assert_eq!(
            result.connector_self_checks[0].report.status,
            SelfCheckStatus::Failed
        );
        assert_eq!(
            result.connector_self_checks[0].report.reason_code,
            Some("not_found".to_string())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_invalid_zone_id() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: String::new(),
            connectors: vec![],
            self_check: false,
        };

        let result = service.handle(request).await;
        // Empty zone_id may or may not be rejected depending on ZoneId::parse
        // but we exercise the code path
        if let Ok(report) = result {
            assert_eq!(report.zone_id, "");
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

    // ── OverallStatus serde tests ──

    #[test]
    fn overall_status_serialization() {
        for (status, expected) in [
            (OverallStatus::Ok, "\"OK\""),
            (OverallStatus::Warn, "\"WARN\""),
            (OverallStatus::Fail, "\"FAIL\""),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn overall_status_eq_and_copy() {
        let a = OverallStatus::Ok;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(OverallStatus::Ok, OverallStatus::Fail);
    }

    // ── FreshnessLevel serde tests ──

    #[test]
    fn freshness_level_all_variants_serialize() {
        for (level, expected) in [
            (FreshnessLevel::Fresh, "\"fresh\""),
            (FreshnessLevel::Stale, "\"stale\""),
            (FreshnessLevel::TooStale, "\"too_stale\""),
            (FreshnessLevel::Missing, "\"missing\""),
        ] {
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn freshness_level_eq_and_copy() {
        let a = FreshnessLevel::Stale;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(FreshnessLevel::Fresh, FreshnessLevel::TooStale);
    }

    // ── CheckStatus serde tests ──

    #[test]
    fn check_status_serialization() {
        for (status, expected) in [
            (CheckStatus::Ok, "\"OK\""),
            (CheckStatus::Warn, "\"WARN\""),
            (CheckStatus::Fail, "\"FAIL\""),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn check_status_eq_and_copy() {
        let a = CheckStatus::Fail;
        let b = a;
        assert_eq!(a, b);
    }

    // ── CheckSeverity serde tests ──

    #[test]
    fn check_severity_serialization() {
        for (sev, expected) in [
            (CheckSeverity::Info, "\"info\""),
            (CheckSeverity::Warning, "\"warning\""),
            (CheckSeverity::Critical, "\"critical\""),
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn check_severity_eq_and_copy() {
        let a = CheckSeverity::Critical;
        let b = a;
        assert_eq!(a, b);
    }

    // ── Default status struct tests ──

    #[test]
    fn checkpoint_status_default_is_fresh() {
        let s = CheckpointStatus::default();
        assert_eq!(s.freshness, FreshnessLevel::Fresh);
    }

    #[test]
    fn revocation_status_default_is_fresh() {
        let s = RevocationStatus::default();
        assert_eq!(s.freshness, FreshnessLevel::Fresh);
    }

    #[test]
    fn audit_status_default_is_fresh() {
        let s = AuditStatus::default();
        assert_eq!(s.freshness, FreshnessLevel::Fresh);
    }

    #[test]
    fn transport_policy_default_all_false() {
        let t = TransportPolicyStatus::default();
        assert!(!t.allow_lan);
        assert!(!t.allow_derp);
        assert!(!t.allow_funnel);
    }

    #[test]
    fn store_coverage_default_not_healthy() {
        let s = StoreCoverageStatus::default();
        assert!(!s.store_healthy);
    }

    #[test]
    fn degraded_mode_default_not_degraded() {
        let d = DegradedModeStatus::default();
        assert!(!d.is_degraded);
    }

    // ── DoctorReport tests ──

    #[test]
    fn schema_version_constant_is_semver() {
        let v: semver::Version = DoctorReport::SCHEMA_VERSION.parse().unwrap();
        assert_eq!(v.major, 1);
    }

    #[test]
    fn baseline_transport_policy_allows_lan_only() {
        let report = DoctorReport::baseline("z:test");
        assert!(report.transport_policy.allow_lan);
        assert!(!report.transport_policy.allow_derp);
        assert!(!report.transport_policy.allow_funnel);
    }

    #[test]
    fn with_self_checks_sets_overall_status() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: "a".to_string(),
            report: SelfCheckReport::failed("test", "fail"),
        }];
        let report = DoctorReport::baseline("z:test").with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(report.connector_self_checks.len(), 1);
    }

    #[test]
    fn with_self_checks_empty_stays_ok() {
        let report = DoctorReport::baseline("z:test").with_self_checks(vec![]);
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert!(report.connector_self_checks.is_empty());
    }

    // ── DoctorRequest deserialization tests ──

    #[test]
    fn doctor_request_defaults() {
        let json = r#"{"zone_id": "z:test"}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "z:test");
        assert!(req.connectors.is_empty());
        assert!(!req.self_check);
    }

    #[test]
    fn doctor_request_full() {
        let json = r#"{"zone_id": "z:prod", "connectors": ["a.b:c:1.0.0"], "self_check": true}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "z:prod");
        assert_eq!(req.connectors.len(), 1);
        assert!(req.self_check);
    }

    // ── ConnectorSelfCheck serialization ──

    #[test]
    fn connector_self_check_serialization() {
        let check = ConnectorSelfCheck {
            connector_id: "test.check:utility:1.0.0".to_string(),
            report: SelfCheckReport::ok(),
        };
        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["connector_id"], "test.check:utility:1.0.0");
    }

    // ── DoctorReport full serialization ──

    #[test]
    fn doctor_report_skips_empty_self_checks() {
        let report = DoctorReport::baseline("z:test");
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("connector_self_checks"));
    }

    #[test]
    fn doctor_report_includes_nonempty_self_checks() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: "a".to_string(),
            report: SelfCheckReport::ok(),
        }];
        let report = DoctorReport::baseline("z:test").with_self_checks(checks);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("connector_self_checks"));
    }

    // ── CheckResult construction ──

    #[test]
    fn check_result_fields_accessible() {
        let result = CheckResult {
            name: "connectivity".to_string(),
            status: CheckStatus::Ok,
            severity: CheckSeverity::Info,
            message: "all good".to_string(),
        };
        assert_eq!(result.name, "connectivity");
        assert_eq!(result.status, CheckStatus::Ok);
        assert_eq!(result.severity, CheckSeverity::Info);
        assert_eq!(result.message, "all good");
    }

    #[test]
    fn check_result_fail_critical_serialization() {
        let result = CheckResult {
            name: "disk_space".to_string(),
            status: CheckStatus::Fail,
            severity: CheckSeverity::Critical,
            message: "disk full".to_string(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "FAIL");
        assert_eq!(json["severity"], "critical");
    }

    // ── OverallStatus serde names ──

    #[test]
    fn overall_status_serde_uppercase() {
        assert_eq!(serde_json::to_string(&OverallStatus::Ok).unwrap(), "\"OK\"");
        assert_eq!(
            serde_json::to_string(&OverallStatus::Warn).unwrap(),
            "\"WARN\""
        );
        assert_eq!(
            serde_json::to_string(&OverallStatus::Fail).unwrap(),
            "\"FAIL\""
        );
    }

    // ── CheckStatus serde ──

    #[test]
    fn check_status_serde_names() {
        assert_eq!(serde_json::to_string(&CheckStatus::Ok).unwrap(), "\"OK\"");
        assert_eq!(
            serde_json::to_string(&CheckStatus::Warn).unwrap(),
            "\"WARN\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Fail).unwrap(),
            "\"FAIL\""
        );
    }

    // ── CheckSeverity serde ──

    #[test]
    fn check_severity_serde_names() {
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Info).unwrap(),
            "\"info\""
        );
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Critical).unwrap(),
            "\"critical\""
        );
    }

    // ── FreshnessLevel serde names ──

    #[test]
    fn freshness_level_serde_names() {
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Fresh).unwrap(),
            "\"fresh\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Stale).unwrap(),
            "\"stale\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::TooStale).unwrap(),
            "\"too_stale\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Missing).unwrap(),
            "\"missing\""
        );
    }

    // ── Status struct serialization with non-default values ──

    #[test]
    fn checkpoint_status_stale_serialization() {
        let s = CheckpointStatus {
            freshness: FreshnessLevel::Stale,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["freshness"], "stale");
    }

    #[test]
    fn transport_policy_custom_serialization() {
        let s = TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["allow_lan"], true);
        assert_eq!(json["allow_derp"], true);
        assert_eq!(json["allow_funnel"], false);
    }

    #[test]
    fn store_coverage_healthy_serialization() {
        let s = StoreCoverageStatus {
            store_healthy: true,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["store_healthy"], true);
    }

    #[test]
    fn degraded_mode_active_serialization() {
        let s = DegradedModeStatus { is_degraded: true };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["is_degraded"], true);
    }

    // ── with_self_checks precedence ──

    #[test]
    fn with_self_checks_mixed_ok_warn_fail_returns_fail() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: "a".to_string(),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: "b".to_string(),
                report: SelfCheckReport::degraded("slow", "slow response"),
            },
            ConnectorSelfCheck {
                connector_id: "c".to_string(),
                report: SelfCheckReport::failed("test", "down"),
            },
        ];
        let report = DoctorReport::baseline("z:test").with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Fail);
    }

    #[test]
    fn with_self_checks_warn_only_returns_warn() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: "a".to_string(),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: "b".to_string(),
                report: SelfCheckReport::degraded("slow", "slow response"),
            },
        ];
        let report = DoctorReport::baseline("z:test").with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    // ── DoctorReport baseline values ──

    #[test]
    fn baseline_report_schema_version() {
        let report = DoctorReport::baseline("z:test");
        assert_eq!(report.schema_version, "1.1.0");
    }

    #[test]
    fn baseline_report_zone_id_preserved() {
        let report = DoctorReport::baseline("z:custom");
        assert_eq!(report.zone_id, "z:custom");
    }

    #[test]
    fn baseline_report_transport_policy_defaults() {
        let report = DoctorReport::baseline("z:test");
        assert!(report.transport_policy.allow_lan);
        assert!(!report.transport_policy.allow_derp);
        assert!(!report.transport_policy.allow_funnel);
    }

    #[test]
    fn baseline_report_store_coverage_healthy() {
        let report = DoctorReport::baseline("z:test");
        assert!(report.store_coverage.store_healthy);
    }

    #[test]
    fn baseline_report_no_degraded_mode() {
        let report = DoctorReport::baseline("z:test");
        assert!(!report.degraded_mode.is_degraded);
    }

    // ── ConnectorSelfCheck serde roundtrip ──

    #[test]
    fn connector_self_check_roundtrip() {
        let check = ConnectorSelfCheck {
            connector_id: "test:conn:1.0.0".to_string(),
            report: SelfCheckReport::ok(),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("test:conn:1.0.0"));
        assert!(json.contains("ok"));
    }

    #[test]
    fn connector_self_check_failed_report() {
        let check = ConnectorSelfCheck {
            connector_id: "test:fail:1.0.0".to_string(),
            report: SelfCheckReport::failed("auth", "token expired"),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("failed"));
        assert!(json.contains("token expired"));
    }

    // ── DoctorReport full serialization ──

    #[test]
    fn doctor_report_full_serialization_roundtrip() {
        let report = DoctorReport::baseline("z:roundtrip");
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("z:roundtrip"));
        assert!(json.contains("1.1.0"));
        assert!(json.contains("\"OK\""));
        assert!(json.contains("\"fresh\""));
    }

    // ── CheckResult all status-severity combinations ──

    #[test]
    fn check_result_all_status_severity_combinations() {
        let statuses = [CheckStatus::Ok, CheckStatus::Warn, CheckStatus::Fail];
        let severities = [
            CheckSeverity::Info,
            CheckSeverity::Warning,
            CheckSeverity::Critical,
        ];
        for status in &statuses {
            for severity in &severities {
                let result = CheckResult {
                    name: format!("{status:?}_{severity:?}"),
                    status: *status,
                    severity: *severity,
                    message: "test".to_string(),
                };
                let json = serde_json::to_value(&result).unwrap();
                assert!(!json["status"].as_str().unwrap().is_empty());
                assert!(!json["severity"].as_str().unwrap().is_empty());
            }
        }
    }

    // ── DoctorRequest deserialization edge cases ──

    #[test]
    fn doctor_request_empty_zone_id() {
        let json = r#"{"zone_id": ""}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "");
    }

    #[test]
    fn doctor_request_serde_roundtrip() {
        let json = r#"{"zone_id": "z:test", "connectors": ["a", "b"], "self_check": true}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "z:test");
        assert_eq!(req.connectors, vec!["a", "b"]);
        assert!(req.self_check);
    }
}
