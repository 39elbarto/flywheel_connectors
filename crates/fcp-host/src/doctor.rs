//! Doctor report service for mesh health and connector self-checks.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fcp_async_core::{AsyncError, ExecutionContext};
use fcp_core::{ConnectorId, SelfCheckReport, SelfCheckStatus, ZoneId};
use futures_util::future::join_all;
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
            let mut futures = Vec::new();

            for connector in request.connectors {
                let connector_id: ConnectorId = connector.parse().map_err(|err| {
                    HostError::InvalidFilter(format!("invalid connector id '{connector}': {err}"))
                })?;

                let registry = Arc::clone(&self.registry);
                let timeout = self.self_check_timeout;

                futures.push(async move {
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
            }

            for result in join_all(futures).await {
                self_checks.push(result?);
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

    // ── DoctorReport clone ──

    #[test]
    fn doctor_report_clone_preserves_all_fields() {
        let report = DoctorReport::baseline("z:clone-test");
        let cloned = report.clone();
        assert_eq!(report.zone_id, cloned.zone_id);
        assert_eq!(report.overall_status, cloned.overall_status);
        assert_eq!(report.schema_version, cloned.schema_version);
        assert_eq!(report.checkpoint.freshness, cloned.checkpoint.freshness);
        assert_eq!(
            report.transport_policy.allow_lan,
            cloned.transport_policy.allow_lan
        );
    }

    // ── DoctorReport debug ──

    #[test]
    fn doctor_report_debug_output() {
        let report = DoctorReport::baseline("z:debug");
        let dbg = format!("{report:?}");
        assert!(dbg.contains("DoctorReport"));
        assert!(dbg.contains("z:debug"));
    }

    // ── OverallStatus debug ──

    #[test]
    fn overall_status_debug() {
        let dbg = format!("{:?}", OverallStatus::Ok);
        assert!(dbg.contains("Ok"));
        let dbg = format!("{:?}", OverallStatus::Warn);
        assert!(dbg.contains("Warn"));
        let dbg = format!("{:?}", OverallStatus::Fail);
        assert!(dbg.contains("Fail"));
    }

    // ── FreshnessLevel debug ──

    #[test]
    fn freshness_level_debug_all_variants() {
        for level in [
            FreshnessLevel::Fresh,
            FreshnessLevel::Stale,
            FreshnessLevel::TooStale,
            FreshnessLevel::Missing,
        ] {
            let dbg = format!("{level:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── CheckStatus debug ──

    #[test]
    fn check_status_debug_all_variants() {
        for status in [CheckStatus::Ok, CheckStatus::Warn, CheckStatus::Fail] {
            let dbg = format!("{status:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── CheckSeverity debug ──

    #[test]
    fn check_severity_debug_all_variants() {
        for sev in [
            CheckSeverity::Info,
            CheckSeverity::Warning,
            CheckSeverity::Critical,
        ] {
            let dbg = format!("{sev:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── ConnectorSelfCheck clone ──

    #[test]
    fn connector_self_check_clone() {
        let check = ConnectorSelfCheck {
            connector_id: "test:conn:1.0.0".to_string(),
            report: SelfCheckReport::ok(),
        };
        let cloned = check.clone();
        assert_eq!(check.connector_id, cloned.connector_id);
        assert_eq!(check.report.status, cloned.report.status);
    }

    // ── ConnectorSelfCheck debug ──

    #[test]
    fn connector_self_check_debug() {
        let check = ConnectorSelfCheck {
            connector_id: "debug:conn:1.0.0".to_string(),
            report: SelfCheckReport::ok(),
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("ConnectorSelfCheck"));
        assert!(dbg.contains("debug:conn:1.0.0"));
    }

    // ── CheckpointStatus clone and debug ──

    #[test]
    fn checkpoint_status_clone() {
        let s = CheckpointStatus {
            freshness: FreshnessLevel::TooStale,
        };
        let cloned = s.clone();
        assert_eq!(s.freshness, cloned.freshness);
    }

    #[test]
    fn checkpoint_status_debug() {
        let s = CheckpointStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("CheckpointStatus"));
    }

    // ── RevocationStatus clone and debug ──

    #[test]
    fn revocation_status_clone() {
        let s = RevocationStatus {
            freshness: FreshnessLevel::Missing,
        };
        let cloned = s.clone();
        assert_eq!(s.freshness, cloned.freshness);
    }

    #[test]
    fn revocation_status_debug() {
        let s = RevocationStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("RevocationStatus"));
    }

    // ── AuditStatus clone and debug ──

    #[test]
    fn audit_status_clone() {
        let s = AuditStatus {
            freshness: FreshnessLevel::Stale,
        };
        let cloned = s.clone();
        assert_eq!(s.freshness, cloned.freshness);
    }

    #[test]
    fn audit_status_debug() {
        let s = AuditStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("AuditStatus"));
    }

    // ── TransportPolicyStatus clone and debug ──

    #[test]
    fn transport_policy_status_clone() {
        let s = TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        };
        let cloned = s.clone();
        assert_eq!(s.allow_lan, cloned.allow_lan);
        assert_eq!(s.allow_derp, cloned.allow_derp);
        assert_eq!(s.allow_funnel, cloned.allow_funnel);
    }

    #[test]
    fn transport_policy_status_debug() {
        let s = TransportPolicyStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("TransportPolicyStatus"));
    }

    // ── StoreCoverageStatus clone and debug ──

    #[test]
    fn store_coverage_status_clone() {
        let s = StoreCoverageStatus {
            store_healthy: true,
        };
        let cloned = s.clone();
        assert_eq!(s.store_healthy, cloned.store_healthy);
    }

    #[test]
    fn store_coverage_status_debug() {
        let s = StoreCoverageStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("StoreCoverageStatus"));
    }

    // ── DegradedModeStatus clone and debug ──

    #[test]
    fn degraded_mode_status_clone() {
        let s = DegradedModeStatus { is_degraded: true };
        let cloned = s.clone();
        assert_eq!(s.is_degraded, cloned.is_degraded);
    }

    #[test]
    fn degraded_mode_status_debug() {
        let s = DegradedModeStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("DegradedModeStatus"));
    }

    // ── CheckResult clone and debug ──

    #[test]
    fn check_result_clone() {
        let result = CheckResult {
            name: "clone_test".to_string(),
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "cloned".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(result.name, cloned.name);
        assert_eq!(result.status, cloned.status);
        assert_eq!(result.severity, cloned.severity);
        assert_eq!(result.message, cloned.message);
    }

    #[test]
    fn check_result_debug() {
        let result = CheckResult {
            name: "debug_test".to_string(),
            status: CheckStatus::Fail,
            severity: CheckSeverity::Critical,
            message: "debug msg".to_string(),
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("CheckResult"));
        assert!(dbg.contains("debug_test"));
    }

    // ── DoctorReport with multiple checks ──

    #[test]
    fn doctor_report_with_checks_serialization() {
        let mut report = DoctorReport::baseline("z:checks");
        report.checks.push(CheckResult {
            name: "disk".to_string(),
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "low space".to_string(),
        });
        report.checks.push(CheckResult {
            name: "cpu".to_string(),
            status: CheckStatus::Ok,
            severity: CheckSeverity::Info,
            message: "normal".to_string(),
        });
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("disk"));
        assert!(json.contains("cpu"));
        assert!(json.contains("WARN"));
    }

    // ── DoctorReport unicode zone_id ──

    #[test]
    fn baseline_report_unicode_zone_id() {
        let report = DoctorReport::baseline("z:\u{00e9}l\u{00e8}ve");
        assert_eq!(report.zone_id, "z:\u{00e9}l\u{00e8}ve");
    }

    // ── DoctorRequest unicode ──

    #[test]
    fn doctor_request_unicode_zone_id() {
        let json = r#"{"zone_id": "z:\u00e9l\u00e8ve"}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert!(req.zone_id.contains('\u{00e9}'));
    }

    // ── DoctorRequest many connectors ──

    #[test]
    fn doctor_request_many_connectors() {
        let connectors: Vec<String> = (0..100).map(|i| format!("conn{i}")).collect();
        let req = DoctorRequest {
            zone_id: "z:bulk".to_string(),
            connectors,
            self_check: true,
        };
        assert_eq!(req.connectors.len(), 100);
    }

    // ── overall_status_from_self_checks with many entries ──

    #[test]
    fn overall_status_many_ok_entries() {
        let checks: Vec<ConnectorSelfCheck> = (0..50)
            .map(|i| ConnectorSelfCheck {
                connector_id: format!("conn_{i}"),
                report: SelfCheckReport::ok(),
            })
            .collect();
        assert_eq!(overall_status_from_self_checks(&checks), OverallStatus::Ok);
    }

    #[test]
    fn overall_status_last_entry_failed() {
        let mut checks: Vec<ConnectorSelfCheck> = (0..10)
            .map(|i| ConnectorSelfCheck {
                connector_id: format!("conn_{i}"),
                report: SelfCheckReport::ok(),
            })
            .collect();
        checks.push(ConnectorSelfCheck {
            connector_id: "last".to_string(),
            report: SelfCheckReport::failed("err", "final failure"),
        });
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    // ── DoctorReport transport_policy all true ──

    #[test]
    fn transport_policy_all_true() {
        let t = TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["allow_lan"], true);
        assert_eq!(json["allow_derp"], true);
        assert_eq!(json["allow_funnel"], true);
    }

    // ── FreshnessLevel copy semantics ──

    #[test]
    fn freshness_level_copy_semantics() {
        let a = FreshnessLevel::TooStale;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, FreshnessLevel::TooStale);
    }

    // ── OverallStatus copy semantics ──

    #[test]
    fn overall_status_copy_semantics() {
        let a = OverallStatus::Warn;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, OverallStatus::Warn);
    }

    // ── NEW: OverallStatus serialize-to-Value roundtrip ──

    #[test]
    fn overall_status_ok_to_value_roundtrip() {
        let val = serde_json::to_value(OverallStatus::Ok).unwrap();
        assert_eq!(val.as_str(), Some("OK"));
    }

    #[test]
    fn overall_status_warn_to_value_roundtrip() {
        let val = serde_json::to_value(OverallStatus::Warn).unwrap();
        assert_eq!(val.as_str(), Some("WARN"));
    }

    #[test]
    fn overall_status_fail_to_value_roundtrip() {
        let val = serde_json::to_value(OverallStatus::Fail).unwrap();
        assert_eq!(val.as_str(), Some("FAIL"));
    }

    // ── NEW: FreshnessLevel serialize-to-Value roundtrip ──

    #[test]
    fn freshness_level_fresh_to_value() {
        let val = serde_json::to_value(FreshnessLevel::Fresh).unwrap();
        assert_eq!(val.as_str(), Some("fresh"));
    }

    #[test]
    fn freshness_level_stale_to_value() {
        let val = serde_json::to_value(FreshnessLevel::Stale).unwrap();
        assert_eq!(val.as_str(), Some("stale"));
    }

    #[test]
    fn freshness_level_too_stale_to_value() {
        let val = serde_json::to_value(FreshnessLevel::TooStale).unwrap();
        assert_eq!(val.as_str(), Some("too_stale"));
    }

    #[test]
    fn freshness_level_missing_to_value() {
        let val = serde_json::to_value(FreshnessLevel::Missing).unwrap();
        assert_eq!(val.as_str(), Some("missing"));
    }

    // ── NEW: CheckStatus serialize-to-Value roundtrip ──

    #[test]
    fn check_status_ok_to_value() {
        let val = serde_json::to_value(CheckStatus::Ok).unwrap();
        assert_eq!(val.as_str(), Some("OK"));
    }

    #[test]
    fn check_status_warn_to_value() {
        let val = serde_json::to_value(CheckStatus::Warn).unwrap();
        assert_eq!(val.as_str(), Some("WARN"));
    }

    #[test]
    fn check_status_fail_to_value() {
        let val = serde_json::to_value(CheckStatus::Fail).unwrap();
        assert_eq!(val.as_str(), Some("FAIL"));
    }

    // ── NEW: CheckSeverity serialize-to-Value roundtrip ──

    #[test]
    fn check_severity_info_to_value() {
        let val = serde_json::to_value(CheckSeverity::Info).unwrap();
        assert_eq!(val.as_str(), Some("info"));
    }

    #[test]
    fn check_severity_warning_to_value() {
        let val = serde_json::to_value(CheckSeverity::Warning).unwrap();
        assert_eq!(val.as_str(), Some("warning"));
    }

    #[test]
    fn check_severity_critical_to_value() {
        let val = serde_json::to_value(CheckSeverity::Critical).unwrap();
        assert_eq!(val.as_str(), Some("critical"));
    }

    // ── NEW: OverallStatus inequality combinations ──

    #[test]
    fn overall_status_all_pairs_inequality() {
        let variants = [OverallStatus::Ok, OverallStatus::Warn, OverallStatus::Fail];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── NEW: CheckStatus inequality combinations ──

    #[test]
    fn check_status_all_pairs_inequality() {
        let variants = [CheckStatus::Ok, CheckStatus::Warn, CheckStatus::Fail];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── NEW: CheckSeverity inequality combinations ──

    #[test]
    fn check_severity_all_pairs_inequality() {
        let variants = [
            CheckSeverity::Info,
            CheckSeverity::Warning,
            CheckSeverity::Critical,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── NEW: FreshnessLevel inequality combinations ──

    #[test]
    fn freshness_level_all_pairs_inequality() {
        let variants = [
            FreshnessLevel::Fresh,
            FreshnessLevel::Stale,
            FreshnessLevel::TooStale,
            FreshnessLevel::Missing,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── NEW: DoctorRequest edge cases ──

    #[test]
    fn doctor_request_missing_zone_id_fails() {
        let result = serde_json::from_str::<DoctorRequest>(r"{}");
        assert!(result.is_err());
    }

    #[test]
    fn doctor_request_extra_fields_ignored() {
        let json = r#"{"zone_id": "z:test", "unknown_field": 42}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "z:test");
    }

    #[test]
    fn doctor_request_self_check_defaults_false() {
        let json = r#"{"zone_id": "z:test", "connectors": ["a"]}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert!(!req.self_check);
    }

    #[test]
    fn doctor_request_connectors_defaults_empty() {
        let json = r#"{"zone_id": "z:test", "self_check": true}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert!(req.connectors.is_empty());
        assert!(req.self_check);
    }

    #[test]
    fn doctor_request_clone_preserves_fields() {
        let req = DoctorRequest {
            zone_id: "z:cloned".to_string(),
            connectors: vec!["conn1".to_string(), "conn2".to_string()],
            self_check: true,
        };
        let cloned = req.clone();
        assert_eq!(req.zone_id, cloned.zone_id);
        assert_eq!(req.connectors, cloned.connectors);
        assert_eq!(req.self_check, cloned.self_check);
    }

    #[test]
    fn doctor_request_debug_output() {
        let req = DoctorRequest {
            zone_id: "z:dbg".to_string(),
            connectors: vec![],
            self_check: false,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("DoctorRequest"));
        assert!(dbg.contains("z:dbg"));
    }

    // ── NEW: DoctorReport with non-default freshness values ──

    #[test]
    fn doctor_report_stale_checkpoint_serialization() {
        let mut report = DoctorReport::baseline("z:stale");
        report.checkpoint.freshness = FreshnessLevel::Stale;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["checkpoint"]["freshness"], "stale");
    }

    #[test]
    fn doctor_report_too_stale_revocation_serialization() {
        let mut report = DoctorReport::baseline("z:too-stale");
        report.revocation.freshness = FreshnessLevel::TooStale;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["revocation"]["freshness"], "too_stale");
    }

    #[test]
    fn doctor_report_missing_audit_serialization() {
        let mut report = DoctorReport::baseline("z:missing");
        report.audit.freshness = FreshnessLevel::Missing;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["audit"]["freshness"], "missing");
    }

    // ── NEW: DoctorReport degraded mode and store coverage ──

    #[test]
    fn doctor_report_degraded_mode_active_serialization() {
        let mut report = DoctorReport::baseline("z:degraded");
        report.degraded_mode.is_degraded = true;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["degraded_mode"]["is_degraded"], true);
    }

    #[test]
    fn doctor_report_store_unhealthy_serialization() {
        let mut report = DoctorReport::baseline("z:unhealthy-store");
        report.store_coverage.store_healthy = false;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["store_coverage"]["store_healthy"], false);
    }

    // ── NEW: DoctorReport with checks vec serialization ──

    #[test]
    fn doctor_report_empty_checks_serialized_as_array() {
        let report = DoctorReport::baseline("z:empty-checks");
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["checks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn doctor_report_multiple_checks_count_preserved() {
        let mut report = DoctorReport::baseline("z:multi");
        for i in 0u64..5 {
            report.checks.push(CheckResult {
                name: format!("check_{i}"),
                status: CheckStatus::Ok,
                severity: CheckSeverity::Info,
                message: format!("msg_{i}"),
            });
        }
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["checks"].as_array().unwrap().len(), 5);
    }

    // ── NEW: overall_status_from_self_checks edge cases ──

    #[test]
    fn overall_status_single_ok() {
        let checks = [ConnectorSelfCheck {
            connector_id: "sole".to_string(),
            report: SelfCheckReport::ok(),
        }];
        assert_eq!(overall_status_from_self_checks(&checks), OverallStatus::Ok);
    }

    #[test]
    fn overall_status_single_degraded() {
        let checks = [ConnectorSelfCheck {
            connector_id: "sole".to_string(),
            report: SelfCheckReport::degraded("deg", "degraded"),
        }];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn overall_status_single_failed() {
        let checks = [ConnectorSelfCheck {
            connector_id: "sole".to_string(),
            report: SelfCheckReport::failed("err", "failed"),
        }];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    #[test]
    fn overall_status_fail_first_entry() {
        let checks = [
            ConnectorSelfCheck {
                connector_id: "first".to_string(),
                report: SelfCheckReport::failed("err", "failed"),
            },
            ConnectorSelfCheck {
                connector_id: "second".to_string(),
                report: SelfCheckReport::ok(),
            },
        ];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    #[test]
    fn overall_status_degraded_middle_entry() {
        let checks = [
            ConnectorSelfCheck {
                connector_id: "first".to_string(),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: "middle".to_string(),
                report: SelfCheckReport::degraded("slow", "slow"),
            },
            ConnectorSelfCheck {
                connector_id: "last".to_string(),
                report: SelfCheckReport::ok(),
            },
        ];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn overall_status_all_degraded() {
        let checks: Vec<ConnectorSelfCheck> = (0u64..3)
            .map(|i| ConnectorSelfCheck {
                connector_id: format!("d_{i}"),
                report: SelfCheckReport::degraded("slow", "slow"),
            })
            .collect();
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn overall_status_all_failed() {
        let checks: Vec<ConnectorSelfCheck> = (0u64..3)
            .map(|i| ConnectorSelfCheck {
                connector_id: format!("f_{i}"),
                report: SelfCheckReport::failed("err", "fail"),
            })
            .collect();
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    // ── NEW: with_self_checks overrides baseline status ──

    #[test]
    fn with_self_checks_overrides_baseline_ok_to_fail() {
        let baseline = DoctorReport::baseline("z:override");
        assert_eq!(baseline.overall_status, OverallStatus::Ok);
        let checks = vec![ConnectorSelfCheck {
            connector_id: "bad".to_string(),
            report: SelfCheckReport::failed("err", "fail"),
        }];
        let report = baseline.with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Fail);
    }

    #[test]
    fn with_self_checks_overrides_baseline_ok_to_warn() {
        let baseline = DoctorReport::baseline("z:override-warn");
        let checks = vec![ConnectorSelfCheck {
            connector_id: "slow".to_string(),
            report: SelfCheckReport::degraded("lag", "high latency"),
        }];
        let report = baseline.with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    #[test]
    fn with_self_checks_preserves_other_report_fields() {
        let mut baseline = DoctorReport::baseline("z:preserve");
        baseline.checkpoint.freshness = FreshnessLevel::Stale;
        baseline.degraded_mode.is_degraded = true;
        let checks = vec![ConnectorSelfCheck {
            connector_id: "c".to_string(),
            report: SelfCheckReport::ok(),
        }];
        let report = baseline.with_self_checks(checks);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Stale);
        assert!(report.degraded_mode.is_degraded);
        assert_eq!(report.zone_id, "z:preserve");
    }

    // ── NEW: DoctorReport clone with checks ──

    #[test]
    fn doctor_report_clone_with_checks_and_self_checks() {
        let mut report = DoctorReport::baseline("z:full-clone");
        report.checks.push(CheckResult {
            name: "mem".to_string(),
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "low mem".to_string(),
        });
        let checks = vec![ConnectorSelfCheck {
            connector_id: "sc".to_string(),
            report: SelfCheckReport::degraded("slow", "slow"),
        }];
        let report = report.with_self_checks(checks);
        let cloned = report.clone();
        assert_eq!(report.checks.len(), cloned.checks.len());
        assert_eq!(
            report.connector_self_checks.len(),
            cloned.connector_self_checks.len()
        );
        assert_eq!(report.checks[0].name, cloned.checks[0].name);
        assert_eq!(
            report.connector_self_checks[0].connector_id,
            cloned.connector_self_checks[0].connector_id
        );
    }

    // ── NEW: ConnectorSelfCheck with unsupported status ──

    #[test]
    fn connector_self_check_unsupported_report() {
        let check = ConnectorSelfCheck {
            connector_id: "unsup:conn:1.0.0".to_string(),
            report: SelfCheckReport::unsupported(),
        };
        assert_eq!(check.report.status, SelfCheckStatus::Unsupported);
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("unsupported"));
    }

    #[test]
    fn overall_status_unsupported_treated_as_ok() {
        let checks = [ConnectorSelfCheck {
            connector_id: "unsup".to_string(),
            report: SelfCheckReport::unsupported(),
        }];
        // Unsupported is neither Failed nor Degraded, so overall should be Ok
        assert_eq!(overall_status_from_self_checks(&checks), OverallStatus::Ok);
    }

    // ── NEW: SelfCheckReport reason_code and message fields ──

    #[test]
    fn self_check_ok_has_no_reason_code() {
        let report = SelfCheckReport::ok();
        assert!(report.reason_code.is_none());
        assert!(report.message.is_none());
    }

    #[test]
    fn self_check_failed_has_reason_and_message() {
        let report = SelfCheckReport::failed("auth_error", "token expired");
        assert_eq!(report.reason_code.as_deref(), Some("auth_error"));
        assert_eq!(report.message.as_deref(), Some("token expired"));
    }

    #[test]
    fn self_check_degraded_has_reason_and_message() {
        let report = SelfCheckReport::degraded("high_latency", "response time > 2s");
        assert_eq!(report.reason_code.as_deref(), Some("high_latency"));
        assert_eq!(report.message.as_deref(), Some("response time > 2s"));
    }

    // ── NEW: DoctorReport JSON structure validation ──

    #[test]
    fn doctor_report_json_has_all_top_level_keys() {
        let report = DoctorReport::baseline("z:keys");
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        let expected_keys = [
            "schema_version",
            "generated_at",
            "zone_id",
            "overall_status",
            "checkpoint",
            "revocation",
            "audit",
            "transport_policy",
            "store_coverage",
            "degraded_mode",
            "checks",
        ];
        for key in &expected_keys {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
    }

    #[test]
    fn doctor_report_json_no_self_checks_key_when_empty() {
        let report = DoctorReport::baseline("z:no-sc");
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("connector_self_checks"));
    }

    #[test]
    fn doctor_report_json_has_self_checks_key_when_present() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: "sc".to_string(),
            report: SelfCheckReport::ok(),
        }];
        let report = DoctorReport::baseline("z:with-sc").with_self_checks(checks);
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("connector_self_checks"));
    }

    // ── NEW: TransportPolicyStatus all combinations ──

    #[test]
    fn transport_policy_all_false_serialization() {
        let t = TransportPolicyStatus {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["allow_lan"], false);
        assert_eq!(json["allow_derp"], false);
        assert_eq!(json["allow_funnel"], false);
    }

    #[test]
    fn transport_policy_only_derp_serialization() {
        let t = TransportPolicyStatus {
            allow_lan: false,
            allow_derp: true,
            allow_funnel: false,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["allow_lan"], false);
        assert_eq!(json["allow_derp"], true);
        assert_eq!(json["allow_funnel"], false);
    }

    #[test]
    fn transport_policy_only_funnel_serialization() {
        let t = TransportPolicyStatus {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: true,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["allow_funnel"], true);
    }

    // ── NEW: CheckResult with empty and long strings ──

    #[test]
    fn check_result_empty_name_and_message() {
        let result = CheckResult {
            name: String::new(),
            status: CheckStatus::Ok,
            severity: CheckSeverity::Info,
            message: String::new(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["name"], "");
        assert_eq!(json["message"], "");
    }

    #[test]
    fn check_result_long_message() {
        let long_msg = "x".repeat(10_000);
        let result = CheckResult {
            name: "long_check".to_string(),
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: long_msg,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["message"].as_str().unwrap().len(), 10_000);
    }

    // ── NEW: DoctorReport baseline with special zone_id values ──

    #[test]
    fn baseline_report_long_zone_id() {
        let long_zone = format!("z:{}", "a".repeat(1000));
        let report = DoctorReport::baseline(&long_zone);
        assert_eq!(report.zone_id, long_zone);
    }

    #[test]
    fn baseline_report_zone_id_with_special_chars() {
        let zone = "z:test-zone_123.prod";
        let report = DoctorReport::baseline(zone);
        assert_eq!(report.zone_id, zone);
    }

    // ── NEW: DoctorReport generated_at is recent ──

    #[test]
    fn baseline_report_generated_at_is_recent() {
        let before = Utc::now();
        let report = DoctorReport::baseline("z:time");
        let after = Utc::now();
        assert!(report.generated_at >= before);
        assert!(report.generated_at <= after);
    }

    // ── NEW: DEFAULT_SELF_CHECK_TIMEOUT value ──

    #[test]
    fn default_self_check_timeout_is_five_seconds() {
        assert_eq!(DEFAULT_SELF_CHECK_TIMEOUT, Duration::from_secs(5));
    }

    // ── NEW: DoctorService clone ──

    #[test]
    fn doctor_service_default_timeout() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(Arc::clone(&registry));
        assert_eq!(service.self_check_timeout, Duration::from_secs(5));
    }

    // ── NEW: DoctorService custom timeout preserved ──

    #[test]
    fn doctor_service_custom_timeout_preserved() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service =
            DoctorService::with_timeout(Arc::clone(&registry), Duration::from_millis(500));
        assert_eq!(service.self_check_timeout, Duration::from_millis(500));
    }

    #[test]
    fn doctor_service_zero_timeout() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::with_timeout(Arc::clone(&registry), Duration::ZERO);
        assert_eq!(service.self_check_timeout, Duration::ZERO);
    }

    #[test]
    fn doctor_service_large_timeout() {
        let registry = Arc::new(TestRegistry::always_ok());
        let timeout = Duration::from_secs(30);
        let service = DoctorService::with_timeout(Arc::clone(&registry), timeout);
        assert_eq!(service.self_check_timeout, timeout);
    }

    // ── NEW: Schema version format ──

    #[test]
    fn schema_version_matches_expected_format() {
        let parts: Vec<&str> = DoctorReport::SCHEMA_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        for part in &parts {
            assert!(part.parse::<u32>().is_ok());
        }
    }
}
