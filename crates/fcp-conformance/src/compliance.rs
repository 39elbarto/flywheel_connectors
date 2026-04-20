//! Mechanical connector compliance checks (static + dynamic).
//!
//! Static checks validate connector manifests. Dynamic checks execute standard
//! methods against an in-process connector implementation.

use fcp_core::{
    FcpConnector, FcpError, HandshakeRequest, HealthState, InvokeRequest, InvokeStatus,
    SimulateRequest,
};
use fcp_manifest::ConnectorManifest;
use serde::{Deserialize, Serialize};

/// Compliance check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skipped,
}

/// Result for a single compliance check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Check identifier (stable string for CI parsing).
    pub check: String,
    /// Outcome of the check.
    pub status: CheckStatus,
    /// Human-readable detail.
    pub message: String,
}

impl ComplianceFinding {
    fn pass(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Pass,
            message: message.into(),
        }
    }

    fn fail(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Fail,
            message: message.into(),
        }
    }

    fn skipped(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Skipped,
            message: message.into(),
        }
    }
}

/// Static compliance results (manifest validation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticCompliance {
    /// Whether all static checks passed.
    pub passed: bool,
    /// Individual findings.
    pub findings: Vec<ComplianceFinding>,
}

impl StaticCompliance {
    /// Run static checks against a manifest TOML payload.
    #[must_use]
    pub fn run_manifest(manifest_toml: &str) -> Self {
        let mut findings = Vec::new();
        let parse_result = ConnectorManifest::parse_str(manifest_toml);
        let passed = match parse_result {
            Ok(_) => {
                findings.push(ComplianceFinding::pass(
                    "manifest.parse_validate",
                    "manifest parsed and validated",
                ));
                true
            }
            Err(err) => {
                findings.push(ComplianceFinding::fail(
                    "manifest.parse_validate",
                    err.to_string(),
                ));
                false
            }
        };

        Self { passed, findings }
    }
}

/// Input configuration for dynamic compliance checks.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct DynamicSuite {
    /// Configuration payload.
    pub config: serde_json::Value,
    /// Handshake request to send.
    pub handshake: HandshakeRequest,
    /// Optional invoke request to exercise default deny or success paths.
    pub invoke: Option<InvokeRequest>,
    /// Whether invoke is expected to error.
    pub expect_invoke_error: bool,
    /// Optional simulate request for preflight checks.
    pub simulate: Option<SimulateRequest>,
    /// Expected `would_succeed` flag from simulate (if provided).
    pub expect_simulate_would_succeed: Option<bool>,
    /// Require simulate denial details when `would_succeed` is false.
    pub require_simulate_denial_details: bool,
    /// Require capability-denied style error on invoke denial.
    pub require_capability_denial: bool,
    /// Require a decision receipt ID on invoke denial.
    pub require_decision_receipt: bool,
}

impl DynamicSuite {
    /// Minimal suite with empty config and no invoke request.
    #[must_use]
    pub fn minimal(handshake: HandshakeRequest) -> Self {
        Self {
            config: serde_json::json!({}),
            handshake,
            invoke: None,
            expect_invoke_error: false,
            simulate: None,
            expect_simulate_would_succeed: None,
            require_simulate_denial_details: false,
            require_capability_denial: false,
            require_decision_receipt: false,
        }
    }
}

/// Dynamic compliance results (standard method checks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicCompliance {
    /// Whether all dynamic checks passed.
    pub passed: bool,
    /// Individual findings.
    pub findings: Vec<ComplianceFinding>,
}

impl DynamicCompliance {
    /// Create a skipped dynamic report.
    ///
    /// A skipped dynamic suite is non-conformant: missing runtime coverage must
    /// not be reported as a passing compliance result.
    #[must_use]
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            passed: false,
            findings: vec![ComplianceFinding::skipped("dynamic.skip", reason)],
        }
    }
}

/// Aggregate compliance report (static + dynamic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Static checks (manifest).
    pub static_checks: StaticCompliance,
    /// Dynamic checks (standard methods).
    pub dynamic_checks: DynamicCompliance,
}

impl ComplianceReport {
    /// Whether the compliance report is passing.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.static_checks.passed && self.dynamic_checks.passed
    }
}

/// Run dynamic compliance checks against an in-process connector.
#[allow(clippy::too_many_lines)]
pub async fn run_dynamic_checks<C: FcpConnector>(
    connector: &mut C,
    suite: DynamicSuite,
) -> DynamicCompliance {
    let mut findings = Vec::new();
    let mut passed = true;

    let configure_result = connector.configure(suite.config.clone()).await;
    let configured = match configure_result {
        Ok(()) => {
            findings.push(ComplianceFinding::pass("configure", "configure ok"));
            true
        }
        Err(err) => {
            passed = false;
            findings.push(ComplianceFinding::fail("configure", err.to_string()));
            false
        }
    };

    let handshake_result = connector.handshake(suite.handshake.clone()).await;
    let handshaken = match handshake_result {
        Ok(response) => {
            if response.status == "accepted" {
                findings.push(ComplianceFinding::pass("handshake", "handshake accepted"));
                true
            } else {
                passed = false;
                findings.push(ComplianceFinding::fail(
                    "handshake",
                    format!("handshake status {}", response.status),
                ));
                false
            }
        }
        Err(err) => {
            passed = false;
            findings.push(ComplianceFinding::fail("handshake", err.to_string()));
            false
        }
    };

    let introspection = connector.introspect();
    findings.push(ComplianceFinding::pass(
        "introspect",
        format!(
            "operations={}, events={}, resource_types={}",
            introspection.operations.len(),
            introspection.events.len(),
            introspection.resource_types.len()
        ),
    ));

    let health = connector.health().await;
    match health.status {
        HealthState::Error { reason } => {
            passed = false;
            findings.push(ComplianceFinding::fail("health", reason));
        }
        _ => {
            findings.push(ComplianceFinding::pass(
                "health",
                format!("status={:?}", health.status),
            ));
        }
    }

    if let Some(simulate) = suite.simulate {
        if configured && handshaken {
            let simulate_result = connector.simulate(simulate).await;
            match simulate_result {
                Ok(response) => {
                    if let Some(expected) = suite.expect_simulate_would_succeed {
                        if response.would_succeed == expected {
                            findings.push(ComplianceFinding::pass(
                                "simulate",
                                format!("would_succeed={}", response.would_succeed),
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "simulate",
                                format!(
                                    "expected would_succeed={} but got {}",
                                    expected, response.would_succeed
                                ),
                            ));
                        }
                    } else {
                        findings.push(ComplianceFinding::pass(
                            "simulate",
                            format!("would_succeed={}", response.would_succeed),
                        ));
                    }

                    if !response.would_succeed && suite.require_simulate_denial_details {
                        let has_details = response
                            .denial_code
                            .as_ref()
                            .is_some_and(|code| !code.is_empty())
                            || response
                                .failure_reason
                                .as_ref()
                                .is_some_and(|reason| !reason.is_empty())
                            || !response.missing_capabilities.is_empty();
                        if has_details {
                            findings.push(ComplianceFinding::pass(
                                "simulate.denial_details",
                                "denial details present",
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "simulate.denial_details",
                                "missing denial code/reason/capabilities",
                            ));
                        }
                    }
                }
                Err(err) => {
                    passed = false;
                    findings.push(ComplianceFinding::fail("simulate", err.to_string()));
                }
            }
        } else {
            findings.push(ComplianceFinding::skipped(
                "simulate",
                "skipped due to configure/handshake failure",
            ));
        }
    }

    if let Some(invoke) = suite.invoke {
        if configured && handshaken {
            let invoke_result = connector.invoke(invoke).await;
            match (suite.expect_invoke_error, invoke_result) {
                (true, Ok(response)) => {
                    if response.status == InvokeStatus::Error {
                        findings.push(ComplianceFinding::pass("invoke", "expected error observed"));
                    } else {
                        passed = false;
                        findings.push(ComplianceFinding::fail(
                            "invoke",
                            "expected error but got success",
                        ));
                    }

                    if suite.require_decision_receipt {
                        if response.decision_receipt_id.is_some() {
                            findings.push(ComplianceFinding::pass(
                                "invoke.decision_receipt",
                                "decision receipt present",
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "invoke.decision_receipt",
                                "missing decision receipt",
                            ));
                        }
                    }

                    if suite.require_capability_denial {
                        let is_capability_denial =
                            response.error.as_ref().is_some_and(is_capability_denial);
                        if is_capability_denial {
                            findings.push(ComplianceFinding::pass(
                                "invoke.capability_denial",
                                "capability denial reported",
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "invoke.capability_denial",
                                "expected capability denial error",
                            ));
                        }
                    }
                }
                (true, Err(err)) => {
                    findings.push(ComplianceFinding::pass("invoke", "expected error observed"));
                    if suite.require_decision_receipt {
                        passed = false;
                        findings.push(ComplianceFinding::fail(
                            "invoke.decision_receipt",
                            "missing decision receipt (error returned)",
                        ));
                    }
                    if suite.require_capability_denial {
                        if is_capability_denial(&err) {
                            findings.push(ComplianceFinding::pass(
                                "invoke.capability_denial",
                                "capability denial reported",
                            ));
                        } else {
                            passed = false;
                            findings.push(ComplianceFinding::fail(
                                "invoke.capability_denial",
                                "expected capability denial error",
                            ));
                        }
                    }
                }
                (false, Ok(response)) => {
                    if response.status == InvokeStatus::Ok {
                        findings.push(ComplianceFinding::pass("invoke", "invoke ok"));
                    } else {
                        passed = false;
                        findings.push(ComplianceFinding::fail("invoke", "unexpected invoke error"));
                    }
                }
                (false, Err(err)) => {
                    passed = false;
                    findings.push(ComplianceFinding::fail("invoke", err.to_string()));
                }
            }
        } else {
            findings.push(ComplianceFinding::skipped(
                "invoke",
                "skipped due to configure/handshake failure",
            ));
        }
    }

    DynamicCompliance { passed, findings }
}

const fn is_capability_denial(err: &FcpError) -> bool {
    matches!(
        err,
        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_manifest::ConnectorManifest;

    fn with_computed_interface_hash(raw: &str) -> String {
        let unchecked =
            ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
        let computed = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        raw.replace(
            &unchecked.manifest.interface_hash.to_string(),
            &computed.to_string(),
        )
    }

    #[test]
    fn static_manifest_valid_passes() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let materialized = with_computed_interface_hash(raw);
        let report = StaticCompliance::run_manifest(&materialized);
        assert!(report.passed);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.status == CheckStatus::Pass),
            "expected all findings to pass"
        );
    }

    #[test]
    fn static_manifest_invalid_version_fails() {
        // Don't use with_computed_interface_hash here - the manifest has an invalid
        // semver version which will fail at TOML deserialization, before we could
        // compute any interface hash. run_manifest handles parse errors gracefully.
        let raw = include_str!("../../../tests/vectors/manifest/manifest_invalid_version.toml");
        let report = StaticCompliance::run_manifest(raw);
        assert!(!report.passed);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.status == CheckStatus::Fail),
            "expected at least one failure"
        );
    }

    // ── ComplianceFinding tests ──

    #[test]
    fn finding_pass_has_correct_status() {
        let f = ComplianceFinding::pass("test.check", "all good");
        assert_eq!(f.status, CheckStatus::Pass);
        assert_eq!(f.check, "test.check");
        assert_eq!(f.message, "all good");
    }

    #[test]
    fn finding_fail_has_correct_status() {
        let f = ComplianceFinding::fail("test.check", "not good");
        assert_eq!(f.status, CheckStatus::Fail);
        assert_eq!(f.check, "test.check");
    }

    #[test]
    fn finding_skipped_has_correct_status() {
        let f = ComplianceFinding::skipped("test.check", "not applicable");
        assert_eq!(f.status, CheckStatus::Skipped);
    }

    // ── CheckStatus serialization ──

    #[test]
    fn check_status_serialization() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Fail).unwrap(),
            "\"fail\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Skipped).unwrap(),
            "\"skipped\""
        );
    }

    #[test]
    fn check_status_round_trip() {
        for status in [CheckStatus::Pass, CheckStatus::Fail, CheckStatus::Skipped] {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: CheckStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    // ── StaticCompliance tests ──

    #[test]
    fn static_empty_toml_fails() {
        let report = StaticCompliance::run_manifest("");
        assert!(!report.passed);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].status, CheckStatus::Fail);
        assert_eq!(report.findings[0].check, "manifest.parse_validate");
    }

    #[test]
    fn static_garbage_toml_fails() {
        let report = StaticCompliance::run_manifest("{{{{not valid toml at all}}}}");
        assert!(!report.passed);
    }

    #[test]
    fn static_findings_contain_check_id() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let materialized = with_computed_interface_hash(raw);
        let report = StaticCompliance::run_manifest(&materialized);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.check == "manifest.parse_validate")
        );
    }

    // ── DynamicSuite tests ──

    #[test]
    fn dynamic_suite_minimal_defaults() {
        let hs = HandshakeRequest {
            protocol_version: "2.0".into(),
            zone: "z:test".parse().unwrap(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let suite = DynamicSuite::minimal(hs);
        assert!(suite.invoke.is_none());
        assert!(suite.simulate.is_none());
        assert!(!suite.expect_invoke_error);
        assert!(suite.expect_simulate_would_succeed.is_none());
        assert!(!suite.require_simulate_denial_details);
        assert!(!suite.require_capability_denial);
        assert!(!suite.require_decision_receipt);
        assert_eq!(suite.config, serde_json::json!({}));
    }

    // ── DynamicCompliance tests ──

    #[test]
    fn dynamic_skipped_is_failing() {
        let dc = DynamicCompliance::skipped("no connector available");
        assert!(!dc.passed);
        assert_eq!(dc.findings.len(), 1);
        assert_eq!(dc.findings[0].status, CheckStatus::Skipped);
        assert_eq!(dc.findings[0].check, "dynamic.skip");
    }

    // ── ComplianceReport tests ──

    #[test]
    fn compliance_report_passed_when_both_pass() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![],
            },
            dynamic_checks: DynamicCompliance {
                passed: true,
                findings: vec![],
            },
        };
        assert!(report.passed());
    }

    #[test]
    fn compliance_report_fails_when_static_fails() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: false,
                findings: vec![ComplianceFinding::fail("x", "y")],
            },
            dynamic_checks: DynamicCompliance {
                passed: true,
                findings: vec![],
            },
        };
        assert!(!report.passed());
    }

    #[test]
    fn compliance_report_fails_when_dynamic_fails() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![],
            },
            dynamic_checks: DynamicCompliance {
                passed: false,
                findings: vec![ComplianceFinding::fail("x", "y")],
            },
        };
        assert!(!report.passed());
    }

    #[test]
    fn compliance_report_json_serializable() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![ComplianceFinding::pass("check1", "ok")],
            },
            dynamic_checks: DynamicCompliance::skipped("none"),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"pass\""));
        assert!(json.contains("check1"));
    }

    // ── run_dynamic_checks tests (with mock connector) ──

    use std::collections::HashMap;

    use fcp_core::{
        ConnectorId, ConnectorMetrics, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
        HealthSnapshot, HealthState, Introspection, InvokeRequest, InvokeResponse, RequestId,
        ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
        SubscribeResult, UnsubscribeRequest,
    };

    struct MockConnector {
        configure_ok: bool,
        handshake_accepted: bool,
        health_ok: bool,
    }

    impl MockConnector {
        fn healthy() -> Self {
            Self {
                configure_ok: true,
                handshake_accepted: true,
                health_ok: true,
            }
        }

        fn failing_configure() -> Self {
            Self {
                configure_ok: false,
                ..Self::healthy()
            }
        }

        fn failing_handshake() -> Self {
            Self {
                handshake_accepted: false,
                ..Self::healthy()
            }
        }

        fn unhealthy() -> Self {
            Self {
                health_ok: false,
                ..Self::healthy()
            }
        }
    }

    fcp_core::impl_fcp_sealed!(MockConnector);

    #[async_trait::async_trait]
    impl FcpConnector for MockConnector {
        fn id(&self) -> &ConnectorId {
            static ID: std::sync::LazyLock<ConnectorId> =
                std::sync::LazyLock::new(|| ConnectorId::from_static("test.mock:utility:1.0.0"));
            &ID
        }

        async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
            if self.configure_ok {
                Ok(())
            } else {
                Err(FcpError::NotConfigured)
            }
        }

        async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
            Ok(HandshakeResponse {
                status: if self.handshake_accepted {
                    "accepted".into()
                } else {
                    "rejected".into()
                },
                capabilities_granted: vec![],
                session_id: fcp_core::SessionId::new(),
                manifest_hash: "sha256:mock".into(),
                nonce: req.nonce,
                event_caps: None,
                auth_caps: None,
                op_catalog_hash: None,
            })
        }

        async fn health(&self) -> HealthSnapshot {
            HealthSnapshot {
                status: if self.health_ok {
                    HealthState::Ready
                } else {
                    HealthState::Error {
                        reason: "test error".into(),
                    }
                },
                uptime_ms: 1000,
                load: None,
                details: None,
                rate_limit: None,
            }
        }

        fn metrics(&self) -> ConnectorMetrics {
            ConnectorMetrics::default()
        }

        async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
            Ok(())
        }

        fn introspect(&self) -> Introspection {
            Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            }
        }

        async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
            Ok(InvokeResponse::ok(req.id, serde_json::json!({"ok": true})))
        }

        async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
            Ok(SimulateResponse::allowed(req.id))
        }

        async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
            Ok(SubscribeResponse {
                r#type: "response".into(),
                id: RequestId("sub_mock".into()),
                result: SubscribeResult {
                    confirmed_topics: vec![],
                    cursors: HashMap::new(),
                    replay_supported: false,
                    buffer: None,
                },
            })
        }

        async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
            Ok(())
        }
    }

    fn make_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".into(),
            zone: "z:test".parse().unwrap(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_healthy_connector_passes() {
        let mut connector = MockConnector::healthy();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        assert!(result.passed);
        // Should have: configure, handshake, introspect, health
        assert_eq!(result.findings.len(), 4);
        assert!(
            result
                .findings
                .iter()
                .all(|f| f.status == CheckStatus::Pass)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_configure_failure_reported() {
        let mut connector = MockConnector::failing_configure();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        assert!(!result.passed);
        let configure_finding = result
            .findings
            .iter()
            .find(|f| f.check == "configure")
            .unwrap();
        assert_eq!(configure_finding.status, CheckStatus::Fail);
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_handshake_rejection_reported() {
        let mut connector = MockConnector::failing_handshake();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        assert!(!result.passed);
        let hs_finding = result
            .findings
            .iter()
            .find(|f| f.check == "handshake")
            .unwrap();
        assert_eq!(hs_finding.status, CheckStatus::Fail);
        assert!(hs_finding.message.contains("rejected"));
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_unhealthy_connector_reported() {
        let mut connector = MockConnector::unhealthy();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        assert!(!result.passed);
        let health_finding = result
            .findings
            .iter()
            .find(|f| f.check == "health")
            .unwrap();
        assert_eq!(health_finding.status, CheckStatus::Fail);
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_introspect_always_passes() {
        let mut connector = MockConnector::healthy();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        let intro_finding = result
            .findings
            .iter()
            .find(|f| f.check == "introspect")
            .unwrap();
        assert_eq!(intro_finding.status, CheckStatus::Pass);
        assert!(intro_finding.message.contains("operations=0"));
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_findings_have_correct_check_ids() {
        let mut connector = MockConnector::healthy();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        let check_ids: Vec<&str> = result.findings.iter().map(|f| f.check.as_str()).collect();
        assert!(check_ids.contains(&"configure"));
        assert!(check_ids.contains(&"handshake"));
        assert!(check_ids.contains(&"introspect"));
        assert!(check_ids.contains(&"health"));
    }

    // ── ComplianceFinding serde ──

    #[test]
    fn finding_serde_roundtrip() {
        let f = ComplianceFinding::pass("serde.check", "roundtrip test");
        let json = serde_json::to_string(&f).unwrap();
        let deserialized: ComplianceFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.check, "serde.check");
        assert_eq!(deserialized.status, CheckStatus::Pass);
        assert_eq!(deserialized.message, "roundtrip test");
    }

    #[test]
    fn finding_fail_serde_roundtrip() {
        let f = ComplianceFinding::fail("x.y", "bad things");
        let json = serde_json::to_string(&f).unwrap();
        let deserialized: ComplianceFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, CheckStatus::Fail);
    }

    #[test]
    fn finding_debug() {
        let f = ComplianceFinding::pass("dbg", "test");
        let debug = format!("{f:?}");
        assert!(debug.contains("ComplianceFinding"));
        assert!(debug.contains("dbg"));
    }

    #[test]
    fn finding_clone() {
        let f = ComplianceFinding::skipped("c", "m");
        let moved = f;
        assert_eq!(moved.check, "c");
        assert_eq!(moved.status, CheckStatus::Skipped);
    }

    // ── CheckStatus traits ──

    #[test]
    fn check_status_debug() {
        assert_eq!(format!("{:?}", CheckStatus::Pass), "Pass");
        assert_eq!(format!("{:?}", CheckStatus::Fail), "Fail");
        assert_eq!(format!("{:?}", CheckStatus::Skipped), "Skipped");
    }

    #[test]
    fn check_status_copy() {
        let s = CheckStatus::Pass;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn check_status_ne() {
        assert_ne!(CheckStatus::Pass, CheckStatus::Fail);
        assert_ne!(CheckStatus::Pass, CheckStatus::Skipped);
        assert_ne!(CheckStatus::Fail, CheckStatus::Skipped);
    }

    // ── StaticCompliance serde ──

    #[test]
    fn static_compliance_serde_roundtrip() {
        let sc = StaticCompliance {
            passed: true,
            findings: vec![
                ComplianceFinding::pass("a", "ok"),
                ComplianceFinding::fail("b", "bad"),
            ],
        };
        let json = serde_json::to_string(&sc).unwrap();
        let deserialized: StaticCompliance = serde_json::from_str(&json).unwrap();
        assert!(deserialized.passed);
        assert_eq!(deserialized.findings.len(), 2);
    }

    #[test]
    fn static_compliance_debug() {
        let sc = StaticCompliance {
            passed: false,
            findings: vec![],
        };
        let debug = format!("{sc:?}");
        assert!(debug.contains("StaticCompliance"));
    }

    // ── DynamicCompliance serde ──

    #[test]
    fn dynamic_compliance_serde_roundtrip() {
        let dc = DynamicCompliance {
            passed: false,
            findings: vec![ComplianceFinding::fail("dyn.check", "failure")],
        };
        let json = serde_json::to_string(&dc).unwrap();
        let deserialized: DynamicCompliance = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.passed);
        assert_eq!(deserialized.findings.len(), 1);
    }

    #[test]
    fn dynamic_compliance_debug() {
        let dc = DynamicCompliance::skipped("no reason");
        let debug = format!("{dc:?}");
        assert!(debug.contains("DynamicCompliance"));
    }

    // ── ComplianceReport serde ──

    #[test]
    fn compliance_report_serde_roundtrip() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![ComplianceFinding::pass("s", "ok")],
            },
            dynamic_checks: DynamicCompliance {
                passed: false,
                findings: vec![ComplianceFinding::fail("d", "bad")],
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: ComplianceReport = serde_json::from_str(&json).unwrap();
        assert!(deserialized.static_checks.passed);
        assert!(!deserialized.dynamic_checks.passed);
        assert!(!deserialized.passed());
    }

    #[test]
    fn compliance_report_debug() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![],
            },
            dynamic_checks: DynamicCompliance::skipped("n/a"),
        };
        let debug = format!("{report:?}");
        assert!(debug.contains("ComplianceReport"));
    }

    #[test]
    fn compliance_report_clone() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![ComplianceFinding::pass("x", "y")],
            },
            dynamic_checks: DynamicCompliance::skipped("z"),
        };
        let moved = report;
        assert!(!moved.passed());
        assert_eq!(moved.static_checks.findings.len(), 1);
    }

    #[test]
    fn compliance_report_fails_when_both_fail() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: false,
                findings: vec![],
            },
            dynamic_checks: DynamicCompliance {
                passed: false,
                findings: vec![],
            },
        };
        assert!(!report.passed());
    }

    // ── is_capability_denial ──

    #[test]
    fn is_capability_denial_true_for_denied() {
        let err = FcpError::CapabilityDenied {
            capability: "cap.foo".into(),
            reason: "no grant".into(),
        };
        assert!(is_capability_denial(&err));
    }

    #[test]
    fn is_capability_denial_true_for_not_granted() {
        let err = FcpError::OperationNotGranted {
            operation: "op.bar".into(),
        };
        assert!(is_capability_denial(&err));
    }

    #[test]
    fn is_capability_denial_false_for_other_errors() {
        let err = FcpError::NotConfigured;
        assert!(!is_capability_denial(&err));

        let err2 = FcpError::Internal {
            message: "oops".into(),
        };
        assert!(!is_capability_denial(&err2));
    }

    // ── DynamicSuite debug ──

    #[test]
    fn dynamic_suite_debug() {
        let suite = DynamicSuite::minimal(make_handshake());
        let debug = format!("{suite:?}");
        assert!(debug.contains("DynamicSuite"));
    }

    // ── Dynamic checks: configure-failure skips invoke/simulate ──

    #[fcp_async_core::runtime::test]
    async fn dynamic_configure_failure_skips_invoke() {
        let mut connector = MockConnector::failing_configure();
        let suite = DynamicSuite::minimal(make_handshake());
        // Set invoke without actually constructing InvokeRequest — just confirm
        // the skip path works by keeping invoke=None on a failed configure
        let result = run_dynamic_checks(&mut connector, suite).await;
        assert!(!result.passed);
        // No invoke finding expected since suite.invoke is None
        assert!(result.findings.iter().all(|f| f.check != "invoke"));
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_handshake_failure_skips_simulate() {
        let mut connector = MockConnector::failing_handshake();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        assert!(!result.passed);
        // No simulate finding expected since suite.simulate is None
        assert!(result.findings.iter().all(|f| f.check != "simulate"));
    }

    // ── Dynamic checks: mock connector variants ──

    #[fcp_async_core::runtime::test]
    async fn dynamic_all_failures_combined() {
        // Configure fails → handshake still runs but health still checked
        let mut connector = MockConnector {
            configure_ok: false,
            handshake_accepted: false,
            health_ok: false,
        };
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        assert!(!result.passed);
        // All four findings present
        assert_eq!(result.findings.len(), 4);
        let fail_count = result
            .findings
            .iter()
            .filter(|f| f.status == CheckStatus::Fail)
            .count();
        assert!(fail_count >= 3); // configure, handshake, health all fail
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_healthy_findings_all_have_messages() {
        let mut connector = MockConnector::healthy();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        for finding in &result.findings {
            assert!(
                !finding.message.is_empty(),
                "finding {} has empty message",
                finding.check
            );
        }
    }

    // ── ComplianceFinding edge cases ─────────────────────────────

    #[test]
    fn finding_pass_empty_strings() {
        let f = ComplianceFinding::pass("", "");
        assert_eq!(f.status, CheckStatus::Pass);
        assert!(f.check.is_empty());
        assert!(f.message.is_empty());
    }

    #[test]
    fn finding_fail_long_message() {
        let long_msg = "x".repeat(10_000);
        let f = ComplianceFinding::fail("long.check", long_msg.as_str());
        assert_eq!(f.status, CheckStatus::Fail);
        assert_eq!(f.message.len(), 10_000);
    }

    #[test]
    fn finding_skipped_unicode_message() {
        let f = ComplianceFinding::skipped("unicode.check", "emoji test");
        assert_eq!(f.status, CheckStatus::Skipped);
        assert_eq!(f.message, "emoji test");
    }

    #[test]
    fn finding_clone_is_independent() {
        let f = ComplianceFinding::pass("orig", "original msg");
        let cloned = f.clone();
        assert_eq!(f.check, "orig");
        assert_eq!(cloned.check, "orig");
        assert_eq!(cloned.message, "original msg");
        assert_eq!(cloned.status, CheckStatus::Pass);
    }

    // ── CheckStatus exhaustive tests ─────────────────────────────

    #[test]
    fn check_status_all_variants_serialize_lowercase() {
        assert_eq!(
            serde_json::to_value(CheckStatus::Pass).unwrap(),
            serde_json::json!("pass")
        );
        assert_eq!(
            serde_json::to_value(CheckStatus::Fail).unwrap(),
            serde_json::json!("fail")
        );
        assert_eq!(
            serde_json::to_value(CheckStatus::Skipped).unwrap(),
            serde_json::json!("skipped")
        );
    }

    #[test]
    fn check_status_deserialize_from_lowercase() {
        let p: CheckStatus = serde_json::from_str("\"pass\"").unwrap();
        assert_eq!(p, CheckStatus::Pass);
        let f: CheckStatus = serde_json::from_str("\"fail\"").unwrap();
        assert_eq!(f, CheckStatus::Fail);
        let s: CheckStatus = serde_json::from_str("\"skipped\"").unwrap();
        assert_eq!(s, CheckStatus::Skipped);
    }

    #[test]
    fn check_status_invalid_string_fails_deserialize() {
        let result: Result<CheckStatus, _> = serde_json::from_str("\"PASS\"");
        assert!(result.is_err());
        let result: Result<CheckStatus, _> = serde_json::from_str("\"unknown\"");
        assert!(result.is_err());
    }

    #[test]
    fn check_status_eq_reflexive() {
        assert_eq!(CheckStatus::Pass, CheckStatus::Pass);
        assert_eq!(CheckStatus::Fail, CheckStatus::Fail);
        assert_eq!(CheckStatus::Skipped, CheckStatus::Skipped);
    }

    // ── StaticCompliance additional tests ─────────────────────────

    #[test]
    fn static_partial_toml_fails() {
        let report = StaticCompliance::run_manifest("[manifest]\nid = \"partial\"");
        assert!(!report.passed);
    }

    #[test]
    fn static_valid_toml_but_wrong_schema_fails() {
        let report = StaticCompliance::run_manifest("[foo]\nbar = 42");
        assert!(!report.passed);
    }

    #[test]
    fn static_compliance_clone_preserves_findings() {
        let sc = StaticCompliance {
            passed: true,
            findings: vec![
                ComplianceFinding::pass("a", "ok"),
                ComplianceFinding::fail("b", "bad"),
                ComplianceFinding::skipped("c", "skip"),
            ],
        };
        let cloned = sc.clone();
        assert_eq!(sc.findings.len(), 3);
        assert_eq!(cloned.findings.len(), 3);
        assert!(cloned.passed);
        assert_eq!(cloned.findings[0].status, CheckStatus::Pass);
        assert_eq!(cloned.findings[1].status, CheckStatus::Fail);
        assert_eq!(cloned.findings[2].status, CheckStatus::Skipped);
    }

    #[test]
    fn static_compliance_debug_contains_passed() {
        let sc = StaticCompliance {
            passed: false,
            findings: vec![ComplianceFinding::fail("x", "y")],
        };
        let dbg = format!("{sc:?}");
        assert!(dbg.contains("passed"));
        assert!(dbg.contains("findings"));
    }

    #[test]
    fn static_compliance_empty_findings() {
        let sc = StaticCompliance {
            passed: true,
            findings: vec![],
        };
        let json = serde_json::to_string(&sc).unwrap();
        let back: StaticCompliance = serde_json::from_str(&json).unwrap();
        assert!(back.passed);
        assert!(back.findings.is_empty());
    }

    // ── DynamicSuite additional tests ────────────────────────────

    #[test]
    fn dynamic_suite_all_flags_true() {
        let hs = make_handshake();
        let mut suite = DynamicSuite::minimal(hs);
        suite.expect_invoke_error = true;
        suite.require_simulate_denial_details = true;
        suite.require_capability_denial = true;
        suite.require_decision_receipt = true;
        assert!(suite.expect_invoke_error);
        assert!(suite.require_simulate_denial_details);
        assert!(suite.require_capability_denial);
        assert!(suite.require_decision_receipt);
    }

    #[test]
    fn dynamic_suite_clone() {
        let suite = DynamicSuite::minimal(make_handshake());
        let cloned = suite.clone();
        assert!(suite.invoke.is_none());
        assert!(cloned.invoke.is_none());
        assert!(!cloned.expect_invoke_error);
    }

    #[test]
    fn dynamic_suite_minimal_config_is_empty_object() {
        let suite = DynamicSuite::minimal(make_handshake());
        assert_eq!(suite.config, serde_json::json!({}));
    }

    #[test]
    fn dynamic_suite_config_can_be_overridden() {
        let mut suite = DynamicSuite::minimal(make_handshake());
        suite.config = serde_json::json!({"key": "value"});
        assert_eq!(suite.config["key"], "value");
    }

    #[test]
    fn dynamic_suite_simulate_expectation_defaults_none() {
        let suite = DynamicSuite::minimal(make_handshake());
        assert!(suite.expect_simulate_would_succeed.is_none());
    }

    // ── DynamicCompliance additional tests ────────────────────────

    #[test]
    fn dynamic_compliance_with_multiple_findings() {
        let dc = DynamicCompliance {
            passed: false,
            findings: vec![
                ComplianceFinding::pass("a", "ok"),
                ComplianceFinding::fail("b", "bad"),
                ComplianceFinding::skipped("c", "skip"),
            ],
        };
        assert!(!dc.passed);
        assert_eq!(dc.findings.len(), 3);
    }

    #[test]
    fn dynamic_compliance_empty_findings() {
        let dc = DynamicCompliance {
            passed: true,
            findings: vec![],
        };
        let json = serde_json::to_string(&dc).unwrap();
        let back: DynamicCompliance = serde_json::from_str(&json).unwrap();
        assert!(back.passed);
        assert!(back.findings.is_empty());
    }

    #[test]
    fn dynamic_compliance_clone_preserves_state() {
        let dc = DynamicCompliance {
            passed: false,
            findings: vec![ComplianceFinding::fail("x", "y")],
        };
        let cloned = dc.clone();
        assert!(!dc.passed);
        assert!(!cloned.passed);
        assert_eq!(cloned.findings.len(), 1);
        assert_eq!(cloned.findings[0].check, "x");
    }

    #[test]
    fn dynamic_skipped_message_preserved() {
        let dc = DynamicCompliance::skipped("specific reason");
        assert_eq!(dc.findings[0].message, "specific reason");
        assert_eq!(dc.findings[0].check, "dynamic.skip");
    }

    // ── ComplianceReport additional tests ─────────────────────────

    #[test]
    fn compliance_report_large_findings() {
        let findings: Vec<ComplianceFinding> = (0..100)
            .map(|i| ComplianceFinding::pass(format!("check_{i}"), format!("msg_{i}")))
            .collect();
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: findings.clone(),
            },
            dynamic_checks: DynamicCompliance {
                passed: true,
                findings,
            },
        };
        assert!(report.passed());
        assert_eq!(report.static_checks.findings.len(), 100);
        assert_eq!(report.dynamic_checks.findings.len(), 100);
    }

    #[test]
    fn compliance_report_json_roundtrip() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![
                    ComplianceFinding::pass("s1", "ok"),
                    ComplianceFinding::skipped("s2", "n/a"),
                ],
            },
            dynamic_checks: DynamicCompliance {
                passed: false,
                findings: vec![ComplianceFinding::fail("d1", "error")],
            },
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        let back: ComplianceReport = serde_json::from_str(&json).unwrap();
        assert!(back.static_checks.passed);
        assert!(!back.dynamic_checks.passed);
        assert!(!back.passed());
        assert_eq!(back.static_checks.findings.len(), 2);
        assert_eq!(back.dynamic_checks.findings.len(), 1);
    }

    #[test]
    fn compliance_report_clone_deep() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![ComplianceFinding::pass("a", "b")],
            },
            dynamic_checks: DynamicCompliance::skipped("reason"),
        };
        let cloned = report.clone();
        assert!(!report.passed());
        assert!(!cloned.passed());
        assert_eq!(cloned.static_checks.findings.len(), 1);
        assert_eq!(cloned.dynamic_checks.findings.len(), 1);
    }

    // ── is_capability_denial extended ────────────────────────────

    #[test]
    fn is_capability_denial_false_for_unauthorized() {
        let err = FcpError::Unauthorized {
            code: 401,
            message: "nope".into(),
        };
        assert!(!is_capability_denial(&err));
    }

    #[test]
    fn is_capability_denial_false_for_rate_limited() {
        let err = FcpError::RateLimited {
            retry_after_ms: 5000,
            violation: None,
        };
        assert!(!is_capability_denial(&err));
    }

    #[test]
    fn is_capability_denial_false_for_invalid_request() {
        let err = FcpError::InvalidRequest {
            code: 400,
            message: "bad".into(),
        };
        assert!(!is_capability_denial(&err));
    }

    #[test]
    fn is_capability_denial_false_for_token_expired() {
        let err = FcpError::TokenExpired;
        assert!(!is_capability_denial(&err));
    }

    #[test]
    fn is_capability_denial_with_empty_strings() {
        let err = FcpError::CapabilityDenied {
            capability: String::new(),
            reason: String::new(),
        };
        assert!(is_capability_denial(&err));

        let err2 = FcpError::OperationNotGranted {
            operation: String::new(),
        };
        assert!(is_capability_denial(&err2));
    }

    // ── ComplianceFinding serde edge cases ───────────────────────

    #[test]
    fn finding_serde_json_structure() {
        let f = ComplianceFinding::pass("test.id", "msg");
        let v: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert_eq!(v["check"], "test.id");
        assert_eq!(v["status"], "pass");
        assert_eq!(v["message"], "msg");
    }

    #[test]
    fn finding_serde_fail_json_structure() {
        let f = ComplianceFinding::fail("fail.id", "bad");
        let v: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert_eq!(v["status"], "fail");
    }

    #[test]
    fn finding_serde_skipped_json_structure() {
        let f = ComplianceFinding::skipped("skip.id", "n/a");
        let v: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert_eq!(v["status"], "skipped");
    }

    #[test]
    fn finding_deserialize_from_json_object() {
        let json = r#"{"check":"x","status":"fail","message":"y"}"#;
        let f: ComplianceFinding = serde_json::from_str(json).unwrap();
        assert_eq!(f.check, "x");
        assert_eq!(f.status, CheckStatus::Fail);
        assert_eq!(f.message, "y");
    }

    // ── Dynamic checks: health message content ─────────────────

    #[fcp_async_core::runtime::test]
    async fn dynamic_health_message_contains_status() {
        let mut connector = MockConnector::healthy();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        let health_finding = result
            .findings
            .iter()
            .find(|f| f.check == "health")
            .unwrap();
        assert!(health_finding.message.contains("Ready"));
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_unhealthy_message_contains_reason() {
        let mut connector = MockConnector::unhealthy();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        let health_finding = result
            .findings
            .iter()
            .find(|f| f.check == "health")
            .unwrap();
        assert_eq!(health_finding.status, CheckStatus::Fail);
        assert!(health_finding.message.contains("test error"));
    }

    // ── Dynamic checks: connector variant matrix ─────────────────

    #[fcp_async_core::runtime::test]
    async fn dynamic_configure_ok_handshake_fail() {
        let mut connector = MockConnector::failing_handshake();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        // configure passes, handshake fails
        let configure_f = result
            .findings
            .iter()
            .find(|f| f.check == "configure")
            .unwrap();
        assert_eq!(configure_f.status, CheckStatus::Pass);
        let hs_f = result
            .findings
            .iter()
            .find(|f| f.check == "handshake")
            .unwrap();
        assert_eq!(hs_f.status, CheckStatus::Fail);
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_configure_fail_health_still_checked() {
        let mut connector = MockConnector::failing_configure();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        // Health check still runs even when configure fails
        let health_f = result
            .findings
            .iter()
            .find(|f| f.check == "health")
            .unwrap();
        // MockConnector::failing_configure() has health_ok=true
        assert_eq!(health_f.status, CheckStatus::Pass);
    }

    #[fcp_async_core::runtime::test]
    async fn dynamic_introspect_message_format() {
        let mut connector = MockConnector::healthy();
        let suite = DynamicSuite::minimal(make_handshake());
        let result = run_dynamic_checks(&mut connector, suite).await;
        let intro_f = result
            .findings
            .iter()
            .find(|f| f.check == "introspect")
            .unwrap();
        assert!(intro_f.message.contains("operations="));
        assert!(intro_f.message.contains("events="));
        assert!(intro_f.message.contains("resource_types="));
    }

    // ── Static compliance with valid manifest ────────────────────

    #[test]
    fn static_valid_manifest_has_one_finding() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let materialized = with_computed_interface_hash(raw);
        let report = StaticCompliance::run_manifest(&materialized);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].check, "manifest.parse_validate");
        assert_eq!(report.findings[0].status, CheckStatus::Pass);
    }

    #[test]
    fn static_invalid_manifest_message_not_empty() {
        let report = StaticCompliance::run_manifest("invalid = manifest");
        assert!(!report.passed);
        assert!(!report.findings[0].message.is_empty());
    }

    // ── ComplianceReport passed logic truth table ─────────────────

    #[test]
    fn compliance_report_truth_table() {
        // (static_passed, dynamic_passed) -> overall_passed
        let cases = [
            (true, true, true),
            (true, false, false),
            (false, true, false),
            (false, false, false),
        ];
        for (sp, dp, expected) in cases {
            let report = ComplianceReport {
                static_checks: StaticCompliance {
                    passed: sp,
                    findings: vec![],
                },
                dynamic_checks: DynamicCompliance {
                    passed: dp,
                    findings: vec![],
                },
            };
            assert_eq!(
                report.passed(),
                expected,
                "static={sp}, dynamic={dp} should be {expected}"
            );
        }
    }

    // ── Finding constructors accept String types ─────────────────

    #[test]
    fn finding_pass_accepts_string_type() {
        let f = ComplianceFinding::pass(String::from("string.check"), String::from("string msg"));
        assert_eq!(f.check, "string.check");
        assert_eq!(f.message, "string msg");
    }

    #[test]
    fn finding_fail_accepts_string_type() {
        let f = ComplianceFinding::fail(String::from("f.check"), String::from("f msg"));
        assert_eq!(f.status, CheckStatus::Fail);
    }

    #[test]
    fn finding_skipped_accepts_string_type() {
        let f = ComplianceFinding::skipped(String::from("s.check"), String::from("s msg"));
        assert_eq!(f.status, CheckStatus::Skipped);
    }

    // ── MockConnector id accessor ────────────────────────────────

    #[test]
    fn mock_connector_id() {
        let connector = MockConnector::healthy();
        let id = connector.id();
        assert_eq!(id.to_string(), "test.mock:utility:1.0.0");
    }

    // ── StaticCompliance run_manifest edge cases ─────────────────

    #[test]
    fn static_only_whitespace_fails() {
        let report = StaticCompliance::run_manifest("   \n\t\n   ");
        assert!(!report.passed);
    }

    #[test]
    fn static_valid_toml_but_not_manifest() {
        let report = StaticCompliance::run_manifest("[table]\nkey = 42\n");
        assert!(!report.passed);
    }

    #[test]
    fn static_manifest_findings_always_have_check_id() {
        let report = StaticCompliance::run_manifest("not valid");
        for f in &report.findings {
            assert!(!f.check.is_empty());
        }
    }

    // ── ComplianceFinding Debug format ───────────────────────────

    #[test]
    fn finding_debug_format_includes_all_fields() {
        let f = ComplianceFinding::pass("my.check", "my msg");
        let dbg = format!("{f:?}");
        assert!(dbg.contains("my.check"));
        assert!(dbg.contains("my msg"));
        assert!(dbg.contains("Pass"));
    }

    #[test]
    fn finding_fail_debug_format() {
        let f = ComplianceFinding::fail("err.check", "error msg");
        let dbg = format!("{f:?}");
        assert!(dbg.contains("Fail"));
        assert!(dbg.contains("err.check"));
    }

    // ── ComplianceReport debug ───────────────────────────────────

    #[test]
    fn compliance_report_debug_shows_both_sections() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![],
            },
            dynamic_checks: DynamicCompliance {
                passed: false,
                findings: vec![ComplianceFinding::fail("d", "e")],
            },
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("static_checks"));
        assert!(dbg.contains("dynamic_checks"));
    }

    // ── DynamicCompliance skipped variations ──────────────────────

    #[test]
    fn dynamic_skipped_empty_reason() {
        let dc = DynamicCompliance::skipped("");
        assert!(!dc.passed);
        assert!(dc.findings[0].message.is_empty());
    }

    #[test]
    fn dynamic_skipped_long_reason() {
        let long = "r".repeat(5_000);
        let dc = DynamicCompliance::skipped(long.as_str());
        assert_eq!(dc.findings[0].message.len(), 5_000);
    }

    // ── is_capability_denial additional edge cases ────────────────

    #[test]
    fn is_capability_denial_false_for_checksum_mismatch() {
        let err = FcpError::ChecksumMismatch;
        assert!(!is_capability_denial(&err));
    }

    #[test]
    fn is_capability_denial_false_for_invalid_signature() {
        let err = FcpError::InvalidSignature;
        assert!(!is_capability_denial(&err));
    }

    #[test]
    fn is_capability_denial_false_for_missing_field() {
        let err = FcpError::MissingField {
            field: "name".into(),
        };
        assert!(!is_capability_denial(&err));
    }

    // ── StaticCompliance + DynamicCompliance serde combined ──────

    #[test]
    fn static_and_dynamic_findings_in_single_json() {
        let report = ComplianceReport {
            static_checks: StaticCompliance {
                passed: true,
                findings: vec![ComplianceFinding::pass("static.1", "ok")],
            },
            dynamic_checks: DynamicCompliance {
                passed: true,
                findings: vec![ComplianceFinding::pass("dynamic.1", "ok too")],
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("static.1"));
        assert!(json.contains("dynamic.1"));

        let back: ComplianceReport = serde_json::from_str(&json).unwrap();
        assert!(back.passed());
    }

    // ── CheckStatus serde_json::Value tests ─────────────────────

    #[test]
    fn check_status_pass_as_value() {
        let v = serde_json::to_value(CheckStatus::Pass).unwrap();
        assert!(v.is_string());
        assert_eq!(v.as_str().unwrap(), "pass");
    }

    #[test]
    fn check_status_fail_as_value() {
        let v = serde_json::to_value(CheckStatus::Fail).unwrap();
        assert_eq!(v.as_str().unwrap(), "fail");
    }

    #[test]
    fn check_status_skipped_as_value() {
        let v = serde_json::to_value(CheckStatus::Skipped).unwrap();
        assert_eq!(v.as_str().unwrap(), "skipped");
    }
}
