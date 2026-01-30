//! E2E connector verification framework (FCP2).
//!
//! This crate provides a lightweight harness for running connector-level
//! end-to-end checks against the FCP2 contract. It is intentionally minimal
//! and deterministic, with structured JSON logging.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)] // duration_ms fits in u64
#![allow(clippy::too_many_arguments)] // test harness functions need many parameters
#![allow(clippy::needless_pass_by_value)] // API ergonomics for TimedResult/TimedValue

mod logging;
mod subprocess;

use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use fcp_conformance::{
    CheckStatus, ComplianceFinding, DynamicSuite, StaticCompliance, run_all_interop_tests,
    run_dynamic_checks,
};
use fcp_core::{
    CorrelationId, FcpConnector, FcpError, HandshakeRequest, HealthSnapshot, Introspection,
    InvokeRequest, InvokeResponse, InvokeStatus, ObjectId,
};
use fcp_testkit::{LogRedactionScanner, ScanSeverity};
use serde::{Deserialize, Serialize};

pub use logging::{
    AssertionsSummary, E2eLogEntry, E2eLogger, LogSchemaError, validate_log_entry_value,
};
pub use subprocess::ConnectorProcessRunner;

/// Summary report for a log scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogScanReport {
    /// Total non-empty lines scanned.
    pub total_lines: u64,
    /// Findings with redacted context.
    pub findings: Vec<LogScanReportFinding>,
    /// Number of error-severity findings.
    pub error_count: u64,
    /// Number of warn-severity findings.
    pub warn_count: u64,
}

/// A single log scan finding with redacted context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogScanReportFinding {
    /// 1-based line number.
    pub line: usize,
    /// Rule identifier.
    pub rule_id: String,
    /// Severity label.
    pub severity: String,
    /// Optional JSON path.
    pub json_path: Option<String>,
    /// Redacted context snippet.
    pub context_redacted: String,
}

/// Scan a JSONL payload for secrets/PII and return a report.
#[must_use]
pub fn scan_log_jsonl(input: &str) -> LogScanReport {
    let scanner = LogRedactionScanner::new();
    let findings = scanner.scan_jsonl(input);
    let lines: Vec<&str> = input.lines().collect();
    let mut report_findings = Vec::new();
    let mut error_count = 0_u64;
    let mut warn_count = 0_u64;

    for finding in findings {
        let line_idx = finding.line.saturating_sub(1);
        let raw = lines.get(line_idx).copied().unwrap_or_default();
        let mut redacted = raw.replace(&finding.snippet, "<redacted>");
        if redacted.len() > 200 {
            redacted.truncate(200);
        }
        let severity = match finding.severity {
            ScanSeverity::Error => {
                error_count += 1;
                "error"
            }
            ScanSeverity::Warn => {
                warn_count += 1;
                "warn"
            }
        };
        report_findings.push(LogScanReportFinding {
            line: finding.line,
            rule_id: finding.rule_id,
            severity: severity.to_string(),
            json_path: finding.json_path,
            context_redacted: redacted,
        });
    }

    let total_lines = lines.iter().filter(|line| !line.trim().is_empty()).count() as u64;
    LogScanReport {
        total_lines,
        findings: report_findings,
        error_count,
        warn_count,
    }
}

/// Errors returned by the E2E harness.
#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    /// Connector returned an error.
    #[error("connector error: {0}")]
    Connector(String),
}

/// Result of a connector suite run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eReport {
    /// Test name.
    pub test_name: String,
    /// Whether the run passed.
    pub passed: bool,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Collected structured logs.
    pub logs: Vec<E2eLogEntry>,
}

impl E2eReport {
    /// Serialize logs to JSON lines.
    #[must_use]
    pub fn to_json_lines(&self) -> String {
        self.logs
            .iter()
            .filter_map(|entry| serde_json::to_string(entry).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Write logs to a JSONL file.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be written.
    pub fn write_json_lines<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = std::fs::File::create(path)?;
        for entry in &self.logs {
            let line = serde_json::to_string(entry)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }
}

/// Combined report for multiple connector suites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eBatchReport {
    /// Whether all suites passed.
    pub passed: bool,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Individual suite reports.
    pub reports: Vec<E2eReport>,
    /// Flattened structured logs.
    pub logs: Vec<E2eLogEntry>,
}

impl E2eBatchReport {
    /// Serialize all logs to JSON lines.
    #[must_use]
    pub fn to_json_lines(&self) -> String {
        self.logs
            .iter()
            .filter_map(|entry| serde_json::to_string(entry).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Write JSONL logs to a file.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be written.
    pub fn write_json_lines<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = std::fs::File::create(path)?;
        for entry in &self.logs {
            let line = serde_json::to_string(entry)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }
}

/// Scenario configuration for a connector suite run.
#[derive(Debug, Clone)]
pub struct ConnectorSuite {
    /// Name for the scenario (used in logs).
    pub test_name: String,
    /// Configuration payload.
    pub config: serde_json::Value,
    /// Handshake request to send.
    pub handshake: HandshakeRequest,
    /// Optional invoke request to test operation handling.
    pub invoke: Option<InvokeRequest>,
    /// Invoke expectations for error and receipts.
    pub invoke_expectations: InvokeExpectations,
}

impl ConnectorSuite {
    /// Create a minimal suite with an empty config.
    #[must_use]
    pub fn minimal(test_name: impl Into<String>, handshake: HandshakeRequest) -> Self {
        Self {
            test_name: test_name.into(),
            config: serde_json::json!({}),
            handshake,
            invoke: None,
            invoke_expectations: InvokeExpectations::default(),
        }
    }

    /// Create a suite expecting a default-deny response with a stable reason code.
    #[must_use]
    pub fn default_deny(
        test_name: impl Into<String>,
        handshake: HandshakeRequest,
        invoke: InvokeRequest,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            test_name: test_name.into(),
            config: serde_json::json!({}),
            handshake,
            invoke: Some(invoke),
            invoke_expectations: InvokeExpectations {
                expect_error: true,
                expect_decision_receipt: true,
                expect_audit_event: false,
                expect_receipt: false,
                expected_reason_code: Some(reason_code.into()),
                rate_limit_pool: None,
            },
        }
    }
}

/// Scenario configuration for a compliance suite run.
#[derive(Debug, Clone)]
pub struct ComplianceSuite {
    /// Name for the scenario (used in logs).
    pub test_name: String,
    /// Manifest TOML payload to validate.
    pub manifest_toml: String,
    /// Dynamic compliance suite (standard methods).
    pub dynamic: DynamicSuite,
}

impl ComplianceSuite {
    /// Create a new compliance suite.
    #[must_use]
    pub fn new(
        test_name: impl Into<String>,
        manifest_toml: impl Into<String>,
        dynamic: DynamicSuite,
    ) -> Self {
        Self {
            test_name: test_name.into(),
            manifest_toml: manifest_toml.into(),
            dynamic,
        }
    }
}

/// Expectations for invoke results.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct InvokeExpectations {
    /// Expect an invoke error (default deny or policy denial).
    pub expect_error: bool,
    /// Expect a decision receipt ID on denial.
    pub expect_decision_receipt: bool,
    /// Expect an audit event ID on success.
    pub expect_audit_event: bool,
    /// Expect an operation receipt ID on success.
    pub expect_receipt: bool,
    /// Expected reason code when denial occurs.
    pub expected_reason_code: Option<String>,
    /// Expected rate limit pool name for throttled invokes.
    pub rate_limit_pool: Option<String>,
}

/// Runner for connector E2E suites.
pub struct E2eRunner {
    module: String,
    logger: E2eLogger,
}

impl E2eRunner {
    /// Create a new runner.
    #[must_use]
    pub fn new(module: impl Into<String>) -> Self {
        Self {
            module: module.into(),
            logger: E2eLogger::new(),
        }
    }

    /// Run the protocol interop suite and emit a report.
    #[must_use]
    pub fn run_interop_suite(&mut self, test_name: impl Into<String>) -> E2eReport {
        let test_name = test_name.into();
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();

        let summary = run_all_interop_tests();
        let passed = summary.all_passed();
        let duration_ms = start.elapsed().as_millis() as u64;

        let failures: Vec<serde_json::Value> = summary
            .failures
            .iter()
            .map(|failure| {
                serde_json::json!({
                    "name": failure.name,
                    "category": failure.category,
                    "message": failure.message,
                })
            })
            .collect();

        let entry = E2eLogEntry::new(
            if passed { "info" } else { "error" },
            test_name.clone(),
            self.module.clone(),
            "verify",
            correlation_id,
            if passed { "pass" } else { "fail" },
            duration_ms,
            AssertionsSummary::new(summary.passed as u32, summary.failed as u32),
            serde_json::json!({
                "interop": {
                    "total": summary.total,
                    "passed": summary.passed,
                    "failed": summary.failed,
                    "failures": failures,
                }
            }),
        );
        self.logger.push(entry);

        E2eReport {
            test_name,
            passed,
            duration_ms,
            logs: self.logger.drain(),
        }
    }

    /// Run compliance checks (static + dynamic) and emit a report.
    ///
    /// # Errors
    /// Returns [`E2eError`] if the connector returns an error in a required phase.
    pub async fn run_compliance_suite<C: FcpConnector>(
        &mut self,
        connector: &mut C,
        suite: ComplianceSuite,
    ) -> Result<E2eReport, E2eError> {
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();

        let static_checks = StaticCompliance::run_manifest(&suite.manifest_toml);
        let dynamic_checks = run_dynamic_checks(connector, suite.dynamic).await;

        let passed = static_checks.passed && dynamic_checks.passed;
        let duration_ms = start.elapsed().as_millis() as u64;

        let (static_passed, static_failed, static_skipped) =
            summarize_findings(&static_checks.findings);
        let (dynamic_passed, dynamic_failed, dynamic_skipped) =
            summarize_findings(&dynamic_checks.findings);

        let entry = E2eLogEntry::new(
            if passed { "info" } else { "error" },
            suite.test_name.clone(),
            self.module.clone(),
            "verify",
            correlation_id,
            if passed { "pass" } else { "fail" },
            duration_ms,
            AssertionsSummary::new(
                static_passed + dynamic_passed,
                static_failed + dynamic_failed,
            ),
            serde_json::json!({
                "static": {
                    "passed": static_checks.passed,
                    "counts": {
                        "passed": static_passed,
                        "failed": static_failed,
                        "skipped": static_skipped,
                    },
                    "findings": findings_to_json(&static_checks.findings),
                },
                "dynamic": {
                    "passed": dynamic_checks.passed,
                    "counts": {
                        "passed": dynamic_passed,
                        "failed": dynamic_failed,
                        "skipped": dynamic_skipped,
                    },
                    "findings": findings_to_json(&dynamic_checks.findings),
                },
            }),
        );
        self.logger.push(entry);

        Ok(E2eReport {
            test_name: suite.test_name,
            passed,
            duration_ms,
            logs: self.logger.drain(),
        })
    }

    /// Execute a connector suite and return a report.
    ///
    /// # Errors
    /// Returns [`E2eError`] if the connector returns an error in a required phase.
    pub async fn run_connector_suite<C: FcpConnector>(
        &mut self,
        connector: &mut C,
        suite: ConnectorSuite,
    ) -> Result<E2eReport, E2eError> {
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();
        let mut passed = true;
        let mut assertions_passed: u32 = 0;
        let mut assertions_failed: u32 = 0;

        let config_result = timed_async(|| connector.configure(suite.config.clone()))
            .await
            .map_value(|()| serde_json::json!({}));
        passed &= log_result(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            "setup",
            &correlation_id,
            "configure",
            config_result,
            false,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let handshake_result = timed_async(|| connector.handshake(suite.handshake.clone()))
            .await
            .map_value(|resp| serde_json::json!({ "status": resp.status }));
        passed &= log_result(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            "setup",
            &correlation_id,
            "handshake",
            handshake_result,
            false,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let health = timed_async_value(|| connector.health()).await;
        passed &= log_health(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            &correlation_id,
            health,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let introspect = timed_sync(|| connector.introspect());
        passed &= log_introspection(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            &correlation_id,
            introspect,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        if let Some(invoke) = suite.invoke.clone() {
            let invoke_result = timed_async(|| connector.invoke(invoke.clone())).await;
            let ok = log_invoke_result(
                &mut self.logger,
                &suite.test_name,
                &self.module,
                &correlation_id,
                invoke_result,
                suite.invoke_expectations,
                &mut assertions_passed,
                &mut assertions_failed,
            );

            passed &= ok;
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        let summary = AssertionsSummary::new(assertions_passed, assertions_failed);
        let summary_entry = E2eLogEntry::new(
            "info",
            suite.test_name.clone(),
            self.module.clone(),
            "teardown",
            correlation_id,
            if passed { "pass" } else { "fail" },
            duration_ms,
            summary,
            serde_json::json!({}),
        );
        self.logger.push(summary_entry);

        Ok(E2eReport {
            test_name: suite.test_name,
            passed,
            duration_ms,
            logs: self.logger.drain(),
        })
    }

    /// Run multiple connector suites and return a combined report.
    ///
    /// # Errors
    /// Returns [`E2eError`] if any suite returns an unexpected connector error.
    pub async fn run_connector_suites<C: FcpConnector>(
        &mut self,
        connector: &mut C,
        suites: Vec<ConnectorSuite>,
    ) -> Result<E2eBatchReport, E2eError> {
        let start = Instant::now();
        let mut passed = true;
        let mut reports = Vec::new();
        let mut logs = Vec::new();

        for suite in suites {
            let report = self.run_connector_suite(connector, suite).await?;
            passed &= report.passed;
            logs.extend(report.logs.iter().cloned());
            reports.push(report);
        }

        Ok(E2eBatchReport {
            passed,
            duration_ms: start.elapsed().as_millis() as u64,
            reports,
            logs,
        })
    }
}

async fn timed_async<T, F, Fut>(f: F) -> TimedResult<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, FcpError>>,
{
    let start = Instant::now();
    let result = f().await;
    TimedResult {
        result,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn timed_sync<T, F>(f: F) -> TimedValue<T>
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = f();
    TimedValue {
        value,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

async fn timed_async_value<T, F, Fut>(f: F) -> TimedValue<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let value = f().await;
    TimedValue {
        value,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

struct TimedResult<T> {
    result: Result<T, FcpError>,
    duration_ms: u64,
}

impl<T> TimedResult<T> {
    fn map_value<U>(self, f: impl FnOnce(T) -> U) -> TimedResult<U> {
        TimedResult {
            result: self.result.map(f),
            duration_ms: self.duration_ms,
        }
    }
}

struct TimedValue<T> {
    value: T,
    duration_ms: u64,
}

fn log_result(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    phase: &str,
    correlation_id: &str,
    operation: &str,
    result: TimedResult<serde_json::Value>,
    expect_error: bool,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = result.result.is_ok();
    let passed = if expect_error { !success } else { success };
    if passed {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let (decision, reason_code, reason_message, error_details, retryable, retry_after_ms) =
        if let Err(err) = &result.result {
            let response = err.to_response();
            (
                Some("deny".to_string()),
                Some(response.code),
                Some(response.message),
                response.details,
                Some(response.retryable),
                response.retry_after_ms,
            )
        } else {
            (None, None, None, None, None, None)
        };

    let entry = E2eLogEntry::new(
        if passed { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        phase.to_string(),
        correlation_id.to_string(),
        if passed { "pass" } else { "fail" },
        result.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation": operation,
            "decision": decision,
            "reason_code": reason_code,
            "reason_message": reason_message,
            "error_details": error_details,
            "retryable": retryable,
            "retry_after_ms": retry_after_ms,
            "expected_error": expect_error,
        }),
    );
    logger.push(entry);

    passed
}

#[allow(clippy::too_many_lines)]
fn log_invoke_result(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    correlation_id: &str,
    result: TimedResult<InvokeResponse>,
    expectations: InvokeExpectations,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let mut passed = true;
    let mut decision: Option<String> = None;
    let mut reason_code: Option<String> = None;
    let mut reason_message: Option<String> = None;
    let mut error_details: Option<serde_json::Value> = None;
    let mut retryable: Option<bool> = None;
    let mut retry_after_ms: Option<u64> = None;
    let mut invoke_status: Option<InvokeStatus> = None;
    let mut receipt_id: Option<String> = None;
    let mut audit_event_id: Option<String> = None;
    let mut decision_receipt_id: Option<String> = None;
    let rate_limit_pool = expectations.rate_limit_pool.clone();
    let mut rate_limit_remaining: Option<u32> = None;
    let mut rate_limit_reset_at: Option<u64> = None;

    match &result.result {
        Ok(resp) => {
            invoke_status = Some(resp.status);
            receipt_id = resp.receipt_id.as_ref().map(ObjectId::to_string);
            audit_event_id = resp.audit_event_id.as_ref().map(ObjectId::to_string);
            decision_receipt_id = resp.decision_receipt_id.as_ref().map(ObjectId::to_string);

            let invoke_error = resp.status == InvokeStatus::Error;
            let error_check_ok = if expectations.expect_error {
                invoke_error
            } else {
                !invoke_error
            };
            if !error_check_ok {
                passed = false;
            }

            if expectations.expect_decision_receipt && resp.decision_receipt_id.is_none() {
                passed = false;
            }
            if expectations.expect_audit_event && resp.audit_event_id.is_none() {
                passed = false;
            }
            if expectations.expect_receipt && resp.receipt_id.is_none() {
                passed = false;
            }

            if invoke_error {
                decision = Some("deny".to_string());
                if let Some(err) = resp.error.as_ref() {
                    let response = err.to_response();
                    reason_code = Some(response.code);
                    reason_message = Some(response.message);
                    error_details = response.details;
                    retryable = Some(response.retryable);
                    retry_after_ms = response.retry_after_ms;
                }
            }
        }
        Err(err) => {
            let error_check_ok = expectations.expect_error;
            if !error_check_ok {
                passed = false;
            }

            if expectations.expect_decision_receipt {
                passed = false;
            }
            if expectations.expect_audit_event {
                passed = false;
            }
            if expectations.expect_receipt {
                passed = false;
            }

            decision = Some("deny".to_string());
            let response = err.to_response();
            reason_code = Some(response.code);
            reason_message = Some(response.message);
            error_details = response.details;
            retryable = Some(response.retryable);
            retry_after_ms = response.retry_after_ms;
        }
    }

    if let Some(details) = error_details.as_ref() {
        if let Some(violation) = details.get("throttle_violation") {
            let limit_value = violation
                .get("limit_value")
                .and_then(serde_json::Value::as_u64);
            let current_value = violation
                .get("current_value")
                .and_then(serde_json::Value::as_u64);
            if let (Some(limit_value), Some(current_value)) = (limit_value, current_value) {
                let remaining = limit_value.saturating_sub(current_value);
                rate_limit_remaining = Some(u32::try_from(remaining).unwrap_or(u32::MAX));
            }

            let timestamp_ms = violation
                .get("timestamp_ms")
                .and_then(serde_json::Value::as_u64);
            let retry_after_ms = violation
                .get("retry_after_ms")
                .and_then(serde_json::Value::as_u64);
            if let (Some(timestamp_ms), Some(retry_after_ms)) = (timestamp_ms, retry_after_ms) {
                rate_limit_reset_at = Some((timestamp_ms + retry_after_ms) / 1000);
            }
        }
    }

    if let Some(expected_reason_code) = expectations.expected_reason_code.as_ref() {
        if reason_code.as_deref() != Some(expected_reason_code.as_str()) {
            passed = false;
        }
    }

    if passed {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if passed { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        "execute".to_string(),
        correlation_id.to_string(),
        if passed { "pass" } else { "fail" },
        result.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation": "invoke",
            "expected_error": expectations.expect_error,
            "expected_decision_receipt": expectations.expect_decision_receipt,
            "expected_audit_event": expectations.expect_audit_event,
            "expected_receipt": expectations.expect_receipt,
            "expected_reason_code": expectations.expected_reason_code,
            "invoke_status": invoke_status.map(|status| format!("{status:?}")),
            "decision": decision,
            "reason_code": reason_code,
            "reason_message": reason_message,
            "error_details": error_details,
            "retryable": retryable,
            "retry_after_ms": retry_after_ms,
            "rate_limit_pool": rate_limit_pool,
            "rate_limit_remaining": rate_limit_remaining,
            "rate_limit_reset_at": rate_limit_reset_at,
            "receipt_id": receipt_id,
            "audit_event_id": audit_event_id,
            "decision_receipt_id": decision_receipt_id,
        }),
    );
    logger.push(entry);

    passed
}

fn summarize_findings(findings: &[ComplianceFinding]) -> (u32, u32, u32) {
    let mut passed = 0_u32;
    let mut failed = 0_u32;
    let mut skipped = 0_u32;
    for finding in findings {
        match finding.status {
            CheckStatus::Pass => passed += 1,
            CheckStatus::Fail => failed += 1,
            CheckStatus::Skipped => skipped += 1,
        }
    }
    (passed, failed, skipped)
}

fn findings_to_json(findings: &[ComplianceFinding]) -> Vec<serde_json::Value> {
    findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "check": finding.check,
                "status": match finding.status {
                    CheckStatus::Pass => "pass",
                    CheckStatus::Fail => "fail",
                    CheckStatus::Skipped => "skipped",
                },
                "message": finding.message,
            })
        })
        .collect()
}

fn log_health(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    correlation_id: &str,
    health: TimedValue<HealthSnapshot>,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = health.value.is_healthy();
    if success {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if success { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        "verify".to_string(),
        correlation_id.to_string(),
        if success { "pass" } else { "fail" },
        health.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "health": serde_json::to_value(&health.value).unwrap_or_default(),
        }),
    );
    logger.push(entry);

    success
}

fn log_introspection(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    correlation_id: &str,
    introspection: TimedValue<Introspection>,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = !introspection.value.operations.is_empty();
    if success {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if success { "info" } else { "warn" },
        test_name.to_string(),
        module.to_string(),
        "verify".to_string(),
        correlation_id.to_string(),
        if success { "pass" } else { "fail" },
        introspection.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation_count": introspection.value.operations.len(),
        }),
    );
    logger.push(entry);

    success
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{
        AgentHint, BaseConnector, CapabilityId, CapabilityToken, ConnectorId, EventCaps, FcpError,
        HandshakeResponse, HealthSnapshot, InstanceId, InvokeResponse, LimitType, ObjectId,
        OperationId, OperationInfo, RateLimit, RiskLevel, SafetyTier, SessionId, ThrottleViolation,
        ThrottleViolationInput, ZoneId,
    };
    use fcp_manifest::ConnectorManifest;
    use fcp_testkit::MockApiServer;

    #[test]
    fn scan_log_report_flags_secret() {
        let input = r#"{"token":"sk-abc123def456ghi789jkl012mno345pqr"}"#;
        let report = scan_log_jsonl(input);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "OPENAI_API_KEY");
        assert!(finding.context_redacted.contains("<redacted>"));
    }

    #[derive(Debug)]
    struct DummyConnector {
        base: BaseConnector,
    }

    impl DummyConnector {
        fn new() -> Self {
            Self {
                base: BaseConnector::new(ConnectorId::from_static(
                    "fcp.dummy:request_response:0.1.0",
                )),
            }
        }
    }

    #[fcp_core::async_trait]
    impl FcpConnector for DummyConnector {
        fn id(&self) -> &fcp_core::ConnectorId {
            &self.base.id
        }

        async fn configure(&mut self, _config: serde_json::Value) -> fcp_core::FcpResult<()> {
            self.base.set_configured(true);
            Ok(())
        }

        async fn handshake(
            &mut self,
            _req: HandshakeRequest,
        ) -> fcp_core::FcpResult<HandshakeResponse> {
            self.base.set_handshaken(true);
            Ok(HandshakeResponse {
                status: "accepted".to_string(),
                capabilities_granted: vec![],
                session_id: SessionId::new(),
                manifest_hash: "sha256:dummy".to_string(),
                nonce: [1u8; 32],
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
            HealthSnapshot::ready()
        }

        fn metrics(&self) -> fcp_core::ConnectorMetrics {
            self.base.metrics()
        }

        async fn shutdown(&mut self, _req: fcp_core::ShutdownRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }

        fn introspect(&self) -> Introspection {
            Introspection {
                operations: vec![
                    OperationInfo {
                        id: OperationId::from_static("dummy.echo"),
                        summary: "Echo".to_string(),
                        description: None,
                        input_schema: serde_json::json!({"type": "object"}),
                        output_schema: serde_json::json!({"type": "object"}),
                        capability: CapabilityId::from_static("dummy.echo"),
                        risk_level: RiskLevel::Low,
                        safety_tier: SafetyTier::Safe,
                        idempotency: fcp_core::IdempotencyClass::None,
                        ai_hints: AgentHint {
                            when_to_use: "echo".to_string(),
                            common_mistakes: vec![],
                            examples: vec![],
                            related: vec![],
                        },
                        rate_limit: None,
                        requires_approval: None,
                    },
                    OperationInfo {
                        id: OperationId::from_static("dummy.rate_limited"),
                        summary: "Rate limited".to_string(),
                        description: None,
                        input_schema: serde_json::json!({"type": "object"}),
                        output_schema: serde_json::json!({"type": "object"}),
                        capability: CapabilityId::from_static("dummy.rate_limited"),
                        risk_level: RiskLevel::Low,
                        safety_tier: SafetyTier::Safe,
                        idempotency: fcp_core::IdempotencyClass::None,
                        ai_hints: AgentHint {
                            when_to_use: "rate limited".to_string(),
                            common_mistakes: vec![],
                            examples: vec![],
                            related: vec![],
                        },
                        rate_limit: Some(RateLimit {
                            max: 100,
                            per_ms: 60_000,
                            burst: None,
                            scope: None,
                            pool_name: Some("test_pool".to_string()),
                        }),
                        requires_approval: None,
                    },
                ],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            }
        }

        async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
            match req.operation.as_str() {
                "dummy.echo" => Ok(InvokeResponse::ok(
                    req.id,
                    serde_json::json!({ "ok": true }),
                )),
                "dummy.denied" => Ok(InvokeResponse::error(
                    req.id,
                    FcpError::CapabilityDenied {
                        capability: "dummy.denied".to_string(),
                        reason: "missing capability".to_string(),
                    },
                )
                .with_decision_receipt_id(ObjectId::from_unscoped_bytes(b"decision"))),
                "dummy.rate_limited" => Err(FcpError::RateLimited {
                    retry_after_ms: 30_000,
                    violation: Some(Box::new(ThrottleViolation::new(ThrottleViolationInput {
                        timestamp_ms: 1_700_000_000_000,
                        zone_id: ZoneId::work(),
                        connector_id: Some(self.id().clone()),
                        operation_id: Some(req.operation.clone()),
                        limit_type: LimitType::Rpm,
                        limit_value: 100,
                        current_value: 120,
                        retry_after_ms: 30_000,
                    }))),
                }),
                _ => Err(FcpError::Unauthorized {
                    code: 2101,
                    message: "Missing capability".to_string(),
                }),
            }
        }

        async fn simulate(
            &self,
            req: fcp_core::SimulateRequest,
        ) -> fcp_core::FcpResult<fcp_core::SimulateResponse> {
            if req.operation.as_str() == "dummy.denied" {
                Ok(
                    fcp_core::SimulateResponse::denied(req.id, "missing capability", "FCP-3001")
                        .with_missing_capabilities(vec!["dummy.denied".to_string()]),
                )
            } else {
                Ok(fcp_core::SimulateResponse::allowed(req.id))
            }
        }

        async fn subscribe(
            &self,
            _req: fcp_core::SubscribeRequest,
        ) -> fcp_core::FcpResult<fcp_core::SubscribeResponse> {
            Err(FcpError::StreamingNotSupported)
        }

        async fn unsubscribe(&self, _req: fcp_core::UnsubscribeRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }
    }

    fn test_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [1u8; 32],
            capabilities_requested: vec![],
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

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

    #[tokio::test]
    async fn runs_minimal_suite() {
        let mut connector = DummyConnector::new();
        let suite = ConnectorSuite::minimal("dummy_suite", test_handshake());
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(report.passed, "suite should pass");
        assert!(!report.logs.is_empty(), "logs should be emitted");
    }

    #[tokio::test]
    async fn logs_denied_invoke() {
        let mut connector = DummyConnector::new();
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-1"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.denied"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite =
            ConnectorSuite::default_deny("deny_invoke", test_handshake(), invoke, "FCP-3001");

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(report.passed, "deny suite should pass when error expected");
        let invoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("operation") == Some(&serde_json::json!("invoke")))
            .expect("invoke log entry");
        assert_eq!(
            invoke_entry.context.get("reason_code"),
            Some(&serde_json::json!("FCP-3001"))
        );
        let expected_receipt = ObjectId::from_unscoped_bytes(b"decision").to_string();
        assert_eq!(
            invoke_entry.context.get("decision_receipt_id"),
            Some(&serde_json::json!(expected_receipt))
        );
    }

    #[tokio::test]
    async fn logs_rate_limit_metadata_from_throttle_violation() {
        let mut connector = DummyConnector::new();
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-rate"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.rate_limited"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite = ConnectorSuite {
            test_name: "rate_limited_invoke".to_string(),
            config: serde_json::json!({}),
            handshake: test_handshake(),
            invoke: Some(invoke),
            invoke_expectations: InvokeExpectations {
                expect_error: true,
                expect_decision_receipt: false,
                expect_audit_event: false,
                expect_receipt: false,
                expected_reason_code: Some("FCP-3002".to_string()),
                rate_limit_pool: Some("test_pool".to_string()),
            },
        };

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(
            report.passed,
            "rate limit suite should pass when error expected"
        );
        let invoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("operation") == Some(&serde_json::json!("invoke")))
            .expect("invoke log entry");

        assert_eq!(
            invoke_entry.context.get("rate_limit_pool"),
            Some(&serde_json::json!("test_pool"))
        );
        assert_eq!(
            invoke_entry.context.get("rate_limit_remaining"),
            Some(&serde_json::json!(0))
        );
        assert_eq!(
            invoke_entry.context.get("rate_limit_reset_at"),
            Some(&serde_json::json!(1_700_000_030_u64))
        );
        assert_eq!(
            invoke_entry.context.get("retry_after_ms"),
            Some(&serde_json::json!(30_000_u64))
        );
    }

    #[tokio::test]
    async fn runs_compliance_suite() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let manifest = with_computed_interface_hash(raw);
        let dynamic = DynamicSuite::minimal(test_handshake());
        let suite = ComplianceSuite::new("dummy_compliance", manifest, dynamic);

        let mut connector = DummyConnector::new();
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_compliance_suite(&mut connector, suite)
            .await
            .expect("compliance runs");

        assert!(report.passed, "compliance suite should pass");
        assert!(!report.logs.is_empty(), "logs should be emitted");
    }

    #[tokio::test]
    async fn compliance_checks_simulate_and_decision_receipt() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let manifest = with_computed_interface_hash(raw);

        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-2"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.denied"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let simulate = fcp_core::SimulateRequest::new(
            invoke.connector_id.clone(),
            invoke.operation.clone(),
            invoke.zone_id.clone(),
            invoke.input.clone(),
            invoke.capability_token.clone(),
        );

        let dynamic = DynamicSuite {
            config: serde_json::json!({}),
            handshake: test_handshake(),
            invoke: Some(invoke),
            expect_invoke_error: true,
            simulate: Some(simulate),
            expect_simulate_would_succeed: Some(false),
            require_simulate_denial_details: true,
            require_capability_denial: true,
            require_decision_receipt: true,
        };
        let suite = ComplianceSuite::new("dummy_compliance_denied", manifest, dynamic);

        let mut connector = DummyConnector::new();
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_compliance_suite(&mut connector, suite)
            .await
            .expect("compliance runs");

        assert!(report.passed, "compliance should pass with expected denial");
    }

    #[tokio::test]
    async fn mock_server_smoke() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/health", serde_json::json!({ "ok": true }))
            .await;

        let url = format!("{}/health", mock.base_url());
        let body: serde_json::Value = reqwest::get(url)
            .await
            .expect("request ok")
            .json()
            .await
            .expect("json body");

        assert_eq!(body, serde_json::json!({ "ok": true }));
        mock.assert_request_count(1).await;
    }

    #[tokio::test]
    async fn runs_batch_suites() {
        let mut connector = DummyConnector::new();
        let suites = vec![
            ConnectorSuite::minimal("batch_one", test_handshake()),
            ConnectorSuite::minimal("batch_two", test_handshake()),
        ];

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suites(&mut connector, suites)
            .await
            .expect("batch runs");

        assert!(report.passed, "batch should pass");
        assert_eq!(report.reports.len(), 2);
        assert!(!report.logs.is_empty());
    }

    #[test]
    fn scan_log_empty_input() {
        let report = scan_log_jsonl("");
        assert_eq!(report.total_lines, 0);
        assert!(report.findings.is_empty());
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warn_count, 0);
    }

    #[test]
    fn scan_log_clean_jsonl() {
        let input = "{\"msg\":\"hello\"}\n{\"msg\":\"world\"}";
        let report = scan_log_jsonl(input);
        assert_eq!(report.total_lines, 2);
        assert!(report.findings.is_empty());
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warn_count, 0);
    }

    #[test]
    fn e2e_error_display() {
        let e = E2eError::Connector("test failure".to_string());
        assert_eq!(e.to_string(), "connector error: test failure");
    }

    #[test]
    fn e2e_report_to_json_lines_empty_logs() {
        let report = E2eReport {
            test_name: "empty".to_string(),
            passed: true,
            duration_ms: 0,
            logs: vec![],
        };
        assert_eq!(report.to_json_lines(), "");
    }

    #[test]
    fn e2e_report_to_json_lines_with_entries() {
        let entry = E2eLogEntry::new(
            "info",
            "test1",
            "mod1",
            "setup",
            "corr-1",
            "pass",
            10,
            AssertionsSummary::new(1, 0),
            serde_json::json!({}),
        );
        let report = E2eReport {
            test_name: "with_entries".to_string(),
            passed: true,
            duration_ms: 10,
            logs: vec![entry],
        };
        let lines = report.to_json_lines();
        assert!(!lines.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&lines).expect("valid JSON");
        assert_eq!(
            parsed.get("test_name").and_then(|v| v.as_str()),
            Some("test1")
        );
    }

    #[test]
    fn e2e_report_serde_roundtrip() {
        let report = E2eReport {
            test_name: "roundtrip".to_string(),
            passed: true,
            duration_ms: 42,
            logs: vec![],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: E2eReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.test_name, "roundtrip");
        assert!(back.passed);
        assert_eq!(back.duration_ms, 42);
        assert!(back.logs.is_empty());
    }

    #[test]
    fn e2e_batch_report_serde_roundtrip() {
        let batch = E2eBatchReport {
            passed: false,
            duration_ms: 100,
            reports: vec![],
            logs: vec![],
        };
        let json = serde_json::to_string(&batch).expect("serialize");
        let back: E2eBatchReport = serde_json::from_str(&json).expect("deserialize");
        assert!(!back.passed);
        assert_eq!(back.duration_ms, 100);
    }

    #[test]
    fn e2e_batch_report_to_json_lines() {
        let entry = E2eLogEntry::new(
            "info",
            "batch_test",
            "mod",
            "teardown",
            "corr-2",
            "pass",
            5,
            AssertionsSummary::new(2, 0),
            serde_json::json!({}),
        );
        let batch = E2eBatchReport {
            passed: true,
            duration_ms: 5,
            reports: vec![],
            logs: vec![entry],
        };
        let lines = batch.to_json_lines();
        assert!(!lines.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&lines).expect("valid JSON");
        assert_eq!(
            parsed.get("test_name").and_then(|v| v.as_str()),
            Some("batch_test")
        );
    }

    #[test]
    fn connector_suite_minimal_defaults() {
        let suite = ConnectorSuite::minimal("test_minimal", test_handshake());
        assert_eq!(suite.test_name, "test_minimal");
        assert_eq!(suite.config, serde_json::json!({}));
        assert!(suite.invoke.is_none());
        assert!(!suite.invoke_expectations.expect_error);
        assert!(!suite.invoke_expectations.expect_decision_receipt);
        assert!(!suite.invoke_expectations.expect_audit_event);
        assert!(!suite.invoke_expectations.expect_receipt);
        assert!(suite.invoke_expectations.expected_reason_code.is_none());
        assert!(suite.invoke_expectations.rate_limit_pool.is_none());
    }

    #[test]
    fn connector_suite_default_deny_expectations() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-deny"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.denied"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite = ConnectorSuite::default_deny("deny_test", test_handshake(), invoke, "DENY-001");
        assert_eq!(suite.test_name, "deny_test");
        assert!(suite.invoke.is_some());
        assert!(suite.invoke_expectations.expect_error);
        assert!(suite.invoke_expectations.expect_decision_receipt);
        assert!(!suite.invoke_expectations.expect_audit_event);
        assert!(!suite.invoke_expectations.expect_receipt);
        assert_eq!(
            suite.invoke_expectations.expected_reason_code.as_deref(),
            Some("DENY-001")
        );
    }

    #[test]
    fn invoke_expectations_default_all_false() {
        let defaults = InvokeExpectations::default();
        assert!(!defaults.expect_error);
        assert!(!defaults.expect_decision_receipt);
        assert!(!defaults.expect_audit_event);
        assert!(!defaults.expect_receipt);
        assert!(defaults.expected_reason_code.is_none());
        assert!(defaults.rate_limit_pool.is_none());
    }

    #[test]
    fn summarize_findings_empty() {
        let findings: Vec<ComplianceFinding> = vec![];
        let (passed, failed, skipped) = summarize_findings(&findings);
        assert_eq!(passed, 0);
        assert_eq!(failed, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn summarize_findings_mixed() {
        let findings = vec![
            ComplianceFinding {
                check: "check1".to_string(),
                status: CheckStatus::Pass,
                message: "ok".to_string(),
            },
            ComplianceFinding {
                check: "check2".to_string(),
                status: CheckStatus::Fail,
                message: "bad".to_string(),
            },
            ComplianceFinding {
                check: "check3".to_string(),
                status: CheckStatus::Skipped,
                message: "skipped".to_string(),
            },
            ComplianceFinding {
                check: "check4".to_string(),
                status: CheckStatus::Pass,
                message: "ok2".to_string(),
            },
        ];
        let (passed, failed, skipped) = summarize_findings(&findings);
        assert_eq!(passed, 2);
        assert_eq!(failed, 1);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn findings_to_json_empty() {
        let findings: Vec<ComplianceFinding> = vec![];
        let json = findings_to_json(&findings);
        assert!(json.is_empty());
    }

    #[test]
    fn findings_to_json_mixed_statuses() {
        let findings = vec![
            ComplianceFinding {
                check: "check_pass".to_string(),
                status: CheckStatus::Pass,
                message: "passed".to_string(),
            },
            ComplianceFinding {
                check: "check_fail".to_string(),
                status: CheckStatus::Fail,
                message: "failed".to_string(),
            },
            ComplianceFinding {
                check: "check_skip".to_string(),
                status: CheckStatus::Skipped,
                message: "skipped".to_string(),
            },
        ];
        let json = findings_to_json(&findings);
        assert_eq!(json.len(), 3);
        assert_eq!(json[0].get("status").and_then(|v| v.as_str()), Some("pass"));
        assert_eq!(
            json[0].get("check").and_then(|v| v.as_str()),
            Some("check_pass")
        );
        assert_eq!(json[1].get("status").and_then(|v| v.as_str()), Some("fail"));
        assert_eq!(
            json[2].get("status").and_then(|v| v.as_str()),
            Some("skipped")
        );
    }

    #[test]
    fn log_scan_report_serde_roundtrip() {
        let report = LogScanReport {
            total_lines: 10,
            findings: vec![LogScanReportFinding {
                line: 3,
                rule_id: "test_rule".to_string(),
                severity: "error".to_string(),
                json_path: Some("$.token".to_string()),
                context_redacted: "<redacted>".to_string(),
            }],
            error_count: 1,
            warn_count: 0,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: LogScanReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.total_lines, 10);
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.findings[0].rule_id, "test_rule");
        assert_eq!(back.error_count, 1);
    }

    #[test]
    fn log_scan_report_finding_serde_roundtrip() {
        let finding = LogScanReportFinding {
            line: 7,
            rule_id: "AWS_KEY".to_string(),
            severity: "warn".to_string(),
            json_path: None,
            context_redacted: "found <redacted> in config".to_string(),
        };
        let json = serde_json::to_string(&finding).expect("serialize");
        let back: LogScanReportFinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.line, 7);
        assert_eq!(back.rule_id, "AWS_KEY");
        assert!(back.json_path.is_none());
    }

    #[test]
    fn runner_interop_suite_produces_report() {
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner.run_interop_suite("interop_test");
        assert_eq!(report.test_name, "interop_test");
        assert!(!report.logs.is_empty());
    }

    #[test]
    fn compliance_suite_new_constructor() {
        let dynamic = DynamicSuite::minimal(test_handshake());
        let suite = ComplianceSuite::new("compliance_test", "manifest_content", dynamic);
        assert_eq!(suite.test_name, "compliance_test");
        assert_eq!(suite.manifest_toml, "manifest_content");
    }

    #[tokio::test]
    async fn runs_echo_invoke_suite() {
        let mut connector = DummyConnector::new();
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-echo"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.echo"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({"message": "hello"}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite = ConnectorSuite {
            test_name: "echo_invoke".to_string(),
            config: serde_json::json!({}),
            handshake: test_handshake(),
            invoke: Some(invoke),
            invoke_expectations: InvokeExpectations {
                expect_error: false,
                expect_decision_receipt: false,
                expect_audit_event: false,
                expect_receipt: false,
                expected_reason_code: None,
                rate_limit_pool: None,
            },
        };

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");
        assert!(report.passed, "echo invoke suite should pass");
        let invoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("operation") == Some(&serde_json::json!("invoke")))
            .expect("invoke log entry");
        assert_eq!(invoke_entry.result, "pass");
    }

    #[tokio::test]
    async fn batch_report_aggregates_pass_status() {
        let mut connector = DummyConnector::new();
        let suites = vec![
            ConnectorSuite::minimal("suite_a", test_handshake()),
            ConnectorSuite::minimal("suite_b", test_handshake()),
            ConnectorSuite::minimal("suite_c", test_handshake()),
        ];

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suites(&mut connector, suites)
            .await
            .expect("batch runs");

        assert!(report.passed);
        assert_eq!(report.reports.len(), 3);
        // duration_ms is u64, always non-negative; just verify it was set
        for r in &report.reports {
            assert!(r.passed);
        }
    }

    #[test]
    fn scan_log_jsonl_counts_nonempty_lines() {
        let input = "{\"a\":1}\n\n{\"b\":2}\n\n\n{\"c\":3}";
        let report = scan_log_jsonl(input);
        assert_eq!(report.total_lines, 3);
    }

    #[test]
    fn e2e_report_multiple_log_entries_json_lines() {
        let entries: Vec<E2eLogEntry> = (0_u64..3)
            .map(|i| {
                E2eLogEntry::new(
                    "info",
                    format!("test_{i}"),
                    "mod",
                    "verify",
                    format!("corr-{i}"),
                    "pass",
                    i,
                    AssertionsSummary::new(1, 0),
                    serde_json::json!({}),
                )
            })
            .collect();
        let report = E2eReport {
            test_name: "multi".to_string(),
            passed: true,
            duration_ms: 10,
            logs: entries,
        };
        let lines = report.to_json_lines();
        let count = lines.split('\n').count();
        assert_eq!(count, 3);
    }
}
