//! Readiness, doctor, and lifecycle assertion helpers.
//!
//! Provides utilities for testing connector readiness checks, doctor diagnostics,
//! lifecycle transitions, and configuration validation patterns.
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::readiness_helpers::*;
//!
//! let report = DoctorCheckBuilder::new("auth_valid")
//!     .status(CheckStatus::Pass)
//!     .message("API key validated successfully")
//!     .build();
//! assert_doctor_check_passes(&report);
//! ```

use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// Doctor Check Types
// ─────────────────────────────────────────────────────────────────────────────

/// Status of an individual doctor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    /// Check passed — component is healthy.
    Pass,
    /// Check produced a warning — component is functional but suboptimal.
    Warn,
    /// Check failed — component is broken or misconfigured.
    Fail,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Warn => write!(f, "WARN"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

/// A single doctor check result for testing.
#[derive(Debug, Clone)]
pub struct DoctorCheck {
    /// Name of the check (e.g., `auth_valid`, `network_reachable`).
    pub name: String,
    /// Status of the check.
    pub status: CheckStatus,
    /// Human-readable message describing the result.
    pub message: String,
    /// Whether this check is critical (failure = connector unusable).
    pub critical: bool,
}

/// Builder for constructing test doctor check results.
pub struct DoctorCheckBuilder {
    name: String,
    status: CheckStatus,
    message: String,
    critical: bool,
}

impl DoctorCheckBuilder {
    /// Create a new builder with the given check name.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: CheckStatus::Pass,
            message: String::new(),
            critical: false,
        }
    }

    /// Set the check status.
    #[must_use]
    pub const fn status(mut self, status: CheckStatus) -> Self {
        self.status = status;
        self
    }

    /// Set the check message.
    #[must_use]
    pub fn message(mut self, msg: &str) -> Self {
        self.message = msg.to_string();
        self
    }

    /// Mark the check as critical.
    #[must_use]
    pub const fn critical(mut self) -> Self {
        self.critical = true;
        self
    }

    /// Build the doctor check.
    #[must_use]
    pub fn build(self) -> DoctorCheck {
        DoctorCheck {
            name: self.name,
            status: self.status,
            message: self.message,
            critical: self.critical,
        }
    }
}

/// A collection of doctor check results.
#[derive(Debug, Clone)]
pub struct DoctorCheckReport {
    /// All checks performed.
    pub checks: Vec<DoctorCheck>,
    /// Overall readiness assessment.
    pub ready: bool,
}

impl DoctorCheckReport {
    /// Create a new report from a list of checks.
    /// Ready is true iff no critical checks failed.
    #[must_use]
    pub fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let ready = !checks
            .iter()
            .any(|c| c.critical && c.status == CheckStatus::Fail);
        Self { checks, ready }
    }

    /// Count checks by status.
    #[must_use]
    pub fn count_by_status(&self, status: &CheckStatus) -> usize {
        self.checks.iter().filter(|c| &c.status == status).count()
    }

    /// Get all failed checks.
    #[must_use]
    pub fn failures(&self) -> Vec<&DoctorCheck> {
        self.checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .collect()
    }

    /// Get all warning checks.
    #[must_use]
    pub fn warnings(&self) -> Vec<&DoctorCheck> {
        self.checks
            .iter()
            .filter(|c| c.status == CheckStatus::Warn)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Doctor Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that a doctor check passed.
///
/// # Panics
///
/// Panics if the check status is not Pass.
pub fn assert_doctor_check_passes(check: &DoctorCheck) {
    assert_eq!(
        check.status,
        CheckStatus::Pass,
        "Expected check '{}' to pass but got: {} - {}",
        check.name,
        check.status,
        check.message
    );
}

/// Assert that a doctor check failed.
///
/// # Panics
///
/// Panics if the check status is not Fail.
pub fn assert_doctor_check_fails(check: &DoctorCheck) {
    assert_eq!(
        check.status,
        CheckStatus::Fail,
        "Expected check '{}' to fail but got: {} - {}",
        check.name,
        check.status,
        check.message
    );
}

/// Assert that a doctor report is ready (no critical failures).
///
/// # Panics
///
/// Panics if the report indicates not-ready.
pub fn assert_doctor_ready(report: &DoctorCheckReport) {
    assert!(
        report.ready,
        "Expected doctor report to be ready but got failures: {:?}",
        report.failures()
    );
}

/// Assert that a doctor report is NOT ready (has critical failures).
///
/// # Panics
///
/// Panics if the report indicates ready.
pub fn assert_doctor_not_ready(report: &DoctorCheckReport) {
    assert!(
        !report.ready,
        "Expected doctor report to be not-ready but all checks passed"
    );
}

/// Assert that a doctor report contains a check with the given name.
///
/// # Panics
///
/// Panics if no check with the given name exists.
pub fn assert_doctor_has_check(report: &DoctorCheckReport, check_name: &str) {
    assert!(
        report.checks.iter().any(|c| c.name == check_name),
        "Expected doctor report to contain check '{check_name}' but found: {:?}",
        report.checks.iter().map(|c| &c.name).collect::<Vec<_>>()
    );
}

/// Assert that a doctor report has exactly N passing checks.
///
/// # Panics
///
/// Panics if the count doesn't match.
pub fn assert_doctor_pass_count(report: &DoctorCheckReport, expected: usize) {
    let actual = report.count_by_status(&CheckStatus::Pass);
    assert_eq!(
        actual, expected,
        "Expected {expected} passing checks but got {actual}"
    );
}

/// Assert that a doctor report has no failures.
///
/// # Panics
///
/// Panics if any check failed.
pub fn assert_doctor_no_failures(report: &DoctorCheckReport) {
    let failures = report.failures();
    assert!(
        failures.is_empty(),
        "Expected no failures but got: {failures:?}",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Readiness Assertions (JSON-based for connector responses)
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that a JSON doctor response contains the expected structure.
///
/// Checks for `ready`, `checks` array, and optional `schema_version`.
///
/// # Panics
///
/// Panics if the structure is invalid.
pub fn assert_doctor_response_valid(response: &Value) {
    assert!(
        response.get("ready").is_some() || response.get("status").is_some(),
        "Doctor response must contain 'ready' or 'status' field: {response}"
    );
    if let Some(checks) = response.get("checks") {
        assert!(
            checks.is_array(),
            "'checks' field must be an array: {checks}"
        );
    }
}

/// Assert that a JSON self-check response indicates readiness.
///
/// # Panics
///
/// Panics if the response doesn't indicate ready.
pub fn assert_self_check_ready(response: &Value) {
    let ready = response.get("ready").and_then(Value::as_bool).or_else(|| {
        response
            .get("status")
            .and_then(Value::as_str)
            .map(|s| s == "ready" || s == "healthy" || s == "ok")
    });
    assert_eq!(
        ready,
        Some(true),
        "Expected self-check to indicate ready: {response}"
    );
}

/// Assert that a JSON self-check response indicates NOT ready.
///
/// # Panics
///
/// Panics if the response indicates ready via either `ready: true`
/// or `status` being one of `"ready"`, `"healthy"`, `"ok"`.
pub fn assert_self_check_not_ready(response: &Value) {
    let ready = response
        .get("ready")
        .and_then(Value::as_bool)
        .or_else(|| {
            response
                .get("status")
                .and_then(Value::as_str)
                .map(|s| s == "ready" || s == "healthy" || s == "ok")
        })
        .unwrap_or(false);
    assert!(
        !ready,
        "Expected self-check to indicate not-ready: {response}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle Transition Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Track lifecycle state transitions for testing.
#[derive(Debug, Clone)]
pub struct LifecycleTracker {
    transitions: Vec<(String, String)>,
}

impl LifecycleTracker {
    /// Create a new lifecycle tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            transitions: Vec::new(),
        }
    }

    /// Record a state transition.
    pub fn record(&mut self, from: &str, to: &str) {
        self.transitions.push((from.to_string(), to.to_string()));
    }

    /// Get the number of transitions recorded.
    #[must_use]
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Get all transitions as (from, to) pairs.
    #[must_use]
    pub fn transitions(&self) -> &[(String, String)] {
        &self.transitions
    }

    /// Assert that the last transition was from `from` to `to`.
    ///
    /// # Panics
    ///
    /// Panics if there are no transitions or the last one doesn't match.
    pub fn assert_last_transition(&self, from: &str, to: &str) {
        let last = self.transitions.last().expect("No transitions recorded");
        assert_eq!(
            (last.0.as_str(), last.1.as_str()),
            (from, to),
            "Expected last transition {from} -> {to} but got {} -> {}",
            last.0,
            last.1
        );
    }

    /// Assert that the transition sequence matches expected.
    ///
    /// # Panics
    ///
    /// Panics if the sequence doesn't match.
    pub fn assert_sequence(&self, expected: &[(&str, &str)]) {
        assert_eq!(
            self.transitions.len(),
            expected.len(),
            "Expected {} transitions but got {}",
            expected.len(),
            self.transitions.len()
        );
        for (i, ((from, to), (ef, et))) in self.transitions.iter().zip(expected.iter()).enumerate()
        {
            assert_eq!(
                (from.as_str(), to.as_str()),
                (*ef, *et),
                "Transition {i}: expected {ef} -> {et} but got {from} -> {to}"
            );
        }
    }
}

impl Default for LifecycleTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doctor_check_builder() {
        let check = DoctorCheckBuilder::new("auth")
            .status(CheckStatus::Pass)
            .message("API key valid")
            .critical()
            .build();
        assert_eq!(check.name, "auth");
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check.critical);
    }

    #[test]
    fn test_doctor_report_ready_when_no_critical_failures() {
        let checks = vec![
            DoctorCheckBuilder::new("auth")
                .status(CheckStatus::Pass)
                .critical()
                .build(),
            DoctorCheckBuilder::new("optional_feature")
                .status(CheckStatus::Fail)
                .build(),
        ];
        let report = DoctorCheckReport::from_checks(checks);
        assert!(report.ready);
    }

    #[test]
    fn test_doctor_report_not_ready_when_critical_failure() {
        let checks = vec![
            DoctorCheckBuilder::new("auth")
                .status(CheckStatus::Fail)
                .critical()
                .build(),
            DoctorCheckBuilder::new("network")
                .status(CheckStatus::Pass)
                .build(),
        ];
        let report = DoctorCheckReport::from_checks(checks);
        assert!(!report.ready);
    }

    #[test]
    fn test_doctor_assertions() {
        let pass_check = DoctorCheckBuilder::new("test")
            .status(CheckStatus::Pass)
            .build();
        assert_doctor_check_passes(&pass_check);

        let fail_check = DoctorCheckBuilder::new("test")
            .status(CheckStatus::Fail)
            .build();
        assert_doctor_check_fails(&fail_check);
    }

    #[test]
    fn test_doctor_report_assertions() {
        let checks = vec![
            DoctorCheckBuilder::new("a")
                .status(CheckStatus::Pass)
                .build(),
            DoctorCheckBuilder::new("b")
                .status(CheckStatus::Pass)
                .build(),
            DoctorCheckBuilder::new("c")
                .status(CheckStatus::Warn)
                .build(),
        ];
        let report = DoctorCheckReport::from_checks(checks);

        assert_doctor_ready(&report);
        assert_doctor_no_failures(&report);
        assert_doctor_has_check(&report, "a");
        assert_doctor_has_check(&report, "c");
        assert_doctor_pass_count(&report, 2);
    }

    #[test]
    fn test_doctor_response_json_valid() {
        let response = serde_json::json!({
            "ready": true,
            "checks": [
                {"name": "auth", "status": "pass"}
            ]
        });
        assert_doctor_response_valid(&response);
    }

    #[test]
    fn test_self_check_ready() {
        assert_self_check_ready(&serde_json::json!({"ready": true}));
        assert_self_check_ready(&serde_json::json!({"status": "ready"}));
        assert_self_check_ready(&serde_json::json!({"status": "healthy"}));
    }

    #[test]
    fn test_self_check_not_ready() {
        assert_self_check_not_ready(&serde_json::json!({"ready": false}));
        assert_self_check_not_ready(&serde_json::json!({"status": "error"}));
    }

    #[test]
    #[should_panic(expected = "Expected self-check to indicate not-ready")]
    fn test_self_check_not_ready_rejects_ready_status_aliases() {
        assert_self_check_not_ready(&serde_json::json!({"status": "ok"}));
    }

    #[test]
    fn test_lifecycle_tracker() {
        let mut tracker = LifecycleTracker::new();
        tracker.record("init", "configured");
        tracker.record("configured", "handshaken");
        tracker.record("handshaken", "running");

        assert_eq!(tracker.transition_count(), 3);
        tracker.assert_last_transition("handshaken", "running");
        tracker.assert_sequence(&[
            ("init", "configured"),
            ("configured", "handshaken"),
            ("handshaken", "running"),
        ]);
    }

    #[test]
    fn test_count_by_status() {
        let checks = vec![
            DoctorCheckBuilder::new("a")
                .status(CheckStatus::Pass)
                .build(),
            DoctorCheckBuilder::new("b")
                .status(CheckStatus::Pass)
                .build(),
            DoctorCheckBuilder::new("c")
                .status(CheckStatus::Warn)
                .build(),
            DoctorCheckBuilder::new("d")
                .status(CheckStatus::Fail)
                .build(),
        ];
        let report = DoctorCheckReport::from_checks(checks);
        assert_eq!(report.count_by_status(&CheckStatus::Pass), 2);
        assert_eq!(report.count_by_status(&CheckStatus::Warn), 1);
        assert_eq!(report.count_by_status(&CheckStatus::Fail), 1);
    }

    #[test]
    fn test_failures_and_warnings() {
        let checks = vec![
            DoctorCheckBuilder::new("ok")
                .status(CheckStatus::Pass)
                .build(),
            DoctorCheckBuilder::new("warn1")
                .status(CheckStatus::Warn)
                .build(),
            DoctorCheckBuilder::new("fail1")
                .status(CheckStatus::Fail)
                .build(),
        ];
        let report = DoctorCheckReport::from_checks(checks);
        assert_eq!(report.failures().len(), 1);
        assert_eq!(report.warnings().len(), 1);
        assert_eq!(report.failures()[0].name, "fail1");
        assert_eq!(report.warnings()[0].name, "warn1");
    }
}
