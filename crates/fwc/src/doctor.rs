//! Connector auto-diagnosis and fix-it recipe engine.
//!
//! Diagnoses common connector issues (auth failure, rate limiting, high latency,
//! config errors) and suggests specific fix-it commands or automatic repairs.

use serde::Serialize;
use serde_json::Value;

// ── Diagnosis types ────────────────────────────────────────────────

/// Severity of a diagnosed issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational — not blocking.
    Info,
    /// Potential issue — monitor.
    Warning,
    /// Issue detected — action recommended.
    Error,
    /// Critical failure — immediate action required.
    Critical,
}

impl Severity {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Category of the diagnosed issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisCategory {
    /// Authentication or authorization failure.
    Auth,
    /// Rate limit or quota exhaustion.
    RateLimit,
    /// Network connectivity issue.
    Network,
    /// High latency or timeout.
    Latency,
    /// Configuration error.
    Config,
    /// TLS/certificate issue.
    Certificate,
    /// Connector not installed or not found.
    NotFound,
    /// Service-side error (5xx).
    ServiceError,
    /// Unknown or unclassifiable issue.
    Unknown,
}

impl DiagnosisCategory {
    /// Human-readable display name.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Auth => "Authentication",
            Self::RateLimit => "Rate Limit",
            Self::Network => "Network",
            Self::Latency => "Latency",
            Self::Config => "Configuration",
            Self::Certificate => "Certificate",
            Self::NotFound => "Not Found",
            Self::ServiceError => "Service Error",
            Self::Unknown => "Unknown",
        }
    }
}

/// A single diagnosed issue with suggested fix.
#[derive(Clone, Debug, Serialize)]
pub struct Diagnosis {
    /// The connector this applies to.
    pub connector_id: String,
    /// Category of the issue.
    pub category: DiagnosisCategory,
    /// Severity level.
    pub severity: Severity,
    /// Human-readable description of the problem.
    pub message: String,
    /// Suggested fix-it commands or actions.
    pub fixes: Vec<FixAction>,
}

/// A suggested fix action.
#[derive(Clone, Debug, Serialize)]
pub struct FixAction {
    /// Human-readable description of what this fix does.
    pub description: String,
    /// The fwc command to run (if applicable).
    pub command: Option<String>,
    /// Whether this fix is safe to auto-apply without confirmation.
    pub auto_safe: bool,
    /// External URL for reference (e.g. status page).
    pub reference_url: Option<String>,
}

impl FixAction {
    /// Create a command-based fix.
    pub fn command(description: impl Into<String>, cmd: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            command: Some(cmd.into()),
            auto_safe: false,
            reference_url: None,
        }
    }

    /// Create a manual action fix.
    pub fn manual(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            command: None,
            auto_safe: false,
            reference_url: None,
        }
    }

    /// Mark this fix as safe for automatic application.
    #[must_use]
    pub const fn safe(mut self) -> Self {
        self.auto_safe = true;
        self
    }

    /// Add a reference URL.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.reference_url = Some(url.into());
        self
    }
}

/// Full diagnostic report for a connector.
#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticReport {
    /// Connector being diagnosed.
    pub connector_id: String,
    /// Overall health status.
    pub status: HealthStatus,
    /// Individual diagnoses.
    pub diagnoses: Vec<Diagnosis>,
}

/// Overall health status of a connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl HealthStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl DiagnosticReport {
    /// Create a healthy report with no diagnoses.
    pub fn healthy(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            status: HealthStatus::Healthy,
            diagnoses: Vec::new(),
        }
    }

    /// Compute status from diagnoses.
    pub fn from_diagnoses(connector_id: impl Into<String>, diagnoses: Vec<Diagnosis>) -> Self {
        let status = compute_status(&diagnoses);
        Self {
            connector_id: connector_id.into(),
            status,
            diagnoses,
        }
    }

    /// Whether this report has any issues.
    pub fn has_issues(&self) -> bool {
        !self.diagnoses.is_empty()
    }

    /// Count of auto-safe fixes available.
    pub fn auto_fixable_count(&self) -> usize {
        self.diagnoses
            .iter()
            .flat_map(|d| &d.fixes)
            .filter(|f| f.auto_safe)
            .count()
    }

    /// All fix commands across all diagnoses.
    pub fn all_fix_commands(&self) -> Vec<&str> {
        self.diagnoses
            .iter()
            .flat_map(|d| &d.fixes)
            .filter_map(|f| f.command.as_deref())
            .collect()
    }

    /// Render as TOON-style summary.
    pub fn summary_line(&self) -> String {
        if self.diagnoses.is_empty() {
            format!("{}  {}", self.connector_id, self.status)
        } else {
            let worst = self
                .diagnoses
                .iter()
                .map(|d| d.severity)
                .max()
                .unwrap_or(Severity::Info);
            format!(
                "{}  {}  {} issue(s), worst: {}",
                self.connector_id,
                self.status,
                self.diagnoses.len(),
                worst
            )
        }
    }

    /// Render as structured JSON value.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

fn compute_status(diagnoses: &[Diagnosis]) -> HealthStatus {
    if diagnoses.is_empty() {
        return HealthStatus::Healthy;
    }
    let max_severity = diagnoses.iter().map(|d| d.severity).max();
    match max_severity {
        Some(Severity::Critical | Severity::Error) => HealthStatus::Unhealthy,
        Some(Severity::Warning) => HealthStatus::Degraded,
        _ => HealthStatus::Healthy,
    }
}

// ── Diagnosis rules engine ─────────────────────────────────────────

/// Symptom data used as input to the diagnosis engine.
#[derive(Clone, Debug, Default)]
pub struct Symptoms {
    /// HTTP status code from last health check (if available).
    pub http_status: Option<u16>,
    /// Error message from last health check (if available).
    pub error_message: Option<String>,
    /// Latency in milliseconds of last health check.
    pub latency_ms: Option<u64>,
    /// Whether the connector is installed/found.
    pub installed: bool,
    /// Whether credentials exist in the credential store.
    pub has_credentials: bool,
    /// Rate limit percentage used (0-100).
    pub rate_limit_percent: Option<u8>,
    /// Whether the last operation succeeded.
    pub last_op_success: Option<bool>,
}

/// Diagnose symptoms for a connector.
pub fn diagnose(connector_id: &str, symptoms: &Symptoms) -> DiagnosticReport {
    let mut diagnoses = Vec::new();

    if !symptoms.installed {
        diagnoses.push(diagnose_not_found(connector_id));
        return DiagnosticReport::from_diagnoses(connector_id, diagnoses);
    }

    if !symptoms.has_credentials {
        diagnoses.push(diagnose_no_credentials(connector_id));
    }

    if let Some(status) = symptoms.http_status {
        if let Some(diag) = diagnose_http_status(connector_id, status) {
            diagnoses.push(diag);
        }
    }

    if let Some(msg) = &symptoms.error_message {
        if let Some(diag) = diagnose_error_message(connector_id, msg) {
            diagnoses.push(diag);
        }
    }

    if let Some(latency) = symptoms.latency_ms {
        if let Some(diag) = diagnose_latency(connector_id, latency) {
            diagnoses.push(diag);
        }
    }

    if let Some(pct) = symptoms.rate_limit_percent {
        if let Some(diag) = diagnose_rate_limit(connector_id, pct) {
            diagnoses.push(diag);
        }
    }

    DiagnosticReport::from_diagnoses(connector_id, diagnoses)
}

fn diagnose_not_found(connector_id: &str) -> Diagnosis {
    Diagnosis {
        connector_id: connector_id.to_owned(),
        category: DiagnosisCategory::NotFound,
        severity: Severity::Critical,
        message: format!("Connector `{connector_id}` is not installed or not found"),
        fixes: vec![
            FixAction::command(
                "Install the connector",
                format!("fwc install {connector_id}"),
            ),
            FixAction::command(
                "Search for available connectors",
                format!("fwc search {connector_id}"),
            ),
        ],
    }
}

fn diagnose_no_credentials(connector_id: &str) -> Diagnosis {
    Diagnosis {
        connector_id: connector_id.to_owned(),
        category: DiagnosisCategory::Auth,
        severity: Severity::Error,
        message: format!("No credentials found for `{connector_id}`"),
        fixes: vec![
            FixAction::command(
                "Add credentials for this connector",
                format!("fwc auth add {connector_id} --token <YOUR_TOKEN>"),
            ),
            FixAction::command("List existing credentials", "fwc auth list".to_owned()),
        ],
    }
}

fn diagnose_http_status(connector_id: &str, status: u16) -> Option<Diagnosis> {
    match status {
        401 => Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Critical,
            message: "Authentication failed (401 Unauthorized)".to_owned(),
            fixes: vec![
                FixAction::command(
                    "Test current credentials",
                    format!("fwc auth test {connector_id}"),
                ),
                FixAction::command(
                    "Re-add credentials",
                    format!("fwc auth add {connector_id} --token <NEW_TOKEN>"),
                ),
            ],
        }),
        403 => Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "Access forbidden (403) — insufficient permissions".to_owned(),
            fixes: vec![
                FixAction::manual("Verify your token has the required scopes/permissions"),
                FixAction::command(
                    "Check connector required scopes",
                    format!("fwc show {connector_id}"),
                ),
            ],
        }),
        429 => Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::RateLimit,
            severity: Severity::Warning,
            message: "Rate limited (429) — too many requests".to_owned(),
            fixes: vec![
                FixAction::manual("Wait for rate limit reset before retrying"),
                FixAction::command(
                    "Check rate limit status",
                    format!("fwc rate-limits {connector_id}"),
                ),
            ],
        }),
        500..=599 => Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::ServiceError,
            severity: Severity::Error,
            message: format!("Service error ({status}) — the provider API returned a server error"),
            fixes: vec![
                FixAction::manual("Wait and retry — this is likely a transient issue"),
                FixAction::manual("Check the provider's status page for outages"),
            ],
        }),
        _ => None,
    }
}

fn diagnose_error_message(connector_id: &str, msg: &str) -> Option<Diagnosis> {
    let lower = msg.to_lowercase();

    if lower.contains("certificate") || lower.contains("ssl") || lower.contains("tls") {
        return Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::Certificate,
            severity: Severity::Error,
            message: format!("TLS/certificate error: {msg}"),
            fixes: vec![
                FixAction::manual("Verify system clock is set correctly"),
                FixAction::manual("Update CA certificates on this system"),
                FixAction::manual("Check if the service endpoint uses a valid certificate"),
            ],
        });
    }

    if lower.contains("connection refused") || lower.contains("connect error") {
        return Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::Network,
            severity: Severity::Critical,
            message: format!("Connection error: {msg}"),
            fixes: vec![
                FixAction::manual("Check network connectivity"),
                FixAction::manual("Verify the service endpoint is correct"),
                FixAction::manual("Check if a proxy or firewall is blocking the connection"),
            ],
        });
    }

    if lower.contains("timeout") || lower.contains("timed out") {
        return Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::Latency,
            severity: Severity::Error,
            message: format!("Request timed out: {msg}"),
            fixes: vec![
                FixAction::manual("Check network connectivity"),
                FixAction::manual("The service may be experiencing high load"),
            ],
        });
    }

    if lower.contains("dns") || lower.contains("resolve") {
        return Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::Network,
            severity: Severity::Critical,
            message: format!("DNS resolution failed: {msg}"),
            fixes: vec![
                FixAction::manual("Check DNS configuration"),
                FixAction::manual("Verify the service hostname is correct"),
            ],
        });
    }

    None
}

fn diagnose_latency(connector_id: &str, latency_ms: u64) -> Option<Diagnosis> {
    if latency_ms > 5000 {
        Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::Latency,
            severity: Severity::Error,
            message: format!("Very high latency ({latency_ms}ms)"),
            fixes: vec![
                FixAction::manual("Check network connectivity"),
                FixAction::manual("The service may be experiencing degraded performance"),
            ],
        })
    } else if latency_ms > 2000 {
        Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::Latency,
            severity: Severity::Warning,
            message: format!("High latency ({latency_ms}ms)"),
            fixes: vec![FixAction::manual(
                "Monitor — latency may improve on subsequent requests",
            )],
        })
    } else {
        None
    }
}

fn diagnose_rate_limit(connector_id: &str, percent: u8) -> Option<Diagnosis> {
    if percent >= 95 {
        Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::RateLimit,
            severity: Severity::Critical,
            message: format!("Rate limit nearly exhausted ({percent}% used)"),
            fixes: vec![
                FixAction::manual("Pause operations until the rate limit resets"),
                FixAction::command(
                    "Check rate limit details",
                    format!("fwc rate-limits {connector_id}"),
                ),
            ],
        })
    } else if percent >= 80 {
        Some(Diagnosis {
            connector_id: connector_id.to_owned(),
            category: DiagnosisCategory::RateLimit,
            severity: Severity::Warning,
            message: format!("Rate limit usage high ({percent}% used)"),
            fixes: vec![
                FixAction::manual("Reduce request frequency to avoid hitting the limit"),
                FixAction::command(
                    "Check rate limit details",
                    format!("fwc rate-limits {connector_id}"),
                ),
            ],
        })
    } else {
        None
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_symptoms() -> Symptoms {
        Symptoms {
            installed: true,
            has_credentials: true,
            ..Default::default()
        }
    }

    // ── Severity ──────────────────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    #[test]
    fn severity_label() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::Error.label(), "error");
        assert_eq!(Severity::Warning.label(), "warning");
        assert_eq!(Severity::Info.label(), "info");
    }

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", Severity::Critical), "critical");
    }

    // ── HealthStatus ──────────────────────────────────────────────

    #[test]
    fn health_status_label() {
        assert_eq!(HealthStatus::Healthy.label(), "healthy");
        assert_eq!(HealthStatus::Degraded.label(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.label(), "unhealthy");
        assert_eq!(HealthStatus::Unknown.label(), "unknown");
    }

    #[test]
    fn health_status_display() {
        assert_eq!(format!("{}", HealthStatus::Healthy), "healthy");
    }

    // ── DiagnosisCategory ─────────────────────────────────────────

    #[test]
    fn category_display_names() {
        assert_eq!(DiagnosisCategory::Auth.display_name(), "Authentication");
        assert_eq!(DiagnosisCategory::RateLimit.display_name(), "Rate Limit");
        assert_eq!(DiagnosisCategory::Network.display_name(), "Network");
        assert_eq!(DiagnosisCategory::Latency.display_name(), "Latency");
        assert_eq!(DiagnosisCategory::Config.display_name(), "Configuration");
        assert_eq!(DiagnosisCategory::Certificate.display_name(), "Certificate");
        assert_eq!(DiagnosisCategory::NotFound.display_name(), "Not Found");
        assert_eq!(
            DiagnosisCategory::ServiceError.display_name(),
            "Service Error"
        );
        assert_eq!(DiagnosisCategory::Unknown.display_name(), "Unknown");
    }

    // ── FixAction ─────────────────────────────────────────────────

    #[test]
    fn fix_action_command() {
        let fix = FixAction::command("Install it", "fwc install github");
        assert_eq!(fix.command.as_deref(), Some("fwc install github"));
        assert!(!fix.auto_safe);
    }

    #[test]
    fn fix_action_manual() {
        let fix = FixAction::manual("Check your network");
        assert!(fix.command.is_none());
    }

    #[test]
    fn fix_action_safe() {
        let fix = FixAction::command("Clear cache", "fwc cache clear").safe();
        assert!(fix.auto_safe);
    }

    #[test]
    fn fix_action_with_url() {
        let fix = FixAction::manual("Check status").with_url("https://status.example.com");
        assert_eq!(
            fix.reference_url.as_deref(),
            Some("https://status.example.com")
        );
    }

    // ── DiagnosticReport ──────────────────────────────────────────

    #[test]
    fn healthy_report() {
        let report = DiagnosticReport::healthy("github");
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(!report.has_issues());
        assert_eq!(report.auto_fixable_count(), 0);
    }

    #[test]
    fn report_summary_line_healthy() {
        let report = DiagnosticReport::healthy("github");
        let line = report.summary_line();
        assert!(line.contains("github"));
        assert!(line.contains("healthy"));
    }

    #[test]
    fn report_summary_line_with_issues() {
        let diags = vec![Diagnosis {
            connector_id: "github".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "Auth failed".to_owned(),
            fixes: vec![],
        }];
        let report = DiagnosticReport::from_diagnoses("github", diags);
        let line = report.summary_line();
        assert!(line.contains("1 issue"));
        assert!(line.contains("error"));
    }

    #[test]
    fn report_to_json() {
        let report = DiagnosticReport::healthy("github");
        let json = report.to_json();
        assert_eq!(json["connector_id"], "github");
        assert_eq!(json["status"], "healthy");
    }

    #[test]
    fn report_auto_fixable_count() {
        let diags = vec![Diagnosis {
            connector_id: "github".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "Auth failed".to_owned(),
            fixes: vec![
                FixAction::command("Fix 1", "cmd1").safe(),
                FixAction::command("Fix 2", "cmd2"),
                FixAction::command("Fix 3", "cmd3").safe(),
            ],
        }];
        let report = DiagnosticReport::from_diagnoses("github", diags);
        assert_eq!(report.auto_fixable_count(), 2);
    }

    #[test]
    fn report_all_fix_commands() {
        let diags = vec![
            Diagnosis {
                connector_id: "github".to_owned(),
                category: DiagnosisCategory::Auth,
                severity: Severity::Error,
                message: "Auth".to_owned(),
                fixes: vec![FixAction::command("Fix 1", "cmd1")],
            },
            Diagnosis {
                connector_id: "github".to_owned(),
                category: DiagnosisCategory::Latency,
                severity: Severity::Warning,
                message: "Slow".to_owned(),
                fixes: vec![
                    FixAction::manual("Wait"),
                    FixAction::command("Fix 2", "cmd2"),
                ],
            },
        ];
        let report = DiagnosticReport::from_diagnoses("github", diags);
        let cmds = report.all_fix_commands();
        assert_eq!(cmds, vec!["cmd1", "cmd2"]);
    }

    // ── compute_status ────────────────────────────────────────────

    #[test]
    fn status_healthy_when_no_diagnoses() {
        assert_eq!(compute_status(&[]), HealthStatus::Healthy);
    }

    #[test]
    fn status_degraded_on_warning() {
        let diags = vec![Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Latency,
            severity: Severity::Warning,
            message: "slow".to_owned(),
            fixes: vec![],
        }];
        assert_eq!(compute_status(&diags), HealthStatus::Degraded);
    }

    #[test]
    fn status_unhealthy_on_error() {
        let diags = vec![Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "auth failed".to_owned(),
            fixes: vec![],
        }];
        assert_eq!(compute_status(&diags), HealthStatus::Unhealthy);
    }

    #[test]
    fn status_unhealthy_on_critical() {
        let diags = vec![Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Network,
            severity: Severity::Critical,
            message: "can't connect".to_owned(),
            fixes: vec![],
        }];
        assert_eq!(compute_status(&diags), HealthStatus::Unhealthy);
    }

    #[test]
    fn status_worst_wins() {
        let diags = vec![
            Diagnosis {
                connector_id: "test".to_owned(),
                category: DiagnosisCategory::Latency,
                severity: Severity::Warning,
                message: "slow".to_owned(),
                fixes: vec![],
            },
            Diagnosis {
                connector_id: "test".to_owned(),
                category: DiagnosisCategory::Auth,
                severity: Severity::Critical,
                message: "auth".to_owned(),
                fixes: vec![],
            },
        ];
        assert_eq!(compute_status(&diags), HealthStatus::Unhealthy);
    }

    // ── diagnose() full flow ──────────────────────────────────────

    #[test]
    fn diagnose_healthy_connector() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: true,
            http_status: Some(200),
            latency_ms: Some(50),
            ..Default::default()
        };
        let report = diagnose("github", &symptoms);
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(!report.has_issues());
    }

    #[test]
    fn diagnose_not_installed() {
        let symptoms = Symptoms {
            installed: false,
            ..Default::default()
        };
        let report = diagnose("fakeco", &symptoms);
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert_eq!(report.diagnoses.len(), 1);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::NotFound);
    }

    #[test]
    fn diagnose_no_credentials() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: false,
            ..Default::default()
        };
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert!(
            report
                .diagnoses
                .iter()
                .any(|d| d.category == DiagnosisCategory::Auth)
        );
    }

    #[test]
    fn diagnose_401_unauthorized() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: true,
            http_status: Some(401),
            ..Default::default()
        };
        let report = diagnose("github", &symptoms);
        assert_eq!(report.status, HealthStatus::Unhealthy);
        let auth_diag = report
            .diagnoses
            .iter()
            .find(|d| d.category == DiagnosisCategory::Auth)
            .unwrap();
        assert_eq!(auth_diag.severity, Severity::Critical);
        assert!(!auth_diag.fixes.is_empty());
    }

    #[test]
    fn diagnose_403_forbidden() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(403);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        let diag = &report.diagnoses[0];
        assert_eq!(diag.severity, Severity::Error);
        assert!(diag.message.contains("403"));
    }

    #[test]
    fn diagnose_429_rate_limited() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(429);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::RateLimit);
    }

    #[test]
    fn diagnose_500_server_error() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(500);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(
            report.diagnoses[0].category,
            DiagnosisCategory::ServiceError
        );
    }

    #[test]
    fn diagnose_502_server_error() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(502);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert!(report.diagnoses[0].message.contains("502"));
    }

    #[test]
    fn diagnose_200_no_issue() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(200);
        let report = diagnose("github", &symptoms);
        assert!(!report.has_issues());
    }

    // ── Error message diagnosis ───────────────────────────────────

    #[test]
    fn diagnose_certificate_error() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("SSL certificate verify failed".to_owned());
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Certificate);
    }

    #[test]
    fn diagnose_tls_error() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("TLS handshake failed".to_owned());
        let report = diagnose("github", &symptoms);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Certificate);
    }

    #[test]
    fn diagnose_connection_refused() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("Connection refused".to_owned());
        let report = diagnose("github", &symptoms);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Network);
        assert_eq!(report.diagnoses[0].severity, Severity::Critical);
    }

    #[test]
    fn diagnose_timeout() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("Request timed out after 30s".to_owned());
        let report = diagnose("github", &symptoms);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Latency);
    }

    #[test]
    fn diagnose_dns_failure() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("DNS resolution failed for api.github.com".to_owned());
        let report = diagnose("github", &symptoms);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Network);
    }

    #[test]
    fn diagnose_unknown_error_message() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("Something unexpected happened".to_owned());
        let report = diagnose("github", &symptoms);
        // Unknown error messages don't generate a diagnosis.
        assert!(!report.has_issues());
    }

    // ── Latency diagnosis ─────────────────────────────────────────

    #[test]
    fn diagnose_normal_latency() {
        let mut symptoms = default_symptoms();
        symptoms.latency_ms = Some(150);
        let report = diagnose("github", &symptoms);
        assert!(!report.has_issues());
    }

    #[test]
    fn diagnose_high_latency() {
        let mut symptoms = default_symptoms();
        symptoms.latency_ms = Some(3000);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Warning);
    }

    #[test]
    fn diagnose_very_high_latency() {
        let mut symptoms = default_symptoms();
        symptoms.latency_ms = Some(8000);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Error);
    }

    // ── Rate limit diagnosis ──────────────────────────────────────

    #[test]
    fn diagnose_rate_limit_ok() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(50);
        let report = diagnose("github", &symptoms);
        assert!(!report.has_issues());
    }

    #[test]
    fn diagnose_rate_limit_warning() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(85);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Warning);
    }

    #[test]
    fn diagnose_rate_limit_critical() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(98);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Critical);
    }

    // ── Multiple symptoms ─────────────────────────────────────────

    #[test]
    fn diagnose_multiple_issues() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: false,
            http_status: Some(500),
            latency_ms: Some(6000),
            rate_limit_percent: Some(90),
            ..Default::default()
        };
        let report = diagnose("github", &symptoms);
        assert_eq!(report.status, HealthStatus::Unhealthy);
        // Should have: no credentials + 500 + high latency + rate limit warning
        assert!(report.diagnoses.len() >= 4);
    }

    // ── Serialization ─────────────────────────────────────────────

    #[test]
    fn diagnosis_serializes_to_json() {
        let diag = Diagnosis {
            connector_id: "github".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "Auth failed".to_owned(),
            fixes: vec![FixAction::command("Fix it", "fwc auth add github")],
        };
        let json = serde_json::to_value(&diag).unwrap();
        assert_eq!(json["category"], "auth");
        assert_eq!(json["severity"], "error");
        assert_eq!(json["fixes"][0]["command"], "fwc auth add github");
    }

    #[test]
    fn fix_action_serializes_to_json() {
        let fix = FixAction::command("Do thing", "fwc do thing")
            .safe()
            .with_url("https://example.com");
        let json = serde_json::to_value(&fix).unwrap();
        assert_eq!(json["auto_safe"], true);
        assert_eq!(json["reference_url"], "https://example.com");
        assert_eq!(json["command"], "fwc do thing");
    }

    // ── Severity additional ──────────────────────────────────────

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Info, Severity::Info);
        assert_ne!(Severity::Info, Severity::Warning);
        assert_ne!(Severity::Warning, Severity::Error);
        assert_ne!(Severity::Error, Severity::Critical);
    }

    #[test]
    fn severity_display_all() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn severity_serializes() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(
            serde_json::to_string(&Severity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn severity_copy_clone() {
        let s = Severity::Warning;
        let c = s;
        assert_eq!(s, c);
    }

    #[test]
    fn severity_debug() {
        let debug = format!("{:?}", Severity::Error);
        assert!(debug.contains("Error"));
    }

    // ── HealthStatus additional ──────────────────────────────────

    #[test]
    fn health_status_display_all() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
        assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Degraded);
        assert_ne!(HealthStatus::Degraded, HealthStatus::Unhealthy);
        assert_ne!(HealthStatus::Unhealthy, HealthStatus::Unknown);
    }

    #[test]
    fn health_status_serializes() {
        assert_eq!(
            serde_json::to_string(&HealthStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn health_status_copy_clone() {
        let s = HealthStatus::Degraded;
        let c = s;
        assert_eq!(s, c);
    }

    // ── DiagnosisCategory additional ─────────────────────────────

    #[test]
    fn category_equality() {
        assert_eq!(DiagnosisCategory::Auth, DiagnosisCategory::Auth);
        assert_ne!(DiagnosisCategory::Auth, DiagnosisCategory::Network);
    }

    #[test]
    fn category_serializes() {
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::Auth).unwrap(),
            "\"auth\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::RateLimit).unwrap(),
            "\"rate_limit\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::Network).unwrap(),
            "\"network\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::Certificate).unwrap(),
            "\"certificate\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::ServiceError).unwrap(),
            "\"service_error\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn category_copy_clone() {
        let c = DiagnosisCategory::Config;
        let c2 = c;
        assert_eq!(c, c2);
    }

    // ── FixAction additional ─────────────────────────────────────

    #[test]
    fn fix_action_command_not_auto_safe_by_default() {
        let fix = FixAction::command("test", "cmd");
        assert!(!fix.auto_safe);
        assert!(fix.reference_url.is_none());
    }

    #[test]
    fn fix_action_manual_no_command() {
        let fix = FixAction::manual("Do something manually");
        assert!(fix.command.is_none());
        assert!(!fix.auto_safe);
        assert!(fix.reference_url.is_none());
    }

    #[test]
    fn fix_action_chained_builders() {
        let fix = FixAction::command("Fix", "fwc fix")
            .safe()
            .with_url("https://docs.example.com");
        assert!(fix.auto_safe);
        assert_eq!(fix.command.as_deref(), Some("fwc fix"));
        assert_eq!(
            fix.reference_url.as_deref(),
            Some("https://docs.example.com")
        );
    }

    #[test]
    fn fix_action_clone() {
        let fix = FixAction::command("Fix", "cmd").safe();
        let cloned = fix.clone();
        assert_eq!(fix.description, "Fix");
        assert!(cloned.auto_safe);
    }

    // ── DiagnosticReport additional ──────────────────────────────

    #[test]
    fn report_from_diagnoses_healthy_when_info_only() {
        let diags = vec![Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Config,
            severity: Severity::Info,
            message: "Just informational".to_owned(),
            fixes: vec![],
        }];
        let report = DiagnosticReport::from_diagnoses("test", diags);
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(report.has_issues());
    }

    #[test]
    fn report_healthy_no_fix_commands() {
        let report = DiagnosticReport::healthy("test");
        assert!(report.all_fix_commands().is_empty());
    }

    #[test]
    fn report_summary_line_multiple_issues() {
        let diags = vec![
            Diagnosis {
                connector_id: "test".to_owned(),
                category: DiagnosisCategory::Auth,
                severity: Severity::Warning,
                message: "warning".to_owned(),
                fixes: vec![],
            },
            Diagnosis {
                connector_id: "test".to_owned(),
                category: DiagnosisCategory::Latency,
                severity: Severity::Critical,
                message: "critical".to_owned(),
                fixes: vec![],
            },
        ];
        let report = DiagnosticReport::from_diagnoses("test", diags);
        let line = report.summary_line();
        assert!(line.contains("2 issue"));
        assert!(line.contains("critical"));
    }

    #[test]
    fn report_to_json_with_issues() {
        let diags = vec![Diagnosis {
            connector_id: "slack".to_owned(),
            category: DiagnosisCategory::RateLimit,
            severity: Severity::Warning,
            message: "Rate limited".to_owned(),
            fixes: vec![FixAction::command("Check", "fwc rate-limits slack")],
        }];
        let report = DiagnosticReport::from_diagnoses("slack", diags);
        let json = report.to_json();
        assert_eq!(json["status"], "degraded");
        assert!(json["diagnoses"].is_array());
        assert_eq!(json["diagnoses"][0]["category"], "rate_limit");
    }

    #[test]
    fn report_clone() {
        let report = DiagnosticReport::healthy("github");
        let cloned = report.clone();
        assert_eq!(report.connector_id, "github");
        assert_eq!(cloned.status, HealthStatus::Healthy);
    }

    #[test]
    fn report_auto_fixable_none() {
        let diags = vec![Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "auth".to_owned(),
            fixes: vec![FixAction::manual("Do it yourself")],
        }];
        let report = DiagnosticReport::from_diagnoses("test", diags);
        assert_eq!(report.auto_fixable_count(), 0);
    }

    // ── compute_status additional ────────────────────────────────

    #[test]
    fn status_healthy_on_info() {
        let diags = vec![Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Config,
            severity: Severity::Info,
            message: "info".to_owned(),
            fixes: vec![],
        }];
        assert_eq!(compute_status(&diags), HealthStatus::Healthy);
    }

    #[test]
    fn status_mixed_warning_and_info() {
        let diags = vec![
            Diagnosis {
                connector_id: "test".to_owned(),
                category: DiagnosisCategory::Config,
                severity: Severity::Info,
                message: "info".to_owned(),
                fixes: vec![],
            },
            Diagnosis {
                connector_id: "test".to_owned(),
                category: DiagnosisCategory::Latency,
                severity: Severity::Warning,
                message: "slow".to_owned(),
                fixes: vec![],
            },
        ];
        assert_eq!(compute_status(&diags), HealthStatus::Degraded);
    }

    // ── diagnose() additional flows ──────────────────────────────

    #[test]
    fn diagnose_503_server_error() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(503);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert!(report.diagnoses[0].message.contains("503"));
    }

    #[test]
    fn diagnose_599_server_error() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(599);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(
            report.diagnoses[0].category,
            DiagnosisCategory::ServiceError
        );
    }

    #[test]
    fn diagnose_404_no_issue() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(404);
        let report = diagnose("github", &symptoms);
        assert!(!report.has_issues());
    }

    #[test]
    fn diagnose_connect_error() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("connect error: network unreachable".to_owned());
        let report = diagnose("github", &symptoms);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Network);
    }

    #[test]
    fn diagnose_resolve_error() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("could not resolve host".to_owned());
        let report = diagnose("github", &symptoms);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Network);
    }

    #[test]
    fn diagnose_ssl_keyword() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("SSL handshake error".to_owned());
        let report = diagnose("github", &symptoms);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Certificate);
    }

    #[test]
    fn diagnose_latency_at_boundary_2000() {
        let mut symptoms = default_symptoms();
        symptoms.latency_ms = Some(2000);
        let report = diagnose("github", &symptoms);
        assert!(!report.has_issues());
    }

    #[test]
    fn diagnose_latency_at_boundary_2001() {
        let mut symptoms = default_symptoms();
        symptoms.latency_ms = Some(2001);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Warning);
    }

    #[test]
    fn diagnose_latency_at_boundary_5000() {
        let mut symptoms = default_symptoms();
        symptoms.latency_ms = Some(5000);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Warning);
    }

    #[test]
    fn diagnose_latency_at_boundary_5001() {
        let mut symptoms = default_symptoms();
        symptoms.latency_ms = Some(5001);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Error);
    }

    #[test]
    fn diagnose_rate_limit_at_79() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(79);
        let report = diagnose("github", &symptoms);
        assert!(!report.has_issues());
    }

    #[test]
    fn diagnose_rate_limit_at_80() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(80);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Warning);
    }

    #[test]
    fn diagnose_rate_limit_at_94() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(94);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Warning);
    }

    #[test]
    fn diagnose_rate_limit_at_95() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(95);
        let report = diagnose("github", &symptoms);
        assert!(report.has_issues());
        assert_eq!(report.diagnoses[0].severity, Severity::Critical);
    }

    #[test]
    fn diagnose_rate_limit_at_100() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(100);
        let report = diagnose("github", &symptoms);
        assert_eq!(report.diagnoses[0].severity, Severity::Critical);
    }

    #[test]
    fn diagnose_not_installed_early_return() {
        // When not installed, no other symptoms should be checked
        let symptoms = Symptoms {
            installed: false,
            has_credentials: false,
            http_status: Some(401),
            latency_ms: Some(10_000),
            rate_limit_percent: Some(100),
            ..Default::default()
        };
        let report = diagnose("fakeco", &symptoms);
        // Only the NotFound diagnosis should be present
        assert_eq!(report.diagnoses.len(), 1);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::NotFound);
    }

    #[test]
    fn diagnose_no_symptoms_at_all() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: true,
            ..Default::default()
        };
        let report = diagnose("github", &symptoms);
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(!report.has_issues());
    }

    // ── Symptoms default ─────────────────────────────────────────

    #[test]
    fn symptoms_default_values() {
        let s = Symptoms::default();
        assert!(!s.installed);
        assert!(!s.has_credentials);
        assert!(s.http_status.is_none());
        assert!(s.error_message.is_none());
        assert!(s.latency_ms.is_none());
        assert!(s.rate_limit_percent.is_none());
        assert!(s.last_op_success.is_none());
    }

    #[test]
    fn symptoms_clone() {
        let s = Symptoms {
            installed: true,
            has_credentials: true,
            http_status: Some(200),
            latency_ms: Some(50),
            ..Default::default()
        };
        let cloned = s.clone();
        assert!(s.installed);
        assert_eq!(cloned.http_status, Some(200));
    }

    // ── Diagnosis clone and debug ────────────────────────────────

    #[test]
    fn diagnosis_clone() {
        let diag = Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "auth failed".to_owned(),
            fixes: vec![FixAction::manual("fix it")],
        };
        let cloned = diag.clone();
        assert_eq!(diag.connector_id, "test");
        assert_eq!(cloned.fixes.len(), 1);
    }

    #[test]
    fn diagnosis_debug() {
        let diag = Diagnosis {
            connector_id: "x".to_owned(),
            category: DiagnosisCategory::Network,
            severity: Severity::Critical,
            message: "down".to_owned(),
            fixes: vec![],
        };
        let debug = format!("{diag:?}");
        assert!(debug.contains("Diagnosis"));
        assert!(debug.contains("Network"));
    }

    // ════════════════════════════════════════════════════════════════
    // Expanded coverage below
    // ════════════════════════════════════════════════════════════════

    // ── Severity expanded ────────────────────────────────────────

    #[test]
    fn severity_all_labels_non_empty() {
        for sev in [Severity::Info, Severity::Warning, Severity::Error, Severity::Critical] {
            assert!(!sev.label().is_empty());
        }
    }

    #[test]
    fn severity_label_matches_display() {
        for sev in [Severity::Info, Severity::Warning, Severity::Error, Severity::Critical] {
            assert_eq!(sev.label(), sev.to_string());
        }
    }

    #[test]
    fn severity_total_ordering() {
        let mut sevs = vec![Severity::Critical, Severity::Info, Severity::Error, Severity::Warning];
        sevs.sort();
        assert_eq!(sevs, vec![Severity::Info, Severity::Warning, Severity::Error, Severity::Critical]);
    }

    #[test]
    fn severity_min_max() {
        let sevs = [Severity::Warning, Severity::Critical, Severity::Info];
        assert_eq!(sevs.iter().copied().min(), Some(Severity::Info));
        assert_eq!(sevs.iter().copied().max(), Some(Severity::Critical));
    }

    #[test]
    fn severity_serialize_roundtrip_info() {
        let json = serde_json::to_string(&Severity::Info).unwrap();
        assert_eq!(json, "\"info\"");
    }

    #[test]
    fn severity_debug_all() {
        for sev in [Severity::Info, Severity::Warning, Severity::Error, Severity::Critical] {
            let debug = format!("{sev:?}");
            assert!(!debug.is_empty());
        }
    }

    // ── HealthStatus expanded ────────────────────────────────────

    #[test]
    fn health_status_label_matches_display() {
        for hs in [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
            HealthStatus::Unknown,
        ] {
            assert_eq!(hs.label(), hs.to_string());
        }
    }

    #[test]
    fn health_status_debug_all() {
        for hs in [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
            HealthStatus::Unknown,
        ] {
            let debug = format!("{hs:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn health_status_serialize_degraded() {
        assert_eq!(
            serde_json::to_string(&HealthStatus::Degraded).unwrap(),
            "\"degraded\""
        );
    }

    #[test]
    fn health_status_serialize_unhealthy() {
        assert_eq!(
            serde_json::to_string(&HealthStatus::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    // ── DiagnosisCategory expanded ───────────────────────────────

    #[test]
    fn category_display_name_all_non_empty() {
        for cat in [
            DiagnosisCategory::Auth,
            DiagnosisCategory::RateLimit,
            DiagnosisCategory::Network,
            DiagnosisCategory::Latency,
            DiagnosisCategory::Config,
            DiagnosisCategory::Certificate,
            DiagnosisCategory::NotFound,
            DiagnosisCategory::ServiceError,
            DiagnosisCategory::Unknown,
        ] {
            assert!(!cat.display_name().is_empty());
        }
    }

    #[test]
    fn category_serialize_config() {
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::Config).unwrap(),
            "\"config\""
        );
    }

    #[test]
    fn category_serialize_latency() {
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::Latency).unwrap(),
            "\"latency\""
        );
    }

    #[test]
    fn category_serialize_not_found() {
        assert_eq!(
            serde_json::to_string(&DiagnosisCategory::NotFound).unwrap(),
            "\"not_found\""
        );
    }

    #[test]
    fn category_debug_all() {
        for cat in [
            DiagnosisCategory::Auth,
            DiagnosisCategory::RateLimit,
            DiagnosisCategory::Network,
            DiagnosisCategory::Latency,
            DiagnosisCategory::Config,
            DiagnosisCategory::Certificate,
            DiagnosisCategory::NotFound,
            DiagnosisCategory::ServiceError,
            DiagnosisCategory::Unknown,
        ] {
            let debug = format!("{cat:?}");
            assert!(!debug.is_empty());
        }
    }

    // ── FixAction expanded ───────────────────────────────────────

    #[test]
    fn fix_action_command_description_preserved() {
        let fix = FixAction::command("My description", "my-command");
        assert_eq!(fix.description, "My description");
        assert_eq!(fix.command.as_deref(), Some("my-command"));
    }

    #[test]
    fn fix_action_manual_description_preserved() {
        let fix = FixAction::manual("Manual step here");
        assert_eq!(fix.description, "Manual step here");
    }

    #[test]
    fn fix_action_safe_is_idempotent() {
        let fix = FixAction::command("test", "cmd").safe().safe();
        assert!(fix.auto_safe);
    }

    #[test]
    fn fix_action_with_url_overwrites() {
        let fix = FixAction::manual("test")
            .with_url("https://first.example.com")
            .with_url("https://second.example.com");
        assert_eq!(fix.reference_url.as_deref(), Some("https://second.example.com"));
    }

    #[test]
    fn fix_action_serialize_manual() {
        let fix = FixAction::manual("Do it manually");
        let json = serde_json::to_value(&fix).unwrap();
        assert!(json["command"].is_null());
        assert_eq!(json["auto_safe"], false);
        assert!(json["reference_url"].is_null());
    }

    #[test]
    fn fix_action_serialize_full_chain() {
        let fix = FixAction::command("Fix everything", "fwc fix all")
            .safe()
            .with_url("https://docs.example.com/fix");
        let json = serde_json::to_value(&fix).unwrap();
        assert_eq!(json["description"], "Fix everything");
        assert_eq!(json["command"], "fwc fix all");
        assert_eq!(json["auto_safe"], true);
        assert_eq!(json["reference_url"], "https://docs.example.com/fix");
    }

    #[test]
    fn fix_action_debug() {
        let fix = FixAction::command("test", "cmd").safe();
        let debug = format!("{fix:?}");
        assert!(debug.contains("FixAction"));
        assert!(debug.contains("auto_safe: true"));
    }

    // ── DiagnosticReport expanded ────────────────────────────────

    #[test]
    fn report_healthy_has_no_issues() {
        let report = DiagnosticReport::healthy("test");
        assert!(!report.has_issues());
        assert_eq!(report.auto_fixable_count(), 0);
        assert!(report.all_fix_commands().is_empty());
    }

    #[test]
    fn report_from_diagnoses_with_empty_vec() {
        let report = DiagnosticReport::from_diagnoses("test", vec![]);
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(!report.has_issues());
    }

    #[test]
    fn report_auto_fixable_count_across_multiple_diagnoses() {
        let diags = vec![
            Diagnosis {
                connector_id: "test".to_owned(),
                category: DiagnosisCategory::Auth,
                severity: Severity::Error,
                message: "auth".to_owned(),
                fixes: vec![
                    FixAction::command("Fix A", "cmd_a").safe(),
                    FixAction::manual("Manual"),
                ],
            },
            Diagnosis {
                connector_id: "test".to_owned(),
                category: DiagnosisCategory::Latency,
                severity: Severity::Warning,
                message: "slow".to_owned(),
                fixes: vec![
                    FixAction::command("Fix B", "cmd_b").safe(),
                    FixAction::command("Fix C", "cmd_c").safe(),
                ],
            },
        ];
        let report = DiagnosticReport::from_diagnoses("test", diags);
        assert_eq!(report.auto_fixable_count(), 3);
    }

    #[test]
    fn report_all_fix_commands_excludes_manual() {
        let diags = vec![Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "auth".to_owned(),
            fixes: vec![
                FixAction::manual("Manual 1"),
                FixAction::command("Cmd 1", "cmd1"),
                FixAction::manual("Manual 2"),
                FixAction::command("Cmd 2", "cmd2"),
            ],
        }];
        let report = DiagnosticReport::from_diagnoses("test", diags);
        let cmds = report.all_fix_commands();
        assert_eq!(cmds, vec!["cmd1", "cmd2"]);
    }

    #[test]
    fn report_summary_line_empty_diagnoses() {
        let report = DiagnosticReport::from_diagnoses("myconn", vec![]);
        let line = report.summary_line();
        assert!(line.contains("myconn"));
        assert!(line.contains("healthy"));
        assert!(!line.contains("issue"));
    }

    #[test]
    fn report_to_json_structure() {
        let diags = vec![Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Network,
            severity: Severity::Critical,
            message: "Network down".to_owned(),
            fixes: vec![
                FixAction::command("Restart", "fwc restart test").safe(),
            ],
        }];
        let report = DiagnosticReport::from_diagnoses("test", diags);
        let json = report.to_json();
        assert_eq!(json["connector_id"], "test");
        assert_eq!(json["status"], "unhealthy");
        assert_eq!(json["diagnoses"][0]["category"], "network");
        assert_eq!(json["diagnoses"][0]["severity"], "critical");
        assert_eq!(json["diagnoses"][0]["fixes"][0]["auto_safe"], true);
    }

    #[test]
    fn report_clone_preserves_all_fields() {
        let diags = vec![Diagnosis {
            connector_id: "x".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "msg".to_owned(),
            fixes: vec![FixAction::command("f", "c").safe()],
        }];
        let report = DiagnosticReport::from_diagnoses("x", diags);
        #[allow(clippy::redundant_clone)]
        let cloned = report.clone();
        assert_eq!(cloned.connector_id, "x");
        assert_eq!(cloned.status, HealthStatus::Unhealthy);
        assert_eq!(cloned.diagnoses.len(), 1);
        assert!(cloned.diagnoses[0].fixes[0].auto_safe);
    }

    #[test]
    fn report_debug() {
        let report = DiagnosticReport::healthy("test");
        let debug = format!("{report:?}");
        assert!(debug.contains("DiagnosticReport"));
        assert!(debug.contains("Healthy"));
    }

    // ── compute_status expanded ──────────────────────────────────

    #[test]
    fn compute_status_multiple_warnings() {
        let diags = vec![
            Diagnosis {
                connector_id: "t".to_owned(),
                category: DiagnosisCategory::Latency,
                severity: Severity::Warning,
                message: "slow".to_owned(),
                fixes: vec![],
            },
            Diagnosis {
                connector_id: "t".to_owned(),
                category: DiagnosisCategory::RateLimit,
                severity: Severity::Warning,
                message: "high".to_owned(),
                fixes: vec![],
            },
        ];
        assert_eq!(compute_status(&diags), HealthStatus::Degraded);
    }

    #[test]
    fn compute_status_error_overrides_warning() {
        let diags = vec![
            Diagnosis {
                connector_id: "t".to_owned(),
                category: DiagnosisCategory::Latency,
                severity: Severity::Warning,
                message: "slow".to_owned(),
                fixes: vec![],
            },
            Diagnosis {
                connector_id: "t".to_owned(),
                category: DiagnosisCategory::Auth,
                severity: Severity::Error,
                message: "fail".to_owned(),
                fixes: vec![],
            },
        ];
        assert_eq!(compute_status(&diags), HealthStatus::Unhealthy);
    }

    #[test]
    fn compute_status_critical_overrides_error() {
        let diags = vec![
            Diagnosis {
                connector_id: "t".to_owned(),
                category: DiagnosisCategory::Auth,
                severity: Severity::Error,
                message: "err".to_owned(),
                fixes: vec![],
            },
            Diagnosis {
                connector_id: "t".to_owned(),
                category: DiagnosisCategory::Network,
                severity: Severity::Critical,
                message: "crit".to_owned(),
                fixes: vec![],
            },
        ];
        assert_eq!(compute_status(&diags), HealthStatus::Unhealthy);
    }

    // ── diagnose() expanded ──────────────────────────────────────

    #[test]
    fn diagnose_not_found_has_install_fix() {
        let symptoms = Symptoms {
            installed: false,
            ..Default::default()
        };
        let report = diagnose("missing", &symptoms);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::NotFound);
        let cmds = report.all_fix_commands();
        assert!(cmds.iter().any(|c| c.contains("install")));
        assert!(cmds.iter().any(|c| c.contains("search")));
    }

    #[test]
    fn diagnose_no_credentials_has_auth_fix() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: false,
            ..Default::default()
        };
        let report = diagnose("test", &symptoms);
        let cmds = report.all_fix_commands();
        assert!(cmds.iter().any(|c| c.contains("auth add")));
        assert!(cmds.iter().any(|c| c.contains("auth list")));
    }

    #[test]
    fn diagnose_401_has_auth_test_fix() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(401);
        let report = diagnose("test", &symptoms);
        let cmds = report.all_fix_commands();
        assert!(cmds.iter().any(|c| c.contains("auth test")));
    }

    #[test]
    fn diagnose_403_has_show_fix() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(403);
        let report = diagnose("test", &symptoms);
        let cmds = report.all_fix_commands();
        assert!(cmds.iter().any(|c| c.contains("show")));
    }

    #[test]
    fn diagnose_429_has_rate_limits_fix() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(429);
        let report = diagnose("test", &symptoms);
        let cmds = report.all_fix_commands();
        assert!(cmds.iter().any(|c| c.contains("rate-limits")));
    }

    #[test]
    fn diagnose_500_has_no_commands_only_manual() {
        let mut symptoms = default_symptoms();
        symptoms.http_status = Some(500);
        let report = diagnose("test", &symptoms);
        assert!(report.all_fix_commands().is_empty());
        assert!(!report.diagnoses[0].fixes.is_empty());
    }

    #[test]
    fn diagnose_certificate_has_three_manual_fixes() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("SSL certificate error".to_owned());
        let report = diagnose("test", &symptoms);
        assert_eq!(report.diagnoses[0].fixes.len(), 3);
        assert!(report.diagnoses[0].fixes.iter().all(|f| f.command.is_none()));
    }

    #[test]
    fn diagnose_connection_refused_has_three_fixes() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("Connection refused by host".to_owned());
        let report = diagnose("test", &symptoms);
        assert_eq!(report.diagnoses[0].fixes.len(), 3);
    }

    #[test]
    fn diagnose_timeout_has_two_fixes() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("timed out waiting for response".to_owned());
        let report = diagnose("test", &symptoms);
        assert_eq!(report.diagnoses[0].fixes.len(), 2);
    }

    #[test]
    fn diagnose_dns_has_two_fixes() {
        let mut symptoms = default_symptoms();
        symptoms.error_message = Some("DNS lookup failed".to_owned());
        let report = diagnose("test", &symptoms);
        assert_eq!(report.diagnoses[0].fixes.len(), 2);
    }

    #[test]
    fn diagnose_rate_limit_95_has_rate_limits_fix() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(95);
        let report = diagnose("test", &symptoms);
        let cmds = report.all_fix_commands();
        assert!(cmds.iter().any(|c| c.contains("rate-limits")));
    }

    #[test]
    fn diagnose_rate_limit_85_has_rate_limits_fix() {
        let mut symptoms = default_symptoms();
        symptoms.rate_limit_percent = Some(85);
        let report = diagnose("test", &symptoms);
        let cmds = report.all_fix_commands();
        assert!(cmds.iter().any(|c| c.contains("rate-limits")));
    }

    // ── diagnose_http_status expanded ────────────────────────────

    #[test]
    fn diagnose_http_200_none() {
        assert!(diagnose_http_status("test", 200).is_none());
    }

    #[test]
    fn diagnose_http_301_none() {
        assert!(diagnose_http_status("test", 301).is_none());
    }

    #[test]
    fn diagnose_http_400_none() {
        assert!(diagnose_http_status("test", 400).is_none());
    }

    #[test]
    fn diagnose_http_404_none() {
        assert!(diagnose_http_status("test", 404).is_none());
    }

    #[test]
    fn diagnose_http_401_critical() {
        let diag = diagnose_http_status("test", 401).unwrap();
        assert_eq!(diag.severity, Severity::Critical);
        assert_eq!(diag.category, DiagnosisCategory::Auth);
        assert!(diag.message.contains("401"));
    }

    #[test]
    fn diagnose_http_403_error() {
        let diag = diagnose_http_status("test", 403).unwrap();
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.category, DiagnosisCategory::Auth);
        assert!(diag.message.contains("403"));
    }

    #[test]
    fn diagnose_http_429_warning() {
        let diag = diagnose_http_status("test", 429).unwrap();
        assert_eq!(diag.severity, Severity::Warning);
        assert_eq!(diag.category, DiagnosisCategory::RateLimit);
    }

    #[test]
    fn diagnose_http_500_error() {
        let diag = diagnose_http_status("test", 500).unwrap();
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.category, DiagnosisCategory::ServiceError);
    }

    #[test]
    fn diagnose_http_502_error() {
        let diag = diagnose_http_status("test", 502).unwrap();
        assert!(diag.message.contains("502"));
    }

    #[test]
    fn diagnose_http_503_error() {
        let diag = diagnose_http_status("test", 503).unwrap();
        assert!(diag.message.contains("503"));
    }

    #[test]
    fn diagnose_http_599_error() {
        let diag = diagnose_http_status("test", 599).unwrap();
        assert_eq!(diag.category, DiagnosisCategory::ServiceError);
    }

    // ── diagnose_error_message expanded ──────────────────────────

    #[test]
    fn diagnose_error_message_none_for_empty() {
        assert!(diagnose_error_message("test", "").is_none());
    }

    #[test]
    fn diagnose_error_message_none_for_generic() {
        assert!(diagnose_error_message("test", "something broke").is_none());
    }

    #[test]
    fn diagnose_error_message_certificate_case_insensitive() {
        let diag = diagnose_error_message("test", "CERTIFICATE VERIFY FAILED").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Certificate);
    }

    #[test]
    fn diagnose_error_message_tls_keyword() {
        let diag = diagnose_error_message("test", "tls negotiation failed").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Certificate);
    }

    #[test]
    fn diagnose_error_message_connection_refused_exact() {
        let diag = diagnose_error_message("test", "connection refused").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Network);
        assert_eq!(diag.severity, Severity::Critical);
    }

    #[test]
    fn diagnose_error_message_connect_error_prefix() {
        let diag = diagnose_error_message("test", "connect error: no route to host").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Network);
    }

    #[test]
    fn diagnose_error_message_timeout_keyword() {
        let diag = diagnose_error_message("test", "request timeout after 30 seconds").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Latency);
    }

    #[test]
    fn diagnose_error_message_timed_out_keyword() {
        let diag = diagnose_error_message("test", "operation timed out").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Latency);
    }

    #[test]
    fn diagnose_error_message_dns_keyword() {
        let diag = diagnose_error_message("test", "DNS resolution error").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Network);
        assert_eq!(diag.severity, Severity::Critical);
    }

    #[test]
    fn diagnose_error_message_resolve_keyword() {
        let diag = diagnose_error_message("test", "could not resolve hostname").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Network);
    }

    #[test]
    fn diagnose_error_message_ssl_keyword() {
        let diag = diagnose_error_message("test", "SSL error occurred").unwrap();
        assert_eq!(diag.category, DiagnosisCategory::Certificate);
    }

    #[test]
    fn diagnose_error_message_preserves_connector_id() {
        let diag = diagnose_error_message("my-connector", "connection refused").unwrap();
        assert_eq!(diag.connector_id, "my-connector");
    }

    #[test]
    fn diagnose_error_message_preserves_original_message() {
        let original = "SSL certificate expired for api.example.com";
        let diag = diagnose_error_message("test", original).unwrap();
        assert!(diag.message.contains(original));
    }

    // ── diagnose_latency expanded ────────────────────────────────

    #[test]
    fn diagnose_latency_0() {
        assert!(diagnose_latency("test", 0).is_none());
    }

    #[test]
    fn diagnose_latency_1999() {
        assert!(diagnose_latency("test", 1999).is_none());
    }

    #[test]
    fn diagnose_latency_2000_none() {
        assert!(diagnose_latency("test", 2000).is_none());
    }

    #[test]
    fn diagnose_latency_2001_warning() {
        let diag = diagnose_latency("test", 2001).unwrap();
        assert_eq!(diag.severity, Severity::Warning);
        assert!(diag.message.contains("2001"));
    }

    #[test]
    fn diagnose_latency_5000_warning() {
        let diag = diagnose_latency("test", 5000).unwrap();
        assert_eq!(diag.severity, Severity::Warning);
    }

    #[test]
    fn diagnose_latency_5001_error() {
        let diag = diagnose_latency("test", 5001).unwrap();
        assert_eq!(diag.severity, Severity::Error);
        assert!(diag.message.contains("5001"));
    }

    #[test]
    fn diagnose_latency_max_u64() {
        let diag = diagnose_latency("test", u64::MAX).unwrap();
        assert_eq!(diag.severity, Severity::Error);
    }

    #[test]
    fn diagnose_latency_preserves_connector_id() {
        let diag = diagnose_latency("my-conn", 10_000).unwrap();
        assert_eq!(diag.connector_id, "my-conn");
    }

    // ── diagnose_rate_limit expanded ─────────────────────────────

    #[test]
    fn diagnose_rate_limit_0() {
        assert!(diagnose_rate_limit("test", 0).is_none());
    }

    #[test]
    fn diagnose_rate_limit_50() {
        assert!(diagnose_rate_limit("test", 50).is_none());
    }

    #[test]
    fn diagnose_rate_limit_79_none() {
        assert!(diagnose_rate_limit("test", 79).is_none());
    }

    #[test]
    fn diagnose_rate_limit_80_warning() {
        let diag = diagnose_rate_limit("test", 80).unwrap();
        assert_eq!(diag.severity, Severity::Warning);
        assert!(diag.message.contains("80%"));
    }

    #[test]
    fn diagnose_rate_limit_94_warning() {
        let diag = diagnose_rate_limit("test", 94).unwrap();
        assert_eq!(diag.severity, Severity::Warning);
    }

    #[test]
    fn diagnose_rate_limit_95_critical() {
        let diag = diagnose_rate_limit("test", 95).unwrap();
        assert_eq!(diag.severity, Severity::Critical);
        assert!(diag.message.contains("95%"));
    }

    #[test]
    fn diagnose_rate_limit_100_critical() {
        let diag = diagnose_rate_limit("test", 100).unwrap();
        assert_eq!(diag.severity, Severity::Critical);
    }

    #[test]
    fn diagnose_rate_limit_preserves_connector_id() {
        let diag = diagnose_rate_limit("my-conn", 99).unwrap();
        assert_eq!(diag.connector_id, "my-conn");
    }

    // ── Symptoms expanded ────────────────────────────────────────

    #[test]
    fn symptoms_all_fields_set() {
        let s = Symptoms {
            http_status: Some(200),
            error_message: Some("msg".to_owned()),
            latency_ms: Some(100),
            installed: true,
            has_credentials: true,
            rate_limit_percent: Some(50),
            last_op_success: Some(true),
        };
        assert!(s.installed);
        assert!(s.has_credentials);
        assert_eq!(s.http_status, Some(200));
        assert_eq!(s.error_message, Some("msg".to_owned()));
        assert_eq!(s.latency_ms, Some(100));
        assert_eq!(s.rate_limit_percent, Some(50));
        assert_eq!(s.last_op_success, Some(true));
    }

    #[test]
    fn symptoms_debug() {
        let s = Symptoms::default();
        let debug = format!("{s:?}");
        assert!(debug.contains("Symptoms"));
    }

    #[test]
    fn symptoms_clone_independence() {
        let mut s = Symptoms {
            installed: true,
            has_credentials: true,
            http_status: Some(200),
            ..Default::default()
        };
        let cloned = s.clone();
        s.http_status = Some(500);
        assert_eq!(cloned.http_status, Some(200));
    }

    // ── Diagnosis expanded ───────────────────────────────────────

    #[test]
    fn diagnosis_serialize_all_fields() {
        let diag = Diagnosis {
            connector_id: "github".to_owned(),
            category: DiagnosisCategory::Network,
            severity: Severity::Critical,
            message: "Network is down".to_owned(),
            fixes: vec![
                FixAction::command("Restart", "fwc restart").safe(),
                FixAction::manual("Check cables").with_url("https://example.com"),
            ],
        };
        let json = serde_json::to_value(&diag).unwrap();
        assert_eq!(json["connector_id"], "github");
        assert_eq!(json["category"], "network");
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["message"], "Network is down");
        assert_eq!(json["fixes"].as_array().unwrap().len(), 2);
        assert_eq!(json["fixes"][0]["auto_safe"], true);
        assert_eq!(json["fixes"][1]["reference_url"], "https://example.com");
    }

    #[test]
    fn diagnosis_empty_fixes() {
        let diag = Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Unknown,
            severity: Severity::Info,
            message: "Unknown issue".to_owned(),
            fixes: vec![],
        };
        let json = serde_json::to_value(&diag).unwrap();
        assert!(json["fixes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn diagnosis_clone_independence() {
        let diag = Diagnosis {
            connector_id: "test".to_owned(),
            category: DiagnosisCategory::Auth,
            severity: Severity::Error,
            message: "auth".to_owned(),
            fixes: vec![FixAction::manual("fix")],
        };
        let mut cloned = diag.clone();
        cloned.message = "changed".to_owned();
        assert_eq!(diag.message, "auth");
        assert_eq!(cloned.message, "changed");
    }

    // ── diagnose() combo flows ───────────────────────────────────

    #[test]
    fn diagnose_all_symptoms_at_once() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: false,
            http_status: Some(401),
            error_message: Some("connection refused".to_owned()),
            latency_ms: Some(10_000),
            rate_limit_percent: Some(99),
            last_op_success: Some(false),
        };
        let report = diagnose("test", &symptoms);
        assert_eq!(report.status, HealthStatus::Unhealthy);
        // Should have: no credentials + 401 + connection refused + latency + rate limit
        assert!(report.diagnoses.len() >= 5);
    }

    #[test]
    fn diagnose_only_latency_symptom() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: true,
            latency_ms: Some(3000),
            ..Default::default()
        };
        let report = diagnose("test", &symptoms);
        assert_eq!(report.diagnoses.len(), 1);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::Latency);
        assert_eq!(report.status, HealthStatus::Degraded);
    }

    #[test]
    fn diagnose_only_rate_limit_symptom() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: true,
            rate_limit_percent: Some(96),
            ..Default::default()
        };
        let report = diagnose("test", &symptoms);
        assert_eq!(report.diagnoses.len(), 1);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::RateLimit);
        assert_eq!(report.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn diagnose_error_message_plus_http_status() {
        let symptoms = Symptoms {
            installed: true,
            has_credentials: true,
            http_status: Some(500),
            error_message: Some("SSL error".to_owned()),
            ..Default::default()
        };
        let report = diagnose("test", &symptoms);
        // Both 500 and SSL error should be diagnosed
        assert!(report.diagnoses.len() >= 2);
        let categories: Vec<_> = report.diagnoses.iter().map(|d| d.category).collect();
        assert!(categories.contains(&DiagnosisCategory::ServiceError));
        assert!(categories.contains(&DiagnosisCategory::Certificate));
    }

    #[test]
    fn diagnose_connector_id_propagated() {
        let symptoms = Symptoms {
            installed: false,
            ..Default::default()
        };
        let report = diagnose("my-specific-connector", &symptoms);
        assert_eq!(report.connector_id, "my-specific-connector");
        assert_eq!(report.diagnoses[0].connector_id, "my-specific-connector");
    }

    #[test]
    fn diagnose_not_installed_ignores_all_other_symptoms() {
        let symptoms = Symptoms {
            installed: false,
            has_credentials: false,
            http_status: Some(500),
            error_message: Some("SSL error".to_owned()),
            latency_ms: Some(10_000),
            rate_limit_percent: Some(100),
            last_op_success: Some(false),
        };
        let report = diagnose("test", &symptoms);
        assert_eq!(report.diagnoses.len(), 1);
        assert_eq!(report.diagnoses[0].category, DiagnosisCategory::NotFound);
    }
}
