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
}
