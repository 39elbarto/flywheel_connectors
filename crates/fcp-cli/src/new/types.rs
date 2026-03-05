//! Types for `fcp new` command output.
//!
//! These types represent scaffold generation results and compliance check output.

use serde::{Deserialize, Serialize};

/// Archetype classification for connectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorArchetype {
    /// Request-response pattern (most APIs).
    RequestResponse,
    /// Continuous data streaming (SSE, WebSocket).
    Streaming,
    /// Full-duplex real-time communication.
    Bidirectional,
    /// Periodic data fetch (getUpdates).
    Polling,
    /// Receives callbacks from external services.
    Webhook,
    /// Message queue integration (SQS, `RabbitMQ`).
    Queue,
    /// File/blob storage operations.
    File,
    /// Database read/write operations.
    Database,
    /// CLI or command execution wrapper.
    Cli,
    /// Browser automation or scraping.
    Browser,
}

impl std::fmt::Display for ConnectorArchetype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestResponse => write!(f, "request-response"),
            Self::Streaming => write!(f, "streaming"),
            Self::Bidirectional => write!(f, "bidirectional"),
            Self::Polling => write!(f, "polling"),
            Self::Webhook => write!(f, "webhook"),
            Self::Queue => write!(f, "queue"),
            Self::File => write!(f, "file"),
            Self::Database => write!(f, "database"),
            Self::Cli => write!(f, "cli"),
            Self::Browser => write!(f, "browser"),
        }
    }
}

impl std::str::FromStr for ConnectorArchetype {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "request-response" | "requestresponse" => Ok(Self::RequestResponse),
            "streaming" => Ok(Self::Streaming),
            "bidirectional" => Ok(Self::Bidirectional),
            "polling" => Ok(Self::Polling),
            "webhook" => Ok(Self::Webhook),
            "queue" => Ok(Self::Queue),
            "file" => Ok(Self::File),
            "database" => Ok(Self::Database),
            "cli" => Ok(Self::Cli),
            "browser" => Ok(Self::Browser),
            _ => Err(format!("unknown archetype: {s}")),
        }
    }
}

/// Result of scaffold generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaffoldResult {
    /// Connector name/ID.
    pub connector_id: String,
    /// Path to generated crate.
    pub crate_path: String,
    /// Files created during scaffolding.
    pub files_created: Vec<CreatedFile>,
    /// Compliance precheck results.
    pub prechecks: PrecheckResults,
    /// Next steps for the developer.
    pub next_steps: Vec<String>,
}

/// A file created during scaffolding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedFile {
    /// Relative path from crate root.
    pub path: String,
    /// Purpose of this file.
    pub purpose: String,
    /// Size in bytes.
    pub size: usize,
}

/// Results of compliance prechecks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecheckResults {
    /// Overall pass/fail status.
    pub passed: bool,
    /// Individual check results.
    pub checks: Vec<PrecheckItem>,
    /// Summary counts.
    pub summary: PrecheckSummary,
}

impl PrecheckResults {
    /// Create a new passed precheck result.
    pub fn passed(checks: Vec<PrecheckItem>) -> Self {
        let passed = checks.iter().all(|c| c.passed);
        let summary = PrecheckSummary::from_checks(&checks);
        Self {
            passed,
            checks,
            summary,
        }
    }
}

/// A single compliance precheck.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecheckItem {
    /// Check identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Pass/fail status.
    pub passed: bool,
    /// Detailed message (especially for failures).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Severity level.
    pub severity: CheckSeverity,
}

/// Severity level for precheck items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverity {
    /// Must pass for compliance.
    Error,
    /// Should pass but not blocking.
    Warning,
    /// Informational only.
    Info,
}

/// Summary of precheck results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecheckSummary {
    /// Total checks run.
    pub total: usize,
    /// Checks that passed.
    pub passed: usize,
    /// Checks that failed.
    pub failed: usize,
    /// Checks with warnings.
    pub warnings: usize,
}

impl PrecheckSummary {
    /// Build summary from checks.
    pub fn from_checks(checks: &[PrecheckItem]) -> Self {
        let total = checks.len();
        let passed = checks.iter().filter(|c| c.passed).count();
        let failed = checks
            .iter()
            .filter(|c| !c.passed && c.severity == CheckSeverity::Error)
            .count();
        let warnings = checks
            .iter()
            .filter(|c| !c.passed && c.severity == CheckSeverity::Warning)
            .count();
        Self {
            total,
            passed,
            failed,
            warnings,
        }
    }
}

/// Result of running `fcp new --check` on an existing connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Connector directory checked.
    pub path: String,
    /// Connector ID from manifest (if found).
    pub connector_id: Option<String>,
    /// Compliance check results.
    pub prechecks: PrecheckResults,
    /// Suggested fixes for failed checks.
    pub suggested_fixes: Vec<SuggestedFix>,
}

/// A suggested fix for a failed check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedFix {
    /// Related check ID.
    pub check_id: String,
    /// What to do.
    pub action: String,
    /// File to modify (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archetype_roundtrip() {
        for arch in [
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
            ConnectorArchetype::Queue,
            ConnectorArchetype::File,
            ConnectorArchetype::Database,
            ConnectorArchetype::Cli,
            ConnectorArchetype::Browser,
        ] {
            let s = arch.to_string();
            let parsed: ConnectorArchetype = s.parse().expect("should parse");
            assert_eq!(arch, parsed);
        }
    }

    #[test]
    fn precheck_summary_counts() {
        let checks = vec![
            PrecheckItem {
                id: "check1".to_string(),
                description: "Check 1".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Error,
            },
            PrecheckItem {
                id: "check2".to_string(),
                description: "Check 2".to_string(),
                passed: false,
                message: Some("Failed".to_string()),
                severity: CheckSeverity::Error,
            },
            PrecheckItem {
                id: "check3".to_string(),
                description: "Check 3".to_string(),
                passed: false,
                message: Some("Warning".to_string()),
                severity: CheckSeverity::Warning,
            },
        ];

        let summary = PrecheckSummary::from_checks(&checks);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.warnings, 1);
    }

    #[test]
    fn scaffold_result_serialization() {
        let result = ScaffoldResult {
            connector_id: "fcp.myservice".to_string(),
            crate_path: "connectors/myservice".to_string(),
            files_created: vec![CreatedFile {
                path: "Cargo.toml".to_string(),
                purpose: "Crate manifest".to_string(),
                size: 512,
            }],
            prechecks: PrecheckResults::passed(vec![PrecheckItem {
                id: "manifest.valid".to_string(),
                description: "Manifest is valid TOML".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Error,
            }]),
            next_steps: vec!["Fill in placeholder operations".to_string()],
        };

        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("fcp.myservice"));
        assert!(json.contains("Cargo.toml"));
    }

    // ---- ConnectorArchetype ----

    #[test]
    fn archetype_from_str_case_insensitive() {
        assert!("REQUEST-RESPONSE".parse::<ConnectorArchetype>().is_ok());
        assert!("Streaming".parse::<ConnectorArchetype>().is_ok());
        assert!("POLLING".parse::<ConnectorArchetype>().is_ok());
    }

    #[test]
    fn archetype_from_str_unknown() {
        let result = "unknown".parse::<ConnectorArchetype>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown archetype"));
    }

    #[test]
    fn archetype_from_str_request_response_alias() {
        // "requestresponse" (no hyphen) should also work
        assert!("requestresponse".parse::<ConnectorArchetype>().is_ok());
    }

    #[test]
    fn archetype_display_all_variants() {
        let variants = [
            (ConnectorArchetype::RequestResponse, "request-response"),
            (ConnectorArchetype::Streaming, "streaming"),
            (ConnectorArchetype::Bidirectional, "bidirectional"),
            (ConnectorArchetype::Polling, "polling"),
            (ConnectorArchetype::Webhook, "webhook"),
            (ConnectorArchetype::Queue, "queue"),
            (ConnectorArchetype::File, "file"),
            (ConnectorArchetype::Database, "database"),
            (ConnectorArchetype::Cli, "cli"),
            (ConnectorArchetype::Browser, "browser"),
        ];
        for (variant, expected) in variants {
            assert_eq!(variant.to_string(), expected);
        }
    }

    #[test]
    fn archetype_serde_roundtrip() {
        let arch = ConnectorArchetype::Bidirectional;
        let json = serde_json::to_string(&arch).unwrap();
        assert_eq!(json, "\"bidirectional\"");
        let parsed: ConnectorArchetype = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, arch);
    }

    // ---- PrecheckResults ----

    #[test]
    fn precheck_results_all_pass() {
        let checks = vec![
            PrecheckItem {
                id: "a".to_string(),
                description: "A".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Error,
            },
            PrecheckItem {
                id: "b".to_string(),
                description: "B".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Warning,
            },
        ];
        let result = PrecheckResults::passed(checks);
        assert!(result.passed);
        assert_eq!(result.summary.total, 2);
        assert_eq!(result.summary.passed, 2);
        assert_eq!(result.summary.failed, 0);
        assert_eq!(result.summary.warnings, 0);
    }

    #[test]
    fn precheck_results_warning_only_still_fails() {
        let checks = vec![PrecheckItem {
            id: "w".to_string(),
            description: "W".to_string(),
            passed: false,
            message: Some("warn".to_string()),
            severity: CheckSeverity::Warning,
        }];
        let result = PrecheckResults::passed(checks);
        assert!(!result.passed);
        assert_eq!(result.summary.warnings, 1);
        assert_eq!(result.summary.failed, 0);
    }

    // ---- CheckSeverity ----

    #[test]
    fn check_severity_serde() {
        let json = serde_json::to_string(&CheckSeverity::Error).unwrap();
        assert_eq!(json, "\"error\"");
        let json = serde_json::to_string(&CheckSeverity::Warning).unwrap();
        assert_eq!(json, "\"warning\"");
        let json = serde_json::to_string(&CheckSeverity::Info).unwrap();
        assert_eq!(json, "\"info\"");
    }

    // ---- CheckResult ----

    #[test]
    fn check_result_serialization() {
        let result = CheckResult {
            path: "/tmp/test".to_string(),
            connector_id: Some("fcp.test".to_string()),
            prechecks: PrecheckResults::passed(vec![]),
            suggested_fixes: vec![SuggestedFix {
                check_id: "manifest.valid".to_string(),
                action: "Fix it".to_string(),
                file: Some("manifest.toml".to_string()),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("fcp.test"));
        assert!(json.contains("Fix it"));
        assert!(json.contains("manifest.toml"));
    }

    #[test]
    fn check_result_no_connector_id() {
        let result = CheckResult {
            path: "/tmp/test".to_string(),
            connector_id: None,
            prechecks: PrecheckResults::passed(vec![]),
            suggested_fixes: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"connector_id\":null"));
    }

    // ---- SuggestedFix ----

    #[test]
    fn suggested_fix_without_file_skips_field() {
        let fix = SuggestedFix {
            check_id: "test".to_string(),
            action: "Do something".to_string(),
            file: None,
        };
        let json = serde_json::to_string(&fix).unwrap();
        assert!(!json.contains("file"));
    }

    // ---- CreatedFile ----

    #[test]
    fn created_file_serde() {
        let file = CreatedFile {
            path: "src/main.rs".to_string(),
            purpose: "Entrypoint".to_string(),
            size: 1024,
        };
        let json = serde_json::to_string(&file).unwrap();
        let parsed: CreatedFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path, "src/main.rs");
        assert_eq!(parsed.size, 1024);
    }

    // ---- PrecheckItem ----

    #[test]
    fn precheck_item_message_skipped_when_none() {
        let item = PrecheckItem {
            id: "test".to_string(),
            description: "Test".to_string(),
            passed: true,
            message: None,
            severity: CheckSeverity::Info,
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("message"));
    }
}
