//! Fixture-backed `fwc doctor self-test` reports.

#![allow(clippy::module_name_repetitions)]

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::info;

const FIXTURE_FILE: &str = "self_test.toml";

/// Overall fixture self-test status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfTestStatus {
    /// All checks passed.
    Ok,
    /// At least one check degraded but no check failed.
    Warn,
    /// At least one check failed.
    Fail,
}

/// Per-check fixture verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckVerdict {
    /// The check passed.
    Pass,
    /// The check produced a warning.
    Warn,
    /// The check failed.
    Fail,
}

/// One check evaluated from a doctor self-test fixture.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelfTestCheck {
    /// Stable check name.
    pub name: String,
    /// Subsystem covered by this check.
    pub subsystem: String,
    /// Fixture verdict.
    pub verdict: CheckVerdict,
    /// Synthetic latency for score calibration.
    pub latency_ms: u64,
    /// Operator-facing result message.
    pub message: String,
    /// Optional operator-gated remediation command or instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Whether this remediation may be applied automatically.
    pub auto_repair: bool,
    /// Score penalty applied by this check.
    pub score_penalty: u16,
}

/// Full fixture self-test report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelfTestReport {
    /// Fixture directory used as input.
    pub fixture: String,
    /// Fixture name from metadata.
    pub fixture_name: String,
    /// Calibrated doctor score, from 0 to 1000.
    pub score: u16,
    /// Overall fixture status.
    pub status: SelfTestStatus,
    /// Per-check results.
    pub checks: Vec<SelfTestCheck>,
    /// Remediation messages for non-passing checks.
    pub remediation_messages: Vec<String>,
    /// Commands the self-test executed. This must remain empty for fixture mode.
    pub executed_commands: Vec<String>,
    /// Safety assertions enforced by fixture mode.
    pub safety_assertions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SelfTestFixture {
    fixture: FixtureMetadata,
    checks: Vec<FixtureCheck>,
}

#[derive(Debug, Deserialize)]
struct FixtureMetadata {
    name: String,
}

#[derive(Debug, Deserialize)]
struct FixtureCheck {
    name: String,
    subsystem: String,
    verdict: CheckVerdict,
    latency_ms: u64,
    message: String,
    remediation: Option<String>,
    #[serde(default)]
    auto_repair: bool,
    #[serde(default)]
    score_penalty: u16,
}

/// Run the doctor self-test against a fixture directory.
///
/// # Errors
///
/// Returns an error if the fixture cannot be read, cannot be parsed, has no
/// checks, or contains a remediation that would violate Agent Mail process
/// protection rules.
pub fn run_self_test(fixture: &Path) -> Result<SelfTestReport> {
    let config_path = fixture.join(FIXTURE_FILE);
    let config_text = fs::read_to_string(&config_path).with_context(|| {
        format!(
            "failed to read doctor self-test fixture {}",
            config_path.display()
        )
    })?;
    let fixture_config: SelfTestFixture = toml::from_str(&config_text).with_context(|| {
        format!(
            "failed to parse doctor self-test fixture {}",
            config_path.display()
        )
    })?;

    if fixture_config.checks.is_empty() {
        bail!(
            "doctor self-test fixture {} must define at least one check",
            config_path.display()
        );
    }

    let mut checks = Vec::with_capacity(fixture_config.checks.len());
    for check in fixture_config.checks {
        if let Some(remediation) = &check.remediation {
            reject_forbidden_agent_mail_remediation(remediation)?;
        }
        info!(
            target: "fwc.doctor.self_test",
            check_name = %check.name,
            subsystem = %check.subsystem,
            verdict = ?check.verdict,
            latency_ms = check.latency_ms,
            remediation_cmd = check.remediation.as_deref(),
            "doctor self-test check evaluated"
        );
        checks.push(SelfTestCheck {
            name: check.name,
            subsystem: check.subsystem,
            verdict: check.verdict,
            latency_ms: check.latency_ms,
            message: check.message,
            remediation: check.remediation,
            auto_repair: check.auto_repair,
            score_penalty: check.score_penalty,
        });
    }

    let remediation_messages = remediation_messages(&checks);
    Ok(SelfTestReport {
        fixture: fixture.display().to_string(),
        fixture_name: fixture_config.fixture.name,
        score: score(&checks),
        status: status(&checks),
        checks,
        remediation_messages,
        executed_commands: Vec::new(),
        safety_assertions: vec![
            "fixture mode does not spawn subprocesses".to_owned(),
            "fixture mode never restarts the shared Agent Mail service".to_owned(),
            "beads WAL repair remains operator-gated".to_owned(),
        ],
    })
}

fn remediation_messages(checks: &[SelfTestCheck]) -> Vec<String> {
    checks
        .iter()
        .filter(|check| check.verdict != CheckVerdict::Pass)
        .map(|check| {
            let remediation = check
                .remediation
                .as_deref()
                .unwrap_or("inspect manually; no automatic repair is available");
            format!("[{}] {remediation}", check.subsystem)
        })
        .collect()
}

fn score(checks: &[SelfTestCheck]) -> u16 {
    checks.iter().fold(1_000_u16, |remaining, check| {
        remaining.saturating_sub(check.score_penalty)
    })
}

fn status(checks: &[SelfTestCheck]) -> SelfTestStatus {
    if checks
        .iter()
        .any(|check| check.verdict == CheckVerdict::Fail)
    {
        SelfTestStatus::Fail
    } else if checks
        .iter()
        .any(|check| check.verdict == CheckVerdict::Warn)
    {
        SelfTestStatus::Warn
    } else {
        SelfTestStatus::Ok
    }
}

fn reject_forbidden_agent_mail_remediation(remediation: &str) -> Result<()> {
    let normalized = remediation.to_ascii_lowercase();
    let mentions_agent_mail = normalized.contains("agent mail")
        || normalized.contains("agent-mail")
        || normalized.contains("am service")
        || normalized.contains("mcp-agent-mail");
    if mentions_agent_mail {
        for operation in ["restart", "repair", "reconstruct", "kill"] {
            if normalized.contains(operation)
                && !explicitly_forbids_agent_mail_operation(&normalized, operation)
            {
                bail!("doctor self-test fixture contains forbidden Agent Mail remediation text");
            }
        }
    }
    Ok(())
}

fn explicitly_forbids_agent_mail_operation(normalized: &str, operation: &str) -> bool {
    normalized.contains(&format!("do not {operation}"))
        || normalized.contains(&format!("never {operation}"))
        || normalized.contains(&format!("must not {operation}"))
}
