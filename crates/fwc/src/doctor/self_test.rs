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

const FORBIDDEN_COMMAND_SUBSTRINGS: &[&str] = &[
    "am service restart",
    "am service stop",
    "am doctor fix",
    "am doctor repair",
    "am doctor reconstruct",
];

fn reject_forbidden_agent_mail_remediation(remediation: &str) -> Result<()> {
    let normalized = remediation.to_ascii_lowercase();
    for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS {
        if let Some(idx) = normalized.find(forbidden)
            && !preceded_by_negator(&normalized, idx)
        {
            bail!(
                "doctor self-test fixture remediation suggests forbidden Agent Mail command: {forbidden}"
            );
        }
    }
    if mentions_killing_agent_mail(&normalized) {
        bail!(
            "doctor self-test fixture remediation suggests killing an Agent Mail process; forbidden by AGENTS.md"
        );
    }
    Ok(())
}

const NEGATORS: &[&str] = &[
    "do not",
    "don't",
    "never",
    "must not",
    "mustn't",
    "forbidden",
];

fn preceded_by_negator(normalized: &str, idx: usize) -> bool {
    let mut window_start = idx.saturating_sub(60);
    while window_start < idx && !normalized.is_char_boundary(window_start) {
        window_start += 1;
    }
    let window = &normalized[window_start..idx];
    NEGATORS.iter().any(|n| window.contains(n))
}

fn mentions_killing_agent_mail(normalized: &str) -> bool {
    const KILL_VERBS: &[&str] = &["kill ", "pkill ", "killall "];
    const AM_TARGETS: &[&str] = &[
        "am service",
        "am serve-http",
        "mcp-agent-mail",
        "agent-mail",
        "agent mail",
    ];
    let mut cursor = 0;
    while let Some(rel) = normalized[cursor..].find(['k', 'p']) {
        let pos = cursor + rel;
        let Some(verb) = KILL_VERBS
            .iter()
            .find(|v| normalized[pos..].starts_with(*v))
        else {
            cursor = pos + 1;
            continue;
        };
        cursor = pos + verb.len();
        if preceded_by_negator(normalized, pos) {
            continue;
        }
        let mut scan_end = (cursor + 80).min(normalized.len());
        while scan_end < normalized.len() && !normalized.is_char_boundary(scan_end) {
            scan_end += 1;
        }
        let mut window = &normalized[cursor..scan_end];
        // Stop at the first clause/sentence delimiter — a `kill` verb only binds
        // to its direct object in the same clause, not to a downstream mention.
        if let Some(stop) = window.find([';', '.', '\n', '!']) {
            window = &window[..stop];
        }
        if AM_TARGETS.iter().any(|t| window.contains(t)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod reject_remediation_tests {
    use super::reject_forbidden_agent_mail_remediation;

    #[test]
    fn allows_remediation_that_negates_restart_of_shared_service() {
        // Verbatim from broken_env/self_test.toml.
        let r =
            "agent-mail: retry once, then continue degraded; do not restart the shared service.";
        reject_forbidden_agent_mail_remediation(r).expect("must allow negated remediation");
    }

    #[test]
    fn allows_remediation_targeting_a_different_subsystem() {
        // Earlier heuristic falsely rejected any "agent-mail" + "restart" combo
        // even when the restart applied to a different subsystem.
        let r = "agent-mail reported a degraded host; restart fcp-host (NOT the am service).";
        reject_forbidden_agent_mail_remediation(r).expect("restart applies to fcp-host, not am");
    }

    #[test]
    fn allows_remediation_with_contraction_negator() {
        let r = "If agent-mail flakes, don't run am service restart; wait for self-heal.";
        reject_forbidden_agent_mail_remediation(r).expect("contraction negator must be honored");
    }

    #[test]
    fn rejects_unnegated_am_service_restart() {
        let r = "If agent-mail is down, run am service restart.";
        assert!(reject_forbidden_agent_mail_remediation(r).is_err());
    }

    #[test]
    fn rejects_each_forbidden_am_doctor_command() {
        for forbidden in [
            "run am doctor fix",
            "execute am doctor repair if degraded",
            "operator: am doctor reconstruct",
            "perform am service stop and restart",
        ] {
            assert!(
                reject_forbidden_agent_mail_remediation(forbidden).is_err(),
                "expected rejection for: {forbidden}"
            );
        }
    }

    #[test]
    fn rejects_killing_agent_mail_process() {
        let r = "find the pid and kill the mcp-agent-mail process";
        assert!(reject_forbidden_agent_mail_remediation(r).is_err());
    }

    #[test]
    fn allows_negated_kill_phrasing() {
        let r = "Never kill the mcp-agent-mail process; restart fcp-host instead.";
        reject_forbidden_agent_mail_remediation(r).expect("negated kill must be allowed");
    }

    #[test]
    fn ignores_kill_unrelated_to_agent_mail() {
        let r = "kill -9 any stuck fcp-host child; agent-mail is unaffected.";
        reject_forbidden_agent_mail_remediation(r).expect("unrelated kill must be allowed");
    }

    #[test]
    fn does_not_panic_on_multibyte_input_near_window() {
        // Non-ASCII near the forbidden substring exercises char-boundary safety
        // in the negator window. Must not panic regardless of verdict.
        let r = "café ☕ — operators must not run am service restart on the mesh.";
        reject_forbidden_agent_mail_remediation(r).expect("negated by 'must not'");
    }
}
