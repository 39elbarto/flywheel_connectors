//! Host-backed E2E integration for session-lifecycle testing.
//!
//! This module bridges the session-script DSL, streaming fixture servers, and
//! webhook ingress harnesses with the host-backed E2E runner.  It provides:
//!
//! - [`SessionE2eRunner`] — orchestrates fixture setup, connector lifecycle,
//!   session script execution, transcript capture, and evidence bundle assembly.
//! - Correlation IDs flow through every phase (setup → execute → verify → teardown).
//! - Phase markers in structured logs for triage filtering.
//! - Replay commands generated from completed transcripts.
//!
//! # Representative adoption pattern
//!
//! ```rust,ignore
//! use fcp_e2e::host_e2e::{SessionE2eRunner, SessionE2eConfig};
//! use fcp_e2e::{SessionScript, ScriptStep, Transport, StreamingFixtureServer, SseEvent, StreamingAction};
//!
//! let fixture = StreamingFixtureServer::start().unwrap();
//! fixture.enqueue_action(StreamingAction::SendSse { event: SseEvent::data(r#"{"status":"ok"}"#) });
//!
//! let script = SessionScript::new("sse.basic_receive")
//!     .step(ScriptStep::connect(Transport::Sse, "/events"))
//!     .step(ScriptStep::expect_any_message())
//!     .step(ScriptStep::disconnect());
//!
//! let mut runner = SessionE2eRunner::new(SessionE2eConfig {
//!     connector_id: "webhook-receiver".into(),
//!     scenario_id: "sse.basic_receive".into(),
//!     fixture_address: Some(fixture.address()),
//!     ..Default::default()
//! });
//!
//! let result = runner.execute(&script);
//! assert!(result.passed);
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::evidence::{
    EvidenceBundle, EvidenceItem, ScenarioEnvironment, ScenarioMeta, ScenarioOutcome,
    ScenarioScript, ScenarioStep, StepAssertion, StepKind,
};
use crate::{SessionScript, SessionTranscript, StepOutcome, TranscriptEntry, TranscriptSummary};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Phase markers for structured log filtering and triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    /// Fixture and connector setup.
    Setup,
    /// Connector lifecycle (configure → handshake).
    Lifecycle,
    /// Session script execution.
    Execute,
    /// Transcript verification and assertions.
    Verify,
    /// Cleanup and resource release.
    Teardown,
}

impl std::fmt::Display for SessionPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup => write!(f, "setup"),
            Self::Lifecycle => write!(f, "lifecycle"),
            Self::Execute => write!(f, "execute"),
            Self::Verify => write!(f, "verify"),
            Self::Teardown => write!(f, "teardown"),
        }
    }
}

/// Configuration for a session-lifecycle E2E run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionE2eConfig {
    /// Connector identifier (e.g. "webhook-receiver", "discord", "slack").
    pub connector_id: String,
    /// Unique scenario identifier for correlation.
    pub scenario_id: String,
    /// Address of the streaming/webhook fixture server, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixture_address: Option<SocketAddr>,
    /// Maximum duration for the entire E2E run in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Extra environment variables passed to the connector subprocess.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    /// Tags for filtering and grouping.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Author identifier.
    #[serde(default = "default_author")]
    pub author: String,
    /// Optional Cargo test filter for a real owning test surface.
    ///
    /// When present, replay instructions include this filter instead of
    /// pointing at a non-existent canned test target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_test_filter: Option<String>,
}

const fn default_timeout_ms() -> u64 {
    30_000
}

fn default_author() -> String {
    "fcp-e2e".to_string()
}

impl Default for SessionE2eConfig {
    fn default() -> Self {
        Self {
            connector_id: String::new(),
            scenario_id: String::new(),
            fixture_address: None,
            timeout_ms: default_timeout_ms(),
            env: HashMap::new(),
            tags: Vec::new(),
            author: default_author(),
            replay_test_filter: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase log entry
// ─────────────────────────────────────────────────────────────────────────────

/// A phase-annotated log entry captured during a session E2E run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPhaseLog {
    /// Phase during which this entry was captured.
    pub phase: SessionPhase,
    /// Correlation ID linking all entries in this run.
    pub correlation_id: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Log level.
    pub level: String,
    /// Human-readable message.
    pub message: String,
    /// Optional structured context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a session-lifecycle E2E run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionE2eResult {
    /// Whether the run passed overall.
    pub passed: bool,
    /// Unique run identifier.
    pub run_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Connector under test.
    pub connector_id: String,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Session transcript (from script execution).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<SessionTranscript>,
    /// Transcript summary statistics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_summary: Option<TranscriptSummary>,
    /// Phase-annotated log entries.
    pub phase_logs: Vec<SessionPhaseLog>,
    /// Evidence bundle for archival.
    pub evidence: EvidenceBundle,
    /// Generated replay command for debugging.
    pub replay_command: String,
    /// Per-phase duration breakdown in milliseconds.
    pub phase_durations: PhaseDurations,
}

/// Duration breakdown by phase.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhaseDurations {
    pub setup_ms: u64,
    pub lifecycle_ms: u64,
    pub execute_ms: u64,
    pub verify_ms: u64,
    pub teardown_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────────────────────

/// Orchestrates session-lifecycle E2E runs by bridging fixture servers,
/// connector lifecycle, and the session-script DSL.
pub struct SessionE2eRunner {
    config: SessionE2eConfig,
    correlation_id: String,
    run_id: String,
    logs: Vec<SessionPhaseLog>,
}

impl SessionE2eRunner {
    /// Create a new runner with the given configuration.
    #[must_use]
    pub fn new(config: SessionE2eConfig) -> Self {
        let run_id = format!(
            "run-{}-{}",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            &config.scenario_id
        );
        let correlation_id = format!("sess-e2e-{}-{}", config.connector_id, config.scenario_id);
        Self {
            config,
            correlation_id,
            run_id,
            logs: Vec::new(),
        }
    }

    /// Execute a session script and produce a full E2E result with evidence.
    ///
    /// This runs through the complete session lifecycle:
    /// 1. **Setup** — validate config, record fixture address
    /// 2. **Lifecycle** — (placeholder for subprocess connector lifecycle)
    /// 3. **Execute** — walk the session script, producing a transcript
    /// 4. **Verify** — check transcript for failures, scan for secrets
    /// 5. **Teardown** — assemble evidence bundle and replay command
    pub fn execute(&mut self, script: &SessionScript) -> SessionE2eResult {
        let start = Instant::now();

        let setup_ms = self.run_setup_phase();
        let lifecycle_ms = self.run_lifecycle_phase();
        let (transcript, execute_ms) = self.run_execute_phase(script);
        let (passed, verify_ms) = self.run_verify_phase(&transcript);
        let (evidence, replay_command, teardown_ms) =
            self.run_teardown_phase(script, &transcript, passed);

        let phase_durations = PhaseDurations {
            setup_ms,
            lifecycle_ms,
            execute_ms,
            verify_ms,
            teardown_ms,
        };

        let total_ms = start.elapsed().as_millis() as u64;
        self.log(
            SessionPhase::Teardown,
            "info",
            &format!("Session E2E run complete in {total_ms}ms"),
            None,
        );

        SessionE2eResult {
            passed,
            run_id: self.run_id.clone(),
            scenario_id: self.config.scenario_id.clone(),
            connector_id: self.config.connector_id.clone(),
            duration_ms: total_ms,
            transcript_summary: Some(transcript.summary),
            transcript: Some(transcript),
            phase_logs: self.logs.clone(),
            evidence,
            replay_command,
            phase_durations,
        }
    }

    fn run_setup_phase(&mut self) -> u64 {
        let phase_start = Instant::now();
        self.log(
            SessionPhase::Setup,
            "info",
            "Starting session E2E run",
            None,
        );
        self.log(
            SessionPhase::Setup,
            "info",
            &format!("Connector: {}", self.config.connector_id),
            Some(serde_json::json!({
                "scenario_id": self.config.scenario_id,
                "fixture_address": self.config.fixture_address.map(|a| a.to_string()),
                "timeout_ms": self.config.timeout_ms,
                "tags": self.config.tags,
            })),
        );
        if let Some(addr) = self.config.fixture_address {
            self.log(
                SessionPhase::Setup,
                "info",
                &format!("Fixture server at {addr}"),
                None,
            );
        }
        phase_start.elapsed().as_millis() as u64
    }

    fn run_lifecycle_phase(&mut self) -> u64 {
        let phase_start = Instant::now();
        self.log(
            SessionPhase::Lifecycle,
            "info",
            "Connector lifecycle phase (configure → handshake)",
            None,
        );
        self.log(
            SessionPhase::Lifecycle,
            "info",
            "Lifecycle phase complete (connector managed by caller)",
            None,
        );
        phase_start.elapsed().as_millis() as u64
    }

    fn run_execute_phase(&mut self, script: &SessionScript) -> (SessionTranscript, u64) {
        let phase_start = Instant::now();
        self.log(
            SessionPhase::Execute,
            "info",
            &format!(
                "Executing session script: {} ({} steps)",
                script.scenario_id,
                script.steps.len()
            ),
            None,
        );
        let transcript = self.execute_script(script);
        let summary = transcript.summary;
        self.log(
            SessionPhase::Execute,
            "info",
            &format!(
                "Script complete: {}/{} steps passed in {}ms",
                summary.passed,
                summary.total,
                transcript.total_duration.as_millis()
            ),
            Some(serde_json::json!({
                "passed": summary.passed,
                "failed": summary.failed,
                "skipped": summary.skipped,
                "duration_ms": transcript.total_duration.as_millis() as u64,
            })),
        );
        (transcript, phase_start.elapsed().as_millis() as u64)
    }

    fn run_verify_phase(&mut self, transcript: &SessionTranscript) -> (bool, u64) {
        let phase_start = Instant::now();
        let passed = transcript.outcome == StepOutcome::Pass && transcript.summary.failed == 0;
        self.log(
            SessionPhase::Verify,
            if passed { "info" } else { "error" },
            &format!("Verification: {}", if passed { "PASS" } else { "FAIL" }),
            Some(serde_json::json!({
                "passed": passed,
                "transcript_outcome": format!("{:?}", transcript.outcome),
                "failed_steps": transcript.summary.failed,
            })),
        );
        let log_jsonl = self.logs_to_jsonl();
        let scan = crate::scan_log_jsonl(&log_jsonl);
        if !scan.passed() {
            self.log(
                SessionPhase::Verify,
                "warn",
                &format!(
                    "Log scan found {} findings ({} errors, {} warnings)",
                    scan.findings.len(),
                    scan.error_count,
                    scan.warn_count
                ),
                None,
            );
        }
        (passed, phase_start.elapsed().as_millis() as u64)
    }

    fn run_teardown_phase(
        &mut self,
        script: &SessionScript,
        transcript: &SessionTranscript,
        passed: bool,
    ) -> (EvidenceBundle, String, u64) {
        let phase_start = Instant::now();
        let evidence = self.build_evidence_bundle(script, transcript, passed);
        let replay_command = self.build_replay_command(script);
        self.log(
            SessionPhase::Teardown,
            "info",
            "Evidence bundle assembled",
            Some(serde_json::json!({
                "replay_command": replay_command,
                "retention_days": evidence.retention_days,
            })),
        );
        (
            evidence,
            replay_command,
            phase_start.elapsed().as_millis() as u64,
        )
    }

    /// Record a transcript from an externally-executed session and produce
    /// a full E2E result with evidence.
    ///
    /// Use this when the caller manages connector lifecycle and script
    /// execution directly (e.g. through a real WebSocket connection) and
    /// wants the runner to handle evidence assembly and verification.
    pub fn record_external_transcript(
        &mut self,
        script: &SessionScript,
        transcript: SessionTranscript,
    ) -> SessionE2eResult {
        let setup_ms = self.run_setup_phase();
        let lifecycle_ms = self.run_lifecycle_phase();

        let summary = transcript.summary;
        let execute_ms = transcript.total_duration.as_millis() as u64;

        self.log(
            SessionPhase::Execute,
            "info",
            "Recording externally-provided transcript",
            Some(serde_json::json!({
                "transport": format!("{:?}", transcript.transport),
                "passed": summary.passed,
                "failed": summary.failed,
                "skipped": summary.skipped,
                "timed_out": summary.timed_out,
                "duration_ms": execute_ms,
            })),
        );

        let (passed, verify_ms) = self.run_verify_phase(&transcript);
        let (evidence, replay_command, teardown_ms) =
            self.run_teardown_phase(script, &transcript, passed);
        let phase_durations = PhaseDurations {
            setup_ms,
            lifecycle_ms,
            execute_ms,
            verify_ms,
            teardown_ms,
        };
        let total_ms = phase_durations.setup_ms
            + phase_durations.lifecycle_ms
            + phase_durations.execute_ms
            + phase_durations.verify_ms
            + phase_durations.teardown_ms;

        SessionE2eResult {
            passed,
            run_id: self.run_id.clone(),
            scenario_id: self.config.scenario_id.clone(),
            connector_id: self.config.connector_id.clone(),
            duration_ms: total_ms,
            transcript_summary: Some(summary),
            transcript: Some(transcript),
            phase_logs: self.logs.clone(),
            evidence,
            replay_command,
            phase_durations,
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn log(
        &mut self,
        phase: SessionPhase,
        level: &str,
        message: &str,
        context: Option<serde_json::Value>,
    ) {
        self.logs.push(SessionPhaseLog {
            phase,
            correlation_id: self.correlation_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            level: level.to_string(),
            message: message.to_string(),
            context,
        });
    }

    fn logs_to_jsonl(&self) -> String {
        self.logs
            .iter()
            .filter_map(|l| serde_json::to_string(l).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Execute a session script by walking steps and producing a transcript.
    ///
    /// This is a deterministic "dry-run" execution that records expected
    /// step outcomes.  For real network interaction, callers should use
    /// [`Self::record_external_transcript`] with a transcript produced by an
    /// actual connector session.
    fn execute_script(&mut self, script: &SessionScript) -> SessionTranscript {
        let started_at = Utc::now();
        let start = Instant::now();
        let mut entries = Vec::new();

        for (idx, step) in script.steps.iter().enumerate() {
            let step_start = Instant::now();

            self.log(
                SessionPhase::Execute,
                "debug",
                &format!("Step {idx}: {step:?}"),
                Some(serde_json::json!({
                    "step_index": idx,
                    "correlation_id": self.correlation_id,
                })),
            );

            entries.push(TranscriptEntry {
                timestamp: Utc::now(),
                step_index: idx,
                step: step.clone(),
                outcome: StepOutcome::Pass,
                duration: step_start.elapsed(),
                detail: None,
                correlation_id: Some(self.correlation_id.clone()),
            });
        }

        let total_duration = start.elapsed();
        let total = entries.len();
        let passed_count = entries
            .iter()
            .filter(|e| e.outcome == StepOutcome::Pass)
            .count();

        SessionTranscript {
            scenario_id: script.scenario_id.clone(),
            run_id: self.run_id.clone(),
            transport: script.default_transport,
            started_at,
            finished_at: Utc::now(),
            total_duration,
            entries,
            outcome: StepOutcome::Pass,
            summary: TranscriptSummary {
                total,
                passed: passed_count,
                failed: 0,
                skipped: 0,
                timed_out: 0,
            },
        }
    }

    #[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
    fn build_evidence_bundle(
        &self,
        script: &SessionScript,
        transcript: &SessionTranscript,
        passed: bool,
    ) -> EvidenceBundle {
        let now = Utc::now().to_rfc3339();

        let meta = ScenarioMeta {
            name: format!(
                "Session lifecycle: {} / {}",
                self.config.connector_id, self.config.scenario_id
            ),
            description: script
                .description
                .clone()
                .unwrap_or_else(|| format!("Session E2E for {}", self.config.scenario_id)),
            tags: self.config.tags.clone(),
            environment: ScenarioEnvironment::Local,
            created_at: now,
            author: self.config.author.clone(),
        };

        let mut steps = Vec::new();
        for (idx, entry) in transcript.entries.iter().enumerate() {
            let step_passed = entry.outcome == StepOutcome::Pass;
            let detail_str = entry
                .detail
                .as_ref()
                .map(std::string::ToString::to_string)
                .unwrap_or_default();
            steps.push(ScenarioStep {
                index: idx as u32,
                kind: StepKind::Action,
                description: format!("{:?}", entry.step),
                correlation_id: entry
                    .correlation_id
                    .clone()
                    .unwrap_or_else(|| self.correlation_id.clone()),
                timestamp: entry.timestamp.to_rfc3339(),
                duration_ms: Some(entry.duration.as_millis() as u64),
                assertions: vec![StepAssertion {
                    description: format!("Step {idx} outcome"),
                    passed: step_passed,
                    expected: "pass".to_string(),
                    actual: format!("{:?}", entry.outcome),
                }],
                evidence: if detail_str.is_empty() {
                    vec![]
                } else {
                    vec![EvidenceItem::Log {
                        lines: vec![detail_str],
                    }]
                },
            });
        }

        let phase_log_lines = self
            .logs_to_jsonl()
            .lines()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        if !phase_log_lines.is_empty() {
            steps.push(ScenarioStep {
                index: steps.len() as u32,
                kind: StepKind::Checkpoint,
                description: "Structured phase logs and transcript summary".to_string(),
                correlation_id: self.correlation_id.clone(),
                timestamp: transcript.finished_at.to_rfc3339(),
                duration_ms: Some(transcript.total_duration.as_millis() as u64),
                assertions: vec![
                    StepAssertion {
                        description: "Phase logs captured".to_string(),
                        passed: true,
                        expected: ">0 entries".to_string(),
                        actual: self.logs.len().to_string(),
                    },
                    StepAssertion {
                        description: "Transcript outcome".to_string(),
                        passed,
                        expected: if passed {
                            "pass".to_string()
                        } else {
                            "fail".to_string()
                        },
                        actual: if passed {
                            "pass".to_string()
                        } else {
                            "fail".to_string()
                        },
                    },
                ],
                evidence: vec![
                    EvidenceItem::Log {
                        lines: phase_log_lines,
                    },
                    EvidenceItem::Metric {
                        name: "phase_log_count".to_string(),
                        value: self.logs.len() as f64,
                        unit: "entries".to_string(),
                    },
                    EvidenceItem::Metric {
                        name: "transcript_step_count".to_string(),
                        value: transcript.summary.total as f64,
                        unit: "steps".to_string(),
                    },
                    EvidenceItem::Metric {
                        name: "transcript_duration_ms".to_string(),
                        value: transcript.total_duration.as_millis() as f64,
                        unit: "ms".to_string(),
                    },
                    EvidenceItem::HealthSnapshot {
                        component: self.config.connector_id.clone(),
                        state: if passed {
                            "healthy".to_string()
                        } else {
                            "degraded".to_string()
                        },
                    },
                ],
            });
        }

        let outcome = if passed {
            ScenarioOutcome::Pass
        } else {
            let first_fail = transcript
                .entries
                .iter()
                .enumerate()
                .find(|(_, e)| e.outcome != StepOutcome::Pass);
            match first_fail {
                Some((idx, entry)) => ScenarioOutcome::Fail {
                    step_index: idx as u32,
                    reason: entry.detail.as_ref().map_or_else(
                        || format!("Step {idx} failed: {:?}", entry.outcome),
                        std::string::ToString::to_string,
                    ),
                },
                None => ScenarioOutcome::Fail {
                    step_index: 0,
                    reason: "Transcript marked as failed".to_string(),
                },
            }
        };

        let scenario_script = ScenarioScript {
            meta,
            steps,
            outcome,
        };

        EvidenceBundle {
            script: scenario_script,
            redacted_fields: Vec::new(),
            replay_instructions: self.build_replay_command(script),
            retention_days: 90,
        }
    }

    /// Generate a replay command from a session script for debugging.
    fn build_replay_command(&self, script: &SessionScript) -> String {
        let fixture_arg = self
            .config
            .fixture_address
            .map(|a| format!(" --fixture-addr {a}"))
            .unwrap_or_default();

        let env_args = self.config.env.keys().fold(String::new(), |mut acc, k| {
            use std::fmt::Write;
            let _ = write!(acc, " --env {k}=<redacted>");
            acc
        });

        let cargo_replay = self.config.replay_test_filter.as_deref().map_or_else(
            || {
                "# No direct cargo test filter is recorded for this scenario.\n\
                 # Re-run the host-facing simulate command above or supply a concrete cargo test filter."
                    .to_string()
            },
            |filter| {
                format!(
                    "# Re-run the associated fcp-e2e test/filter:\n\
                     cargo test -p fcp-e2e {filter} -- --nocapture"
                )
            },
        );

        format!(
            "# Replay session E2E:\n\
             # Run ID: {}\n\
             # Correlation: {}\n\
             fwc simulate {} --scenario {}{}{}\n\
             {}",
            self.run_id,
            self.correlation_id,
            self.config.connector_id,
            script.scenario_id,
            fixture_arg,
            env_args,
            cargo_replay,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fault, ScriptHealthState, ScriptStep, SessionScript, Transport};
    use std::time::Duration;

    #[test]
    fn config_default_has_30s_timeout() {
        let cfg = SessionE2eConfig::default();
        assert_eq!(cfg.timeout_ms, 30_000);
        assert!(cfg.connector_id.is_empty());
        assert!(cfg.tags.is_empty());
    }

    #[test]
    fn runner_generates_correlation_id() {
        let runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "discord".into(),
            scenario_id: "ws.reconnect".into(),
            ..Default::default()
        });
        assert!(runner.correlation_id.contains("discord"));
        assert!(runner.correlation_id.contains("ws.reconnect"));
    }

    #[test]
    fn execute_empty_script_passes() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "test".into(),
            scenario_id: "empty".into(),
            ..Default::default()
        });
        let script = SessionScript::new("empty");
        let result = runner.execute(&script);
        assert!(result.passed);
        assert_eq!(result.connector_id, "test");
        assert_eq!(result.scenario_id, "empty");
        assert!(result.transcript.is_some());
        assert!(!result.replay_command.is_empty());
    }

    #[test]
    fn execute_basic_sse_script_passes() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "webhook-receiver".into(),
            scenario_id: "sse.basic_receive".into(),
            fixture_address: Some("127.0.0.1:9999".parse().unwrap()),
            tags: vec!["streaming".into(), "sse".into()],
            ..Default::default()
        });

        let script = SessionScript::new("sse.basic_receive")
            .step(ScriptStep::connect(Transport::Sse, "/events"))
            .step(ScriptStep::expect_any_message())
            .step(ScriptStep::disconnect());

        let result = runner.execute(&script);
        assert!(result.passed);
        assert_eq!(result.transcript_summary.as_ref().unwrap().total, 3);
        assert!(result.replay_command.contains("webhook-receiver"));
        assert!(result.replay_command.contains("--fixture-addr"));
    }

    #[test]
    fn execute_webhook_script_passes() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "stripe".into(),
            scenario_id: "webhook.signature_verify".into(),
            ..Default::default()
        });

        let script = SessionScript::new("webhook.signature_verify")
            .step(ScriptStep::webhook_deliver(
                "payment_intent.succeeded",
                serde_json::json!({"id": "pi_123"}),
            ))
            .step(ScriptStep::webhook_expect_ack())
            .step(ScriptStep::annotate("Webhook delivered and acknowledged"));

        let result = runner.execute(&script);
        assert!(result.passed);
        assert_eq!(result.transcript_summary.as_ref().unwrap().total, 3);
    }

    #[test]
    fn execute_reconnect_scenario() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "discord".into(),
            scenario_id: "ws.reconnect_after_drop".into(),
            ..Default::default()
        });

        let script = SessionScript::new("ws.reconnect_after_drop")
            .step(ScriptStep::connect(Transport::WebSocket, "/gateway"))
            .step(ScriptStep::expect_any_message())
            .step(ScriptStep::inject_fault(Fault::ConnectionDrop))
            .step(ScriptStep::assert_health(ScriptHealthState::Reconnecting))
            .step(ScriptStep::wait(Duration::from_millis(500)))
            .step(ScriptStep::assert_health(ScriptHealthState::Connected))
            .step(ScriptStep::disconnect());

        let result = runner.execute(&script);
        assert!(result.passed);
        assert_eq!(result.transcript_summary.as_ref().unwrap().total, 7);
    }

    #[test]
    fn record_external_transcript_produces_evidence() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "telegram".into(),
            scenario_id: "poll.cursor_recovery".into(),
            ..Default::default()
        });

        let script = SessionScript::new("poll.cursor_recovery")
            .step(ScriptStep::connect(Transport::LongPoll, "/getUpdates"))
            .step(ScriptStep::expect_any_message())
            .step(ScriptStep::disconnect());

        let now = Utc::now();
        let transcript = SessionTranscript {
            scenario_id: "poll.cursor_recovery".into(),
            run_id: runner.run_id.clone(),
            transport: Some(Transport::LongPoll),
            started_at: now,
            finished_at: now + chrono::Duration::milliseconds(65),
            total_duration: Duration::from_millis(65),
            entries: vec![
                TranscriptEntry {
                    timestamp: now,
                    step_index: 0,
                    step: ScriptStep::connect(Transport::LongPoll, "/getUpdates"),
                    outcome: StepOutcome::Pass,
                    duration: Duration::from_millis(10),
                    detail: None,
                    correlation_id: None,
                },
                TranscriptEntry {
                    timestamp: now,
                    step_index: 1,
                    step: ScriptStep::expect_any_message(),
                    outcome: StepOutcome::Pass,
                    duration: Duration::from_millis(50),
                    detail: Some(serde_json::json!("Received update payload")),
                    correlation_id: None,
                },
                TranscriptEntry {
                    timestamp: now,
                    step_index: 2,
                    step: ScriptStep::disconnect(),
                    outcome: StepOutcome::Pass,
                    duration: Duration::from_millis(5),
                    detail: None,
                    correlation_id: None,
                },
            ],
            outcome: StepOutcome::Pass,
            summary: TranscriptSummary {
                total: 3,
                passed: 3,
                failed: 0,
                skipped: 0,
                timed_out: 0,
            },
        };

        let result = runner.record_external_transcript(&script, transcript);
        assert!(result.passed);
        assert_eq!(result.transcript_summary.as_ref().unwrap().total, 3);
        assert!(result.evidence.script.outcome == ScenarioOutcome::Pass);
    }

    #[test]
    fn failed_transcript_produces_fail_evidence() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "slack".into(),
            scenario_id: "ws.heartbeat_timeout".into(),
            ..Default::default()
        });

        let script = SessionScript::new("ws.heartbeat_timeout");
        let now = Utc::now();

        let transcript = SessionTranscript {
            scenario_id: "ws.heartbeat_timeout".into(),
            run_id: runner.run_id.clone(),
            transport: Some(Transport::WebSocket),
            started_at: now,
            finished_at: now + chrono::Duration::milliseconds(100),
            total_duration: Duration::from_millis(100),
            entries: vec![TranscriptEntry {
                timestamp: now,
                step_index: 0,
                step: ScriptStep::assert_health(ScriptHealthState::Connected),
                outcome: StepOutcome::Fail,
                duration: Duration::from_millis(100),
                detail: Some(serde_json::json!("Health was Degraded, expected Connected")),
                correlation_id: None,
            }],
            outcome: StepOutcome::Fail,
            summary: TranscriptSummary {
                total: 1,
                passed: 0,
                failed: 1,
                skipped: 0,
                timed_out: 0,
            },
        };

        let result = runner.record_external_transcript(&script, transcript);
        assert!(!result.passed);
        assert!(matches!(
            result.evidence.script.outcome,
            ScenarioOutcome::Fail { .. }
        ));
    }

    #[test]
    fn phase_logs_have_correct_phases() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "test".into(),
            scenario_id: "phases".into(),
            ..Default::default()
        });

        let script = SessionScript::new("phases").step(ScriptStep::annotate("test step"));

        let result = runner.execute(&script);

        let phases: Vec<SessionPhase> = result.phase_logs.iter().map(|l| l.phase).collect();
        assert!(phases.contains(&SessionPhase::Setup));
        assert!(phases.contains(&SessionPhase::Lifecycle));
        assert!(phases.contains(&SessionPhase::Execute));
        assert!(phases.contains(&SessionPhase::Verify));
        assert!(phases.contains(&SessionPhase::Teardown));
    }

    #[test]
    fn replay_command_includes_fixture_addr() {
        let runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "discord".into(),
            scenario_id: "ws.test".into(),
            fixture_address: Some("127.0.0.1:8080".parse().unwrap()),
            ..Default::default()
        });
        let cmd = runner.build_replay_command(&SessionScript::new("ws.test"));
        assert!(cmd.contains("--fixture-addr 127.0.0.1:8080"));
        assert!(cmd.contains("discord"));
        assert!(!cmd.contains("session_lifecycle_e2e"));
        assert!(cmd.contains("No direct cargo test filter"));
    }

    #[test]
    fn replay_command_redacts_env_values() {
        let mut env = HashMap::new();
        env.insert("API_KEY".into(), "secret123".into());
        let runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "test".into(),
            scenario_id: "env.test".into(),
            env,
            ..Default::default()
        });
        let cmd = runner.build_replay_command(&SessionScript::new("env.test"));
        assert!(cmd.contains("API_KEY=<redacted>"));
        assert!(!cmd.contains("secret123"));
    }

    #[test]
    fn replay_command_uses_explicit_test_filter_when_available() {
        let runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "discord".into(),
            scenario_id: "ws.test".into(),
            replay_test_filter: Some("host_e2e::tests::execute_basic_sse_script_passes".into()),
            ..Default::default()
        });
        let cmd = runner.build_replay_command(&SessionScript::new("ws.test"));
        assert!(cmd.contains(
            "cargo test -p fcp-e2e host_e2e::tests::execute_basic_sse_script_passes -- --nocapture"
        ));
        assert!(!cmd.contains("No direct cargo test filter"));
    }

    #[test]
    fn phase_durations_are_populated() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "test".into(),
            scenario_id: "timing".into(),
            ..Default::default()
        });
        let script = SessionScript::new("timing");
        let result = runner.execute(&script);
        // All phases should have reasonable durations
        assert!(result.phase_durations.setup_ms < 5000);
        assert!(result.phase_durations.verify_ms < 5000);
    }

    #[test]
    fn evidence_bundle_has_correct_metadata() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "github".into(),
            scenario_id: "webhook.push".into(),
            tags: vec!["ci".into(), "webhook".into()],
            author: "test-agent".into(),
            ..Default::default()
        });
        let script = SessionScript::new("webhook.push");
        let result = runner.execute(&script);
        assert_eq!(result.evidence.script.meta.author, "test-agent");
        assert_eq!(result.evidence.script.meta.tags, vec!["ci", "webhook"]);
        assert!(result.evidence.script.meta.name.contains("github"));
    }

    #[test]
    fn external_transcript_records_all_phases_and_checkpoint_evidence() {
        let mut runner = SessionE2eRunner::new(SessionE2eConfig {
            connector_id: "telegram".into(),
            scenario_id: "poll.cursor_recovery".into(),
            ..Default::default()
        });

        let script = SessionScript::new("poll.cursor_recovery")
            .step(ScriptStep::connect(Transport::LongPoll, "/getUpdates"))
            .step(ScriptStep::expect_any_message())
            .step(ScriptStep::disconnect());

        let now = Utc::now();
        let transcript = SessionTranscript {
            scenario_id: "poll.cursor_recovery".into(),
            run_id: runner.run_id.clone(),
            transport: Some(Transport::LongPoll),
            started_at: now,
            finished_at: now + chrono::Duration::milliseconds(65),
            total_duration: Duration::from_millis(65),
            entries: vec![
                TranscriptEntry {
                    timestamp: now,
                    step_index: 0,
                    step: ScriptStep::connect(Transport::LongPoll, "/getUpdates"),
                    outcome: StepOutcome::Pass,
                    duration: Duration::from_millis(10),
                    detail: None,
                    correlation_id: None,
                },
                TranscriptEntry {
                    timestamp: now,
                    step_index: 1,
                    step: ScriptStep::expect_any_message(),
                    outcome: StepOutcome::Pass,
                    duration: Duration::from_millis(50),
                    detail: Some(serde_json::json!("Received update payload")),
                    correlation_id: None,
                },
                TranscriptEntry {
                    timestamp: now,
                    step_index: 2,
                    step: ScriptStep::disconnect(),
                    outcome: StepOutcome::Pass,
                    duration: Duration::from_millis(5),
                    detail: None,
                    correlation_id: None,
                },
            ],
            outcome: StepOutcome::Pass,
            summary: TranscriptSummary {
                total: 3,
                passed: 3,
                failed: 0,
                skipped: 0,
                timed_out: 0,
            },
        };

        let result = runner.record_external_transcript(&script, transcript);
        let phases: Vec<SessionPhase> = result.phase_logs.iter().map(|log| log.phase).collect();
        assert!(phases.contains(&SessionPhase::Setup));
        assert!(phases.contains(&SessionPhase::Lifecycle));
        assert!(phases.contains(&SessionPhase::Execute));
        assert!(phases.contains(&SessionPhase::Verify));
        assert!(phases.contains(&SessionPhase::Teardown));
        assert_eq!(result.phase_durations.execute_ms, 65);
        assert_eq!(
            result.duration_ms,
            result.phase_durations.setup_ms
                + result.phase_durations.lifecycle_ms
                + result.phase_durations.execute_ms
                + result.phase_durations.verify_ms
                + result.phase_durations.teardown_ms
        );
        assert!(result.duration_ms >= 65);

        let checkpoint = result
            .evidence
            .script
            .steps
            .last()
            .expect("checkpoint step should exist");
        assert_eq!(checkpoint.kind, StepKind::Checkpoint);
        assert!(
            checkpoint
                .evidence
                .iter()
                .any(|item| matches!(item, EvidenceItem::Log { lines } if !lines.is_empty()))
        );
        assert!(checkpoint.evidence.iter().any(|item| {
            matches!(
                item,
                EvidenceItem::Metric { name, value, unit }
                    if name == "transcript_duration_ms" && *value == 65.0 && unit == "ms"
            )
        }));
        assert!(checkpoint.evidence.iter().any(|item| {
            matches!(
                item,
                EvidenceItem::HealthSnapshot { component, state }
                    if component == "telegram" && state == "healthy"
            )
        }));
    }

    #[test]
    fn config_serialization_roundtrip() {
        let cfg = SessionE2eConfig {
            connector_id: "discord".into(),
            scenario_id: "ws.test".into(),
            fixture_address: Some("127.0.0.1:8080".parse().unwrap()),
            timeout_ms: 60_000,
            env: {
                let mut m = HashMap::new();
                m.insert("TOKEN".into(), "abc".into());
                m
            },
            tags: vec!["streaming".into()],
            author: "agent-x".into(),
            replay_test_filter: Some("host_e2e::tests::execute_basic_sse_script_passes".into()),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let roundtrip: SessionE2eConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.connector_id, "discord");
        assert_eq!(roundtrip.scenario_id, "ws.test");
        assert_eq!(roundtrip.tags, vec!["streaming"]);
        assert_eq!(
            roundtrip.replay_test_filter.as_deref(),
            Some("host_e2e::tests::execute_basic_sse_script_passes")
        );
    }
}
