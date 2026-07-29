//! Deterministic pre-copy migration policy.

use serde::{Deserialize, Serialize};

const DEFAULT_DIRTY_THRESHOLD_PCT: u8 = 80;
const DEFAULT_MAX_ROUNDS: u8 = 5;
const DEFAULT_BANDWIDTH_MIB_PER_SECOND: u64 = 100;
const MIB: u64 = 1024 * 1024;
pub const PRECOPY_ROUND_OTLP_SPAN: &str = "fcp.criu.precopy_round";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bandwidth {
    bytes_per_second: u64,
}

impl Bandwidth {
    #[must_use]
    pub const fn from_bytes_per_second(bytes_per_second: u64) -> Self {
        Self { bytes_per_second }
    }

    #[must_use]
    pub const fn from_mib_per_second(mib_per_second: u64) -> Self {
        Self {
            bytes_per_second: mib_per_second.saturating_mul(MIB),
        }
    }

    #[must_use]
    pub const fn bytes_per_second(self) -> u64 {
        self.bytes_per_second
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.bytes_per_second == 0
    }
}

impl Default for Bandwidth {
    fn default() -> Self {
        Self::from_mib_per_second(DEFAULT_BANDWIDTH_MIB_PER_SECOND)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    pub working_set_bytes: u64,
    pub dirty_rate_bytes_per_second: u64,
    pub page_size_bytes: u64,
}

impl Workload {
    #[must_use]
    pub const fn new(
        working_set_bytes: u64,
        dirty_rate_bytes_per_second: u64,
        page_size_bytes: u64,
    ) -> Self {
        Self {
            working_set_bytes,
            dirty_rate_bytes_per_second,
            page_size_bytes,
        }
    }

    #[must_use]
    pub const fn synthetic_mib(working_set_mib: u64, dirty_rate_mib_per_second: u64) -> Self {
        Self {
            working_set_bytes: working_set_mib.saturating_mul(MIB),
            dirty_rate_bytes_per_second: dirty_rate_mib_per_second.saturating_mul(MIB),
            page_size_bytes: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreCopyDecision {
    Continue,
    Converged,
    StopAndCheckpoint,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreCopyRoundLog {
    pub round_idx: u8,
    pub dirty_pages_this_round: u64,
    pub bandwidth_estimate_bytes_per_second: u64,
    pub dirty_rate_bytes_per_second: u64,
    pub dirty_rate_pct_of_bandwidth: u16,
    pub remaining_dirty_bytes: u64,
    pub decision: PreCopyDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreCopyRoundJsonLog {
    pub timestamp: String,
    pub op_id: String,
    pub round_idx: u8,
    pub dirty_pages_this_round: u64,
    pub bandwidth_estimate_mbps: u64,
    pub dirty_rate_mbps: u64,
    pub decision: PreCopyDecision,
}

impl PreCopyRoundLog {
    #[must_use]
    pub const fn bandwidth_estimate_mbps(&self) -> u64 {
        bytes_per_second_to_mibps(self.bandwidth_estimate_bytes_per_second)
    }

    #[must_use]
    pub const fn dirty_rate_mbps(&self) -> u64 {
        bytes_per_second_to_mibps(self.dirty_rate_bytes_per_second)
    }

    #[must_use]
    pub const fn fallback_triggered(&self) -> bool {
        matches!(
            self.decision,
            PreCopyDecision::StopAndCheckpoint | PreCopyDecision::Aborted
        )
    }

    #[must_use]
    pub fn json_log(
        &self,
        timestamp: impl Into<String>,
        op_id: impl Into<String>,
    ) -> PreCopyRoundJsonLog {
        PreCopyRoundJsonLog {
            timestamp: timestamp.into(),
            op_id: op_id.into(),
            round_idx: self.round_idx,
            dirty_pages_this_round: self.dirty_pages_this_round,
            bandwidth_estimate_mbps: self.bandwidth_estimate_mbps(),
            dirty_rate_mbps: self.dirty_rate_mbps(),
            decision: self.decision,
        }
    }

    #[must_use]
    pub fn otlp_span(&self, op_id: &str) -> tracing::Span {
        tracing::info_span!(
            PRECOPY_ROUND_OTLP_SPAN,
            op_id,
            round_idx = self.round_idx,
            dirty_pages = self.dirty_pages_this_round,
            dirty_pages_this_round = self.dirty_pages_this_round,
            fallback_triggered = self.fallback_triggered(),
            bandwidth_estimate_mbps = self.bandwidth_estimate_mbps(),
            dirty_rate_mbps = self.dirty_rate_mbps(),
            decision = ?self.decision,
        )
    }

    pub fn emit_info(&self, op_id: &str) {
        tracing::info!(
            target: "fcp.criu",
            op_id,
            round_idx = self.round_idx,
            dirty_pages = self.dirty_pages_this_round,
            dirty_pages_this_round = self.dirty_pages_this_round,
            fallback_triggered = self.fallback_triggered(),
            bandwidth_estimate_mbps = self.bandwidth_estimate_mbps(),
            dirty_rate_mbps = self.dirty_rate_mbps(),
            decision = ?self.decision,
            "CRIU pre-copy round"
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreCopyReport {
    pub rounds: u8,
    pub final_dirty_bytes: u64,
    pub dirty_rate_pct_of_bandwidth: u16,
    pub logs: Vec<PreCopyRoundLog>,
}

impl PreCopyReport {
    #[must_use]
    pub fn json_round_logs(&self, timestamp: &str, op_id: &str) -> Vec<PreCopyRoundJsonLog> {
        self.logs
            .iter()
            .map(|log| log.json_log(timestamp, op_id))
            .collect()
    }

    /// Serializes pre-copy round logs as newline-delimited JSON.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if a round payload cannot be encoded.
    pub fn jsonl_round_logs(
        &self,
        timestamp: &str,
        op_id: &str,
    ) -> Result<String, serde_json::Error> {
        let mut jsonl = String::new();
        for log in self.json_round_logs(timestamp, op_id) {
            jsonl.push_str(&serde_json::to_string(&log)?);
            jsonl.push('\n');
        }
        Ok(jsonl)
    }

    pub fn emit_info_logs(&self, op_id: &str) {
        for log in &self.logs {
            log.emit_info(op_id);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreCopyOutcome {
    Converged(PreCopyReport),
    StopAndCheckpoint(PreCopyReport),
    Aborted {
        reason: String,
        report: PreCopyReport,
    },
}

impl PreCopyOutcome {
    #[must_use]
    pub const fn is_converged(&self) -> bool {
        matches!(self, Self::Converged(_))
    }

    #[must_use]
    pub const fn is_stop_and_checkpoint(&self) -> bool {
        matches!(self, Self::StopAndCheckpoint(_))
    }

    #[must_use]
    pub const fn report(&self) -> &PreCopyReport {
        match self {
            Self::Converged(report)
            | Self::StopAndCheckpoint(report)
            | Self::Aborted { report, .. } => report,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreCopyController {
    pub bandwidth_estimate: Bandwidth,
    pub dirty_threshold_pct: u8,
    pub max_rounds: u8,
}

impl Default for PreCopyController {
    fn default() -> Self {
        Self {
            bandwidth_estimate: Bandwidth::default(),
            dirty_threshold_pct: DEFAULT_DIRTY_THRESHOLD_PCT,
            max_rounds: DEFAULT_MAX_ROUNDS,
        }
    }
}

impl PreCopyController {
    #[must_use]
    pub const fn new(
        bandwidth_estimate: Bandwidth,
        dirty_threshold_pct: u8,
        max_rounds: u8,
    ) -> Self {
        Self {
            bandwidth_estimate,
            dirty_threshold_pct,
            max_rounds,
        }
    }

    #[must_use]
    pub fn run_precopy(&self, workload: &Workload) -> PreCopyOutcome {
        if self.bandwidth_estimate.is_zero() {
            return PreCopyOutcome::Aborted {
                reason: "bandwidth estimate must be greater than zero".to_owned(),
                report: empty_report(self),
            };
        }
        if self.max_rounds == 0 {
            return PreCopyOutcome::Aborted {
                reason: "max rounds must be greater than zero".to_owned(),
                report: empty_report(self),
            };
        }
        if workload.page_size_bytes == 0 {
            return PreCopyOutcome::Aborted {
                reason: "page size must be greater than zero".to_owned(),
                report: empty_report(self),
            };
        }

        let bandwidth = self.bandwidth_estimate.bytes_per_second();
        let copy_budget = bandwidth.saturating_mul(2);
        let threshold_bytes = bandwidth
            .saturating_mul(u64::from(self.dirty_threshold_pct))
            .saturating_div(100);
        let dirty_rate_pct = dirty_rate_pct(workload.dirty_rate_bytes_per_second, bandwidth);
        let mut remaining = workload.working_set_bytes;
        let mut logs = Vec::with_capacity(usize::from(self.max_rounds));

        if remaining == 0 {
            let report = PreCopyReport {
                rounds: 0,
                final_dirty_bytes: 0,
                dirty_rate_pct_of_bandwidth: dirty_rate_pct,
                logs,
            };
            return PreCopyOutcome::Converged(report);
        }

        let high_dirty_rate = workload.dirty_rate_bytes_per_second >= threshold_bytes;
        for round_idx in 1..=self.max_rounds {
            let copied = remaining.min(copy_budget);
            if copied >= remaining && !high_dirty_rate {
                remaining = 0;
                logs.push(round_log(
                    round_idx,
                    workload,
                    bandwidth,
                    dirty_rate_pct,
                    remaining,
                    PreCopyDecision::Converged,
                ));
                let report = PreCopyReport {
                    rounds: round_idx,
                    final_dirty_bytes: remaining,
                    dirty_rate_pct_of_bandwidth: dirty_rate_pct,
                    logs,
                };
                return PreCopyOutcome::Converged(report);
            }

            let dirtied_during_round = bytes_dirtied_while_copying(
                workload.dirty_rate_bytes_per_second,
                copied,
                bandwidth,
            );
            remaining = remaining
                .saturating_sub(copied)
                .saturating_add(dirtied_during_round);
            let decision = if high_dirty_rate && round_idx == self.max_rounds {
                PreCopyDecision::StopAndCheckpoint
            } else {
                PreCopyDecision::Continue
            };
            logs.push(round_log(
                round_idx,
                workload,
                bandwidth,
                dirty_rate_pct,
                remaining,
                decision,
            ));
            if high_dirty_rate && round_idx == self.max_rounds {
                let report = PreCopyReport {
                    rounds: round_idx,
                    final_dirty_bytes: remaining,
                    dirty_rate_pct_of_bandwidth: dirty_rate_pct,
                    logs,
                };
                return PreCopyOutcome::StopAndCheckpoint(report);
            }
        }

        let report = PreCopyReport {
            rounds: self.max_rounds,
            final_dirty_bytes: remaining,
            dirty_rate_pct_of_bandwidth: dirty_rate_pct,
            logs,
        };
        if remaining == 0 {
            PreCopyOutcome::Converged(report)
        } else {
            PreCopyOutcome::StopAndCheckpoint(report)
        }
    }
}

#[must_use]
pub fn run_precopy(workload: &Workload) -> PreCopyOutcome {
    PreCopyController::default().run_precopy(workload)
}

fn empty_report(controller: &PreCopyController) -> PreCopyReport {
    PreCopyReport {
        rounds: 0,
        final_dirty_bytes: 0,
        dirty_rate_pct_of_bandwidth: 0,
        logs: Vec::with_capacity(usize::from(controller.max_rounds)),
    }
}

const fn round_log(
    round_idx: u8,
    workload: &Workload,
    bandwidth: u64,
    dirty_rate_pct_of_bandwidth: u16,
    remaining_dirty_bytes: u64,
    decision: PreCopyDecision,
) -> PreCopyRoundLog {
    PreCopyRoundLog {
        round_idx,
        dirty_pages_this_round: pages_for_bytes(
            workload.dirty_rate_bytes_per_second,
            workload.page_size_bytes,
        ),
        bandwidth_estimate_bytes_per_second: bandwidth,
        dirty_rate_bytes_per_second: workload.dirty_rate_bytes_per_second,
        dirty_rate_pct_of_bandwidth,
        remaining_dirty_bytes,
        decision,
    }
}

fn bytes_dirtied_while_copying(
    dirty_rate_bytes_per_second: u64,
    copied: u64,
    bandwidth: u64,
) -> u64 {
    if bandwidth == 0 {
        return 0;
    }
    let dirty = u128::from(dirty_rate_bytes_per_second);
    let copied = u128::from(copied);
    let bandwidth = u128::from(bandwidth);
    u64::try_from(dirty.saturating_mul(copied).saturating_div(bandwidth)).unwrap_or(u64::MAX)
}

fn dirty_rate_pct(dirty_rate_bytes_per_second: u64, bandwidth: u64) -> u16 {
    if bandwidth == 0 {
        return 0;
    }
    let pct = u128::from(dirty_rate_bytes_per_second)
        .saturating_mul(100)
        .saturating_div(u128::from(bandwidth));
    u16::try_from(pct).unwrap_or(u16::MAX)
}

const fn pages_for_bytes(bytes: u64, page_size_bytes: u64) -> u64 {
    if bytes == 0 || page_size_bytes == 0 {
        return 0;
    }
    bytes.div_ceil(page_size_bytes)
}

const fn bytes_per_second_to_mibps(bytes_per_second: u64) -> u64 {
    bytes_per_second / MIB
}
