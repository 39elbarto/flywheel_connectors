//! Batch/map progress tracking and partial result collection.
//!
//! Tracks real-time progress of batch operations, emits periodic status
//! updates, persists partial results for interruption recovery, and supports
//! resume-from-progress-file.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Progress state ─────────────────────────────────────────────────────

/// Current status of a batch operation progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchPhase {
    /// Batch is being prepared (parsing, validation).
    Preparing,
    /// Batch is actively executing items.
    Running,
    /// Batch completed all items.
    Completed,
    /// Batch was interrupted (Ctrl-C, error in abort mode).
    Interrupted,
    /// Batch failed.
    Failed,
}

impl std::fmt::Display for BatchPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preparing => f.write_str("preparing"),
            Self::Running => f.write_str("running"),
            Self::Completed => f.write_str("completed"),
            Self::Interrupted => f.write_str("interrupted"),
            Self::Failed => f.write_str("failed"),
        }
    }
}

/// Progress snapshot for a batch execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProgress {
    /// Current phase.
    pub phase: BatchPhase,
    /// Total number of items.
    pub total: usize,
    /// Items completed (success or error).
    pub completed: usize,
    /// Items succeeded.
    pub succeeded: usize,
    /// Items failed.
    pub failed: usize,
    /// Items skipped.
    pub skipped: usize,
    /// Items still pending.
    pub pending: usize,
    /// Epoch seconds when the batch started.
    pub started_at: u64,
    /// Epoch seconds of last update.
    pub updated_at: u64,
    /// Estimated seconds remaining (if calculable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_seconds: Option<u64>,
    /// Items per second throughput.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throughput: Option<f64>,
}

impl BatchProgress {
    /// Create a new progress tracker for a batch of `total` items.
    pub fn new(total: usize) -> Self {
        let now = epoch_seconds();
        Self {
            phase: BatchPhase::Preparing,
            total,
            completed: 0,
            succeeded: 0,
            failed: 0,
            skipped: 0,
            pending: total,
            started_at: now,
            updated_at: now,
            eta_seconds: None,
            throughput: None,
        }
    }

    /// Mark the batch as running.
    pub fn start(&mut self) {
        self.phase = BatchPhase::Running;
        self.started_at = epoch_seconds();
        self.updated_at = self.started_at;
    }

    /// Record a successful item.
    pub fn record_success(&mut self) {
        self.succeeded += 1;
        self.completed += 1;
        self.pending = self.total.saturating_sub(self.completed + self.skipped);
        self.update_estimates();
    }

    /// Record a failed item.
    pub fn record_failure(&mut self) {
        self.failed += 1;
        self.completed += 1;
        self.pending = self.total.saturating_sub(self.completed + self.skipped);
        self.update_estimates();
    }

    /// Record a skipped item.
    pub fn record_skip(&mut self) {
        self.skipped += 1;
        self.pending = self.total.saturating_sub(self.completed + self.skipped);
        self.update_estimates();
    }

    /// Mark the batch as completed.
    pub fn complete(&mut self) {
        self.phase = BatchPhase::Completed;
        self.pending = 0;
        self.eta_seconds = Some(0);
        self.updated_at = epoch_seconds();
    }

    /// Mark the batch as interrupted.
    pub fn interrupt(&mut self) {
        self.phase = BatchPhase::Interrupted;
        self.updated_at = epoch_seconds();
    }

    /// Mark the batch as failed.
    pub fn fail(&mut self) {
        self.phase = BatchPhase::Failed;
        self.updated_at = epoch_seconds();
    }

    /// Progress as a fraction [0.0, 1.0].
    #[allow(clippy::cast_precision_loss)] // Intentional: batch sizes ≪ 2^52.
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        (self.completed + self.skipped) as f64 / self.total as f64
    }

    /// Progress as a percentage [0, 100].
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn percent(&self) -> u8 {
        let pct = (self.fraction() * 100.0) as u64;
        pct.min(100) as u8
    }

    /// Elapsed seconds since start.
    pub fn elapsed_seconds(&self) -> u64 {
        epoch_seconds().saturating_sub(self.started_at)
    }

    /// Whether all items are done.
    pub const fn is_done(&self) -> bool {
        matches!(
            self.phase,
            BatchPhase::Completed | BatchPhase::Interrupted | BatchPhase::Failed
        )
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn update_estimates(&mut self) {
        let now = epoch_seconds();
        self.updated_at = now;
        let elapsed = now.saturating_sub(self.started_at);
        if elapsed > 0 && self.completed > 0 {
            let rate = self.completed as f64 / elapsed as f64;
            self.throughput = Some(rate);
            if self.pending > 0 {
                self.eta_seconds = Some((self.pending as f64 / rate).ceil() as u64);
            } else {
                self.eta_seconds = Some(0);
            }
        }
    }
}

// ── Progress file (partial results) ────────────────────────────────────

/// A single item result persisted to the progress file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialResult {
    /// Item index in the batch.
    pub index: usize,
    /// Operation ID (for batch-file) or item index string.
    pub id: String,
    /// Whether this item succeeded.
    pub success: bool,
    /// Result or error payload.
    pub payload: Value,
    /// Epoch seconds when completed.
    pub completed_at: u64,
}

/// Progress file state — written as JSON to a sidecar file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressFile {
    /// Batch operation that was executed.
    pub operation: String,
    /// Current progress snapshot.
    pub progress: BatchProgress,
    /// Results collected so far.
    pub results: Vec<PartialResult>,
    /// Indices of items still pending.
    pub pending_indices: Vec<usize>,
}

impl ProgressFile {
    /// Create a new progress file state.
    pub fn new(operation: &str, total: usize) -> Self {
        Self {
            operation: operation.to_owned(),
            progress: BatchProgress::new(total),
            results: Vec::new(),
            pending_indices: (0..total).collect(),
        }
    }

    /// Record a result and update progress.
    pub fn record_result(&mut self, result: PartialResult) {
        self.pending_indices.retain(|&i| i != result.index);
        if result.success {
            self.progress.record_success();
        } else {
            self.progress.record_failure();
        }
        self.results.push(result);
    }

    /// Get indices that need to be processed (for resume).
    pub fn remaining_indices(&self) -> &[usize] {
        &self.pending_indices
    }

    /// Whether the batch can be resumed.
    pub fn is_resumable(&self) -> bool {
        matches!(
            self.progress.phase,
            BatchPhase::Interrupted | BatchPhase::Running
        ) && !self.pending_indices.is_empty()
    }

    /// Write to a file as JSON.
    pub fn write_to(&self, path: &Path) -> Result<(), String> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("serialize error: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("write error: {e}"))
    }

    /// Read from a file.
    pub fn read_from(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
        serde_json::from_str(&content).map_err(|e| format!("parse error: {e}"))
    }
}

// ── Progress rendering ─────────────────────────────────────────────────

/// Render a terminal-friendly progress bar.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn render_progress_bar(progress: &BatchProgress, width: usize) -> String {
    let filled = ((progress.fraction() * width as f64).round() as usize).min(width);
    let empty = width.saturating_sub(filled);
    let bar: String = "█".repeat(filled) + &"░".repeat(empty);

    let eta_str = progress.eta_seconds.map_or_else(
        || "ETA: --".to_owned(),
        |s| {
            if s == 0 {
                "ETA: done".to_owned()
            } else {
                format!("ETA: {s}s")
            }
        },
    );

    format!(
        "[{bar}] {}% ({}/{}) ✓{} ✗{} ◇{} | {eta_str}",
        progress.percent(),
        progress.completed + progress.skipped,
        progress.total,
        progress.succeeded,
        progress.failed,
        progress.skipped,
    )
}

/// Render a JSON status update line.
pub fn render_progress_json(progress: &BatchProgress) -> String {
    serde_json::to_string(progress).unwrap_or_default()
}

// ── Resume plan ────────────────────────────────────────────────────────

/// Plan for resuming a batch from a progress file.
#[derive(Debug, Clone, Serialize)]
pub struct ResumePlan {
    /// Path to the progress file.
    pub progress_file: PathBuf,
    /// Operation being resumed.
    pub operation: String,
    /// Total items in original batch.
    pub total: usize,
    /// Items already completed.
    pub completed: usize,
    /// Items remaining to process.
    pub remaining: usize,
    /// Indices of remaining items.
    pub remaining_indices: Vec<usize>,
}

impl ResumePlan {
    /// Build a resume plan from a progress file.
    pub fn from_progress(path: &Path, progress_file: &ProgressFile) -> Self {
        Self {
            progress_file: path.to_owned(),
            operation: progress_file.operation.clone(),
            total: progress_file.progress.total,
            completed: progress_file.progress.completed,
            remaining: progress_file.pending_indices.len(),
            remaining_indices: progress_file.pending_indices.clone(),
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── BatchProgress ──────────────────────────────────────────────

    #[test]
    fn new_progress_is_preparing() {
        let p = BatchProgress::new(10);
        assert_eq!(p.phase, BatchPhase::Preparing);
        assert_eq!(p.total, 10);
        assert_eq!(p.completed, 0);
        assert_eq!(p.pending, 10);
        assert!(!p.is_done());
    }

    #[test]
    fn start_sets_running() {
        let mut p = BatchProgress::new(5);
        p.start();
        assert_eq!(p.phase, BatchPhase::Running);
    }

    #[test]
    fn record_success_updates_counts() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_success();
        assert_eq!(p.succeeded, 1);
        assert_eq!(p.completed, 1);
        assert_eq!(p.pending, 2);
    }

    #[test]
    fn record_failure_updates_counts() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_failure();
        assert_eq!(p.failed, 1);
        assert_eq!(p.completed, 1);
        assert_eq!(p.pending, 2);
    }

    #[test]
    fn record_skip_updates_counts() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_skip();
        assert_eq!(p.skipped, 1);
        assert_eq!(p.pending, 2);
    }

    #[test]
    fn complete_sets_done() {
        let mut p = BatchProgress::new(2);
        p.start();
        p.record_success();
        p.record_success();
        p.complete();
        assert!(p.is_done());
        assert_eq!(p.phase, BatchPhase::Completed);
        assert_eq!(p.pending, 0);
    }

    #[test]
    fn interrupt_sets_done() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.record_success();
        p.interrupt();
        assert!(p.is_done());
        assert_eq!(p.phase, BatchPhase::Interrupted);
    }

    #[test]
    fn fail_sets_done() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.fail();
        assert!(p.is_done());
        assert_eq!(p.phase, BatchPhase::Failed);
    }

    #[test]
    fn fraction_zero_total() {
        let p = BatchProgress::new(0);
        assert!((p.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fraction_half() {
        let mut p = BatchProgress::new(4);
        p.start();
        p.record_success();
        p.record_success();
        assert!((p.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn percent_full() {
        let mut p = BatchProgress::new(1);
        p.start();
        p.record_success();
        assert_eq!(p.percent(), 100);
    }

    #[test]
    fn percent_zero() {
        let p = BatchProgress::new(10);
        assert_eq!(p.percent(), 0);
    }

    #[test]
    fn progress_serializes() {
        let p = BatchProgress::new(5);
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["phase"], "preparing");
        assert_eq!(json["total"], 5);
        assert_eq!(json["pending"], 5);
    }

    #[test]
    fn progress_roundtrip() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_success();
        let json = serde_json::to_string(&p).unwrap();
        let back: BatchProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phase, BatchPhase::Running);
        assert_eq!(back.succeeded, 1);
    }

    // ── BatchPhase ─────────────────────────────────────────────────

    #[test]
    fn phase_display() {
        assert_eq!(BatchPhase::Preparing.to_string(), "preparing");
        assert_eq!(BatchPhase::Running.to_string(), "running");
        assert_eq!(BatchPhase::Completed.to_string(), "completed");
        assert_eq!(BatchPhase::Interrupted.to_string(), "interrupted");
        assert_eq!(BatchPhase::Failed.to_string(), "failed");
    }

    #[test]
    fn phase_roundtrip() {
        for phase in [
            BatchPhase::Preparing,
            BatchPhase::Running,
            BatchPhase::Completed,
            BatchPhase::Interrupted,
            BatchPhase::Failed,
        ] {
            let json = serde_json::to_string(&phase).unwrap();
            let back: BatchPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(back, phase);
        }
    }

    // ── PartialResult ──────────────────────────────────────────────

    #[test]
    fn partial_result_success() {
        let r = PartialResult {
            index: 0,
            id: "s1".to_owned(),
            success: true,
            payload: json!({"data": "ok"}),
            completed_at: 1000,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["index"], 0);
    }

    #[test]
    fn partial_result_failure() {
        let r = PartialResult {
            index: 1,
            id: "s2".to_owned(),
            success: false,
            payload: json!({"error": "timeout"}),
            completed_at: 1001,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["success"], false);
    }

    #[test]
    fn partial_result_roundtrip() {
        let r = PartialResult {
            index: 5,
            id: "step5".to_owned(),
            success: true,
            payload: json!(42),
            completed_at: 9999,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.index, 5);
        assert_eq!(back.id, "step5");
    }

    // ── ProgressFile ───────────────────────────────────────────────

    #[test]
    fn progress_file_new() {
        let pf = ProgressFile::new("github.get_issue", 5);
        assert_eq!(pf.operation, "github.get_issue");
        assert_eq!(pf.progress.total, 5);
        assert_eq!(pf.pending_indices, vec![0, 1, 2, 3, 4]);
        assert!(pf.results.is_empty());
    }

    #[test]
    fn progress_file_record_result() {
        let mut pf = ProgressFile::new("op", 3);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        assert_eq!(pf.results.len(), 1);
        assert_eq!(pf.pending_indices, vec![1, 2]);
        assert_eq!(pf.progress.succeeded, 1);
    }

    #[test]
    fn progress_file_remaining_indices() {
        let mut pf = ProgressFile::new("op", 4);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 1,
            id: "1".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        pf.record_result(PartialResult {
            index: 3,
            id: "3".to_owned(),
            success: false,
            payload: json!({}),
            completed_at: 101,
        });
        assert_eq!(pf.remaining_indices(), &[0, 2]);
    }

    #[test]
    fn progress_file_resumable_after_interrupt() {
        let mut pf = ProgressFile::new("op", 3);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        pf.progress.interrupt();
        assert!(pf.is_resumable());
    }

    #[test]
    fn progress_file_not_resumable_after_complete() {
        let mut pf = ProgressFile::new("op", 1);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        pf.progress.complete();
        assert!(!pf.is_resumable());
    }

    #[test]
    fn progress_file_write_and_read() {
        let dir = std::env::temp_dir().join("fwc-progress-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_progress.json");

        let mut pf = ProgressFile::new("github.get_issue", 3);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "s0".to_owned(),
            success: true,
            payload: json!({"id": 42}),
            completed_at: epoch_seconds(),
        });
        pf.progress.interrupt();
        pf.write_to(&path).unwrap();

        let loaded = ProgressFile::read_from(&path).unwrap();
        assert_eq!(loaded.operation, "github.get_issue");
        assert_eq!(loaded.progress.phase, BatchPhase::Interrupted);
        assert_eq!(loaded.results.len(), 1);
        assert_eq!(loaded.pending_indices, vec![1, 2]);
        assert!(loaded.is_resumable());
    }

    #[test]
    fn progress_file_serializes() {
        let pf = ProgressFile::new("op", 2);
        let json = serde_json::to_value(&pf).unwrap();
        assert_eq!(json["operation"], "op");
        assert!(json["progress"].is_object());
        assert!(json["results"].is_array());
        assert_eq!(json["pending_indices"].as_array().unwrap().len(), 2);
    }

    // ── ResumePlan ─────────────────────────────────────────────────

    #[test]
    fn resume_plan_from_progress() {
        let mut pf = ProgressFile::new("github.get_issue", 5);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        pf.record_result(PartialResult {
            index: 2,
            id: "2".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 101,
        });
        pf.progress.interrupt();

        let plan = ResumePlan::from_progress(Path::new("progress.json"), &pf);
        assert_eq!(plan.total, 5);
        assert_eq!(plan.completed, 2);
        assert_eq!(plan.remaining, 3);
        assert_eq!(plan.remaining_indices, vec![1, 3, 4]);
    }

    #[test]
    fn resume_plan_serializes() {
        let plan = ResumePlan {
            progress_file: PathBuf::from("progress.json"),
            operation: "op".to_owned(),
            total: 10,
            completed: 3,
            remaining: 7,
            remaining_indices: vec![3, 4, 5, 6, 7, 8, 9],
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["total"], 10);
        assert_eq!(json["remaining"], 7);
    }

    // ── Progress bar rendering ─────────────────────────────────────

    #[test]
    fn render_bar_empty() {
        let p = BatchProgress::new(10);
        let bar = render_progress_bar(&p, 20);
        assert!(bar.contains("0%"));
        assert!(bar.contains("0/10"));
    }

    #[test]
    fn render_bar_half() {
        let mut p = BatchProgress::new(4);
        p.start();
        p.record_success();
        p.record_success();
        let bar = render_progress_bar(&p, 20);
        assert!(bar.contains("50%"));
        assert!(bar.contains("2/4"));
    }

    #[test]
    fn render_bar_complete() {
        let mut p = BatchProgress::new(2);
        p.start();
        p.record_success();
        p.record_success();
        p.complete();
        let bar = render_progress_bar(&p, 10);
        assert!(bar.contains("100%"));
        assert!(bar.contains("done"));
    }

    #[test]
    fn render_bar_with_failures() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_success();
        p.record_failure();
        let bar = render_progress_bar(&p, 20);
        assert!(bar.contains("✓1"));
        assert!(bar.contains("✗1"));
    }

    // ── Progress JSON rendering ────────────────────────────────────

    #[test]
    fn render_json_parseable() {
        let p = BatchProgress::new(5);
        let json_str = render_progress_json(&p);
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["total"], 5);
    }

    // ── Mixed scenarios ────────────────────────────────────────────

    #[test]
    fn mixed_success_failure_skip() {
        let mut p = BatchProgress::new(6);
        p.start();
        p.record_success();
        p.record_success();
        p.record_failure();
        p.record_skip();
        assert_eq!(p.succeeded, 2);
        assert_eq!(p.failed, 1);
        assert_eq!(p.skipped, 1);
        assert_eq!(p.completed, 3);
        assert_eq!(p.pending, 2);
        assert!((p.fraction() - 4.0 / 6.0).abs() < 0.01);
    }

    #[test]
    fn all_items_done_progress() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_success();
        p.record_failure();
        p.record_skip();
        assert_eq!(p.pending, 0);
        assert_eq!(p.percent(), 100);
    }
}
