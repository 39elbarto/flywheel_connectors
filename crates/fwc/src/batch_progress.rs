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

    // ── Additional BatchPhase tests ───────────────────────────────

    #[test]
    fn phase_clone_and_equality() {
        let phase = BatchPhase::Running;
        let cloned = phase.clone();
        assert_eq!(phase, cloned);
    }

    #[test]
    fn phase_inequality() {
        assert_ne!(BatchPhase::Preparing, BatchPhase::Running);
        assert_ne!(BatchPhase::Running, BatchPhase::Completed);
        assert_ne!(BatchPhase::Completed, BatchPhase::Interrupted);
        assert_ne!(BatchPhase::Interrupted, BatchPhase::Failed);
    }

    #[test]
    fn phase_debug_format() {
        assert_eq!(format!("{:?}", BatchPhase::Preparing), "Preparing");
        assert_eq!(format!("{:?}", BatchPhase::Failed), "Failed");
    }

    #[test]
    fn phase_serde_all_snake_case() {
        assert_eq!(
            serde_json::to_string(&BatchPhase::Preparing).unwrap(),
            "\"preparing\""
        );
        assert_eq!(
            serde_json::to_string(&BatchPhase::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&BatchPhase::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&BatchPhase::Interrupted).unwrap(),
            "\"interrupted\""
        );
        assert_eq!(
            serde_json::to_string(&BatchPhase::Failed).unwrap(),
            "\"failed\""
        );
    }

    // ── Additional BatchProgress tests ────────────────────────────

    #[test]
    fn progress_zero_total_is_done_initially() {
        let p = BatchProgress::new(0);
        assert_eq!(p.percent(), 100);
        assert_eq!(p.pending, 0);
    }

    #[test]
    fn progress_large_batch() {
        let mut p = BatchProgress::new(10_000);
        p.start();
        for _ in 0..5_000 {
            p.record_success();
        }
        assert_eq!(p.succeeded, 5_000);
        assert_eq!(p.pending, 5_000);
        assert_eq!(p.percent(), 50);
    }

    #[test]
    fn progress_all_failures() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_failure();
        p.record_failure();
        p.record_failure();
        assert_eq!(p.failed, 3);
        assert_eq!(p.succeeded, 0);
        assert_eq!(p.pending, 0);
        assert_eq!(p.percent(), 100);
    }

    #[test]
    fn progress_all_skips() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_skip();
        p.record_skip();
        p.record_skip();
        assert_eq!(p.skipped, 3);
        assert_eq!(p.completed, 0);
        assert_eq!(p.pending, 0);
        assert_eq!(p.percent(), 100);
    }

    #[test]
    fn progress_fraction_with_skips() {
        let mut p = BatchProgress::new(4);
        p.start();
        p.record_success();
        p.record_skip();
        // 2 of 4 done (completed=1, skipped=1)
        assert!((p.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_is_done_false_for_preparing() {
        let p = BatchProgress::new(5);
        assert!(!p.is_done());
    }

    #[test]
    fn progress_is_done_false_for_running() {
        let mut p = BatchProgress::new(5);
        p.start();
        assert!(!p.is_done());
    }

    #[test]
    fn progress_is_done_true_for_completed() {
        let mut p = BatchProgress::new(1);
        p.start();
        p.record_success();
        p.complete();
        assert!(p.is_done());
    }

    #[test]
    fn progress_is_done_true_for_interrupted() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.interrupt();
        assert!(p.is_done());
    }

    #[test]
    fn progress_is_done_true_for_failed() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.fail();
        assert!(p.is_done());
    }

    #[test]
    fn progress_complete_sets_eta_zero() {
        let mut p = BatchProgress::new(2);
        p.start();
        p.record_success();
        p.record_success();
        p.complete();
        assert_eq!(p.eta_seconds, Some(0));
    }

    #[test]
    fn progress_elapsed_seconds_non_negative() {
        let p = BatchProgress::new(5);
        assert!(p.elapsed_seconds() < 60); // should be near zero
    }

    #[test]
    fn progress_percent_capped_at_100() {
        let mut p = BatchProgress::new(1);
        p.start();
        p.record_success();
        p.record_success(); // over-count
        // pending saturates at 0
        assert!(p.percent() <= 100);
    }

    #[test]
    fn progress_serde_optional_fields_absent() {
        let p = BatchProgress::new(5);
        let json = serde_json::to_value(&p).unwrap();
        // eta_seconds and throughput should be absent due to skip_serializing_if
        assert!(json.get("eta_seconds").is_none());
        assert!(json.get("throughput").is_none());
    }

    #[test]
    fn progress_clone() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_success();
        let cloned = p.clone();
        assert_eq!(cloned.succeeded, p.succeeded);
        assert_eq!(cloned.total, p.total);
        assert_eq!(cloned.phase, p.phase);
    }

    // ── Additional PartialResult tests ────────────────────────────

    #[test]
    fn partial_result_clone() {
        let r = PartialResult {
            index: 0,
            id: "test".to_owned(),
            success: true,
            payload: json!({"key": "value"}),
            completed_at: 1000,
        };
        let cloned = r.clone();
        assert_eq!(cloned.index, r.index);
        assert_eq!(cloned.id, r.id);
        assert_eq!(cloned.payload, r.payload);
    }

    #[test]
    fn partial_result_with_null_payload() {
        let r = PartialResult {
            index: 0,
            id: "x".to_owned(),
            success: true,
            payload: json!(null),
            completed_at: 0,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert!(json["payload"].is_null());
    }

    #[test]
    fn partial_result_with_array_payload() {
        let r = PartialResult {
            index: 2,
            id: "multi".to_owned(),
            success: true,
            payload: json!([1, 2, 3]),
            completed_at: 500,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["payload"].as_array().unwrap().len(), 3);
    }

    // ── Additional ProgressFile tests ─────────────────────────────

    #[test]
    fn progress_file_zero_items() {
        let pf = ProgressFile::new("op", 0);
        assert!(pf.pending_indices.is_empty());
        assert!(pf.results.is_empty());
    }

    #[test]
    fn progress_file_record_multiple_results() {
        let mut pf = ProgressFile::new("op", 5);
        pf.progress.start();
        for i in 0..5 {
            pf.record_result(PartialResult {
                index: i,
                id: format!("{i}"),
                success: i % 2 == 0,
                payload: json!({}),
                completed_at: 100 + i as u64,
            });
        }
        assert_eq!(pf.results.len(), 5);
        assert!(pf.pending_indices.is_empty());
        assert_eq!(pf.progress.succeeded, 3); // 0, 2, 4
        assert_eq!(pf.progress.failed, 2); // 1, 3
    }

    #[test]
    fn progress_file_not_resumable_when_failed() {
        let mut pf = ProgressFile::new("op", 3);
        pf.progress.start();
        pf.progress.fail();
        assert!(!pf.is_resumable());
    }

    #[test]
    fn progress_file_resumable_while_running_with_pending() {
        let mut pf = ProgressFile::new("op", 3);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        assert!(pf.is_resumable());
    }

    #[test]
    fn progress_file_not_resumable_when_all_done_running() {
        let mut pf = ProgressFile::new("op", 1);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        // Still Running but no pending
        assert!(!pf.is_resumable());
    }

    #[test]
    fn progress_file_roundtrip_serde() {
        let mut pf = ProgressFile::new("batch.op", 3);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 1,
            id: "item-1".to_owned(),
            success: true,
            payload: json!({"ok": true}),
            completed_at: 999,
        });
        let json = serde_json::to_string(&pf).unwrap();
        let back: ProgressFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operation, "batch.op");
        assert_eq!(back.results.len(), 1);
        assert_eq!(back.pending_indices, vec![0, 2]);
    }

    // ── Additional ResumePlan tests ───────────────────────────────

    #[test]
    fn resume_plan_all_remaining() {
        let pf = ProgressFile::new("op", 5);
        let plan = ResumePlan::from_progress(Path::new("p.json"), &pf);
        assert_eq!(plan.total, 5);
        assert_eq!(plan.completed, 0);
        assert_eq!(plan.remaining, 5);
        assert_eq!(plan.remaining_indices, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn resume_plan_none_remaining() {
        let mut pf = ProgressFile::new("op", 2);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        pf.record_result(PartialResult {
            index: 1,
            id: "1".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 101,
        });
        let plan = ResumePlan::from_progress(Path::new("p.json"), &pf);
        assert_eq!(plan.remaining, 0);
        assert!(plan.remaining_indices.is_empty());
    }

    #[test]
    fn resume_plan_operation_preserved() {
        let pf = ProgressFile::new("github.list_repos", 3);
        let plan = ResumePlan::from_progress(Path::new("x.json"), &pf);
        assert_eq!(plan.operation, "github.list_repos");
    }

    #[test]
    fn resume_plan_progress_file_path() {
        let pf = ProgressFile::new("op", 1);
        let plan = ResumePlan::from_progress(Path::new("/tmp/my_progress.json"), &pf);
        assert_eq!(plan.progress_file, PathBuf::from("/tmp/my_progress.json"));
    }

    // ── Additional rendering tests ────────────────────────────────

    #[test]
    fn render_bar_zero_width() {
        let p = BatchProgress::new(5);
        let bar = render_progress_bar(&p, 0);
        assert!(bar.contains("0%"));
    }

    #[test]
    fn render_bar_with_skips() {
        let mut p = BatchProgress::new(4);
        p.start();
        p.record_success();
        p.record_skip();
        let bar = render_progress_bar(&p, 10);
        assert!(bar.contains("◇1"));
        assert!(bar.contains("✓1"));
    }

    #[test]
    fn render_bar_all_failures() {
        let mut p = BatchProgress::new(2);
        p.start();
        p.record_failure();
        p.record_failure();
        p.complete();
        let bar = render_progress_bar(&p, 10);
        assert!(bar.contains("✗2"));
        assert!(bar.contains("✓0"));
    }

    #[test]
    fn render_bar_no_eta() {
        let p = BatchProgress::new(5);
        let bar = render_progress_bar(&p, 10);
        assert!(bar.contains("ETA: --"));
    }

    #[test]
    fn render_json_contains_phase() {
        let p = BatchProgress::new(3);
        let json_str = render_progress_json(&p);
        assert!(json_str.contains("preparing"));
    }

    #[test]
    fn render_json_running_phase() {
        let mut p = BatchProgress::new(3);
        p.start();
        let json_str = render_progress_json(&p);
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["phase"], "running");
    }

    // ── Progress file I/O edge cases ──────────────────────────────

    #[test]
    fn progress_file_read_nonexistent() {
        let result = ProgressFile::read_from(Path::new("/nonexistent/path/file.json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("read error"));
    }

    #[test]
    fn progress_file_write_and_read_empty() {
        let dir = std::env::temp_dir().join("fwc-bp-empty-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty_progress.json");

        let pf = ProgressFile::new("empty.op", 0);
        pf.write_to(&path).unwrap();

        let loaded = ProgressFile::read_from(&path).unwrap();
        assert_eq!(loaded.operation, "empty.op");
        assert_eq!(loaded.progress.total, 0);
        assert!(loaded.results.is_empty());
    }

    // ── BatchPhase extended tests ─────────────────────────────────

    #[test]
    fn phase_clone_all_variants() {
        for phase in [
            BatchPhase::Preparing,
            BatchPhase::Running,
            BatchPhase::Completed,
            BatchPhase::Interrupted,
            BatchPhase::Failed,
        ] {
            let cloned = phase.clone();
            assert_eq!(phase, cloned);
        }
    }

    #[test]
    fn phase_debug_all_variants() {
        assert_eq!(format!("{:?}", BatchPhase::Running), "Running");
        assert_eq!(format!("{:?}", BatchPhase::Completed), "Completed");
        assert_eq!(format!("{:?}", BatchPhase::Interrupted), "Interrupted");
    }

    #[test]
    fn phase_display_matches_serde() {
        for phase in [
            BatchPhase::Preparing,
            BatchPhase::Running,
            BatchPhase::Completed,
            BatchPhase::Interrupted,
            BatchPhase::Failed,
        ] {
            let display = phase.to_string();
            let serde_str = serde_json::to_string(&phase).unwrap();
            // serde wraps in quotes
            assert_eq!(format!("\"{display}\""), serde_str);
        }
    }

    #[test]
    fn phase_deserialize_from_string() {
        let p: BatchPhase = serde_json::from_str("\"preparing\"").unwrap();
        assert_eq!(p, BatchPhase::Preparing);
        let p: BatchPhase = serde_json::from_str("\"failed\"").unwrap();
        assert_eq!(p, BatchPhase::Failed);
    }

    #[test]
    fn phase_deserialize_invalid_variant() {
        let result = serde_json::from_str::<BatchPhase>("\"unknown_phase\"");
        assert!(result.is_err());
    }

    #[test]
    fn phase_deserialize_not_a_string() {
        let result = serde_json::from_str::<BatchPhase>("42");
        assert!(result.is_err());
    }

    // ── BatchProgress extended tests ──────────────────────────────

    #[test]
    fn progress_new_sets_timestamps() {
        let before = epoch_seconds();
        let p = BatchProgress::new(5);
        let after = epoch_seconds();
        assert!(p.started_at >= before && p.started_at <= after);
        assert!(p.updated_at >= before && p.updated_at <= after);
    }

    #[test]
    fn progress_start_resets_started_at() {
        let p1 = BatchProgress::new(5);
        let original_start = p1.started_at;
        let mut p2 = p1;
        // started_at should be updated on start
        p2.start();
        assert!(p2.started_at >= original_start);
        assert_eq!(p2.started_at, p2.updated_at);
    }

    #[test]
    fn progress_record_success_decrements_pending() {
        let mut p = BatchProgress::new(5);
        p.start();
        for i in 0..5 {
            p.record_success();
            assert_eq!(p.pending, 5 - (i + 1));
        }
        assert_eq!(p.pending, 0);
    }

    #[test]
    fn progress_record_failure_decrements_pending() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_failure();
        assert_eq!(p.pending, 2);
        p.record_failure();
        assert_eq!(p.pending, 1);
        p.record_failure();
        assert_eq!(p.pending, 0);
    }

    #[test]
    fn progress_record_skip_decrements_pending() {
        let mut p = BatchProgress::new(2);
        p.start();
        p.record_skip();
        assert_eq!(p.pending, 1);
        p.record_skip();
        assert_eq!(p.pending, 0);
    }

    #[test]
    fn progress_skip_does_not_increment_completed() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_skip();
        assert_eq!(p.completed, 0);
        assert_eq!(p.skipped, 1);
    }

    #[test]
    fn progress_fraction_one_of_one() {
        let mut p = BatchProgress::new(1);
        p.start();
        p.record_success();
        assert!((p.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_fraction_none_completed() {
        let p = BatchProgress::new(10);
        assert!((p.fraction() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_fraction_all_skipped() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_skip();
        p.record_skip();
        p.record_skip();
        assert!((p.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_fraction_mixed_complete_and_skip() {
        let mut p = BatchProgress::new(10);
        p.start();
        for _ in 0..3 {
            p.record_success();
        }
        for _ in 0..2 {
            p.record_skip();
        }
        // fraction = (3 completed + 2 skipped) / 10 = 0.5
        assert!((p.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_percent_quarter() {
        let mut p = BatchProgress::new(4);
        p.start();
        p.record_success();
        assert_eq!(p.percent(), 25);
    }

    #[test]
    fn progress_percent_three_quarters() {
        let mut p = BatchProgress::new(4);
        p.start();
        p.record_success();
        p.record_success();
        p.record_skip();
        assert_eq!(p.percent(), 75);
    }

    #[test]
    fn progress_percent_zero_total_returns_100() {
        let p = BatchProgress::new(0);
        assert_eq!(p.percent(), 100);
    }

    #[test]
    fn progress_complete_zeros_pending_regardless() {
        let mut p = BatchProgress::new(10);
        p.start();
        p.record_success();
        // Only 1 done, but complete() forces pending = 0
        p.complete();
        assert_eq!(p.pending, 0);
    }

    #[test]
    fn progress_interrupt_does_not_change_pending() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.record_success();
        let pending_before = p.pending;
        p.interrupt();
        assert_eq!(p.pending, pending_before);
    }

    #[test]
    fn progress_fail_does_not_change_pending() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.record_failure();
        let pending_before = p.pending;
        p.fail();
        assert_eq!(p.pending, pending_before);
    }

    #[test]
    fn progress_saturating_sub_on_overcount() {
        let mut p = BatchProgress::new(1);
        p.start();
        p.record_success();
        p.record_success();
        p.record_success();
        // pending should saturate at 0, not underflow
        assert_eq!(p.pending, 0);
        assert_eq!(p.completed, 3);
    }

    #[test]
    fn progress_throughput_none_initially() {
        let p = BatchProgress::new(10);
        assert!(p.throughput.is_none());
    }

    #[test]
    fn progress_eta_none_initially() {
        let p = BatchProgress::new(10);
        assert!(p.eta_seconds.is_none());
    }

    #[test]
    fn progress_serde_running_phase_preserved() {
        let mut p = BatchProgress::new(5);
        p.start();
        let json = serde_json::to_string(&p).unwrap();
        let back: BatchProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phase, BatchPhase::Running);
    }

    #[test]
    fn progress_serde_completed_phase_preserved() {
        let mut p = BatchProgress::new(1);
        p.start();
        p.record_success();
        p.complete();
        let json = serde_json::to_string(&p).unwrap();
        let back: BatchProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phase, BatchPhase::Completed);
        assert_eq!(back.eta_seconds, Some(0));
    }

    #[test]
    fn progress_serde_interrupted_phase_preserved() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.interrupt();
        let json = serde_json::to_string(&p).unwrap();
        let back: BatchProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phase, BatchPhase::Interrupted);
    }

    #[test]
    fn progress_serde_failed_phase_preserved() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.fail();
        let json = serde_json::to_string(&p).unwrap();
        let back: BatchProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phase, BatchPhase::Failed);
    }

    #[test]
    fn progress_serde_all_fields_present_when_set() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.throughput = Some(10.0);
        p.eta_seconds = Some(42);
        let json = serde_json::to_value(&p).unwrap();
        assert!(json.get("throughput").is_some());
        assert!(json.get("eta_seconds").is_some());
        assert_eq!(json["throughput"], 10.0);
        assert_eq!(json["eta_seconds"], 42);
    }

    #[test]
    fn progress_debug_format_contains_fields() {
        let p = BatchProgress::new(5);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Preparing"));
        assert!(dbg.contains("total: 5"));
    }

    #[test]
    fn progress_clone_independence() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.record_success();
        let mut cloned = p.clone();
        cloned.record_success();
        // Original should not be affected
        assert_eq!(p.succeeded, 1);
        assert_eq!(cloned.succeeded, 2);
    }

    #[test]
    fn progress_elapsed_seconds_after_start() {
        let mut p = BatchProgress::new(5);
        p.start();
        // elapsed should be very small (< 2s)
        assert!(p.elapsed_seconds() < 2);
    }

    #[test]
    fn progress_elapsed_with_past_start() {
        let mut p = BatchProgress::new(5);
        p.started_at = epoch_seconds().saturating_sub(100);
        assert!(p.elapsed_seconds() >= 100);
    }

    // ── PartialResult extended tests ─────────────────────────────

    #[test]
    fn partial_result_debug_format() {
        let r = PartialResult {
            index: 7,
            id: "test-7".to_owned(),
            success: false,
            payload: json!("err"),
            completed_at: 500,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("index: 7"));
        assert!(dbg.contains("test-7"));
        assert!(dbg.contains("false"));
    }

    #[test]
    fn partial_result_with_nested_payload() {
        let r = PartialResult {
            index: 0,
            id: "nested".to_owned(),
            success: true,
            payload: json!({"outer": {"inner": [1, 2, 3]}}),
            completed_at: 100,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload["outer"]["inner"][1], 2);
    }

    #[test]
    fn partial_result_with_string_payload() {
        let r = PartialResult {
            index: 0,
            id: "str".to_owned(),
            success: true,
            payload: json!("hello world"),
            completed_at: 100,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["payload"], "hello world");
    }

    #[test]
    fn partial_result_with_boolean_payload() {
        let r = PartialResult {
            index: 0,
            id: "bool".to_owned(),
            success: false,
            payload: json!(false),
            completed_at: 100,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["payload"], false);
    }

    #[test]
    fn partial_result_with_numeric_payload() {
        let r = PartialResult {
            index: 0,
            id: "num".to_owned(),
            success: true,
            payload: json!(3.14),
            completed_at: 100,
        };
        let json = serde_json::to_value(&r).unwrap();
        let val = json["payload"].as_f64().unwrap();
        assert!((val - 3.14).abs() < f64::EPSILON);
    }

    #[test]
    fn partial_result_with_empty_object_payload() {
        let r = PartialResult {
            index: 0,
            id: "empty_obj".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 0,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert!(json["payload"].is_object());
        assert!(json["payload"].as_object().unwrap().is_empty());
    }

    #[test]
    fn partial_result_with_empty_array_payload() {
        let r = PartialResult {
            index: 0,
            id: "empty_arr".to_owned(),
            success: true,
            payload: json!([]),
            completed_at: 0,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert!(json["payload"].is_array());
        assert!(json["payload"].as_array().unwrap().is_empty());
    }

    #[test]
    fn partial_result_clone_independence() {
        let r = PartialResult {
            index: 0,
            id: "orig".to_owned(),
            success: true,
            payload: json!({"k": "v"}),
            completed_at: 1000,
        };
        let mut cloned = r.clone();
        cloned.id = "cloned".to_owned();
        cloned.index = 99;
        assert_eq!(r.id, "orig");
        assert_eq!(r.index, 0);
    }

    #[test]
    fn partial_result_large_index() {
        let r = PartialResult {
            index: usize::MAX,
            id: "max".to_owned(),
            success: true,
            payload: json!(null),
            completed_at: 0,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.index, usize::MAX);
    }

    #[test]
    fn partial_result_empty_id() {
        let r = PartialResult {
            index: 0,
            id: String::new(),
            success: true,
            payload: json!(null),
            completed_at: 0,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: PartialResult = serde_json::from_str(&json).unwrap();
        assert!(back.id.is_empty());
    }

    // ── ProgressFile extended tests ──────────────────────────────

    #[test]
    fn progress_file_record_out_of_order() {
        let mut pf = ProgressFile::new("op", 5);
        pf.progress.start();
        // Record indices out of order: 4, 1, 3
        for idx in [4, 1, 3] {
            pf.record_result(PartialResult {
                index: idx,
                id: format!("{idx}"),
                success: true,
                payload: json!({}),
                completed_at: 100,
            });
        }
        assert_eq!(pf.results.len(), 3);
        assert_eq!(pf.pending_indices, vec![0, 2]);
    }

    #[test]
    fn progress_file_record_duplicate_index() {
        let mut pf = ProgressFile::new("op", 3);
        pf.progress.start();
        let result = PartialResult {
            index: 1,
            id: "1".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        };
        pf.record_result(result.clone());
        pf.record_result(result);
        // The duplicate retain call won't find index 1 again, so results grows
        assert_eq!(pf.results.len(), 2);
        // But pending_indices won't have 1 in it
        assert!(!pf.pending_indices.contains(&1));
    }

    #[test]
    fn progress_file_clone() {
        let mut pf = ProgressFile::new("op", 3);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        let cloned = pf.clone();
        assert_eq!(cloned.operation, pf.operation);
        assert_eq!(cloned.results.len(), pf.results.len());
        assert_eq!(cloned.pending_indices, pf.pending_indices);
    }

    #[test]
    fn progress_file_clone_independence() {
        let mut pf = ProgressFile::new("op", 3);
        pf.progress.start();
        let mut cloned = pf.clone();
        cloned.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        // Original should not be affected
        assert!(pf.results.is_empty());
        assert_eq!(cloned.results.len(), 1);
    }

    #[test]
    fn progress_file_not_resumable_when_preparing() {
        let pf = ProgressFile::new("op", 3);
        // Phase is Preparing, which is not resumable
        assert!(!pf.is_resumable());
    }

    #[test]
    fn progress_file_not_resumable_after_interrupt_all_done() {
        let mut pf = ProgressFile::new("op", 2);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        pf.record_result(PartialResult {
            index: 1,
            id: "1".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 101,
        });
        pf.progress.interrupt();
        // Interrupted but no pending items
        assert!(!pf.is_resumable());
    }

    #[test]
    fn progress_file_debug_format() {
        let pf = ProgressFile::new("test.op", 2);
        let dbg = format!("{pf:?}");
        assert!(dbg.contains("test.op"));
        assert!(dbg.contains("ProgressFile"));
    }

    #[test]
    fn progress_file_large_batch() {
        let pf = ProgressFile::new("op", 1000);
        assert_eq!(pf.pending_indices.len(), 1000);
        assert_eq!(*pf.pending_indices.last().unwrap(), 999);
    }

    #[test]
    fn progress_file_all_results_failure() {
        let mut pf = ProgressFile::new("op", 3);
        pf.progress.start();
        for i in 0..3 {
            pf.record_result(PartialResult {
                index: i,
                id: format!("{i}"),
                success: false,
                payload: json!({"error": "fail"}),
                completed_at: 100 + i as u64,
            });
        }
        assert_eq!(pf.progress.failed, 3);
        assert_eq!(pf.progress.succeeded, 0);
        assert!(pf.pending_indices.is_empty());
    }

    #[test]
    fn progress_file_write_to_invalid_path() {
        let result = ProgressFile::new("op", 1).write_to(Path::new("/nonexistent/dir/file.json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("write error"));
    }

    #[test]
    fn progress_file_read_invalid_json() {
        let dir = std::env::temp_dir().join("fwc-bp-invalid-json");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("invalid.json");
        std::fs::write(&path, "not valid json").unwrap();
        let result = ProgressFile::read_from(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parse error"));
    }

    #[test]
    fn progress_file_write_read_with_results() {
        let dir = std::env::temp_dir().join("fwc-bp-results-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("results_progress.json");

        let mut pf = ProgressFile::new("batch.process", 5);
        pf.progress.start();
        for i in 0..3 {
            pf.record_result(PartialResult {
                index: i,
                id: format!("item-{i}"),
                success: i != 1,
                payload: json!({"idx": i}),
                completed_at: 200 + i as u64,
            });
        }
        pf.progress.interrupt();
        pf.write_to(&path).unwrap();

        let loaded = ProgressFile::read_from(&path).unwrap();
        assert_eq!(loaded.results.len(), 3);
        assert_eq!(loaded.pending_indices, vec![3, 4]);
        assert_eq!(loaded.progress.succeeded, 2);
        assert_eq!(loaded.progress.failed, 1);
        assert!(loaded.is_resumable());
    }

    #[test]
    fn progress_file_remaining_indices_empty_when_done() {
        let mut pf = ProgressFile::new("op", 2);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "0".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 100,
        });
        pf.record_result(PartialResult {
            index: 1,
            id: "1".to_owned(),
            success: true,
            payload: json!({}),
            completed_at: 101,
        });
        assert!(pf.remaining_indices().is_empty());
    }

    // ── ResumePlan extended tests ────────────────────────────────

    #[test]
    fn resume_plan_clone() {
        let pf = ProgressFile::new("op", 5);
        let plan = ResumePlan::from_progress(Path::new("p.json"), &pf);
        let cloned = plan.clone();
        assert_eq!(cloned.total, plan.total);
        assert_eq!(cloned.operation, plan.operation);
        assert_eq!(cloned.remaining_indices, plan.remaining_indices);
    }

    #[test]
    fn resume_plan_debug_format() {
        let pf = ProgressFile::new("test.op", 3);
        let plan = ResumePlan::from_progress(Path::new("debug.json"), &pf);
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("test.op"));
        assert!(dbg.contains("ResumePlan"));
    }

    #[test]
    fn resume_plan_serialize_all_fields() {
        let plan = ResumePlan {
            progress_file: PathBuf::from("/data/progress.json"),
            operation: "github.get_issues".to_owned(),
            total: 100,
            completed: 42,
            remaining: 58,
            remaining_indices: (42..100).collect(),
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["progress_file"], "/data/progress.json");
        assert_eq!(json["operation"], "github.get_issues");
        assert_eq!(json["total"], 100);
        assert_eq!(json["completed"], 42);
        assert_eq!(json["remaining"], 58);
        assert_eq!(json["remaining_indices"].as_array().unwrap().len(), 58);
    }

    #[test]
    fn resume_plan_from_partial_progress() {
        let mut pf = ProgressFile::new("op", 10);
        pf.progress.start();
        // Complete indices 0, 2, 4, 6, 8 (evens)
        for i in (0..10).step_by(2) {
            pf.record_result(PartialResult {
                index: i,
                id: format!("{i}"),
                success: true,
                payload: json!({}),
                completed_at: 100,
            });
        }
        pf.progress.interrupt();
        let plan = ResumePlan::from_progress(Path::new("p.json"), &pf);
        assert_eq!(plan.completed, 5);
        assert_eq!(plan.remaining, 5);
        assert_eq!(plan.remaining_indices, vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn resume_plan_zero_total() {
        let pf = ProgressFile::new("op", 0);
        let plan = ResumePlan::from_progress(Path::new("p.json"), &pf);
        assert_eq!(plan.total, 0);
        assert_eq!(plan.completed, 0);
        assert_eq!(plan.remaining, 0);
        assert!(plan.remaining_indices.is_empty());
    }

    #[test]
    fn resume_plan_preserves_path_with_spaces() {
        let pf = ProgressFile::new("op", 1);
        let plan = ResumePlan::from_progress(Path::new("/my path/with spaces/p.json"), &pf);
        assert_eq!(
            plan.progress_file,
            PathBuf::from("/my path/with spaces/p.json")
        );
    }

    // ── Rendering extended tests ─────────────────────────────────

    #[test]
    fn render_bar_single_width() {
        let p = BatchProgress::new(2);
        let bar = render_progress_bar(&p, 1);
        assert!(bar.contains('['));
        assert!(bar.contains(']'));
    }

    #[test]
    fn render_bar_large_width() {
        let mut p = BatchProgress::new(4);
        p.start();
        p.record_success();
        p.record_success();
        let bar = render_progress_bar(&p, 100);
        // Should have ~50 filled blocks
        let filled_count = bar.chars().filter(|&c| c == '█').count();
        assert_eq!(filled_count, 50);
    }

    #[test]
    fn render_bar_zero_total() {
        let p = BatchProgress::new(0);
        let bar = render_progress_bar(&p, 10);
        // fraction=1.0 for zero total, so 100%
        assert!(bar.contains("100%"));
    }

    #[test]
    fn render_bar_eta_with_seconds() {
        let mut p = BatchProgress::new(10);
        p.start();
        p.eta_seconds = Some(30);
        let bar = render_progress_bar(&p, 10);
        assert!(bar.contains("ETA: 30s"));
    }

    #[test]
    fn render_bar_eta_done() {
        let mut p = BatchProgress::new(1);
        p.start();
        p.record_success();
        p.complete();
        let bar = render_progress_bar(&p, 10);
        assert!(bar.contains("ETA: done"));
    }

    #[test]
    fn render_bar_format_structure() {
        let mut p = BatchProgress::new(3);
        p.start();
        p.record_success();
        let bar = render_progress_bar(&p, 10);
        // Should contain the structure: [bar] pct% (done/total) ...
        assert!(bar.starts_with('['));
        assert!(bar.contains(']'));
        assert!(bar.contains('/'));
        assert!(bar.contains('%'));
    }

    #[test]
    fn render_bar_empty_bar_chars() {
        let p = BatchProgress::new(5);
        let bar = render_progress_bar(&p, 10);
        let empty_count = bar.chars().filter(|&c| c == '░').count();
        assert_eq!(empty_count, 10);
    }

    #[test]
    fn render_bar_full_bar_chars() {
        let mut p = BatchProgress::new(2);
        p.start();
        p.record_success();
        p.record_success();
        p.complete();
        let bar = render_progress_bar(&p, 10);
        let filled_count = bar.chars().filter(|&c| c == '█').count();
        assert_eq!(filled_count, 10);
        let empty_count = bar.chars().filter(|&c| c == '░').count();
        assert_eq!(empty_count, 0);
    }

    #[test]
    fn render_json_roundtrip() {
        let mut p = BatchProgress::new(5);
        p.start();
        p.record_success();
        p.record_failure();
        let json_str = render_progress_json(&p);
        let back: BatchProgress = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.succeeded, 1);
        assert_eq!(back.failed, 1);
        assert_eq!(back.total, 5);
    }

    #[test]
    fn render_json_includes_all_counts() {
        let mut p = BatchProgress::new(10);
        p.start();
        p.record_success();
        p.record_failure();
        p.record_skip();
        let json_str = render_progress_json(&p);
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["succeeded"], 1);
        assert_eq!(parsed["failed"], 1);
        assert_eq!(parsed["skipped"], 1);
        assert_eq!(parsed["pending"], 7);
    }

    #[test]
    fn render_json_completed_state() {
        let mut p = BatchProgress::new(1);
        p.start();
        p.record_success();
        p.complete();
        let json_str = render_progress_json(&p);
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["phase"], "completed");
        assert_eq!(parsed["pending"], 0);
    }

    // ── End-to-end scenario tests ────────────────────────────────

    #[test]
    fn scenario_full_lifecycle_success() {
        let mut pf = ProgressFile::new("github.list_repos", 3);
        assert_eq!(pf.progress.phase, BatchPhase::Preparing);

        pf.progress.start();
        assert_eq!(pf.progress.phase, BatchPhase::Running);

        for i in 0..3 {
            pf.record_result(PartialResult {
                index: i,
                id: format!("repo-{i}"),
                success: true,
                payload: json!({"name": format!("repo-{i}")}),
                completed_at: epoch_seconds(),
            });
        }
        pf.progress.complete();

        assert!(pf.progress.is_done());
        assert_eq!(pf.progress.succeeded, 3);
        assert_eq!(pf.progress.failed, 0);
        assert_eq!(pf.progress.pending, 0);
        assert!(pf.pending_indices.is_empty());
        assert!(!pf.is_resumable());
    }

    #[test]
    fn scenario_interrupt_and_resume() {
        let dir = std::env::temp_dir().join("fwc-bp-resume-scenario");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("resume_scenario.json");

        // Phase 1: Run and get interrupted
        let mut pf = ProgressFile::new("slack.send_message", 5);
        pf.progress.start();
        pf.record_result(PartialResult {
            index: 0,
            id: "msg-0".to_owned(),
            success: true,
            payload: json!({"ok": true}),
            completed_at: epoch_seconds(),
        });
        pf.record_result(PartialResult {
            index: 1,
            id: "msg-1".to_owned(),
            success: true,
            payload: json!({"ok": true}),
            completed_at: epoch_seconds(),
        });
        pf.progress.interrupt();
        pf.write_to(&path).unwrap();

        // Phase 2: Load and build resume plan
        let loaded = ProgressFile::read_from(&path).unwrap();
        assert!(loaded.is_resumable());
        let plan = ResumePlan::from_progress(&path, &loaded);
        assert_eq!(plan.completed, 2);
        assert_eq!(plan.remaining, 3);
        assert_eq!(plan.remaining_indices, vec![2, 3, 4]);
    }

    #[test]
    fn scenario_mixed_results_with_rendering() {
        let mut p = BatchProgress::new(6);
        p.start();
        p.record_success();
        p.record_success();
        p.record_failure();
        p.record_skip();

        let bar = render_progress_bar(&p, 12);
        assert!(bar.contains("✓2"));
        assert!(bar.contains("✗1"));
        assert!(bar.contains("◇1"));
        assert!(bar.contains("4/6"));
        assert!(bar.contains("66%"));

        let json_str = render_progress_json(&p);
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["succeeded"], 2);
        assert_eq!(parsed["failed"], 1);
        assert_eq!(parsed["skipped"], 1);
        assert_eq!(parsed["pending"], 2);
    }

    #[test]
    fn scenario_all_skipped_batch() {
        let mut pf = ProgressFile::new("filter.apply", 4);
        pf.progress.start();
        for i in 0..4 {
            pf.progress.record_skip();
            pf.pending_indices.retain(|&idx| idx != i);
        }
        pf.progress.complete();

        assert_eq!(pf.progress.skipped, 4);
        assert_eq!(pf.progress.completed, 0);
        assert_eq!(pf.progress.succeeded, 0);
        assert_eq!(pf.progress.pending, 0);
        assert!(pf.pending_indices.is_empty());
    }

    // ── epoch_seconds helper test ────────────────────────────────

    #[test]
    fn epoch_seconds_is_reasonable() {
        let now = epoch_seconds();
        // Should be after 2024-01-01 (1704067200) and before 2100-01-01 (4102444800)
        assert!(now > 1_704_067_200);
        assert!(now < 4_102_444_800);
    }
}
