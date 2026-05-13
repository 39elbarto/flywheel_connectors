//! Distribution-free confidence scoring for audit decision receipts.
//!
//! The estimator is intentionally conservative: it only scores a connector /
//! operation pair from its own receipt history, falls back to a low confidence
//! when history is sparse, and decays confidence as the history goes stale.

use serde::{Deserialize, Serialize};

use crate::DecisionReceipt;

const SCORE_SCALE: u32 = 1_000_000;
const DEFAULT_WINDOW_SIZE: usize = 128;
const DEFAULT_MIN_HISTORY: usize = 5;
const DEFAULT_CONSERVATIVE_SCORE_PPM: u32 = 250_000;
const DEFAULT_STALENESS_HALF_LIFE_SECS: u64 = 7 * 24 * 60 * 60;

/// Calibrated p-value-style reliability score carried by a receipt.
///
/// `score_ppm` is parts-per-million in `[0, 1_000_000]`. Integer storage keeps
/// receipt equality and canonical receipt IDs deterministic while
/// [`Self::value`] exposes the operator-facing `[0.0, 1.0]` score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalScore {
    /// Reliability score as parts-per-million.
    pub score_ppm: u32,
    /// Receipts used to calibrate this score.
    pub sample_count: u32,
    /// Nonconforming receipts in the calibration window.
    pub nonconforming_count: u32,
    /// Age in seconds of the newest receipt in the calibration window.
    pub staleness_secs: u64,
    /// Why the conservative fallback was used, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conservative_reason: Option<String>,
}

impl ConformalScore {
    /// Build a score from a floating-point value, clamped into `[0.0, 1.0]`.
    #[must_use]
    pub fn from_value(
        value: f64,
        sample_count: u32,
        nonconforming_count: u32,
        staleness_secs: u64,
        conservative_reason: Option<String>,
    ) -> Self {
        let clamped = value.clamp(0.0, 1.0);
        let scaled = clamped * f64::from(SCORE_SCALE);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let score_ppm = scaled.round() as u32;
        Self {
            score_ppm: score_ppm.min(SCORE_SCALE),
            sample_count,
            nonconforming_count,
            staleness_secs,
            conservative_reason,
        }
    }

    /// Build the default conservative score.
    #[must_use]
    pub fn conservative(
        sample_count: u32,
        nonconforming_count: u32,
        staleness_secs: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            score_ppm: DEFAULT_CONSERVATIVE_SCORE_PPM,
            sample_count,
            nonconforming_count,
            staleness_secs,
            conservative_reason: Some(reason.into()),
        }
    }

    /// Operator-facing value in `[0.0, 1.0]`.
    #[must_use]
    pub fn value(&self) -> f64 {
        f64::from(self.score_ppm) / f64::from(SCORE_SCALE)
    }

    /// Short stable display string for tables and narratives.
    #[must_use]
    pub fn display_value(&self) -> String {
        format!("{:.3}", self.value())
    }
}

/// Rolling-window conformal score estimator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformalScoreEstimator {
    window_size: usize,
    min_history: usize,
    staleness_half_life_secs: u64,
}

impl Default for ConformalScoreEstimator {
    fn default() -> Self {
        Self {
            window_size: DEFAULT_WINDOW_SIZE,
            min_history: DEFAULT_MIN_HISTORY,
            staleness_half_life_secs: DEFAULT_STALENESS_HALF_LIFE_SECS,
        }
    }
}

impl ConformalScoreEstimator {
    /// Build an estimator with default production parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the maximum number of recent receipts used for calibration.
    #[must_use]
    pub fn with_window_size(mut self, window_size: usize) -> Self {
        self.window_size = window_size.max(1);
        self
    }

    /// Override the minimum history required before leaving conservative mode.
    #[must_use]
    pub fn with_min_history(mut self, min_history: usize) -> Self {
        self.min_history = min_history.max(1);
        self
    }

    /// Override the staleness half-life used to decay confidence.
    #[must_use]
    pub fn with_staleness_half_life_secs(mut self, staleness_half_life_secs: u64) -> Self {
        self.staleness_half_life_secs = staleness_half_life_secs.max(1);
        self
    }

    /// Score a receipt using prior receipts for the same connector operation.
    #[must_use]
    pub fn score_receipt(
        &self,
        receipt: &DecisionReceipt,
        history: &[DecisionReceipt],
        now_secs: u64,
    ) -> ConformalScore {
        let Some(connector_id) = receipt.connector_id.as_deref() else {
            return ConformalScore::conservative(0, 0, 0, "missing_connector_id");
        };
        let Some(operation_id) = receipt.operation_id.as_deref() else {
            return ConformalScore::conservative(0, 0, 0, "missing_operation_id");
        };

        let mut matching: Vec<&DecisionReceipt> = history
            .iter()
            .filter(|candidate| {
                candidate.connector_id.as_deref() == Some(connector_id)
                    && candidate.operation_id.as_deref() == Some(operation_id)
            })
            .collect();
        matching.sort_by_key(|candidate| candidate.decided_at);

        let start = matching.len().saturating_sub(self.window_size);
        let window = &matching[start..];
        let sample_count = saturating_u32(window.len());
        let nonconforming_count = saturating_u32(
            window
                .iter()
                .filter(|candidate| candidate.decision.is_deny())
                .count(),
        );
        let staleness_secs = window
            .last()
            .map_or(0, |candidate| now_secs.saturating_sub(candidate.decided_at));

        if window.len() < self.min_history {
            return ConformalScore::conservative(
                sample_count,
                nonconforming_count,
                staleness_secs,
                "insufficient_history",
            );
        }

        let conforming_count = sample_count.saturating_sub(nonconforming_count);
        let smoothed_reliability = f64::from(conforming_count.saturating_add(1))
            / f64::from(sample_count.saturating_add(2));
        let staleness_decay =
            1.0 / (1.0 + age_ratio(staleness_secs, self.staleness_half_life_secs));
        ConformalScore::from_value(
            smoothed_reliability * staleness_decay,
            sample_count,
            nonconforming_count,
            staleness_secs,
            None,
        )
    }
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn age_ratio(age_secs: u64, half_life_secs: u64) -> f64 {
    let age = f64::from(u32::try_from(age_secs).unwrap_or(u32::MAX));
    let half_life = f64::from(u32::try_from(half_life_secs).unwrap_or(u32::MAX));
    age / half_life
}
