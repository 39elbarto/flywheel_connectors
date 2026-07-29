//! Statistical summaries for performance evidence.
//!
//! `StatPack` is intentionally deterministic: percentile selection, bootstrap
//! resampling, and Welch comparisons do not depend on wall-clock time or OS
//! randomness. That makes benchmark evidence replayable in CI and audit logs.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_BOOTSTRAP_RESAMPLES: usize = 1_000;
const BOOTSTRAP_CI_LOW_PER_MILLE: usize = 25;
const BOOTSTRAP_CI_HIGH_PER_MILLE: usize = 975;
const MIN_STD_EPSILON: f64 = 1.0e-12;

/// Summary statistics used by benchmark evidence gates.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StatPack {
    /// 50th percentile.
    pub p50: f64,
    /// 99th percentile.
    pub p99: f64,
    /// 99.9th percentile.
    pub p999: f64,
    /// Arithmetic mean.
    pub mean: f64,
    /// Sample standard deviation.
    pub std: f64,
    /// Welch t-statistic for the most recent baseline comparison.
    ///
    /// Standalone packs have no baseline, so this is `NaN` until a comparison
    /// is made through [`Self::compare_welch`].
    pub welch_t: f64,
    /// Percentile bootstrap 95% confidence interval for the mean.
    pub bootstrap_ci: (f64, f64),
    /// Tail amplification ratio `(p999 - p99) / (p99 - p50)`.
    pub tail_amp: f64,

    #[serde(skip)]
    sample_count: usize,
    #[serde(skip)]
    variance: f64,
}

impl StatPack {
    /// Compute a `StatPack` using the default 1000 bootstrap resamples.
    #[must_use]
    pub fn from_samples(samples: &[f64]) -> Self {
        Self::with_resamples(samples, DEFAULT_BOOTSTRAP_RESAMPLES)
    }

    /// Compute a `StatPack` with an explicit bootstrap resample count.
    ///
    /// Empty or non-finite-only inputs produce a pack with `NaN` numeric fields
    /// rather than panicking. Benchmark gates should treat that as invalid
    /// evidence.
    #[must_use]
    pub fn with_resamples(samples: &[f64], resamples: usize) -> Self {
        let sorted = finite_sorted(samples);
        if sorted.is_empty() {
            return Self::nan();
        }

        let sample_count = sorted.len();
        let mean = arithmetic_mean(&sorted);
        let variance = sample_variance(&sorted, mean);
        let std = variance.sqrt();
        tracing::debug!(
            target: "fcp.bench.stats",
            fcp_bench_stats_phase = "sample_summary",
            fcp_bench_stats_sample_count = sample_count,
            fcp_bench_stats_bootstrap_resamples = resamples,
            "fcp.bench.stats sample loop summary"
        );
        let p50 = percentile(&sorted, 0.500);
        let p99 = percentile(&sorted, 0.990);
        let p999 = percentile(&sorted, 0.999);
        let bootstrap_ci = bootstrap_mean_ci(&sorted, resamples);
        let tail_amp = tail_amplification(p50, p99, p999);

        Self {
            p50,
            p99,
            p999,
            mean,
            std,
            welch_t: f64::NAN,
            bootstrap_ci,
            tail_amp,
            sample_count,
            variance,
        }
    }

    /// Compare this sample set against a baseline with Welch's unequal-variance
    /// t-test and return the two-sided p-value.
    #[must_use]
    pub fn welch_vs(&self, baseline: &Self) -> f64 {
        self.compare_welch(baseline).p_value
    }

    /// Compare this sample set against a baseline and return both t and p.
    #[must_use]
    pub fn compare_welch(&self, baseline: &Self) -> WelchComparison {
        if self.sample_count < 2
            || baseline.sample_count < 2
            || !self.variance.is_finite()
            || !baseline.variance.is_finite()
        {
            return WelchComparison::nan();
        }

        let self_n = self.sample_count as f64;
        let baseline_n = baseline.sample_count as f64;
        let self_term = self.variance / self_n;
        let baseline_term = baseline.variance / baseline_n;
        let standard_error = (self_term + baseline_term).sqrt();

        if standard_error <= MIN_STD_EPSILON {
            return WelchComparison::nan();
        }

        let t = (self.mean - baseline.mean) / standard_error;
        let df_num = (self_term + baseline_term).powi(2);
        let df_den =
            (self_term.powi(2) / (self_n - 1.0)) + (baseline_term.powi(2) / (baseline_n - 1.0));

        if df_den <= MIN_STD_EPSILON {
            return WelchComparison::nan();
        }

        let degrees_of_freedom = df_num / df_den;
        let p_value = student_t_two_sided_p_value(t, degrees_of_freedom);

        WelchComparison {
            t,
            degrees_of_freedom,
            p_value,
        }
    }

    /// Return a copy carrying the Welch t-statistic from a baseline comparison.
    #[must_use]
    pub fn with_welch_baseline(mut self, baseline: &Self) -> Self {
        self.welch_t = self.compare_welch(baseline).t;
        self
    }

    /// Serialize a redaction-safe JSON value for logs or evidence bundles.
    #[must_use]
    pub fn to_json_value(&self) -> Value {
        json!({
            "p50": self.p50,
            "p99": self.p99,
            "p999": self.p999,
            "mean": self.mean,
            "std": self.std,
            "welch_t": finite_or_null(self.welch_t),
            "bootstrap_ci": [self.bootstrap_ci.0, self.bootstrap_ci.1],
            "tail_amp": self.tail_amp,
            "sample_count": self.sample_count,
        })
    }

    /// Emit the final `StatPack` as an INFO JSON line through `tracing`.
    pub fn log_info_json_line(&self) {
        tracing::info!(
            target: "fcp.bench.stats",
            fcp_bench_stats_p50 = self.p50,
            fcp_bench_stats_p99 = self.p99,
            fcp_bench_stats_p999 = self.p999,
            fcp_bench_stats_mean = self.mean,
            fcp_bench_stats_std = self.std,
            fcp_bench_stats_welch_t = self.welch_t,
            fcp_bench_stats_bootstrap_ci_low = self.bootstrap_ci.0,
            fcp_bench_stats_bootstrap_ci_high = self.bootstrap_ci.1,
            fcp_bench_stats_tail_amp = self.tail_amp,
            fcp_bench_stats_sample_count = self.sample_count,
            statpack = %self.to_json_value(),
            "fcp.bench.stats.statpack"
        );
    }

    const fn nan() -> Self {
        Self {
            p50: f64::NAN,
            p99: f64::NAN,
            p999: f64::NAN,
            mean: f64::NAN,
            std: f64::NAN,
            welch_t: f64::NAN,
            bootstrap_ci: (f64::NAN, f64::NAN),
            tail_amp: f64::NAN,
            sample_count: 0,
            variance: f64::NAN,
        }
    }
}

/// Welch unequal-variance t-test result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WelchComparison {
    /// Welch t-statistic.
    pub t: f64,
    /// Satterthwaite degrees of freedom.
    pub degrees_of_freedom: f64,
    /// Two-sided p-value.
    pub p_value: f64,
}

impl WelchComparison {
    const fn nan() -> Self {
        Self {
            t: f64::NAN,
            degrees_of_freedom: f64::NAN,
            p_value: f64::NAN,
        }
    }
}

fn finite_sorted(samples: &[f64]) -> Vec<f64> {
    let mut sorted: Vec<f64> = samples
        .iter()
        .copied()
        .filter(|sample| sample.is_finite())
        .collect();
    sorted.sort_by(f64::total_cmp);
    sorted
}

fn arithmetic_mean(samples: &[f64]) -> f64 {
    samples.iter().sum::<f64>() / samples.len() as f64
}

fn sample_variance(samples: &[f64], mean: f64) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }

    let squared_error = samples
        .iter()
        .map(|sample| {
            let delta = *sample - mean;
            delta * delta
        })
        .sum::<f64>();

    squared_error / (samples.len() - 1) as f64
}

fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    debug_assert!(!sorted.is_empty());

    if sorted.len() == 1 {
        return sorted[0];
    }

    let rank = quantile.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;

    if lower == upper {
        sorted[lower]
    } else {
        let weight = rank - lower as f64;
        sorted[lower].mul_add(1.0 - weight, sorted[upper] * weight)
    }
}

fn bootstrap_mean_ci(sorted: &[f64], resamples: usize) -> (f64, f64) {
    if sorted.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    if resamples == 0 {
        let mean = arithmetic_mean(sorted);
        return (mean, mean);
    }

    let mut seed = bootstrap_seed(sorted);
    let mut means = Vec::with_capacity(resamples);

    for resample_index in 0..resamples {
        tracing::debug!(
            target: "fcp.bench.stats",
            fcp_bench_stats_phase = "bootstrap_resample",
            fcp_bench_stats_resample_index = resample_index,
            fcp_bench_stats_sample_count = sorted.len(),
            "fcp.bench.stats bootstrap resample"
        );
        let mut sum = 0.0;
        for _ in 0..sorted.len() {
            let index = next_index(&mut seed, sorted.len());
            sum += sorted[index];
        }
        means.push(sum / sorted.len() as f64);
    }

    means.sort_by(f64::total_cmp);
    (
        nearest_rank(&means, BOOTSTRAP_CI_LOW_PER_MILLE),
        nearest_rank(&means, BOOTSTRAP_CI_HIGH_PER_MILLE),
    )
}

fn bootstrap_seed(sorted: &[f64]) -> u64 {
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64 ^ sorted.len() as u64;
    for sample in sorted.iter().take(64) {
        seed ^= sample.to_bits();
        seed = splitmix64(&mut seed);
    }
    seed
}

const fn next_index(seed: &mut u64, len: usize) -> usize {
    let value = splitmix64(seed);
    (value as usize) % len
}

const fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *seed;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn nearest_rank(sorted: &[f64], per_mille: usize) -> f64 {
    debug_assert!(!sorted.is_empty());

    let len = sorted.len();
    let mut index = (len * per_mille).div_ceil(1_000).saturating_sub(1);
    if index >= len {
        index = len - 1;
    }
    sorted[index]
}

fn tail_amplification(p50: f64, p99: f64, p999: f64) -> f64 {
    let central_span = p99 - p50;
    let far_tail_span = p999 - p99;

    if central_span.abs() <= MIN_STD_EPSILON {
        if far_tail_span.abs() <= MIN_STD_EPSILON {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        far_tail_span / central_span
    }
}

fn student_t_two_sided_p_value(t: f64, degrees_of_freedom: f64) -> f64 {
    if !t.is_finite() || !degrees_of_freedom.is_finite() || degrees_of_freedom <= 0.0 {
        return f64::NAN;
    }

    let abs_t = t.abs();
    if abs_t <= MIN_STD_EPSILON {
        return 1.0;
    }
    if abs_t > 12.0 {
        return 0.0;
    }

    let integral = integrate_student_t_pdf(abs_t, degrees_of_freedom);
    (2.0 * (0.5 - integral)).clamp(0.0, 1.0)
}

fn integrate_student_t_pdf(upper: f64, degrees_of_freedom: f64) -> f64 {
    let mut steps = ((upper * 128.0).ceil() as usize).max(64);
    if steps % 2 == 1 {
        steps += 1;
    }

    let h = upper / steps as f64;
    let mut sum = student_t_pdf(0.0, degrees_of_freedom) + student_t_pdf(upper, degrees_of_freedom);

    for step in 1..steps {
        let x = step as f64 * h;
        let weight = if step % 2 == 0 { 2.0 } else { 4.0 };
        sum += weight * student_t_pdf(x, degrees_of_freedom);
    }

    sum * h / 3.0
}

fn student_t_pdf(x: f64, degrees_of_freedom: f64) -> f64 {
    let half_df = degrees_of_freedom / 2.0;
    let half_df_plus_half = f64::midpoint(degrees_of_freedom, 1.0);
    let log_coeff = (-0.5_f64).mul_add(
        (degrees_of_freedom * std::f64::consts::PI).ln(),
        ln_gamma(half_df_plus_half) - ln_gamma(half_df),
    );
    let log_kernel = -half_df_plus_half * (x * x / degrees_of_freedom).ln_1p();

    (log_coeff + log_kernel).exp()
}

fn ln_gamma(value: f64) -> f64 {
    const COEFFICIENTS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];

    if value < 0.5 {
        return std::f64::consts::PI.ln()
            - (std::f64::consts::PI * value).sin().ln()
            - ln_gamma(1.0 - value);
    }

    let shifted = value - 1.0;
    let mut x = COEFFICIENTS[0];
    for (index, coefficient) in COEFFICIENTS.iter().enumerate().skip(1) {
        x += coefficient / (shifted + index as f64);
    }

    let t = shifted + 7.5;
    (shifted + 0.5).mul_add(t.ln(), (2.0 * std::f64::consts::PI).ln() / 2.0) - t + x.ln()
}

fn finite_or_null(value: f64) -> Value {
    if value.is_finite() {
        json!(value)
    } else {
        Value::Null
    }
}
