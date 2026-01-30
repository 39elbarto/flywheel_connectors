//! Benchmark runner with statistical analysis.
//!
//! Provides utilities for running benchmarks with warmup iterations
//! and calculating percentile statistics (p50, p90, p99).

use std::time::Instant;

use super::types::Percentiles;

/// Run a benchmark function that returns a value (to prevent optimization).
///
/// The return value is passed to `std::hint::black_box` to prevent
/// the compiler from optimizing away the computation.
///
/// # Returns
/// A tuple of (`Percentiles`, outlier count).
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
pub fn run_benchmark_with_result<F, R>(warmup: u32, iterations: u32, mut f: F) -> (Percentiles, u32)
where
    F: FnMut() -> R,
{
    // Warmup iterations (not measured).
    for _ in 0..warmup {
        std::hint::black_box(f());
    }

    // Measured iterations.
    let mut durations_ns: Vec<u64> = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed();
        std::hint::black_box(result);
        // Note: as_nanos() returns u128, but benchmark durations should fit in u64
        // (max ~584 years in nanoseconds).
        durations_ns.push(elapsed.as_nanos() as u64);
    }

    // Sort for percentile calculation.
    durations_ns.sort_unstable();

    // Detect outliers using IQR method.
    let outlier_count = count_outliers(&durations_ns);

    // Calculate statistics.
    let percentiles = calculate_percentiles(&durations_ns);

    (percentiles, outlier_count)
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn calculate_percentiles(sorted_ns: &[u64]) -> Percentiles {
    let len = sorted_ns.len();
    if len == 0 {
        return Percentiles {
            p50_ms: 0.0,
            p90_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            min_ms: 0.0,
            max_ms: 0.0,
            mean_ms: 0.0,
            stddev_ms: 0.0,
        };
    }

    // Convert nanoseconds to milliseconds directly.
    let ns_to_ms = |ns: u64| ns as f64 / 1_000_000.0;

    let p50_idx = (len as f64 * 0.50) as usize;
    let p90_idx = (len as f64 * 0.90) as usize;
    let p95_idx = (len as f64 * 0.95) as usize;
    let p99_idx = (len as f64 * 0.99) as usize;

    let p50_ms = ns_to_ms(sorted_ns[p50_idx.min(len - 1)]);
    let p90_ms = ns_to_ms(sorted_ns[p90_idx.min(len - 1)]);
    let p95_ms = ns_to_ms(sorted_ns[p95_idx.min(len - 1)]);
    let p99_ms = ns_to_ms(sorted_ns[p99_idx.min(len - 1)]);
    let min_ms = ns_to_ms(sorted_ns[0]);
    let max_ms = ns_to_ms(sorted_ns[len - 1]);

    // Calculate mean.
    let sum: u64 = sorted_ns.iter().sum();
    let mean_nanoseconds = sum as f64 / len as f64;
    let mean_ms = mean_nanoseconds / 1_000_000.0;

    // Calculate standard deviation.
    let variance: f64 = sorted_ns
        .iter()
        .map(|&ns| {
            let diff = ns as f64 - mean_nanoseconds;
            diff * diff
        })
        .sum::<f64>()
        / len as f64;
    let stddev_nanoseconds = variance.sqrt();
    let stddev_ms = stddev_nanoseconds / 1_000_000.0;

    Percentiles {
        p50_ms,
        p90_ms,
        p95_ms,
        p99_ms,
        min_ms,
        max_ms,
        mean_ms,
        stddev_ms,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn count_outliers(sorted_ns: &[u64]) -> u32 {
    let len = sorted_ns.len();
    if len < 4 {
        return 0;
    }

    // Calculate IQR (Interquartile Range).
    let q1_idx = len / 4;
    let q3_idx = (3 * len) / 4;
    let q1 = sorted_ns[q1_idx] as f64;
    let q3 = sorted_ns[q3_idx] as f64;
    let iqr = q3 - q1;

    // Outlier bounds: Q1 - 1.5*IQR and Q3 + 1.5*IQR.
    let lower_bound = 1.5f64.mul_add(-iqr, q1);
    let upper_bound = 1.5f64.mul_add(iqr, q3);

    // Count values outside bounds.
    sorted_ns
        .iter()
        .filter(|&&ns| (ns as f64) < lower_bound || (ns as f64) > upper_bound)
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_calculation() {
        // Create a simple sorted array: 1, 2, 3, ..., 100.
        let sorted: Vec<u64> = (1..=100).map(|x| x * 1_000_000).collect(); // In nanoseconds.

        let p = calculate_percentiles(&sorted);

        // p50 should be around 50ms, p90 around 90ms, p99 around 99ms.
        assert!((p.p50_ms - 50.0).abs() < 2.0);
        assert!((p.p90_ms - 90.0).abs() < 2.0);
        assert!((p.p95_ms - 95.0).abs() < 2.0);
        assert!((p.p99_ms - 99.0).abs() < 2.0);
        assert!((p.min_ms - 1.0).abs() < 0.01);
        assert!((p.max_ms - 100.0).abs() < 0.01);
    }

    #[test]
    fn outlier_detection() {
        // Normal values with one extreme outlier.
        let mut sorted: Vec<u64> = (1..=99).collect();
        sorted.push(1000); // Outlier.
        sorted.sort_unstable();

        let outliers = count_outliers(&sorted);
        assert!(outliers >= 1);
    }
}
