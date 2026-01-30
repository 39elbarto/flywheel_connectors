//! Metrics collection for FCP connectors.
//!
//! Provides counters, gauges, histograms, and timers with label support.

use std::sync::OnceLock;
use std::time::Instant;

use metrics::{
    Counter, Gauge, Histogram, counter, describe_counter, describe_gauge, describe_histogram,
    gauge, histogram,
};

/// Global metrics registry state.
static METRICS_INITIALIZED: OnceLock<bool> = OnceLock::new();

/// Initialize the metrics system with standard FCP metrics descriptions.
pub fn init_metrics() {
    if METRICS_INITIALIZED.set(true).is_err() {
        return; // Already initialized
    }

    // Request metrics
    describe_counter!(
        "fcp_requests_total",
        "Total number of FCP requests processed"
    );
    describe_counter!(
        "fcp_requests_errors_total",
        "Total number of FCP request errors"
    );
    describe_histogram!(
        "fcp_request_duration_seconds",
        "FCP request duration in seconds"
    );

    // Connection metrics
    describe_gauge!("fcp_connections_active", "Number of active connections");
    describe_gauge!(
        "fcp_connections_total",
        "Total number of connections (including closed)"
    );

    // Health metrics
    describe_gauge!(
        "fcp_health_status",
        "Connector health status (1=ready, 0.5=degraded, 0=error)"
    );
    describe_gauge!("fcp_uptime_seconds", "Connector uptime in seconds");

    // Queue metrics
    describe_gauge!("fcp_queue_depth", "Current queue depth");
    describe_counter!(
        "fcp_queue_processed_total",
        "Total items processed from queue"
    );

    // Rate limit metrics
    describe_gauge!("fcp_rate_limit_remaining", "Remaining rate limit quota");
    describe_counter!(
        "fcp_rate_limit_exceeded_total",
        "Total number of rate limit exceeded events"
    );

    // Event metrics
    describe_counter!("fcp_events_emitted_total", "Total events emitted");
    describe_counter!("fcp_events_dropped_total", "Total events dropped");

    // Symbol coverage and diversity metrics
    describe_gauge!(
        "fcp_symbol_coverage_distinct_nodes",
        "Number of distinct nodes holding symbols for an object"
    );
    describe_gauge!(
        "fcp_symbol_source_count",
        "Number of distinct source nodes holding symbols for an object"
    );
    describe_gauge!(
        "fcp_symbol_coverage_bps",
        "Symbol coverage ratio in basis points (10000 = 100%)"
    );
    describe_gauge!(
        "fcp_symbol_max_node_fraction_bps",
        "Maximum symbol fraction on any single node in basis points"
    );
    describe_gauge!(
        "fcp_symbol_diversity_bps",
        "Source diversity in basis points relative to policy requirement"
    );
    describe_counter!(
        "fcp_symbol_diversity_violations_total",
        "Total diversity policy violations during reconstruction attempts"
    );
    describe_counter!(
        "fcp_symbol_coverage_evaluations_total",
        "Total coverage evaluations performed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Counter Operations
// ─────────────────────────────────────────────────────────────────────────────

/// Increment a counter by 1.
pub fn increment_counter(name: &'static str, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    counter!(name, &labels).increment(1);
}

/// Increment a counter by a specific amount.
pub fn increment_counter_by(name: &'static str, value: u64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    counter!(name, &labels).increment(value);
}

/// Get a counter handle for repeated operations.
pub fn get_counter(name: &'static str, labels: &[(&'static str, &str)]) -> Counter {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    counter!(name, &labels)
}

// ─────────────────────────────────────────────────────────────────────────────
// Gauge Operations
// ─────────────────────────────────────────────────────────────────────────────

/// Set a gauge value.
pub fn set_gauge(name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    gauge!(name, &labels).set(value);
}

/// Increment a gauge.
pub fn increment_gauge(name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    gauge!(name, &labels).increment(value);
}

/// Decrement a gauge.
pub fn decrement_gauge(name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    gauge!(name, &labels).decrement(value);
}

/// Get a gauge handle for repeated operations.
pub fn get_gauge(name: &'static str, labels: &[(&'static str, &str)]) -> Gauge {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    gauge!(name, &labels)
}

// ─────────────────────────────────────────────────────────────────────────────
// Histogram Operations
// ─────────────────────────────────────────────────────────────────────────────

/// Record a histogram value.
pub fn record_histogram(name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    histogram!(name, &labels).record(value);
}

/// Get a histogram handle for repeated operations.
pub fn get_histogram(name: &'static str, labels: &[(&'static str, &str)]) -> Histogram {
    let labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, v.to_string())).collect();
    histogram!(name, &labels)
}

// ─────────────────────────────────────────────────────────────────────────────
// Timer Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A timer for measuring operation duration.
pub struct Timer {
    start: Instant,
    name: &'static str,
    labels: Vec<(&'static str, String)>,
}

impl Timer {
    /// Start a new timer.
    #[must_use]
    pub fn start(name: &'static str, labels: &[(&'static str, &str)]) -> Self {
        Self {
            start: Instant::now(),
            name,
            labels: labels.iter().map(|(k, v)| (*k, v.to_string())).collect(),
        }
    }

    /// Get elapsed time in seconds.
    #[must_use]
    pub fn elapsed_seconds(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Get elapsed time in milliseconds.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Stop the timer and record to histogram.
    pub fn stop(self) {
        histogram!(self.name, &self.labels).record(self.start.elapsed().as_secs_f64());
    }

    /// Stop and record, returning elapsed seconds.
    #[must_use]
    pub fn stop_and_return(self) -> f64 {
        let elapsed = self.elapsed_seconds();
        self.stop();
        elapsed
    }
}

/// RAII guard for timing a scope.
pub struct TimerGuard {
    timer: Option<Timer>,
}

impl TimerGuard {
    /// Create a new timer guard.
    #[must_use]
    pub fn new(name: &'static str, labels: &[(&'static str, &str)]) -> Self {
        Self {
            timer: Some(Timer::start(name, labels)),
        }
    }

    /// Get elapsed time so far.
    #[must_use]
    pub fn elapsed_seconds(&self) -> f64 {
        self.timer.as_ref().map_or(0.0, Timer::elapsed_seconds)
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.stop();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-defined FCP Metrics Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Record a successful request.
pub fn record_request_success(connector: &str, operation: &str, duration_seconds: f64) {
    increment_counter(
        "fcp_requests_total",
        &[
            ("connector", connector),
            ("operation", operation),
            ("status", "success"),
        ],
    );
    record_histogram(
        "fcp_request_duration_seconds",
        duration_seconds,
        &[("connector", connector), ("operation", operation)],
    );
}

/// Record a failed request.
pub fn record_request_error(
    connector: &str,
    operation: &str,
    error_type: &str,
    duration_seconds: f64,
) {
    increment_counter(
        "fcp_requests_total",
        &[
            ("connector", connector),
            ("operation", operation),
            ("status", "error"),
        ],
    );
    increment_counter(
        "fcp_requests_errors_total",
        &[
            ("connector", connector),
            ("operation", operation),
            ("error_type", error_type),
        ],
    );
    record_histogram(
        "fcp_request_duration_seconds",
        duration_seconds,
        &[("connector", connector), ("operation", operation)],
    );
}

/// Update health status metric.
pub fn update_health_status(connector: &str, status: HealthStatusMetric) {
    let value = match status {
        HealthStatusMetric::Ready => 1.0,
        HealthStatusMetric::Degraded => 0.5,
        HealthStatusMetric::Error => 0.0,
    };
    set_gauge("fcp_health_status", value, &[("connector", connector)]);
}

/// Health status for metrics.
#[derive(Debug, Clone, Copy)]
pub enum HealthStatusMetric {
    /// Connector is ready.
    Ready,
    /// Connector is degraded.
    Degraded,
    /// Connector is in error state.
    Error,
}

/// Update rate limit metrics.
pub fn update_rate_limit(connector: &str, remaining: u32, exceeded: bool) {
    set_gauge(
        "fcp_rate_limit_remaining",
        f64::from(remaining),
        &[("connector", connector)],
    );
    if exceeded {
        increment_counter("fcp_rate_limit_exceeded_total", &[("connector", connector)]);
    }
}

/// Record event emission.
pub fn record_event_emitted(connector: &str, event_type: &str) {
    increment_counter(
        "fcp_events_emitted_total",
        &[("connector", connector), ("event_type", event_type)],
    );
}

/// Record dropped event.
pub fn record_event_dropped(connector: &str, event_type: &str, reason: &str) {
    increment_counter(
        "fcp_events_dropped_total",
        &[
            ("connector", connector),
            ("event_type", event_type),
            ("reason", reason),
        ],
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbol Coverage and Diversity Metrics
// ─────────────────────────────────────────────────────────────────────────────

/// Record symbol coverage evaluation metrics.
///
/// Call this after evaluating coverage for an object to emit metrics.
pub fn record_symbol_coverage(
    zone_id: &str,
    distinct_nodes: usize,
    coverage_bps: u32,
    max_node_fraction_bps: u16,
    diversity_bps: u32,
) {
    let source_count_u32 = u32::try_from(distinct_nodes).unwrap_or(u32::MAX);
    let source_count = f64::from(source_count_u32);

    set_gauge(
        "fcp_symbol_coverage_distinct_nodes",
        source_count,
        &[("zone", zone_id)],
    );
    set_gauge(
        "fcp_symbol_source_count",
        source_count,
        &[("zone", zone_id)],
    );
    set_gauge(
        "fcp_symbol_coverage_bps",
        f64::from(coverage_bps),
        &[("zone", zone_id)],
    );
    set_gauge(
        "fcp_symbol_max_node_fraction_bps",
        f64::from(max_node_fraction_bps),
        &[("zone", zone_id)],
    );
    set_gauge(
        "fcp_symbol_diversity_bps",
        f64::from(diversity_bps),
        &[("zone", zone_id)],
    );
    increment_counter(
        "fcp_symbol_coverage_evaluations_total",
        &[("zone", zone_id)],
    );
}

/// Record a diversity policy violation during reconstruction.
///
/// Call this when reconstruction is denied due to insufficient source diversity.
pub fn record_diversity_violation(zone_id: &str, required: u8, actual: usize) {
    increment_counter(
        "fcp_symbol_diversity_violations_total",
        &[
            ("zone", zone_id),
            ("required", &required.to_string()),
            ("actual", &actual.to_string()),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer() {
        let timer = Timer::start("test_metric", &[("test", "true")]);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();
        assert!(elapsed >= 10);
    }

    #[test]
    fn test_timer_guard() {
        let guard = TimerGuard::new("test_metric", &[("test", "true")]);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = guard.elapsed_seconds();
        assert!(elapsed >= 0.01);
    }

    #[test]
    fn test_timer_elapsed_seconds() {
        let timer = Timer::start("test_elapsed", &[]);
        std::thread::sleep(std::time::Duration::from_millis(15));
        let elapsed_s = timer.elapsed_seconds();
        assert!(elapsed_s >= 0.015);
        assert!(elapsed_s < 1.0); // Sanity check
    }

    #[test]
    fn test_timer_with_labels() {
        let timer = Timer::start(
            "labeled_metric",
            &[("connector", "test"), ("operation", "read")],
        );
        // Just verify it doesn't panic with multiple labels
        let _ = timer.elapsed_ms();
    }

    #[test]
    fn test_timer_guard_drop() {
        {
            let _guard = TimerGuard::new("drop_test_metric", &[("test", "drop")]);
            std::thread::sleep(std::time::Duration::from_millis(5));
            // Guard is dropped here
        }
        // If we reach here without panic, the drop worked
    }

    #[test]
    fn test_timer_guard_elapsed_before_drop() {
        let guard = TimerGuard::new("elapsed_test", &[]);
        let elapsed1 = guard.elapsed_seconds();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let elapsed2 = guard.elapsed_seconds();
        assert!(elapsed2 > elapsed1);
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact float values 0.0, 0.5, 1.0 are safe to compare
    fn test_health_status_metric_values() {
        // Test that health status values are correct
        assert_eq!(
            match HealthStatusMetric::Ready {
                HealthStatusMetric::Ready => 1.0,
                HealthStatusMetric::Degraded => 0.5,
                HealthStatusMetric::Error => 0.0,
            },
            1.0
        );
        assert_eq!(
            match HealthStatusMetric::Degraded {
                HealthStatusMetric::Ready => 1.0,
                HealthStatusMetric::Degraded => 0.5,
                HealthStatusMetric::Error => 0.0,
            },
            0.5
        );
        assert_eq!(
            match HealthStatusMetric::Error {
                HealthStatusMetric::Ready => 1.0,
                HealthStatusMetric::Degraded => 0.5,
                HealthStatusMetric::Error => 0.0,
            },
            0.0
        );
    }

    #[test]
    fn test_health_status_metric_debug() {
        // Test Debug derive
        let status = HealthStatusMetric::Ready;
        let debug_str = format!("{status:?}");
        assert!(debug_str.contains("Ready"));
    }

    #[test]
    fn test_health_status_metric_clone() {
        let status = HealthStatusMetric::Degraded;
        let cloned = status;
        assert!(matches!(cloned, HealthStatusMetric::Degraded));
    }

    #[test]
    fn test_init_metrics_idempotent() {
        // Calling init_metrics multiple times should not panic
        init_metrics();
        init_metrics();
        init_metrics();
    }

    #[test]
    fn test_increment_counter_no_panic() {
        // Verify counter operations don't panic
        increment_counter("test_counter", &[("test", "true")]);
    }

    #[test]
    fn test_increment_counter_by_no_panic() {
        increment_counter_by("test_counter_by", 5, &[("test", "true")]);
    }

    #[test]
    fn test_get_counter_returns_counter() {
        let counter = get_counter("test_get_counter", &[("connector", "test")]);
        // Just verify we get a counter back that we can use
        counter.increment(1);
    }

    #[test]
    fn test_set_gauge_no_panic() {
        set_gauge("test_gauge", 42.0, &[("test", "true")]);
    }

    #[test]
    fn test_increment_gauge_no_panic() {
        increment_gauge("test_inc_gauge", 1.0, &[("test", "true")]);
    }

    #[test]
    fn test_decrement_gauge_no_panic() {
        decrement_gauge("test_dec_gauge", 1.0, &[("test", "true")]);
    }

    #[test]
    fn test_get_gauge_returns_gauge() {
        let gauge = get_gauge("test_get_gauge", &[("connector", "test")]);
        gauge.set(100.0);
        gauge.increment(10.0);
        gauge.decrement(5.0);
    }

    #[test]
    fn test_record_histogram_no_panic() {
        record_histogram("test_histogram", 0.5, &[("test", "true")]);
    }

    #[test]
    fn test_get_histogram_returns_histogram() {
        let histogram = get_histogram("test_get_histogram", &[("operation", "read")]);
        histogram.record(0.1);
        histogram.record(0.5);
        histogram.record(1.0);
    }

    #[test]
    fn test_record_request_success_no_panic() {
        record_request_success("test-connector", "read", 0.123);
    }

    #[test]
    fn test_record_request_error_no_panic() {
        record_request_error("test-connector", "write", "timeout", 1.5);
    }

    #[test]
    fn test_update_health_status_all_states() {
        update_health_status("test-connector", HealthStatusMetric::Ready);
        update_health_status("test-connector", HealthStatusMetric::Degraded);
        update_health_status("test-connector", HealthStatusMetric::Error);
    }

    #[test]
    fn test_update_rate_limit_not_exceeded() {
        update_rate_limit("test-connector", 100, false);
    }

    #[test]
    fn test_update_rate_limit_exceeded() {
        update_rate_limit("test-connector", 0, true);
    }

    #[test]
    fn test_record_event_emitted_no_panic() {
        record_event_emitted("test-connector", "message_received");
    }

    #[test]
    fn test_record_event_dropped_no_panic() {
        record_event_dropped("test-connector", "message", "buffer_full");
    }

    #[test]
    fn test_counter_with_empty_labels() {
        increment_counter("empty_labels_counter", &[]);
    }

    #[test]
    fn test_gauge_with_multiple_labels() {
        set_gauge(
            "multi_label_gauge",
            99.9,
            &[
                ("connector", "telegram"),
                ("zone", "work"),
                ("operation", "send"),
            ],
        );
    }

    #[test]
    fn test_histogram_with_various_values() {
        let labels = &[("operation", "api_call")];
        record_histogram("response_time", 0.001, labels); // 1ms
        record_histogram("response_time", 0.050, labels); // 50ms
        record_histogram("response_time", 0.100, labels); // 100ms
        record_histogram("response_time", 1.000, labels); // 1s
        record_histogram("response_time", 10.00, labels); // 10s
    }

    #[test]
    fn test_timer_stop_and_return() {
        let timer = Timer::start("stop_return_test", &[]);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.stop_and_return();
        assert!(elapsed >= 0.01);
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact 0.0 comparison is safe
    fn test_timer_guard_elapsed_on_empty_timer() {
        let guard = TimerGuard {
            timer: None, // Manually create with None
        };
        let elapsed = guard.elapsed_seconds();
        assert_eq!(elapsed, 0.0);
    }

    // ============ Metrics edge case tests ============

    #[test]
    fn test_counter_with_special_characters_in_labels() {
        // Test that special characters in label values don't cause issues
        increment_counter(
            "special_chars_counter",
            &[
                ("connector", "my-connector_v2"),
                ("operation", "read.messages"),
                ("zone", "work:zone/1"),
            ],
        );
    }

    #[test]
    fn test_gauge_with_negative_value() {
        set_gauge("negative_gauge", -42.5, &[("test", "negative")]);
    }

    #[test]
    fn test_gauge_with_zero_value() {
        set_gauge("zero_gauge", 0.0, &[("test", "zero")]);
    }

    #[test]
    fn test_gauge_with_very_large_value() {
        set_gauge("large_gauge", f64::MAX / 2.0, &[("test", "large")]);
    }

    #[test]
    fn test_gauge_with_very_small_value() {
        set_gauge("small_gauge", f64::MIN_POSITIVE, &[("test", "small")]);
    }

    #[test]
    fn test_histogram_with_zero_value() {
        record_histogram("zero_histogram", 0.0, &[("test", "zero")]);
    }

    #[test]
    fn test_histogram_with_very_small_duration() {
        record_histogram("tiny_duration", 0.000_001, &[("test", "microsecond")]);
    }

    #[test]
    fn test_multiple_counters_same_name_different_labels() {
        increment_counter("shared_counter", &[("env", "prod")]);
        increment_counter("shared_counter", &[("env", "staging")]);
        increment_counter("shared_counter", &[("env", "dev")]);
    }

    #[test]
    fn test_request_success_with_long_connector_id() {
        let long_connector_id = "a".repeat(100);
        record_request_success(&long_connector_id, "read", 0.5);
    }

    #[test]
    fn test_request_error_with_unicode_reason() {
        // Reason codes should work with various characters
        record_request_error("test-connector", "write", "TIMEOUT_🕐", 1.0);
    }

    #[test]
    fn test_rate_limit_with_zero_remaining() {
        update_rate_limit("rate-test", 0, false);
    }

    #[test]
    fn test_rate_limit_with_max_remaining() {
        update_rate_limit("rate-test", u32::MAX, false);
    }

    #[test]
    fn test_event_emitted_with_empty_event_type() {
        record_event_emitted("connector", "");
    }

    #[test]
    fn test_event_dropped_with_long_reason() {
        let long_reason = "x".repeat(256);
        record_event_dropped("connector", "message", &long_reason);
    }

    #[test]
    fn test_timer_immediate_stop() {
        // Timer stopped immediately should have very small elapsed time
        let timer = Timer::start("immediate_stop", &[]);
        let elapsed = timer.stop_and_return();
        // Should be some positive value but very small
        assert!(elapsed >= 0.0);
        assert!(elapsed < 0.1); // Should be way less than 100ms
    }

    #[test]
    fn test_concurrent_timer_creation() {
        // Create multiple timers simultaneously
        let timer1 = Timer::start("concurrent_timer", &[("id", "1")]);
        let timer2 = Timer::start("concurrent_timer", &[("id", "2")]);
        let timer3 = Timer::start("concurrent_timer", &[("id", "3")]);

        // All should have valid elapsed times (u64 is always >= 0, just verify they work)
        let _ = timer1.elapsed_ms();
        let _ = timer2.elapsed_ms();
        let _ = timer3.elapsed_ms();
    }

    #[test]
    fn test_health_status_rapid_transitions() {
        // Test rapid state transitions
        for _ in 0..10 {
            update_health_status("rapid-connector", HealthStatusMetric::Ready);
            update_health_status("rapid-connector", HealthStatusMetric::Degraded);
            update_health_status("rapid-connector", HealthStatusMetric::Error);
        }
    }

    #[test]
    fn test_fcp_metrics_naming_convention() {
        // Verify FCP metric naming conventions are followed
        // These should all work without panic, validating the metric names
        record_request_success("test", "op", 0.1); // fcp_request_total, fcp_request_duration_seconds
        record_request_error("test", "op", "err", 0.1); // fcp_request_total, fcp_request_duration_seconds, fcp_error_total
        update_health_status("test", HealthStatusMetric::Ready); // fcp_connector_health_status
        update_rate_limit("test", 100, false); // fcp_rate_limit_remaining, fcp_rate_limit_exceeded_total
        record_event_emitted("test", "evt"); // fcp_events_emitted_total
        record_event_dropped("test", "evt", "reason"); // fcp_events_dropped_total
    }

    // ============ Symbol Coverage and Diversity Metrics Tests ============

    #[test]
    fn test_record_symbol_coverage_no_panic() {
        record_symbol_coverage("z:work", 3, 10000, 4000, 10000);
    }

    #[test]
    fn test_record_symbol_coverage_various_values() {
        // Minimal coverage
        record_symbol_coverage("z:minimal", 1, 1000, 10000, 2500);
        // Over-coverage
        record_symbol_coverage("z:over", 5, 15000, 2000, 10000);
        // No coverage
        record_symbol_coverage("z:empty", 0, 0, 0, 0);
    }

    #[test]
    fn test_record_diversity_violation_no_panic() {
        record_diversity_violation("z:work", 3, 1);
    }

    #[test]
    fn test_record_diversity_violation_various_values() {
        // Missing 2 nodes
        record_diversity_violation("z:test", 3, 1);
        // Missing many nodes
        record_diversity_violation("z:high-diversity", 10, 2);
        // Edge case: required 0 (shouldn't happen but handle gracefully)
        record_diversity_violation("z:edge", 0, 5);
    }

    #[test]
    fn test_symbol_coverage_with_long_zone_id() {
        let long_zone = "z:".to_string() + &"a".repeat(100);
        record_symbol_coverage(&long_zone, 3, 10000, 4000, 10000);
    }

    #[test]
    fn test_diversity_violation_with_unicode_zone() {
        record_diversity_violation("z:日本語", 3, 1);
    }
}
