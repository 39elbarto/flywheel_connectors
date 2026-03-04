//! Benchmark result types for machine-readable JSON output.
//!
//! These types define the stable JSON schema for benchmark results,
//! enabling regression tracking and CI integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete benchmark report including environment metadata and all results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,

    /// Environment information for reproducibility.
    pub environment: EnvironmentInfo,

    /// Individual benchmark results.
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkReport {
    /// Create a new benchmark report with the given environment and results.
    #[must_use]
    pub fn new(environment: EnvironmentInfo, results: Vec<BenchmarkResult>) -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            environment,
            results,
        }
    }
}

/// Environment information for reproducibility and regression tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    /// Operating system name (e.g., `linux`, `macos`, `windows`).
    pub os: String,

    /// Operating system version.
    pub os_version: String,

    /// CPU architecture (e.g., `x86_64`, `aarch64`).
    pub arch: String,

    /// Number of logical CPUs.
    pub cpu_count: usize,

    /// Total system memory in bytes (if available).
    pub memory_bytes: Option<u64>,

    /// Git commit hash (if in a git repository).
    pub git_commit: Option<String>,

    /// Git branch (if in a git repository).
    pub git_branch: Option<String>,

    /// Whether the working directory is clean (no uncommitted changes).
    pub git_dirty: Option<bool>,

    /// FCP CLI version.
    pub fcp_version: String,

    /// Rust compiler version used to build the CLI.
    pub rustc_version: Option<String>,

    /// Timestamp when the benchmark started.
    pub timestamp: DateTime<Utc>,
}

/// Result of a single benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Unique benchmark name (e.g., "cbor-serialize", "connector-activate").
    pub name: String,

    /// Human-readable description of what was measured.
    pub description: String,

    /// Parameters used for this benchmark run.
    pub parameters: serde_json::Value,

    /// Number of samples taken.
    pub sample_count: u32,

    /// Number of warmup iterations performed.
    pub warmup_count: u32,

    /// Percentile statistics (if benchmark completed successfully).
    pub percentiles: Option<Percentiles>,

    /// Whether this benchmark passed its target thresholds.
    pub passed: Option<bool>,

    /// Target thresholds for pass/fail determination.
    pub targets: Option<Targets>,

    /// Additional notes (e.g., "not yet implemented").
    pub note: Option<String>,

    /// Any outliers detected during measurement.
    pub outliers_detected: u32,
}

impl BenchmarkResult {
    /// Create a new benchmark result with the given measurements.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        sample_count: u32,
        warmup_count: u32,
        percentiles: Percentiles,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters: serde_json::Value::Object(serde_json::Map::new()),
            sample_count,
            warmup_count,
            percentiles: Some(percentiles),
            passed: None,
            targets: None,
            note: None,
            outliers_detected: 0,
        }
    }

    /// Create a placeholder result for unimplemented benchmarks.
    #[must_use]
    pub fn placeholder(name: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: "Not yet implemented".to_string(),
            parameters: serde_json::Value::Object(serde_json::Map::new()),
            sample_count: 0,
            warmup_count: 0,
            percentiles: None,
            passed: None,
            targets: None,
            note: Some(note.into()),
            outliers_detected: 0,
        }
    }

    /// Set parameters for this benchmark.
    #[must_use]
    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = parameters;
        self
    }

    /// Set target thresholds and determine pass/fail.
    #[must_use]
    pub fn with_targets(mut self, targets: Targets) -> Self {
        if let Some(ref p) = self.percentiles {
            self.passed =
                Some(p.p50_ms <= targets.p50_target_ms && p.p99_ms <= targets.p99_target_ms);
        }
        self.targets = Some(targets);
        self
    }
}

/// Percentile statistics for benchmark measurements.
///
/// All fields are in milliseconds. The `_ms` suffix is intentional to indicate units
/// in the JSON output schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct Percentiles {
    /// 50th percentile (median) in milliseconds.
    pub p50_ms: f64,

    /// 90th percentile in milliseconds.
    pub p90_ms: f64,

    /// 95th percentile in milliseconds.
    pub p95_ms: f64,

    /// 99th percentile in milliseconds.
    pub p99_ms: f64,

    /// Minimum measurement in milliseconds.
    pub min_ms: f64,

    /// Maximum measurement in milliseconds.
    pub max_ms: f64,

    /// Mean (average) in milliseconds.
    pub mean_ms: f64,

    /// Standard deviation in milliseconds.
    pub stddev_ms: f64,
}

/// Target thresholds for pass/fail determination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Targets {
    /// Target p50 latency in milliseconds.
    pub p50_target_ms: f64,

    /// Target p99 latency in milliseconds.
    pub p99_target_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    // ---- BenchmarkResult::new ----

    fn test_percentiles() -> Percentiles {
        Percentiles {
            p50_ms: 1.0,
            p90_ms: 2.0,
            p95_ms: 2.5,
            p99_ms: 3.0,
            min_ms: 0.5,
            max_ms: 4.0,
            mean_ms: 1.5,
            stddev_ms: 0.2,
        }
    }

    #[test]
    fn benchmark_result_new_defaults() {
        let result = BenchmarkResult::new("test", "description", 100, 10, test_percentiles());
        assert_eq!(result.name, "test");
        assert_eq!(result.description, "description");
        assert_eq!(result.sample_count, 100);
        assert_eq!(result.warmup_count, 10);
        assert!(result.percentiles.is_some());
        assert!(result.passed.is_none());
        assert!(result.targets.is_none());
        assert!(result.note.is_none());
        assert_eq!(result.outliers_detected, 0);
        assert!(result.parameters.is_object());
        assert!(result.parameters.as_object().unwrap().is_empty());
    }

    // ---- with_parameters ----

    #[test]
    fn benchmark_result_with_parameters() {
        let result = BenchmarkResult::new("test", "desc", 50, 5, test_percentiles())
            .with_parameters(json!({"size": "1mb", "count": 42}));
        assert_eq!(result.parameters["size"], "1mb");
        assert_eq!(result.parameters["count"], 42);
    }

    // ---- with_targets pass/fail logic ----

    #[test]
    fn with_targets_passes_when_within() {
        let result = BenchmarkResult::new("test", "desc", 100, 10, test_percentiles())
            .with_targets(Targets {
                p50_target_ms: 5.0,
                p99_target_ms: 10.0,
            });
        assert_eq!(result.passed, Some(true));
        assert!(result.targets.is_some());
    }

    #[test]
    fn with_targets_fails_when_p50_exceeded() {
        let result = BenchmarkResult::new("test", "desc", 100, 10, test_percentiles())
            .with_targets(Targets {
                p50_target_ms: 0.5, // p50 is 1.0
                p99_target_ms: 10.0,
            });
        assert_eq!(result.passed, Some(false));
    }

    #[test]
    fn with_targets_fails_when_p99_exceeded() {
        let result = BenchmarkResult::new("test", "desc", 100, 10, test_percentiles())
            .with_targets(Targets {
                p50_target_ms: 5.0,
                p99_target_ms: 2.0, // p99 is 3.0
            });
        assert_eq!(result.passed, Some(false));
    }

    #[test]
    fn with_targets_passes_at_exact_boundary() {
        let result = BenchmarkResult::new("test", "desc", 100, 10, test_percentiles())
            .with_targets(Targets {
                p50_target_ms: 1.0, // p50 is exactly 1.0
                p99_target_ms: 3.0, // p99 is exactly 3.0
            });
        assert_eq!(result.passed, Some(true));
    }

    #[test]
    fn with_targets_placeholder_no_pass() {
        let result = BenchmarkResult::placeholder("test", "pending").with_targets(Targets {
            p50_target_ms: 5.0,
            p99_target_ms: 10.0,
        });
        // Placeholder has no percentiles, so passed stays None
        assert!(result.passed.is_none());
        assert!(result.targets.is_some());
    }

    // ---- BenchmarkReport::new ----

    #[test]
    fn benchmark_report_new_schema_version() {
        let env = EnvironmentInfo {
            os: "test".to_string(),
            os_version: "1.0".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 4,
            memory_bytes: None,
            git_commit: None,
            git_branch: None,
            git_dirty: None,
            fcp_version: "0.1.0".to_string(),
            rustc_version: None,
            timestamp: Utc::now(),
        };
        let report = BenchmarkReport::new(env, vec![]);
        assert_eq!(report.schema_version, "1.0.0");
        assert!(report.results.is_empty());
    }

    // ---- Percentiles serde ----

    #[test]
    fn percentiles_serde_roundtrip() {
        let p = test_percentiles();
        let json = serde_json::to_string(&p).unwrap();
        let back: Percentiles = serde_json::from_str(&json).unwrap();
        assert!((back.p50_ms - 1.0).abs() < f64::EPSILON);
        assert!((back.p99_ms - 3.0).abs() < f64::EPSILON);
        assert!((back.stddev_ms - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn percentiles_debug() {
        let p = test_percentiles();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("p50_ms"));
        assert!(dbg.contains("p99_ms"));
    }

    #[test]
    fn percentiles_clone() {
        let p = test_percentiles();
        let cloned = p.clone();
        assert!((cloned.p50_ms - p.p50_ms).abs() < f64::EPSILON);
    }

    // ---- Targets serde ----

    #[test]
    fn targets_serde_roundtrip() {
        let t = Targets {
            p50_target_ms: 2.0,
            p99_target_ms: 10.0,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: Targets = serde_json::from_str(&json).unwrap();
        assert!((back.p50_target_ms - 2.0).abs() < f64::EPSILON);
        assert!((back.p99_target_ms - 10.0).abs() < f64::EPSILON);
    }

    // ---- EnvironmentInfo serde ----

    #[test]
    fn environment_info_serde_roundtrip() {
        let env = EnvironmentInfo {
            os: "linux".to_string(),
            os_version: "6.6".to_string(),
            arch: "aarch64".to_string(),
            cpu_count: 8,
            memory_bytes: Some(16_000_000_000),
            git_commit: Some("abc123".to_string()),
            git_branch: Some("main".to_string()),
            git_dirty: Some(true),
            fcp_version: "0.2.0".to_string(),
            rustc_version: Some("1.85.0".to_string()),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: EnvironmentInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.os, "linux");
        assert_eq!(back.cpu_count, 8);
        assert_eq!(back.memory_bytes, Some(16_000_000_000));
        assert_eq!(back.git_dirty, Some(true));
    }

    #[test]
    fn environment_info_minimal() {
        let env = EnvironmentInfo {
            os: "test".to_string(),
            os_version: "0".to_string(),
            arch: "wasm".to_string(),
            cpu_count: 1,
            memory_bytes: None,
            git_commit: None,
            git_branch: None,
            git_dirty: None,
            fcp_version: "0.0.1".to_string(),
            rustc_version: None,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: EnvironmentInfo = serde_json::from_str(&json).unwrap();
        assert!(back.memory_bytes.is_none());
        assert!(back.git_commit.is_none());
    }

    // ---- BenchmarkResult full serde ----

    #[test]
    fn benchmark_result_full_serde_roundtrip() {
        let result = BenchmarkResult::new("bench-a", "Full bench", 200, 20, test_percentiles())
            .with_parameters(json!({"key": "value"}))
            .with_targets(Targets {
                p50_target_ms: 5.0,
                p99_target_ms: 15.0,
            });
        let json = serde_json::to_string(&result).unwrap();
        let back: BenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "bench-a");
        assert_eq!(back.sample_count, 200);
        assert_eq!(back.passed, Some(true));
        assert!(back.percentiles.is_some());
        assert!(back.targets.is_some());
    }

    // ---- Original snapshot test ----

    #[test]
    fn benchmark_report_json_snapshot() {
        let generated_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let env = EnvironmentInfo {
            os: "linux".to_string(),
            os_version: "6.6.0".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 16,
            memory_bytes: Some(32_000_000_000),
            git_commit: Some("deadbeef".to_string()),
            git_branch: Some("main".to_string()),
            git_dirty: Some(false),
            fcp_version: "0.1.0".to_string(),
            rustc_version: Some("rustc 1.85.0".to_string()),
            timestamp: generated_at,
        };

        let percentiles = Percentiles {
            p50_ms: 1.0,
            p90_ms: 2.0,
            p95_ms: 2.5,
            p99_ms: 3.0,
            min_ms: 0.5,
            max_ms: 4.0,
            mean_ms: 1.5,
            stddev_ms: 0.2,
        };
        let mut result = BenchmarkResult::new(
            "cbor-serialize",
            "CBOR canonical serialization",
            100,
            10,
            percentiles,
        )
        .with_parameters(json!({ "payload_bytes": 1024 }))
        .with_targets(Targets {
            p50_target_ms: 2.0,
            p99_target_ms: 5.0,
        });
        result.outliers_detected = 1;
        let report = BenchmarkReport {
            schema_version: "1.0.0".to_string(),
            generated_at,
            environment: env,
            results: vec![result],
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        let expected = r#"{
  "schema_version": "1.0.0",
  "generated_at": "2026-01-01T00:00:00Z",
  "environment": {
    "os": "linux",
    "os_version": "6.6.0",
    "arch": "x86_64",
    "cpu_count": 16,
    "memory_bytes": 32000000000,
    "git_commit": "deadbeef",
    "git_branch": "main",
    "git_dirty": false,
    "fcp_version": "0.1.0",
    "rustc_version": "rustc 1.85.0",
    "timestamp": "2026-01-01T00:00:00Z"
  },
  "results": [
    {
      "name": "cbor-serialize",
      "description": "CBOR canonical serialization",
      "parameters": {
        "payload_bytes": 1024
      },
      "sample_count": 100,
      "warmup_count": 10,
      "percentiles": {
        "p50_ms": 1.0,
        "p90_ms": 2.0,
        "p95_ms": 2.5,
        "p99_ms": 3.0,
        "min_ms": 0.5,
        "max_ms": 4.0,
        "mean_ms": 1.5,
        "stddev_ms": 0.2
      },
      "passed": true,
      "targets": {
        "p50_target_ms": 2.0,
        "p99_target_ms": 5.0
      },
      "note": null,
      "outliers_detected": 1
    }
  ]
}"#;

        assert_eq!(json, expected);
    }
}
