//! Integration tests for `fcp bench` command.

use assert_cmd::Command;
use predicates::prelude::*;

/// Get the `fcp` command for testing.
fn fcp_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fcp"));
    // Suppress tracing output during tests
    cmd.env("RUST_LOG", "error");
    cmd
}

mod bench {
    use super::*;

    #[test]
    fn bench_requires_subcommand() {
        fcp_cmd()
            .arg("bench")
            .assert()
            .failure()
            .stderr(predicate::str::contains("subcommand"));
    }

    #[test]
    fn bench_help() {
        fcp_cmd()
            .args(["bench", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Performance benchmark suite"))
            .stdout(predicate::str::contains("--format"))
            .stdout(predicate::str::contains("--iterations"));
    }

    // Note: --iterations, --warmup, --format are global to `fcp bench` and must come BEFORE the subcommand

    #[test]
    fn bench_cbor_json_output() {
        fcp_cmd()
            .args([
                "bench",
                "--format",
                "json",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "cbor",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"environment\""))
            .stdout(predicate::str::contains("\"results\""));
    }

    #[test]
    fn bench_cbor_human_output() {
        fcp_cmd()
            .args([
                "bench",
                "--format",
                "human",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "cbor",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("FCP2 Benchmark Report"))
            .stdout(predicate::str::contains("Environment:"));
    }

    #[test]
    fn bench_cbor_target_schema_hash() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "cbor",
                "--target",
                "schema-hash",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("cbor-schema-hash"));
    }

    #[test]
    fn bench_cbor_target_serialize() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "cbor",
                "--target",
                "serialize",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("cbor-serialize"));
    }

    #[test]
    fn bench_primitives_object_id() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "primitives",
                "--target",
                "object-id",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("object-id-derive"));
    }

    #[test]
    fn bench_primitives_capability_verify() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "primitives",
                "--target",
                "capability-verify",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("capability-verify"));
    }

    #[test]
    fn bench_primitives_session_mac() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "primitives",
                "--target",
                "session-mac",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("session-mac-verify"));
    }

    #[test]
    fn bench_primitives_fcps_frame() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "primitives",
                "--target",
                "fcps-frame",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("fcps-frame-parse-mac"));
    }

    #[test]
    fn bench_raptorq_small_size() {
        // Use a small size for faster testing in debug mode
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "2",
                "--warmup",
                "1",
                "raptorq",
                "--size",
                "10kb",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("raptorq-10kb"));
    }

    #[test]
    fn bench_raptorq_medium_size() {
        // Use a moderate size to test the benchmark runs
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "2",
                "--warmup",
                "1",
                "raptorq",
                "--size",
                "50kb",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("raptorq-50kb"));
    }

    #[test]
    fn bench_raptorq_presets() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "2",
                "--warmup",
                "1",
                "raptorq-presets",
                "--size",
                "10kb",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("raptorq-lan-10kb"))
            .stdout(predicate::str::contains("raptorq-derp-10kb"));
    }

    #[test]
    fn bench_connector_activate_placeholder() {
        // This benchmark returns a placeholder until fcp-sdk is implemented.
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "connector-activate",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("connector-activate"))
            .stdout(predicate::str::contains("fcp-sdk not yet implemented"));
    }

    #[test]
    fn bench_invoke_local_placeholder() {
        // This benchmark returns a placeholder until fcp-mesh is implemented.
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "invoke-local",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("invoke-local"))
            .stdout(predicate::str::contains("fcp-mesh not yet implemented"));
    }

    #[test]
    fn bench_invoke_mesh_direct_placeholder() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "invoke-mesh",
                "--path",
                "direct",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("invoke-mesh-direct"))
            .stdout(predicate::str::contains("fcp-mesh not yet implemented"));
    }

    #[test]
    fn bench_invoke_mesh_derp_placeholder() {
        fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "5",
                "--warmup",
                "1",
                "invoke-mesh",
                "--path",
                "derp",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("invoke-mesh-derp"))
            .stdout(predicate::str::contains("fcp-mesh not yet implemented"));
    }

    #[test]
    fn bench_secrets_placeholder() {
        fcp_cmd()
            .args(["bench", "--iterations", "5", "--warmup", "1", "secrets"])
            .assert()
            .success()
            .stdout(predicate::str::contains("secrets-3-of-5"))
            .stdout(predicate::str::contains(
                "fcp-crypto Shamir not yet implemented",
            ));
    }

    #[test]
    #[ignore = "slow: runs all benchmarks including 1MB RaptorQ"]
    fn bench_all_runs_all_benchmarks() {
        let output = fcp_cmd()
            .args(["bench", "--iterations", "2", "--warmup", "1", "all"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value =
            serde_json::from_slice(&output).expect("Output should be valid JSON");

        // Verify we have multiple results
        let results = json["results"].as_array().expect("results should be array");
        assert!(results.len() >= 5, "Should have multiple benchmark results");

        // Verify we have environment metadata
        assert!(json["environment"]["os"].is_string());
        assert!(json["environment"]["arch"].is_string());
        assert!(json["environment"]["cpu_count"].is_number());
    }

    #[test]
    fn bench_json_valid_structure() {
        let output = fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "3",
                "--warmup",
                "1",
                "primitives",
                "--target",
                "object-id",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value =
            serde_json::from_slice(&output).expect("Output should be valid JSON");

        // Verify environment section
        let env = &json["environment"];
        assert!(env["os"].is_string());
        assert!(env["os_version"].is_string());
        assert!(env["arch"].is_string());
        assert!(env["cpu_count"].is_number());
        assert!(env["timestamp"].is_string());

        // Verify results section
        let results = json["results"].as_array().expect("results should be array");
        assert!(!results.is_empty());

        let result = &results[0];
        assert!(result["name"].is_string());
        assert!(result["description"].is_string());
        assert!(result["sample_count"].is_number());
        assert!(result["warmup_count"].is_number());
    }

    #[test]
    fn bench_percentiles_present() {
        let output = fcp_cmd()
            .args([
                "bench",
                "--iterations",
                "10",
                "--warmup",
                "2",
                "primitives",
                "--target",
                "session-mac",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value =
            serde_json::from_slice(&output).expect("Output should be valid JSON");

        let result = &json["results"][0];
        let percentiles = &result["percentiles"];

        // Verify percentile fields are present
        assert!(percentiles["p50_ms"].is_number());
        assert!(percentiles["p90_ms"].is_number());
        assert!(percentiles["p95_ms"].is_number());
        assert!(percentiles["p99_ms"].is_number());
        assert!(percentiles["min_ms"].is_number());
        assert!(percentiles["max_ms"].is_number());

        // Verify values are reasonable (p50 <= p90 <= p99)
        let p50 = percentiles["p50_ms"].as_f64().unwrap();
        let p90 = percentiles["p90_ms"].as_f64().unwrap();
        let p95 = percentiles["p95_ms"].as_f64().unwrap();
        let p99 = percentiles["p99_ms"].as_f64().unwrap();
        assert!(p50 <= p90, "p50 should be <= p90");
        assert!(p90 <= p95, "p90 should be <= p95");
        assert!(p95 <= p99, "p95 should be <= p99");
    }
}
