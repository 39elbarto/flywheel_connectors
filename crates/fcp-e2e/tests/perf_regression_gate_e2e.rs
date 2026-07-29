use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::json;

const BENCH: &str = "mock_bench";

#[test]
fn test_gate_catches_synthetic_10pct_regression() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_baseline_series(tempdir.path(), &[9.9, 10.1, 10.0, 10.2, 9.8, 10.0, 10.0]);
    write_run(tempdir.path(), "2026-05-08-current.json", 11.5, &[]);

    let output = run_gate(tempdir.path(), "10.0");

    assert!(
        !output.status.success(),
        "gate must reject a 15 percent p99 regression: {}",
        output_text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("regressed_bench=mock_bench"), "{stderr}");
    assert!(stderr.contains("delta_pct=15.0"), "{stderr}");
}

#[test]
fn test_gate_accepts_noisy_steady_state() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_baseline_series(tempdir.path(), &[9.9, 10.1, 10.0, 10.2, 9.8, 10.0, 10.0]);
    write_run(tempdir.path(), "2026-05-08-current.json", 10.2, &[]);

    let output = run_gate(tempdir.path(), "10.0");

    assert!(
        output.status.success(),
        "gate must accept steady-state noise: {}",
        output_text(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"verdict\": \"pass\""), "{stdout}");
}

#[test]
fn test_gate_welch_p_alarm() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let baseline_samples = sample_series(10.0, 10_000);
    let current_samples = sample_series(10.5, 10_000);
    for day in 1..=7 {
        write_run(
            tempdir.path(),
            &format!("2026-05-0{day}-baseline.json"),
            10.0,
            &baseline_samples,
        );
    }
    write_run(
        tempdir.path(),
        "2026-05-08-current.json",
        10.5,
        &current_samples,
    );

    let output = run_gate(tempdir.path(), "10.0");

    assert!(
        !output.status.success(),
        "gate must reject low-magnitude statistically significant drift: {}",
        output_text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("regressed_bench=mock_bench"), "{stderr}");
    assert!(stderr.contains("welch_p="), "{stderr}");
    assert!(stderr.contains("delta_pct=5.0"), "{stderr}");
}

#[test]
fn test_force_resnap_emits_audit() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_baseline_series(tempdir.path(), &[9.9, 10.1, 10.0, 10.2, 9.8, 10.0, 10.0]);
    write_run(tempdir.path(), "2026-05-08-current.json", 11.5, &[]);
    let audit_path = tempdir.path().join("audit.jsonl");
    let history_dir = tempdir.path().join("history");

    let output = gate_command(tempdir.path(), "10.0")
        .arg("--force-baseline-resnap")
        .arg("--audit-path")
        .arg(&audit_path)
        .arg("--history-dir")
        .arg(&history_dir)
        .env("FCP_PERF_GATE_ALLOW_BASELINE_RESNAP", "1")
        .output()
        .expect("run perf regression gate resnap");

    assert!(
        output.status.success(),
        "operator-approved resnap must pass: {}",
        output_text(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"verdict\": \"baseline_resnap\""),
        "{stdout}"
    );
    let audit = fs::read_to_string(audit_path).expect("read resnap audit");
    assert!(audit.contains("perf.baseline_resnap"), "{audit}");
    assert!(audit.contains("operator_fingerprint"), "{audit}");
    let history =
        fs::read_to_string(history_dir.join("mock_bench_history.md")).expect("read history line");
    assert!(history.contains("verdict=baseline_resnap"), "{history}");
}

fn write_baseline_series(root: &Path, p99_values: &[f64]) {
    for (index, p99) in p99_values.iter().enumerate() {
        write_run(
            root,
            &format!("2026-05-0{}-baseline.json", index + 1),
            *p99,
            &[],
        );
    }
}

fn write_run(root: &Path, file_name: &str, p99_ms: f64, samples_ms: &[f64]) {
    let path = root.join(file_name);
    let payload = json!({
        "bench": BENCH,
        "statpack": {
            "p99_ms": p99_ms,
        },
        "samples_ms": samples_ms,
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&payload).expect("serialize synthetic perf artifact"),
    )
    .expect("write synthetic perf artifact");
}

fn sample_series(center: f64, n: usize) -> Vec<f64> {
    (0..n)
        .map(|index| {
            let offset = match index % 4 {
                0 => -0.02,
                1 => -0.01,
                2 => 0.01,
                _ => 0.02,
            };
            center + offset
        })
        .collect()
}

fn run_gate(artifacts_dir: &Path, target_p99: &str) -> Output {
    gate_command(artifacts_dir, target_p99)
        .arg("--history-dir")
        .arg(artifacts_dir.join("history"))
        .output()
        .expect("run perf regression gate")
}

fn gate_command(artifacts_dir: &Path, target_p99: &str) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(repo_root().join("scripts/ci/perf_regression_gate.sh"))
        .arg("--artifacts-dir")
        .arg(artifacts_dir)
        .arg("--target-bench")
        .arg(BENCH)
        .arg("--target-p99")
        .arg(target_p99)
        .arg("--tolerance-pct")
        .arg("10.0");
    command
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root ancestor")
        .to_path_buf()
}

fn output_text(output: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
