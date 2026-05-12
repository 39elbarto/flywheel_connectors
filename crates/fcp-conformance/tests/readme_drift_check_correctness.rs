use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[test]
fn test_drift_check_passes_on_valid_readme() {
    let output = run_drift_check("good.md");

    assert!(
        output.status.success(),
        "valid fixture should pass drift check: {}",
        output_text(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"paths_missing\": 0"), "{stdout}");
    assert!(stdout.contains("\"symbols_missing\": 0"), "{stdout}");
}

#[test]
fn test_drift_check_fails_on_stale_path() {
    let output = run_drift_check("bad_path.md");

    assert!(
        !output.status.success(),
        "stale path fixture should fail drift check: {}",
        output_text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("crates/nonexistent/foo.rs"), "{stderr}");
}

#[test]
fn test_drift_check_fails_on_missing_symbol() {
    let output = run_drift_check("bad_symbol.md");

    assert!(
        !output.status.success(),
        "missing symbol fixture should fail drift check: {}",
        output_text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("fcp_core::deleted_fn"), "{stderr}");
}

#[test]
fn test_drift_check_reports_file_line() {
    let output = run_drift_check("bad_path.md");

    assert!(
        !output.status.success(),
        "stale path fixture should fail drift check: {}",
        output_text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let fixture_path = fixture("bad_path.md");
    let expected = format!("{}:3:", fixture_path.display());
    assert!(
        stderr.contains(&expected),
        "stderr did not contain expected file:line `{expected}`:\n{stderr}"
    );
}

#[test]
fn test_skip_hint_honored() {
    let output = run_drift_check("skip_hint.md");

    assert!(
        output.status.success(),
        "skip hint fixture should pass drift check: {}",
        output_text(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"paths_missing\": 0"), "{stdout}");
}

fn run_drift_check(fixture_name: &str) -> Output {
    Command::new("bash")
        .arg(repo_root().join("scripts/ci/readme_drift_check.sh"))
        .arg("--readme")
        .arg(fixture(fixture_name))
        .arg("--repo-root")
        .arg(repo_root())
        .output()
        .expect("run readme drift check")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/readme_drift")
        .join(name)
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
