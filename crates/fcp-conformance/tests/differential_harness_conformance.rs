//! Conformance gate for the Phase H.1 differential harness.
//!
//! Connectors that already prove both the local loopback boundary and gated
//! live boundary must grow a `tests/differential.rs` harness. The baseline below
//! records the pre-existing connectors still awaiting that wiring; any new
//! connector with both prerequisite files must add differential coverage instead
//! of expanding the baseline.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED_DIFFERENTIAL_GAP_CONNECTORS: &[&str] =
    &["arxiv", "brave-search", "feishu", "hackernews"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .parent()
        .expect("workspace root exists")
        .to_path_buf()
}

fn connectors_dir() -> PathBuf {
    repo_root().join("connectors")
}

fn connector_dirs() -> Vec<PathBuf> {
    let mut dirs = fs::read_dir(connectors_dir())
        .expect("read connectors directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_dir() {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    dirs.sort();
    dirs
}

fn connector_name(connector: &Path) -> String {
    connector
        .file_name()
        .expect("connector path has basename")
        .to_string_lossy()
        .to_string()
}

fn has_both_prerequisite_suites(connector: &Path) -> bool {
    connector.join("tests/local_non_mock.rs").exists()
        && connector.join("tests/live_verification.rs").exists()
}

fn has_differential_harness(connector: &Path) -> bool {
    connector.join("tests/differential.rs").exists()
}

#[test]
fn github_pilot_differential_test_is_present() {
    let github = connectors_dir()
        .join("github")
        .join("tests")
        .join("differential.rs");
    assert!(
        github.exists(),
        "GitHub pilot differential harness must exist at {}",
        github.display()
    );
}

#[test]
fn every_proven_connector_with_both_test_files_has_differential_or_baseline() {
    let baseline = EXPECTED_DIFFERENTIAL_GAP_CONNECTORS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let regressions = connector_dirs()
        .into_iter()
        .filter(|connector| {
            has_both_prerequisite_suites(connector) && !has_differential_harness(connector)
        })
        .map(|connector| connector_name(&connector))
        .filter(|name| !baseline.contains(name.as_str()))
        .collect::<Vec<_>>();

    assert!(
        regressions.is_empty(),
        "connectors with both local_non_mock.rs and live_verification.rs must add tests/differential.rs: {regressions:?}"
    );
}

#[test]
fn differential_gap_baseline_stays_sorted_and_fresh() {
    let baseline = EXPECTED_DIFFERENTIAL_GAP_CONNECTORS;
    let mut sorted = baseline.to_vec();
    sorted.sort_unstable();
    assert_eq!(
        baseline,
        sorted.as_slice(),
        "EXPECTED_DIFFERENTIAL_GAP_CONNECTORS must stay sorted"
    );

    let stale = baseline
        .iter()
        .copied()
        .filter(|name| {
            let connector = connectors_dir().join(name);
            !has_both_prerequisite_suites(&connector) || has_differential_harness(&connector)
        })
        .collect::<Vec<_>>();
    assert!(
        stale.is_empty(),
        "differential gap baseline contains stale entries that should be removed: {stale:?}"
    );
}
