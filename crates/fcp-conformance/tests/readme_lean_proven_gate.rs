use std::{
    fs,
    path::{Path, PathBuf},
};

const ZONE_ROW: &str = "Zone Isolation";
const ZONE_THEOREM: &str = "Fcp.Zone.Lattice.zone_flow_soundness";
const ZONE_THEOREM_SHORT: &str = "zone_flow_soundness";

#[test]
fn test_readme_zone_isolation_proven_requires_lean_ci_green() {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("read README.md");
    let artifact = latest_lean_artifact().and_then(|path| fs::read_to_string(path).ok());

    assert!(
        check_zone_isolation_gate(&readme, artifact.as_deref()).is_ok(),
        "README Zone Isolation PROVEN row must be backed by a green Lean artifact"
    );
}

#[test]
fn test_no_proven_marker_when_lean_red() {
    let readme = "| Feature | Status | Notes | Evidence |\n\
                  | --- | --- | --- | --- |\n\
                  | **Zone Isolation** | `PROVEN` | synthetic | lean/Fcp/Zone/Lattice.lean |\n";
    let red_artifact = "{\"proof_file\":\"lean/Fcp/Zone/Lattice.lean\",\"theorem\":\"zone_flow_soundness\",\"success\":false}\n";

    let error = check_zone_isolation_gate(readme, Some(red_artifact))
        .expect_err("red Lean artifact must reject a PROVEN marker");
    assert!(error.contains("zone_flow_soundness"), "{error}");
}

#[test]
fn test_skeleton_files_present() {
    for (path, theorem) in [
        ("lean/Fcp/Zone/Lattice.lean", "theorem zone_flow_soundness"),
        (
            "lean/Fcp/Capability/Typestate.lean",
            "theorem typestate_progression_no_skip",
        ),
        (
            "lean/Fcp/Audit/HashChain.lean",
            "theorem chain_tamper_evident",
        ),
        (
            "lean/Fcp/Crypto/HybridSignature.lean",
            "theorem hybrid_unforgeable_under_one_break",
        ),
        (
            "lean/Fcp/Mesh/CrdtMerge.lean",
            "theorem crdt_merge_lattice_laws",
        ),
    ] {
        let source = fs::read_to_string(repo_root().join(path))
            .unwrap_or_else(|err| panic!("read {path}: {err}"));
        assert!(source.contains(theorem), "{path} missing {theorem}");
        assert!(!source.contains("sorry"), "{path} must not contain sorry");
    }
}

fn check_zone_isolation_gate(readme: &str, artifact: Option<&str>) -> Result<(), String> {
    let row = readme
        .lines()
        .find(|line| line.contains(&format!("**{ZONE_ROW}**")))
        .ok_or_else(|| format!("README status row missing for {ZONE_ROW}"))?;

    if !row.contains("`PROVEN`") {
        return Ok(());
    }

    let artifact =
        artifact.ok_or_else(|| format!("{ZONE_ROW} PROVEN requires latest Lean CI artifact"))?;
    if !artifact.contains(ZONE_THEOREM_SHORT) {
        return Err(format!("Lean artifact missing {ZONE_THEOREM}"));
    }
    if !(artifact.contains("\"success\":true") || artifact.contains("green")) {
        return Err(format!(
            "{ZONE_THEOREM} is not green in latest Lean artifact"
        ));
    }

    Ok(())
}

fn latest_lean_artifact() -> Option<PathBuf> {
    let artifact_dir = repo_root().join("artifacts/lean");
    let mut artifacts = fs::read_dir(artifact_dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect::<Vec<_>>();
    artifacts.sort();
    artifacts.pop()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root ancestor")
        .to_path_buf()
}
