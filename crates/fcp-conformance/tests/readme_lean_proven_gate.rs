use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const ZONE_ISOLATION: &str = "Zone Isolation";
const ZONE_LATTICE_FILE: &str = "lean/Fcp/Zone/Lattice.lean";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeanGateVerdict {
    Limited,
    Green,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fcp-conformance must live under crates/")
        .to_path_buf()
}

fn read_feature_status(readme: &str, feature: &str) -> Option<String> {
    readme.lines().find_map(|line| {
        let cells = line
            .split('|')
            .map(str::trim)
            .filter(|cell| !cell.is_empty())
            .collect::<Vec<_>>();
        let feature_cell = cells
            .first()
            .and_then(|cell| cell.strip_prefix("**"))
            .and_then(|cell| cell.strip_suffix("**"));
        if cells.len() < 2 || feature_cell != Some(feature) {
            return None;
        }
        Some(cells[1].trim_matches('`').to_owned())
    })
}

fn latest_lean_artifact(artifact_dir: &Path) -> std::io::Result<Option<String>> {
    let Ok(entries) = fs::read_dir(artifact_dir) else {
        return Ok(None);
    };

    let mut latest: Option<(SystemTime, PathBuf)> = None;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("txt") {
            continue;
        }
        let modified = entry
            .metadata()?
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(current_modified, _)| modified > *current_modified)
        {
            latest = Some((modified, path));
        }
    }

    latest.map(|(_, path)| fs::read_to_string(path)).transpose()
}

fn artifact_reports_green(artifact: &str, proof_file: &str) -> bool {
    artifact.lines().any(|line| {
        line.contains(proof_file)
            && line.contains(r#""verdict":"green""#)
            && line.contains(r#""theorems_proven":1"#)
            && line.contains(r#""sorries_remaining":0"#)
    })
}

fn evaluate_zone_isolation_gate(
    readme: &str,
    artifact: Option<&str>,
) -> Result<LeanGateVerdict, String> {
    let status = read_feature_status(readme, ZONE_ISOLATION)
        .ok_or_else(|| "README feature-status table is missing Zone Isolation".to_owned())?;
    if status != "PROVEN" {
        return Ok(LeanGateVerdict::Limited);
    }

    let artifact = artifact
        .ok_or_else(|| "Zone Isolation is PROVEN but no Lean artifact exists".to_owned())?;
    if artifact_reports_green(artifact, ZONE_LATTICE_FILE) {
        Ok(LeanGateVerdict::Green)
    } else {
        Err("Zone Isolation is PROVEN but lean-verify artifact is not green".to_owned())
    }
}

#[test]
fn test_readme_zone_isolation_proven_requires_lean_ci_green() {
    let root = workspace_root();
    let readme = fs::read_to_string(root.join("README.md")).expect("README.md must be readable");
    let artifact =
        latest_lean_artifact(&root.join("artifacts/lean")).expect("artifact scan must not fail");

    let _verdict = evaluate_zone_isolation_gate(&readme, artifact.as_deref())
        .expect("README Lean proof gate must be internally consistent");
}

#[test]
fn test_no_proven_marker_when_lean_red() {
    let readme = "| Feature | Status | What It Does | Evidence |\n\
                  |---------|--------|--------------|----------|\n\
                  | **Zone Isolation** | `PROVEN` | synthetic | synthetic |\n";
    let artifact = r#"INFO {"span":"fcp.proof.lean_verify","file":"lean/Fcp/Zone/Lattice.lean","verdict":"red","theorems_total":1,"theorems_proven":0,"sorries_remaining":1,"duration_s":0}"#;

    assert!(
        evaluate_zone_isolation_gate(readme, Some(artifact)).is_err(),
        "a red Lean artifact must not allow a PROVEN Zone Isolation marker"
    );
}

#[test]
fn test_skeleton_files_present() {
    let root = workspace_root();
    for relative in [
        ZONE_LATTICE_FILE,
        "lean/Fcp/Capability/Typestate.lean",
        "lean/Fcp/Audit/HashChain.lean",
        "lean/Fcp/Crypto/HybridSignature.lean",
        "lean/Fcp/Mesh/CrdtMerge.lean",
    ] {
        let path = root.join(relative);
        let source = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "expected skeleton file {} to be readable: {err}",
                path.display()
            )
        });
        assert!(
            !source.contains("sorry") && !source.contains("admit"),
            "skeleton file {relative} must compile without unfinished proofs"
        );
    }
}

#[test]
fn test_artifact_missing_falls_back_to_limited() {
    let readme = "| Feature | Status | What It Does | Evidence |\n\
                  |---------|--------|--------------|----------|\n\
                  | **Zone Isolation** | `LIMITED` | synthetic | synthetic |\n";

    assert_eq!(
        evaluate_zone_isolation_gate(readme, None).expect("LIMITED row must not need artifact"),
        LeanGateVerdict::Limited
    );
}
