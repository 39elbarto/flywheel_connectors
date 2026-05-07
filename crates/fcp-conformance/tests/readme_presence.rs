//! Soft connector README coverage check.
//!
//! `flywheel_connectors-4kw5f.12` tracks the workspace-wide README convention.
//! Most connector READMEs are still missing, so the enforcement test is ignored
//! by default until the wave work finishes. Running it explicitly gives a
//! deterministic, redaction-safe inventory of the remaining gaps.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

const MIN_README_BYTES: u64 = 500;
const REQUIRED_HEADINGS: &[&str] = &["## Purpose", "## Operations"];

#[derive(Debug)]
struct ConnectorReadmeRecord {
    connector: String,
    readme_path: String,
    exists: bool,
    byte_len: u64,
    missing_headings: Vec<&'static str>,
}

impl ConnectorReadmeRecord {
    fn is_complete(&self) -> bool {
        self.exists && self.byte_len >= MIN_README_BYTES && self.missing_headings.is_empty()
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |relative| relative.display().to_string(),
    )
}

fn discover_connector_readmes(root: &Path) -> Result<Vec<ConnectorReadmeRecord>, String> {
    let manifests_parent = root.join("connectors");
    let entries = fs::read_dir(&manifests_parent)
        .map_err(|error| format!("cannot read {}: {error}", manifests_parent.display()))?;
    let mut records = Vec::new();

    for entry_result in entries {
        let entry = entry_result
            .map_err(|error| format!("cannot read connector directory entry: {error}"))?;
        let candidate = entry.path();
        if !candidate.is_dir() || !candidate.join("manifest.toml").is_file() {
            continue;
        }

        let Some(name) = candidate
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
        else {
            continue;
        };

        let readme = candidate.join("README.md");
        let readme_path = display_path(root, &readme);
        let contents = fs::read_to_string(&readme).unwrap_or_default();
        let exists = readme.is_file();
        let byte_len = if exists {
            fs::metadata(&readme)
                .map(|metadata| metadata.len())
                .map_err(|error| format!("cannot stat {readme_path}: {error}"))?
        } else {
            0
        };
        let missing_headings = if exists {
            REQUIRED_HEADINGS
                .iter()
                .copied()
                .filter(|heading| !contents.contains(heading))
                .collect()
        } else {
            Vec::new()
        };

        records.push(ConnectorReadmeRecord {
            connector: name,
            readme_path,
            exists,
            byte_len,
            missing_headings,
        });
    }

    records.sort_by(|left, right| left.connector.cmp(&right.connector));
    Ok(records)
}

#[test]
fn connector_readme_template_documents_required_operator_contract() -> Result<(), String> {
    let root = workspace_root()?;
    let template_path = root.join("docs/connector-readme-template.md");
    let template = fs::read_to_string(&template_path)
        .map_err(|error| format!("cannot read {}: {error}", template_path.display()))?;

    for heading in [
        "## Purpose",
        "## Current Runtime Snapshot",
        "## Auth And Scope Boundary",
        "## Operation Inventory",
        "## Readiness And Verification Surface",
        "## Operator Guidance",
    ] {
        assert!(
            template.contains(heading),
            "connector README template must include `{heading}`"
        );
    }
    Ok(())
}

#[test]
#[ignore = "soft convention ratchet: enable after README wave work closes flywheel_connectors-4kw5f.12"]
fn all_manifest_backed_connectors_have_operator_readmes() -> Result<(), String> {
    let root = workspace_root()?;
    let records = discover_connector_readmes(&root)?;
    let incomplete = records
        .iter()
        .filter(|record| !record.is_complete())
        .collect::<Vec<_>>();

    for record in &incomplete {
        println!(
            "{}",
            json!({
                "event": "connector_readme_presence",
                "connector": record.connector,
                "readme_path": record.readme_path,
                "exists": record.exists,
                "byte_len": record.byte_len,
                "missing_headings": record.missing_headings,
                "min_readme_bytes": MIN_README_BYTES,
                "redaction_decision": "connector names and repository-relative README paths only; no credentials, payloads, prompts, transcripts, or PII read",
            })
        );
    }

    assert!(
        incomplete.is_empty(),
        "connector README convention gaps remain: {} of {} manifest-backed connectors incomplete",
        incomplete.len(),
        records.len()
    );
    Ok(())
}
