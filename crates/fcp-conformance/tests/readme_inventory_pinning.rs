//! Pin README headline inventory counts to the live workspace tree.
//!
//! `flywheel_connectors-qywo5` exists because these counts drifted twice. This
//! test intentionally checks every matching README count so stale repeated
//! claims fail with the same signal as the headline paragraph.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

const DRIFT_GUIDANCE: &str = "see flywheel_connectors-qywo5 and docs/quarterly/TEMPLATE.md";

#[derive(Debug, Clone, Copy)]
struct InventoryCounts {
    connector_crates: usize,
    platform_crates: usize,
    full_layout_connectors: usize,
    operation_info_connectors: usize,
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn crate_dirs(root: &Path, directory: &str) -> Result<Vec<PathBuf>, String> {
    let parent = root.join(directory);
    let entries = fs::read_dir(&parent)
        .map_err(|error| format!("cannot read {}: {error}", parent.display()))?;
    let mut crates = Vec::new();

    for entry_result in entries {
        let entry = entry_result
            .map_err(|error| format!("cannot read {directory} directory entry: {error}"))?;
        let path = entry.path();
        if path.is_dir() && path.join("Cargo.toml").is_file() {
            crates.push(path);
        }
    }

    crates.sort();
    Ok(crates)
}

fn has_full_connector_layout(connector: &Path) -> bool {
    let src = connector.join("src");
    src.join("client.rs").is_file()
        && src.join("connector.rs").is_file()
        && src.join("types.rs").is_file()
}

fn rust_file_contains_operation_info(path: &Path) -> Result<bool, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(contents.contains("OperationInfo"))
}

fn directory_contains_operation_info(root: &Path) -> Result<bool, String> {
    let mut pending = vec![root.to_path_buf()];

    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
        for entry_result in entries {
            let entry =
                entry_result.map_err(|error| format!("cannot read directory entry: {error}"))?;
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs")
                && rust_file_contains_operation_info(&path)?
            {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn measure_inventory(root: &Path) -> Result<InventoryCounts, String> {
    let connector_crates = crate_dirs(root, "connectors")?;
    let platform_crates = crate_dirs(root, "crates")?;

    let full_layout_connectors = connector_crates
        .iter()
        .filter(|connector| has_full_connector_layout(connector))
        .count();

    let mut operation_info_connectors = 0;
    for connector in &connector_crates {
        if directory_contains_operation_info(connector)? {
            operation_info_connectors += 1;
        }
    }

    Ok(InventoryCounts {
        connector_crates: connector_crates.len(),
        platform_crates: platform_crates.len(),
        full_layout_connectors,
        operation_info_connectors,
    })
}

fn parse_readme_claims(readme: &str, pattern: &str, label: &str) -> Result<Vec<usize>, String> {
    let regex = Regex::new(pattern)
        .map_err(|error| format!("invalid README inventory regex for {label}: {error}"))?;
    let claims = regex
        .captures_iter(readme)
        .map(|capture| {
            capture[1]
                .parse::<usize>()
                .map_err(|error| format!("cannot parse README {label} count: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if claims.is_empty() {
        return Err(format!(
            "README.md no longer has a parseable {label} inventory claim; {DRIFT_GUIDANCE}"
        ));
    }

    Ok(claims)
}

fn assert_claims_match(label: &str, actual: usize, claims: &[usize]) {
    for claim in claims {
        assert_eq!(
            *claim, actual,
            "README inventory drift for {label}: actual count is {actual}, \
             but README claims {claims:?}; {DRIFT_GUIDANCE}"
        );
    }
}

#[test]
fn readme_inventory_counts_match_workspace_reality() -> Result<(), String> {
    let root = workspace_root()?;
    let readme_path = root.join("README.md");
    let readme = fs::read_to_string(&readme_path)
        .map_err(|error| format!("cannot read {}: {error}", readme_path.display()))?;
    let counts = measure_inventory(&root)?;

    let platform_claims = parse_readme_claims(
        &readme,
        r"(?m)(\d+)\s+platform crates?\b",
        "platform crates",
    )?;
    assert_claims_match("platform crates", counts.platform_crates, &platform_claims);

    let connector_claims = parse_readme_claims(
        &readme,
        r"(?m)(\d+)\s+(?:separate\s+)?connector crates?\b",
        "connector crates",
    )?;
    assert_claims_match(
        "connector crates",
        counts.connector_crates,
        &connector_claims,
    );

    let full_layout_claims = parse_readme_claims(
        &readme,
        r"(?m)(\d+)\s+(?:currently\s+)?(?:follow|use)s?\s+the\s+full\s+(?:`?src/client\.rs`?\s*\+\s*`?src/connector\.rs`?\s*\+\s*`?src/types\.rs`?\s+layout|`?client\.rs`?/`?connector\.rs`?/`?types\.rs`?\s+layout|client/connector/types\s+layout)",
        "full connector layout",
    )?;
    assert_claims_match(
        "full connector layout",
        counts.full_layout_connectors,
        &full_layout_claims,
    );

    let operation_info_claims = parse_readme_claims(
        &readme,
        r"(?m)(\d+)\s+(?:currently\s+)?publish(?:es)?\s+explicit\s+`?OperationInfo`?\s+structs?\b",
        "OperationInfo connector coverage",
    )?;
    assert_claims_match(
        "OperationInfo connector coverage",
        counts.operation_info_connectors,
        &operation_info_claims,
    );

    Ok(())
}
