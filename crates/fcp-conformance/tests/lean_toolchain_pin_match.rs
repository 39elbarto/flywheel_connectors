use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const TOOLCHAIN_DOC: &str = "docs/formal/toolchain_pin.md";
const LEAN_TOOLCHAIN: &str = "lean-toolchain";
const LAKEFILE: &str = "lakefile.lean";
const LAKE_MANIFEST: &str = "lake-manifest.json";
const MAKEFILE: &str = "Makefile";

const REQUIRED_PROOF_FILES: [&str; 5] = [
    "lean/Fcp/Zone/Lattice.lean",
    "lean/Fcp/Capability/Typestate.lean",
    "lean/Fcp/Audit/HashChain.lean",
    "lean/Fcp/Crypto/HybridSignature.lean",
    "lean/Fcp/Mesh/CrdtMerge.lean",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fcp-conformance must live under crates/")
        .to_path_buf()
}

fn read_to_string(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative))
        .unwrap_or_else(|err| panic!("expected {relative} to be readable: {err}"))
}

fn doc_value(doc: &str, key: &str) -> String {
    let prefix = format!("- {key}: `");
    doc.lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix(&prefix)?;
            let (value, _suffix) = rest.split_once('`')?;
            Some(value.to_owned())
        })
        .unwrap_or_else(|| panic!("{TOOLCHAIN_DOC} missing `{key}` pin"))
}

fn mathlib_manifest(manifest: &Value) -> &Value {
    manifest
        .get("packages")
        .and_then(Value::as_array)
        .and_then(|packages| {
            packages
                .iter()
                .find(|package| package.get("name").and_then(Value::as_str) == Some("mathlib"))
        })
        .expect("lake-manifest.json must include a mathlib package entry")
}

fn makefile_lean_proof_files(makefile: &str) -> BTreeSet<String> {
    let mut in_list = false;
    let mut files = BTreeSet::new();

    for line in makefile.lines() {
        if line.trim_start().starts_with("LEAN_PROOF_FILES :=") {
            in_list = true;
            continue;
        }
        if !in_list {
            continue;
        }

        let trimmed = line.trim().trim_end_matches('\\').trim();
        if trimmed.is_empty() {
            break;
        }
        files.insert(trimmed.to_owned());
    }

    assert!(
        !files.is_empty(),
        "Makefile must define a non-empty LEAN_PROOF_FILES list"
    );
    files
}

fn markdown_cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(str::trim)
        .map(|cell| cell.trim_matches('`').to_owned())
        .collect()
}

fn documented_proof_files(doc: &str) -> BTreeSet<String> {
    doc.lines()
        .filter(|line| line.trim_start().starts_with("| `lean/"))
        .map(markdown_cells)
        .map(|cells| {
            assert!(
                cells.len() >= 2,
                "proof corpus row must have proof_file and theorem columns"
            );
            cells[0].clone()
        })
        .collect()
}

#[test]
fn test_lean_toolchain_pin_matches_documented_contract() {
    let root = workspace_root();
    let doc = read_to_string(&root, TOOLCHAIN_DOC);
    let documented_toolchain = doc_value(&doc, "Lean compiler");

    let toolchain = read_to_string(&root, LEAN_TOOLCHAIN);
    assert_eq!(
        toolchain.trim(),
        documented_toolchain,
        "lean-toolchain must match {TOOLCHAIN_DOC}"
    );
}

#[test]
fn test_mathlib_pin_matches_lakefile_manifest_and_documentation() {
    let root = workspace_root();
    let doc = read_to_string(&root, TOOLCHAIN_DOC);
    let documented_mathlib = doc_value(&doc, "Mathlib revision");
    let documented_manifest_version = doc_value(&doc, "Lake manifest version");

    let lakefile = read_to_string(&root, LAKEFILE);
    assert!(
        lakefile.contains("require mathlib from git"),
        "lakefile.lean must declare mathlib as an explicit git dependency"
    );
    assert!(
        lakefile.contains(&format!("\"{documented_mathlib}\"")),
        "lakefile.lean mathlib revision must match {TOOLCHAIN_DOC}"
    );

    let manifest: Value =
        serde_json::from_str(&read_to_string(&root, LAKE_MANIFEST)).expect("valid lake manifest");
    assert_eq!(
        manifest.get("version").and_then(Value::as_str),
        Some(documented_manifest_version.as_str()),
        "lake-manifest.json version must match {TOOLCHAIN_DOC}"
    );

    let mathlib = mathlib_manifest(&manifest);
    assert_eq!(
        mathlib.get("rev").and_then(Value::as_str),
        Some(documented_mathlib.as_str()),
        "lake-manifest.json mathlib rev must match {TOOLCHAIN_DOC}"
    );
    assert_eq!(
        mathlib.get("inputRev").and_then(Value::as_str),
        Some(documented_mathlib.as_str()),
        "direct mathlib dependency must not float on a branch name"
    );
}

#[test]
fn test_makefile_proof_corpus_matches_documented_contract() {
    let root = workspace_root();
    let doc = read_to_string(&root, TOOLCHAIN_DOC);
    let makefile = read_to_string(&root, MAKEFILE);
    let expected = REQUIRED_PROOF_FILES
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        makefile_lean_proof_files(&makefile),
        expected,
        "Makefile LEAN_PROOF_FILES must keep the formal gate corpus stable"
    );
    assert_eq!(
        documented_proof_files(&doc),
        expected,
        "{TOOLCHAIN_DOC} must document the exact formal gate proof corpus"
    );
}
