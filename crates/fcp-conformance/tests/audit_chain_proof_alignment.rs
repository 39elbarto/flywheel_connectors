use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LEAN_FILE: &str = "lean/Fcp/Audit/HashChain.lean";
const RUNTIME_FILE: &str = "crates/fcp-audit/src/lib.rs";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fcp-conformance must live under crates/")
        .to_path_buf()
}

fn read_relative(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative))
        .unwrap_or_else(|err| panic!("expected {relative} to be readable: {err}"))
}

fn contains_lean_theorem(source: &str, name: &str) -> bool {
    let declaration = format!("theorem {name}");
    source
        .lines()
        .any(|line| line.trim_start().starts_with(&declaration))
}

fn explicit_axiom_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| line.trim_start().starts_with("axiom "))
        .count()
}

#[test]
fn test_lean_audit_hash_chain_compiles_clean() {
    let root = workspace_root();
    let output = Command::new("lake")
        .args(["build", "Fcp.Audit.HashChain"])
        .current_dir(&root)
        .output()
        .expect("lake build must be invokable for the pinned Lean toolchain");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "lake build Fcp.Audit.HashChain failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("sorry") && !stderr.contains("sorry"),
        "compiled proof output must not report sorry tokens\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn test_lean_model_matches_runtime_entry_shape() {
    let root = workspace_root();
    let lean = read_relative(&root, LEAN_FILE);
    let runtime = read_relative(&root, RUNTIME_FILE);

    for theorem in [
        "chain_tamper_evident",
        "chain_matching_hash_extends",
        "extension_preserves_prior_hash_link",
        "extension_sequence_strictly_increases",
        "no_retroactive_insertion",
        "hash_chain_collision_resistance_assumption_unique",
    ] {
        assert!(
            contains_lean_theorem(&lean, theorem),
            "missing Lean theorem {theorem} in {LEAN_FILE}"
        );
    }

    for needle in [
        "structure AuditEntry where",
        "id : Nat",
        "prev : Option Nat",
        "seq : Nat",
        "def canonicalId",
        "def Genesis",
        "def Extends",
        "child.prev = some (canonicalId parent)",
        "child.seq = parent.seq + 1",
    ] {
        assert!(
            lean.contains(needle),
            "Lean audit-chain model is missing `{needle}`"
        );
    }

    for needle in [
        "pub struct AuditEntry",
        "pub id: String",
        "pub seq: u64",
        "pub prev: Option<String>",
        "pub fn computed_id(&self)",
        "pub fn follows(&self, other: &Self) -> bool",
        "checked_add(1)",
        "self.prev.as_deref() == Some(other.id.as_str())",
    ] {
        assert!(
            runtime.contains(needle),
            "runtime audit-chain surface is missing `{needle}` in {RUNTIME_FILE}"
        );
    }
}

#[test]
fn test_verify_chain_rejects_non_monotonic_or_broken_links() {
    let root = workspace_root();
    let runtime = read_relative(&root, RUNTIME_FILE);

    for needle in [
        "pub fn verify_chain(",
        "pub fn verify_chain_with_precomputed_ids(",
        "AuditEntry::computed_id",
        "seen_seq.insert(entry.seq, effective_id)",
        "\"audit.fork_detected\"",
        "\"audit.genesis_invalid\"",
        "\"audit.seq_gap\"",
        "\"audit.prev_mismatch\"",
        "entry.seq != expected_seq",
        "entry.prev.as_deref() != Some(prev_canonical_id)",
        "head.head_entry != last_canonical_id",
        "head.head_seq != last.seq",
    ] {
        assert!(
            runtime.contains(needle),
            "verify_chain no longer exposes expected audit-chain guard `{needle}`"
        );
    }
}

#[test]
fn test_no_axiom_inflation() {
    let root = workspace_root();
    let source = read_relative(&root, LEAN_FILE);

    assert_eq!(
        explicit_axiom_count(&source),
        0,
        "audit hash-chain proof must not add explicit FCP axioms"
    );
    for forbidden in ["sorry", "admit"] {
        assert!(
            !source.contains(forbidden),
            "{LEAN_FILE} must not contain `{forbidden}`"
        );
    }
}
