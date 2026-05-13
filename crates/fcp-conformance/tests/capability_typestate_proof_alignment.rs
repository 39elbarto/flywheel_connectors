use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LEAN_FILE: &str = "lean/Fcp/Capability/Typestate.lean";
const RUNTIME_FILE: &str = "crates/fcp-core/src/capability.rs";

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

fn explicit_axiom_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| line.trim_start().starts_with("axiom "))
        .count()
}

fn lean_cap_states(source: &str) -> BTreeSet<String> {
    let mut states = BTreeSet::new();
    let mut in_cap_state = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == "inductive CapState where" {
            in_cap_state = true;
            continue;
        }
        if !in_cap_state {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('|') {
            let lean_name = rest
                .split_whitespace()
                .next()
                .expect("Lean constructor must have a name");
            let mut chars = lean_name.chars();
            let first = chars
                .next()
                .expect("Lean constructor name must be non-empty")
                .to_ascii_uppercase();
            let rust_name = format!("{first}{}", chars.as_str());
            states.insert(rust_name);
            continue;
        }
        if trimmed.starts_with("deriving ") {
            break;
        }
    }

    states
}

fn rust_capability_lifecycle_states(source: &str) -> BTreeSet<String> {
    let mut states = BTreeSet::new();
    let mut in_enum = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == "pub enum CapabilityLifecycleState {" {
            in_enum = true;
            continue;
        }
        if !in_enum {
            continue;
        }
        if trimmed == "}" {
            break;
        }
        let variant = trimmed.trim_end_matches(',');
        if !variant.is_empty() {
            states.insert(variant.to_owned());
        }
    }

    states
}

#[test]
fn test_lean_proof_compiles_clean() {
    let root = workspace_root();
    let output = Command::new("lake")
        .args(["build", "Fcp.Capability.Typestate"])
        .current_dir(&root)
        .output()
        .expect("lake build must be invokable for the pinned Lean toolchain");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "lake build Fcp.Capability.Typestate failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("sorry") && !stderr.contains("sorry"),
        "compiled proof output must not report sorry tokens\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn test_runtime_state_enum_matches_lean() {
    let root = workspace_root();
    let lean = read_relative(&root, LEAN_FILE);
    let runtime = read_relative(&root, RUNTIME_FILE);

    let expected = BTreeSet::from([
        "Pending".to_owned(),
        "Approved".to_owned(),
        "Used".to_owned(),
        "Revoked".to_owned(),
        "Expired".to_owned(),
    ]);

    assert_eq!(
        lean_cap_states(&lean),
        expected,
        "Lean CapState constructors must match the runtime lifecycle names"
    );
    assert_eq!(
        rust_capability_lifecycle_states(&runtime),
        expected,
        "CapabilityLifecycleState variants must match the Lean proof model"
    );
}

#[test]
fn test_runtime_transitions_cover_lean_steps() {
    let root = workspace_root();
    let lean = read_relative(&root, LEAN_FILE);
    let runtime = read_relative(&root, RUNTIME_FILE);

    for constructor in [
        "approve",
        "useApproved",
        "revokePending",
        "revokeApproved",
        "expirePending",
        "expireApproved",
        "revocationObserved",
    ] {
        assert!(
            lean.contains(&format!("| {constructor}")),
            "Lean LifecycleStep must include constructor {constructor}"
        );
    }

    for runtime_needle in [
        "CapabilityLifecycleTransition::Approve",
        "CapabilityLifecycleTransition::UseAndEmitReceipt",
        "CapabilityLifecycleTransition::RevokePending",
        "CapabilityLifecycleTransition::RevokeApproved",
        "CapabilityLifecycleTransition::ExpirePending",
        "CapabilityLifecycleTransition::ExpireApproved",
        "CapabilityLifecycleTransition::PushRevocation",
        "pub fn approve(",
        "pub fn mark_used(",
        "pub fn revoke(",
        "pub fn expire(",
        "pub fn push_revocation(",
    ] {
        assert!(
            runtime.contains(runtime_needle),
            "runtime lifecycle surface is missing `{runtime_needle}`"
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
        "capability typestate proof must not add explicit FCP axioms"
    );
    for forbidden in ["sorry", "admit"] {
        assert!(
            !source.contains(forbidden),
            "{LEAN_FILE} must not contain `{forbidden}`"
        );
    }
}
