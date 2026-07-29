use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const ZONE_LATTICE_FILE: &str = "lean/Fcp/Zone/Lattice.lean";
const HOST_INVOKE_FILE: &str = "crates/fcp-host/src/bin/fcp-host.rs";

struct Alignment<'a> {
    proof_symbol: &'a str,
    proof_needles: &'a [&'a str],
    runtime_path: &'a str,
    runtime_needles: &'a [&'a str],
}

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
fn test_lean_proof_compiles_clean() {
    let root = workspace_root();
    let output = Command::new("lake")
        .args(["build", "Fcp.Zone.Lattice"])
        .current_dir(&root)
        .output()
        .expect("lake build must be invokable for the pinned Lean toolchain");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "lake build Fcp.Zone.Lattice failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("sorry") && !stderr.contains("sorry"),
        "compiled proof output must not report sorry tokens\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn test_zone_lattice_axiom_count() {
    let root = workspace_root();
    let source = read_relative(&root, ZONE_LATTICE_FILE);

    assert_eq!(
        explicit_axiom_count(&source),
        0,
        "zone lattice proof must not add explicit FCP axioms"
    );
}

#[test]
fn test_runtime_zone_check_matches_proof_signature() {
    let root = workspace_root();
    let proof = read_relative(&root, ZONE_LATTICE_FILE);
    let runtime = read_relative(&root, HOST_INVOKE_FILE);
    let alignments = [
        Alignment {
            proof_symbol: "zone_lattice_sound",
            proof_needles: &[
                "theorem zone_lattice_sound",
                "(op : Operation)",
                "(h : zone_check op = ZoneCheck.pass)",
                "¬ ∃ leak : Leak, reachable op leak",
            ],
            runtime_path: HOST_INVOKE_FILE,
            runtime_needles: &[
                "async fn verify_live_request",
                "allowed_zones",
                "request.zone_id.as_str()",
                "HostError::PreflightFailed",
            ],
        },
        Alignment {
            proof_symbol: "no_silent_downgrade_lemma",
            proof_needles: &[
                "theorem no_silent_downgrade_lemma",
                "(flow : ZoneFlow)",
                "(h : FlowAllowed flow)",
                "¬ flow.sourceLevel < flow.targetLevel",
            ],
            runtime_path: HOST_INVOKE_FILE,
            runtime_needles: &["allowed_zones", "enforce_empty_allow_lists"],
        },
    ];

    for alignment in alignments {
        assert!(
            contains_lean_theorem(&proof, alignment.proof_symbol),
            "missing Lean theorem {} in {ZONE_LATTICE_FILE}",
            alignment.proof_symbol
        );
        for needle in alignment.proof_needles {
            assert!(
                proof.contains(needle),
                "Lean proof signature for {} is missing needle `{needle}`",
                alignment.proof_symbol
            );
        }
        for needle in alignment.runtime_needles {
            assert!(
                runtime.contains(needle),
                "runtime alignment for {} is missing `{needle}` in {}",
                alignment.proof_symbol,
                alignment.runtime_path
            );
        }
    }
}

#[test]
fn test_no_sorry_in_proof_body() {
    let root = workspace_root();
    let source = read_relative(&root, ZONE_LATTICE_FILE);

    for forbidden in ["sorry", "admit"] {
        assert!(
            !source.contains(forbidden),
            "{ZONE_LATTICE_FILE} must not contain `{forbidden}`"
        );
    }
}
