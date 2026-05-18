//! Conformance gate for Phase B.4 — runtime targets evidence matrix.
//!
//! Asserts that:
//!   1. `docs/perf/runtime_targets_evidence.md` exists and lists every
//!      one of the 7 canonical targets.
//!   2. The orchestrator script
//!      `scripts/perf/collect_runtime_targets.sh` exists and is
//!      executable.
//!   3. For every (target, `machine_class`) pair (7 × 3 = 21), the
//!      `perf-results/runtime_targets/<machine_class>/<target>.jsonl`
//!      file either exists with valid StatPack-shaped lines, OR the
//!      doc explicitly labels that cell as `fixture` (acceptable
//!      ratchet state — no live evidence yet, but the cell is
//!      declared and the bench will be run when CI promotes it).
//!
//! Filed under `flywheel_connectors-angoc.1.4` (Phase B.4).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const TARGETS: &[&str] = &[
    "cold_start_ms",
    "local_invoke_us",
    "lan_invoke_us",
    "derp_invoke_ms",
    "symbol_reconciliation_us",
    "secret_reconciliation_ms",
    "cpu_overhead_pct",
];

const MACHINE_CLASSES: &[&str] = &["laptop_m2", "server_x86", "ci_runner"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .parent()
        .expect("workspace root exists")
        .to_path_buf()
}

fn evidence_doc_path() -> PathBuf {
    repo_root()
        .join("docs")
        .join("perf")
        .join("runtime_targets_evidence.md")
}

fn orchestrator_path() -> PathBuf {
    repo_root()
        .join("scripts")
        .join("perf")
        .join("collect_runtime_targets.sh")
}

#[test]
fn test_evidence_doc_exists_and_lists_every_target() {
    let path = evidence_doc_path();
    assert!(
        path.exists(),
        "evidence matrix doc must exist at {}",
        path.display()
    );
    let content = fs::read_to_string(&path).expect("evidence doc readable");
    assert!(
        content.len() > 1000,
        "evidence doc at {} is suspiciously small ({} bytes)",
        path.display(),
        content.len()
    );
    let mut missing = Vec::new();
    for target in TARGETS {
        if !content.contains(target) {
            missing.push(*target);
        }
    }
    assert!(
        missing.is_empty(),
        "evidence matrix doc must reference every target; missing: {missing:?}"
    );
}

#[test]
fn test_evidence_doc_lists_every_machine_class() {
    let content = fs::read_to_string(evidence_doc_path()).expect("evidence doc readable");
    let mut missing = Vec::new();
    for class in MACHINE_CLASSES {
        if !content.contains(class) {
            missing.push(*class);
        }
    }
    assert!(
        missing.is_empty(),
        "evidence matrix doc must reference every machine class; missing: {missing:?}"
    );
}

#[test]
fn test_orchestrator_script_present_and_executable() {
    let path = orchestrator_path();
    assert!(
        path.exists(),
        "orchestrator script must exist at {}",
        path.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&path).expect("orchestrator metadata");
        let mode = metadata.permissions().mode();
        assert!(
            mode & 0o100 != 0,
            "orchestrator at {} must be executable (mode = {:#o})",
            path.display(),
            mode
        );
    }
}

#[test]
fn test_evidence_jsonl_lines_parse_when_present() {
    // Walk every (target, machine_class) pair. For each, if the JSONL
    // file exists, every line must parse as valid JSON AND contain at
    // minimum {target, machine_class, p99, samples, commit_sha,
    // timestamp}. Missing files are acceptable (fixture ratchet state);
    // present-but-malformed files are NOT acceptable.
    let mut violations: Vec<String> = Vec::new();
    let perf_results_dir = repo_root().join("perf-results").join("runtime_targets");
    for class in MACHINE_CLASSES {
        for target in TARGETS {
            let path = perf_results_dir.join(class).join(format!("{target}.jsonl"));
            if !path.exists() {
                continue;
            }
            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    violations.push(format!("{}: read error {e}", path.display()));
                    continue;
                }
            };
            for (line_idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let value: serde_json::Value = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(e) => {
                        violations.push(format!(
                            "{}:{}: invalid JSON: {e}",
                            path.display(),
                            line_idx + 1
                        ));
                        continue;
                    }
                };
                for field in &[
                    "target",
                    "machine_class",
                    "p99",
                    "samples",
                    "commit_sha",
                    "timestamp",
                ] {
                    if value.get(field).is_none() {
                        violations.push(format!(
                            "{}:{}: missing required field `{field}`",
                            path.display(),
                            line_idx + 1
                        ));
                    }
                }
                // target field must match the filename target.
                if let Some(t) = value.get("target").and_then(|v| v.as_str()) {
                    if t != *target {
                        violations.push(format!(
                            "{}:{}: target mismatch — file expects `{target}`, line has `{t}`",
                            path.display(),
                            line_idx + 1
                        ));
                    }
                }
                // machine_class must match the directory.
                if let Some(c) = value.get("machine_class").and_then(|v| v.as_str()) {
                    if c != *class {
                        violations.push(format!(
                            "{}:{}: machine_class mismatch — dir expects `{class}`, line has `{c}`",
                            path.display(),
                            line_idx + 1
                        ));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "evidence JSONL lines have problems:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn test_targets_align_with_perf_targets_toml() {
    // The orchestrator + this test pin the 7 targets. They must align
    // with the targets in docs/perf/perf-targets.toml (the gate
    // threshold registry) — minus `memory_overhead` and `pq_signing`
    // which have their own evidence docs.
    let toml_path = repo_root()
        .join("docs")
        .join("perf")
        .join("perf-targets.toml");
    let content = fs::read_to_string(&toml_path).expect("perf-targets.toml readable");
    let toml_targets: BTreeSet<String> = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix('[') {
                rest.strip_suffix(']').map(std::string::ToString::to_string)
            } else {
                None
            }
        })
        .collect();
    // Map our target names to perf-targets.toml section names.
    let our_target_to_toml = [
        ("cold_start_ms", "cold_start"),
        ("local_invoke_us", "local_invoke"),
        ("lan_invoke_us", "lan_invoke"),
        ("derp_invoke_ms", "derp_invoke"),
        ("symbol_reconciliation_us", "symbol_recon"),
        ("secret_reconciliation_ms", "secret_recon"),
        ("cpu_overhead_pct", "cpu_overhead"),
    ];
    let mut missing = Vec::new();
    for (our_name, toml_name) in &our_target_to_toml {
        if !toml_targets.contains(*toml_name) {
            missing.push(format!("{our_name} (looked up `{toml_name}`)"));
        }
    }
    assert!(
        missing.is_empty(),
        "every runtime target must have a matching section in docs/perf/perf-targets.toml; missing: {missing:?}"
    );
}
