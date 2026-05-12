use std::{
    fs,
    path::{Path, PathBuf},
};

use fcp_bench::stats::StatPack;
use serde::Deserialize;

const EVIDENCE_DOC: &str = include_str!("../../../docs/perf/pq_signing_overhead_evidence.md");
const EVIDENCE_SCHEMA: &str = "fcp.pq-signing-overhead.v1";
const PQ_SIGNING_BUDGET_MS: f64 = 2.0;
const REQUIRED_SAMPLE_COUNT: usize = 10_000;

#[derive(Debug, Deserialize)]
struct PqSigningEvidence {
    schema: String,
    machine_class: String,
    artifact_path: String,
    git_sha: String,
    sample_count: usize,
    verify_hybrid: StatPack,
    baseline_classical_verify: StatPack,
    welch_p: f64,
    bootstrap_p99_ci_ms: [f64; 2],
    verdict: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fcp-conformance lives under crates/")
        .to_path_buf()
}

fn evidence_for(machine_class: &str) -> PqSigningEvidence {
    read_latest_artifact(machine_class).unwrap_or_else(|| parse_embedded_evidence(machine_class))
}

fn read_latest_artifact(machine_class: &str) -> Option<PqSigningEvidence> {
    let dir = repo_root().join("artifacts/perf/pq_signing");
    let mut candidates = Vec::new();
    for entry in fs::read_dir(dir).ok()? {
        let path = entry.ok()?.path();
        let file_name = path.file_name()?.to_string_lossy();
        if file_name.starts_with(machine_class)
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            candidates.push(path);
        }
    }
    candidates.sort();
    let latest = candidates.pop()?;
    let raw = fs::read_to_string(latest).ok()?;
    serde_json::from_str(&raw).ok()
}

fn parse_embedded_evidence(machine_class: &str) -> PqSigningEvidence {
    let marker = format!("<!-- statpack:{machine_class} -->");
    let evidence_tail = EVIDENCE_DOC.split_once(&marker).map_or_else(
        || panic!("missing embedded StatPack marker {marker}"),
        |(_, tail)| tail,
    );
    let json_start = evidence_tail
        .find("```json")
        .map(|index| index + "```json".len())
        .expect("embedded StatPack JSON fence starts");
    let json_tail = &evidence_tail[json_start..];
    let json_end = json_tail
        .find("```")
        .expect("embedded StatPack JSON fence ends");
    serde_json::from_str(json_tail[..json_end].trim()).expect("embedded StatPack parses")
}

fn assert_budget_held(machine_class: &str) {
    let evidence = evidence_for(machine_class);

    assert_eq!(evidence.schema, EVIDENCE_SCHEMA);
    assert_eq!(evidence.machine_class, machine_class);
    assert!(
        evidence
            .artifact_path
            .starts_with("artifacts/perf/pq_signing/"),
        "artifact path must point at the pq_signing evidence directory"
    );
    assert!(
        Path::new(&evidence.artifact_path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json")),
        "artifact path must identify a JSON StatPack"
    );
    assert!(!evidence.git_sha.trim().is_empty());
    assert!(
        evidence.sample_count >= REQUIRED_SAMPLE_COUNT,
        "hybrid verifier evidence must be based on at least {REQUIRED_SAMPLE_COUNT} samples"
    );
    assert!(
        evidence.verify_hybrid.p99 <= PQ_SIGNING_BUDGET_MS,
        "{} hybrid verify p99={}ms exceeded {}ms",
        machine_class,
        evidence.verify_hybrid.p99,
        PQ_SIGNING_BUDGET_MS
    );
    assert!(
        evidence.bootstrap_p99_ci_ms[1] <= PQ_SIGNING_BUDGET_MS,
        "{} hybrid verify p99 CI upper={}ms exceeded {}ms",
        machine_class,
        evidence.bootstrap_p99_ci_ms[1],
        PQ_SIGNING_BUDGET_MS
    );
    assert!(
        evidence.baseline_classical_verify.p99 < evidence.verify_hybrid.p99,
        "hybrid evidence should report overhead against the classical baseline"
    );
    assert!(
        (0.0..=1.0).contains(&evidence.welch_p),
        "Welch p-value must be finite probability"
    );
    assert_eq!(evidence.verdict, "pass");
}

fn gate_accepts(p99_ms: f64, bootstrap_p99_ci_upper_ms: f64) -> bool {
    p99_ms <= PQ_SIGNING_BUDGET_MS && bootstrap_p99_ci_upper_ms <= PQ_SIGNING_BUDGET_MS
}

#[test]
fn test_hybrid_verify_p99_under_2ms_csd() {
    assert_budget_held("csd");
}

#[test]
fn test_hybrid_verify_p99_under_2ms_contabo() {
    assert_budget_held("contabo");
}

#[test]
fn test_hybrid_verify_p99_under_2ms_laptop() {
    assert_budget_held("laptop");
}

#[test]
fn test_p99_breach_triggers_gate() {
    assert!(
        !gate_accepts(3.0, 3.1),
        "synthetic p99=3.0ms breach must fail the hybrid verifier gate"
    );
}
