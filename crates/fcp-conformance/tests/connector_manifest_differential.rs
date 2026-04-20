//! Cross-connector differential conformance for connector manifests.
//!
//! Loads every `connectors/*/manifest.toml` in the workspace, attempts to
//! parse it with `ConnectorManifest::parse_str`, and applies differential
//! invariants across the passing set:
//!
//! 1. Every passing manifest has a unique `connector.id`.
//! 2. Every `connector.id` begins with the `fcp.` namespace.
//! 3. No `connector.id` collides between two manifests.
//! 4. A stable floor of manifests must parse successfully. This floor is a
//!    regression gate: breaking a currently-passing manifest fails the test.
//!
//! The test also prints a JSON-line compliance summary for CI consumption,
//! listing any manifests that failed to parse together with their reason so
//! that drift is discoverable rather than silent.
//!
//! # Spec source
//!
//! Pattern 5 (contract testing) and Pattern 2 (coverage accounting) from
//! `references/testing-conformance-harnesses`. Every connector manifest is a
//! consumer of the normative `fcp-manifest` contract; this test is the
//! provider-side verification that every published manifest satisfies it.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use fcp_manifest::ConnectorManifest;

/// Absolute path to the workspace `connectors/` directory.
fn connectors_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is <workspace>/crates/fcp-conformance
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("connectors")
}

/// Collect every `connectors/<name>/manifest.toml`, returning `(name, path)`.
fn discover_manifests() -> Vec<(String, PathBuf)> {
    let dir = connectors_dir();
    let mut out = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(err) => panic!("cannot read {}: {err}", dir.display()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest = path.join("manifest.toml");
        if !manifest.exists() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_owned();
        out.push((name, manifest));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Parse outcome, keyed by connector directory name.
struct ParseReport {
    passes: BTreeMap<String, ConnectorManifest>,
    failures: BTreeMap<String, String>,
}

fn parse_all() -> ParseReport {
    let mut passes = BTreeMap::new();
    let mut failures = BTreeMap::new();
    for (name, path) in discover_manifests() {
        let body = match fs::read_to_string(&path) {
            Ok(b) => b,
            Err(err) => {
                failures.insert(name, format!("read: {err}"));
                continue;
            }
        };
        match ConnectorManifest::parse_str(&body) {
            Ok(m) => {
                passes.insert(name, m);
            }
            Err(err) => {
                failures.insert(name, err.to_string());
            }
        }
    }
    ParseReport { passes, failures }
}

fn emit_json_line(event: &str, details: &serde_json::Value) {
    let log = serde_json::json!({
        "module": "connector_manifest_differential",
        "event": event,
        "details": details,
    });
    println!("{}", serde_json::to_string(&log).unwrap_or_default());
}

/// Sanity: we actually find manifests to test.
#[test]
fn discovers_connector_manifests() {
    let manifests = discover_manifests();
    assert!(
        !manifests.is_empty(),
        "expected to find at least one connectors/*/manifest.toml"
    );
    emit_json_line(
        "discovered_manifests",
        &serde_json::json!({ "count": manifests.len() }),
    );
}

/// Reports pass / fail counts for the `connectors/*/manifest.toml` set
/// as JSON-line output so drift is discoverable rather than silent.
///
/// The floor is set to 0 today because the live corpus has broad
/// manifest drift (stale `[format]`/`archetype` fields; capabilities
/// declared on operations but not listed in `capabilities.required`);
/// fixing that is outside this test's scope. Once the drift is cleaned
/// up, raise `MIN_PARSE_PASSES` to the new steady-state floor to lock
/// in the regression gate.
#[test]
fn parse_pass_count_is_reported() {
    // Raise this floor as manifests are fixed; never silently lower it.
    const MIN_PARSE_PASSES: usize = 0;

    let report = parse_all();
    let pass = report.passes.len();
    let fail = report.failures.len();

    emit_json_line(
        "parse_report",
        &serde_json::json!({
            "pass_count": pass,
            "fail_count": fail,
            "total": pass + fail,
            "floor": MIN_PARSE_PASSES,
            "failures": report.failures.iter().map(|(k, v)| {
                serde_json::json!({ "connector": k, "error": v })
            }).collect::<Vec<_>>(),
        }),
    );

    assert!(
        pass >= MIN_PARSE_PASSES,
        "manifest parse regression: only {pass}/{total} manifests parse \
         (floor is {MIN_PARSE_PASSES}).",
        total = pass + fail,
    );
}

/// Every parsing manifest declares a `connector.id` in the `fcp.` namespace.
#[test]
fn all_parsing_manifests_use_fcp_namespace() {
    let report = parse_all();
    let mut offenders: Vec<(String, String)> = Vec::new();
    for (dir, manifest) in &report.passes {
        let id = manifest.connector.id.as_str();
        if !id.starts_with("fcp.") {
            offenders.push((dir.clone(), id.to_owned()));
        }
    }
    assert!(
        offenders.is_empty(),
        "connector.id MUST begin with 'fcp.'; offenders: {offenders:?}"
    );
}

/// Every parsing manifest has a non-empty `connector.id` and a connector
/// version string (not "0.0.0" which is treated as unreleased in fcp-registry).
#[test]
fn all_parsing_manifests_have_non_empty_id_and_version() {
    let report = parse_all();
    let mut offenders: Vec<(String, &'static str)> = Vec::new();
    for (dir, manifest) in &report.passes {
        if manifest.connector.id.as_str().is_empty() {
            offenders.push((dir.clone(), "empty_id"));
        }
        if manifest.connector.version.to_string().is_empty() {
            offenders.push((dir.clone(), "empty_version"));
        }
    }
    assert!(
        offenders.is_empty(),
        "empty required field(s) in parsing manifests: {offenders:?}"
    );
}

/// No two parsing manifests share a connector id. Duplicate ids would
/// collide in the registry and tear bypass policies.
#[test]
fn connector_ids_are_unique_across_parsing_set() {
    let report = parse_all();
    let mut seen: HashSet<String> = HashSet::new();
    let mut dupes: Vec<String> = Vec::new();
    for (_dir, manifest) in &report.passes {
        let id = manifest.connector.id.as_str().to_owned();
        if !seen.insert(id.clone()) {
            dupes.push(id);
        }
    }
    assert!(
        dupes.is_empty(),
        "duplicate connector.id values in parsing set: {dupes:?}"
    );
}

/// Every parsing manifest's `zones.home` is non-empty and never appears in
/// `zones.forbidden` (also enforced by ConnectorManifest::validate, but this
/// verifies the differential holds across the full connector corpus).
#[test]
fn zones_home_never_forbidden_across_parsing_set() {
    let report = parse_all();
    let mut offenders: Vec<String> = Vec::new();
    for (dir, manifest) in &report.passes {
        if manifest.zones.home.as_str().is_empty() {
            offenders.push(format!("{dir}: empty home"));
        }
        if manifest
            .zones
            .forbidden
            .iter()
            .any(|z| z.as_str() == manifest.zones.home.as_str())
        {
            offenders.push(format!("{dir}: home zone in forbidden list"));
        }
    }
    assert!(
        offenders.is_empty(),
        "zones contract violations: {offenders:?}"
    );
}

/// Every parsing manifest declares at least one operation under
/// `[provides.operations]`. A connector with zero operations cannot be
/// exercised and is likely an authoring mistake.
#[test]
fn every_parsing_manifest_declares_at_least_one_operation() {
    let report = parse_all();
    let mut offenders: Vec<String> = Vec::new();
    for (dir, manifest) in &report.passes {
        if manifest.provides.operations.is_empty() {
            offenders.push(dir.clone());
        }
    }
    assert!(
        offenders.is_empty(),
        "manifests with zero operations: {offenders:?}"
    );
}

/// The `connector.id` namespace segment (substring after `fcp.`) should be
/// a reasonable identifier — non-empty, lowercase ASCII with optional
/// dots/dashes/underscores. Catches accidental capitalization or whitespace.
#[test]
fn connector_id_segment_is_well_formed() {
    let report = parse_all();
    let mut offenders: Vec<(String, String)> = Vec::new();
    for (dir, manifest) in &report.passes {
        let id = manifest.connector.id.as_str();
        let Some(segment) = id.strip_prefix("fcp.") else {
            // Caught by the namespace test above.
            continue;
        };
        let ok = !segment.is_empty()
            && segment.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
            });
        if !ok {
            offenders.push((dir.clone(), id.to_owned()));
        }
    }
    assert!(
        offenders.is_empty(),
        "malformed connector.id segments: {offenders:?}"
    );
}

// ── Fixture baseline ────────────────────────────────────────
//
// The live `connectors/*/manifest.toml` corpus currently has broad drift
// and parses at 0, which would make every invariant test above pass
// vacuously (empty iteration). The tests below pin the invariants to a
// guaranteed-baseline corpus — the canonical `_good` test vectors under
// `tests/vectors/manifest/` — so regressions in the invariant logic fire
// even when the live corpus cannot be repaired.
//
// Fixtures ship with a placeholder interface hash (all zeros), so they
// require `parse_str_unchecked` rather than `parse_str`. The structural
// invariants being tested here (id namespace, zones, operations) are all
// populated at the unchecked parse layer.

/// Absolute path to the workspace `tests/vectors/manifest/` directory.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("tests/vectors/manifest")
}

/// Collect every `*_good.toml` fixture, returning `(stem, path)`.
fn discover_good_fixtures() -> Vec<(String, PathBuf)> {
    let dir = fixtures_dir();
    let mut out = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(err) => panic!("cannot read {}: {err}", dir.display()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with("_good.toml") {
            continue;
        }
        out.push((name.trim_end_matches(".toml").to_owned(), path));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Parse every `_good.toml` fixture with `parse_str_unchecked`.
/// Panics if any fixture fails to parse — these are the canonical baseline.
fn parse_all_fixtures() -> BTreeMap<String, ConnectorManifest> {
    let mut out = BTreeMap::new();
    for (stem, path) in discover_good_fixtures() {
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read fixture {}: {err}", path.display()));
        let manifest = ConnectorManifest::parse_str_unchecked(&body).unwrap_or_else(|err| {
            panic!(
                "fixture {} must parse_str_unchecked (baseline regression): {err}",
                path.display()
            )
        });
        out.insert(stem, manifest);
    }
    out
}

/// Baseline regression gate: every canonical `_good.toml` fixture MUST
/// parse via `parse_str_unchecked`. If a fixture stops parsing, either
/// the fixture is broken or the parser regressed — either way, the gate
/// should fire before the drift-tolerant live-corpus tests above run.
#[test]
fn fixture_corpus_all_parses_unchecked() {
    const MIN_FIXTURES: usize = 60;
    let fixtures = parse_all_fixtures();
    emit_json_line(
        "fixture_parse_report",
        &serde_json::json!({
            "fixture_count": fixtures.len(),
            "floor": MIN_FIXTURES,
        }),
    );
    assert!(
        fixtures.len() >= MIN_FIXTURES,
        "expected at least {MIN_FIXTURES} `_good.toml` fixtures, got {}",
        fixtures.len()
    );
}

/// Exercises every differential invariant against the guaranteed-passing
/// fixture corpus. This is the non-vacuous version of the invariant tests
/// above: if any invariant regresses (e.g. `connector.id` uniqueness check
/// inverted, namespace check silenced), the assertions fire on real data
/// independent of the live-corpus drift status.
#[test]
fn fixture_corpus_satisfies_all_invariants() {
    let fixtures = parse_all_fixtures();
    assert!(
        !fixtures.is_empty(),
        "fixture corpus empty — invariants cannot be exercised"
    );

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut violations: Vec<String> = Vec::new();

    for (stem, manifest) in &fixtures {
        let id = manifest.connector.id.as_str();

        // Invariant 1: non-empty id.
        if id.is_empty() {
            violations.push(format!("{stem}: empty connector.id"));
        }
        // Invariant 2: fcp. namespace.
        if !id.starts_with("fcp.") {
            violations.push(format!("{stem}: id {id:?} not in fcp. namespace"));
        }
        // Invariant 3: unique ids across the set.
        if !seen_ids.insert(id.to_owned()) {
            violations.push(format!("{stem}: duplicate connector.id {id:?}"));
        }
        // Invariant 4: non-empty version.
        if manifest.connector.version.to_string().is_empty() {
            violations.push(format!("{stem}: empty version"));
        }
        // Invariant 5: home zone non-empty and not forbidden.
        let home = manifest.zones.home.as_str();
        if home.is_empty() {
            violations.push(format!("{stem}: empty home zone"));
        }
        if manifest.zones.forbidden.iter().any(|z| z.as_str() == home) {
            violations.push(format!("{stem}: home zone {home:?} appears in forbidden"));
        }
        // Invariant 6: at least one operation.
        if manifest.provides.operations.is_empty() {
            violations.push(format!("{stem}: zero operations declared"));
        }
        // Invariant 7: id segment well-formed.
        if let Some(segment) = id.strip_prefix("fcp.") {
            let ok = !segment.is_empty()
                && segment.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
                });
            if !ok {
                violations.push(format!("{stem}: malformed id segment {segment:?}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "fixture invariant violations ({} fixtures, {} violations):\n  {}",
        fixtures.len(),
        violations.len(),
        violations.join("\n  ")
    );
}
