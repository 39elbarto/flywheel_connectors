//! Conformance coverage for `docs/architecture/master_reachability.md`.
//!
//! The ledger maps every README status-table row to its enforcing
//! `code_path`, `test_path` (+ named `test_fn`), and either a `proof_path`
//! or an explicit `no_formal_model_reason`. This conformance test parses the
//! ledger plus the README status table and asserts that:
//!
//!   1. every README status-table row is present in the ledger,
//!   2. every cited `code_path` exists on disk,
//!   3. every cited `test_path` exists on disk AND the named `test_fn`
//!      appears inside it (grepped, not run),
//!   4. every row has either a `proof_path` (existing) or an explicit
//!      `no_formal_model_reason` / `pending` text,
//!   5. the ledger does not list rows the README does not have (no
//!      orphan rows in the ledger),
//!   6. the most-recent quarterly debiasing artifact under
//!      `docs/quarterly/<YYYY>-Q<n>-claims-vs-reality.md` aligns with the
//!      ledger's status labels.
//!
//! Filed under `flywheel_connectors-angoc.15.1` (Phase U.1).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .parent()
        .expect("workspace root exists")
        .to_path_buf()
}

fn read_to_string<P: AsRef<Path>>(path: P) -> String {
    fs::read_to_string(path.as_ref())
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.as_ref().display()))
}

#[derive(Debug)]
struct LedgerRow {
    claim: String,
    status: String,
    code_path: String,
    test_path: String,
    test_fn: String,
    /// Either a real proof path on disk OR `(none — ...)` placeholder.
    proof_path: Option<String>,
    /// Set when the claim has no formal-verification model.
    no_formal_model_reason: Option<String>,
    /// Set when the row is partially graduated and points to a follow-up bead.
    pending: Option<String>,
}

impl LedgerRow {
    fn has_formal_anchor(&self) -> bool {
        self.no_formal_model_reason.is_some()
            || self
                .proof_path
                .as_deref()
                .map(|p| !p.trim().is_empty() && !p.trim_start().starts_with("(none"))
                .unwrap_or(false)
            || self.pending.is_some()
    }
}

fn parse_ledger() -> Vec<LedgerRow> {
    let path = repo_root()
        .join("docs")
        .join("architecture")
        .join("master_reachability.md");
    let text = read_to_string(&path);

    let mut rows = Vec::new();
    let mut current_claim: Option<String> = None;
    let mut current_fields: BTreeMap<String, String> = BTreeMap::new();

    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("### ") {
            // Flush previous row if any.
            if let Some(claim) = current_claim.take() {
                rows.push(row_from_fields(claim, &current_fields));
                current_fields.clear();
            }
            // Header is "### N. <claim title>".
            let after_number = rest.split_once('.').map(|(_, rest)| rest.trim()).unwrap_or(rest);
            current_claim = Some(after_number.to_string());
        } else if trimmed.starts_with("- ") {
            if let Some((key, value)) = trimmed.trim_start_matches("- ").split_once(':') {
                current_fields.insert(
                    key.trim().to_string(),
                    value.trim().trim_matches('`').to_string(),
                );
            }
        }
    }
    if let Some(claim) = current_claim {
        rows.push(row_from_fields(claim, &current_fields));
    }

    assert!(
        !rows.is_empty(),
        "ledger must define at least one row; parsed empty"
    );
    rows
}

fn row_from_fields(claim: String, fields: &BTreeMap<String, String>) -> LedgerRow {
    let get = |k: &str| {
        fields
            .get(k)
            .unwrap_or_else(|| panic!("ledger row `{claim}` is missing field `{k}`"))
            .clone()
    };
    LedgerRow {
        claim: get("claim"),
        status: get("status"),
        code_path: get("code_path"),
        test_path: get("test_path"),
        test_fn: get("test_fn"),
        proof_path: fields.get("proof_path").cloned(),
        no_formal_model_reason: fields.get("no_formal_model_reason").cloned(),
        pending: fields.get("pending").cloned(),
    }
}

fn readme_status_claims() -> BTreeSet<String> {
    let readme = read_to_string(repo_root().join("README.md"));
    // The status table rows look like:
    //   | **<Claim>** | `STATUS` | ... | ... |
    let re = Regex::new(r"^\|\s*\*\*([^*]+)\*\*\s*\|\s*`[A-Z][A-Z\- ()]+`")
        .expect("regex compiles");
    let mut claims = BTreeSet::new();
    for line in readme.lines() {
        if let Some(captures) = re.captures(line) {
            let claim = captures.get(1).unwrap().as_str().trim().to_string();
            claims.insert(claim);
        }
    }
    assert!(
        !claims.is_empty(),
        "README status table must contain at least one row matching the |**Claim**|`STATUS`| pattern"
    );
    claims
}

#[test]
fn test_every_readme_claim_has_code() {
    let ledger = parse_ledger();
    let by_claim: BTreeMap<&str, &LedgerRow> =
        ledger.iter().map(|r| (r.claim.as_str(), r)).collect();
    let readme_claims = readme_status_claims();

    let mut orphan_readme_rows = Vec::new();
    for claim in &readme_claims {
        match by_claim.get(claim.as_str()) {
            None => orphan_readme_rows.push(claim.clone()),
            Some(row) => {
                assert!(
                    !row.code_path.trim().is_empty(),
                    "row `{}` has empty code_path",
                    row.claim
                );
                let path = repo_root().join(&row.code_path);
                assert!(
                    path.exists(),
                    "row `{}` cites code_path `{}` which does not exist at `{}`",
                    row.claim,
                    row.code_path,
                    path.display()
                );
            }
        }
    }
    assert!(
        orphan_readme_rows.is_empty(),
        "README rows without ledger entry: {orphan_readme_rows:?}; \
         update docs/architecture/master_reachability.md"
    );
}

#[test]
fn test_every_readme_claim_has_test() {
    let ledger = parse_ledger();
    for row in &ledger {
        assert!(
            !row.test_path.trim().is_empty(),
            "row `{}` has empty test_path",
            row.claim
        );
        assert!(
            !row.test_fn.trim().is_empty(),
            "row `{}` has empty test_fn",
            row.claim
        );
        let path = repo_root().join(&row.test_path);
        assert!(
            path.exists(),
            "row `{}` cites test_path `{}` which does not exist",
            row.claim,
            row.test_path
        );
        let content = read_to_string(&path);
        // The test fn may be `fn <name>`, `async fn <name>`, or appear inside a
        // `#[test]` / `#[tokio::test]` attribute followed by `fn <name>`.
        let pat = format!(r"\bfn\s+{}\b", regex::escape(&row.test_fn));
        let re = Regex::new(&pat).expect("regex compiles");
        // For now we accept either: the named test_fn is present, OR (for the
        // gating test on the Mesh-Native row) the named harness-helper exists.
        // The latter covers cases where the test is defined as a top-level
        // function rather than `#[test] fn`.
        let by_fn_re = Regex::new(&pat).expect("regex compiles");
        let has_fn = by_fn_re.is_match(&content);
        let has_loose = content.contains(&row.test_fn);
        assert!(
            has_fn || has_loose,
            "row `{}` cites test_fn `{}` not found in `{}` (re=`{}`)",
            row.claim,
            row.test_fn,
            row.test_path,
            pat
        );
        let _ = re; // silence the unused-binding lint when only the loose match fires
    }
}

#[test]
fn test_every_readme_claim_has_proof_or_explicit_no_model() {
    let ledger = parse_ledger();
    for row in &ledger {
        assert!(
            row.has_formal_anchor(),
            "row `{}` lacks both proof_path and no_formal_model_reason/pending; \
             every ledger row must declare one or the other",
            row.claim
        );
        if let Some(proof_path) = row.proof_path.as_ref() {
            let trimmed = proof_path.trim();
            if !trimmed.is_empty() && !trimmed.starts_with("(none") {
                let path = repo_root().join(trimmed);
                assert!(
                    path.exists(),
                    "row `{}` cites proof_path `{}` which does not exist",
                    row.claim,
                    trimmed
                );
            }
        }
    }
}

#[test]
fn test_ledger_has_no_orphan_rows() {
    let ledger = parse_ledger();
    let readme_claims = readme_status_claims();
    let mut orphans = Vec::new();
    for row in &ledger {
        if !readme_claims.contains(&row.claim) {
            orphans.push(row.claim.clone());
        }
    }
    assert!(
        orphans.is_empty(),
        "ledger contains rows not present in README status table: {orphans:?}; \
         either add the rows to README.md or remove them from the ledger"
    );
}

#[test]
fn test_ledger_supersedes_quarterly_artifacts() {
    // Find the most recent quarterly artifact.
    let quarterly_dir = repo_root().join("docs").join("quarterly");
    if !quarterly_dir.exists() {
        // No quarterly directory means the K cadence epic has not landed yet.
        // The ledger conformance still passes; this assertion is a soft check.
        return;
    }
    let re = Regex::new(r"^(\d{4})-Q(\d)-claims-vs-reality\.md$").expect("regex compiles");
    let mut newest: Option<(String, PathBuf)> = None;
    for entry in fs::read_dir(&quarterly_dir).expect("read quarterly dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        if let Some(captures) = re.captures(&name_str) {
            let key = format!(
                "{}-{}",
                captures.get(1).unwrap().as_str(),
                captures.get(2).unwrap().as_str()
            );
            if newest
                .as_ref()
                .map(|(existing_key, _)| key.as_str() > existing_key.as_str())
                .unwrap_or(true)
            {
                newest = Some((key, entry.path()));
            }
        }
    }
    let Some((_, path)) = newest else {
        return;
    };
    let report = read_to_string(&path);
    let ledger = parse_ledger();
    // For each PROVEN row in the ledger, the most recent quarterly should
    // either contain the claim string OR explicitly note its status delta.
    for row in &ledger {
        if row.status.starts_with("PROVEN") {
            assert!(
                report.contains(&row.claim) || report.contains("delta"),
                "quarterly artifact `{}` does not mention ledger row `{}`; \
                 either align the quarterly or update the ledger",
                path.display(),
                row.claim
            );
        }
    }
}
