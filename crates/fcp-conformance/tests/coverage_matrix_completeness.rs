use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;

use tracing::{debug, info, info_span};

const MATRIX_PATH: &str = "docs/formal/coverage-matrix.md";

#[derive(Clone, Debug)]
struct CoverageRow {
    readme_section: String,
    claim: String,
    lean_theorem: String,
    tla_spec: String,
    csp_spec: String,
    no_formal_model_reason: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LeanRef {
    path: String,
    theorem: String,
}

static TRACE_INIT: Once = Once::new();

fn install_test_subscriber() {
    TRACE_INIT.call_once(|| {
        match tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init()
        {
            Ok(()) | Err(_) => {}
        }
    });
}

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

fn markdown_cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(str::trim)
        .map(ToOwned::to_owned)
        .collect()
}

fn is_separator_row(cells: &[String]) -> bool {
    cells.iter().all(|cell| {
        !cell.is_empty()
            && cell
                .chars()
                .all(|character| matches!(character, '-' | ':' | ' '))
    })
}

fn is_null_cell(cell: &str) -> bool {
    matches!(cell.trim().trim_matches('`'), "" | "none" | "null" | "-")
}

fn readme_status_rows(readme: &str) -> BTreeSet<String> {
    let mut rows = BTreeSet::new();
    let mut in_feature_status_table = false;

    for line in readme.lines() {
        let cells = markdown_cells(line);
        if cells == ["Feature", "Status", "What It Does", "Evidence"] {
            in_feature_status_table = true;
            continue;
        }
        if !in_feature_status_table {
            continue;
        }
        if !line.trim_start().starts_with('|') {
            break;
        }
        if is_separator_row(&cells) {
            continue;
        }
        assert_eq!(
            cells.len(),
            4,
            "README feature-status row must have 4 columns: {line}"
        );
        if let Some(feature) = cells[0]
            .strip_prefix("**")
            .and_then(|feature| feature.strip_suffix("**"))
        {
            rows.insert(feature.to_owned());
        }
    }

    assert!(
        !rows.is_empty(),
        "README.md must contain a non-empty feature-status table"
    );
    rows
}

fn parse_coverage_matrix(matrix: &str) -> Vec<CoverageRow> {
    let mut rows = Vec::new();
    let mut in_table = false;

    for line in matrix.lines() {
        if !line.trim_start().starts_with('|') {
            continue;
        }

        let cells = markdown_cells(line);
        if cells.first().is_some_and(|cell| cell == "readme_section") {
            in_table = true;
            continue;
        }
        if !in_table || is_separator_row(&cells) {
            continue;
        }

        assert_eq!(
            cells.len(),
            6,
            "coverage-matrix row must have 6 columns: {line}"
        );
        rows.push(CoverageRow {
            readme_section: cells[0].clone(),
            claim: cells[1].clone(),
            lean_theorem: cells[2].clone(),
            tla_spec: cells[3].clone(),
            csp_spec: cells[4].clone(),
            no_formal_model_reason: cells[5].clone(),
        });
    }

    assert!(
        in_table,
        "{MATRIX_PATH} must contain a readme_section coverage table"
    );
    assert!(
        !rows.is_empty(),
        "{MATRIX_PATH} must contain at least one coverage row"
    );
    rows
}

fn load_inputs() -> (BTreeSet<String>, Vec<CoverageRow>) {
    let root = workspace_root();
    let readme = read_to_string(&root, "README.md");
    let matrix = read_to_string(&root, MATRIX_PATH);
    let readme_rows = readme_status_rows(&readme);
    let matrix_rows = parse_coverage_matrix(&matrix);
    log_coverage_summary(&readme_rows, &matrix_rows);
    (readme_rows, matrix_rows)
}

fn split_lean_refs(cell: &str) -> Vec<&str> {
    cell.split("<br>")
        .flat_map(|chunk| chunk.split(','))
        .map(str::trim)
        .filter(|reference| !reference.is_empty())
        .collect()
}

fn parse_lean_reference(raw: &str) -> LeanRef {
    let cleaned = raw.trim().trim_matches('`');
    let (path, theorem) = cleaned
        .split_once(':')
        .unwrap_or_else(|| panic!("Lean reference must be path:theorem_name: {cleaned}"));
    let has_lean_extension = Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lean"));
    assert!(
        path.starts_with("lean/") && has_lean_extension,
        "Lean reference path must point under lean/ and end in .lean: {cleaned}"
    );
    assert!(
        !theorem.is_empty(),
        "Lean reference theorem name must be non-empty: {cleaned}"
    );
    LeanRef {
        path: path.to_owned(),
        theorem: theorem.to_owned(),
    }
}

fn matrix_lean_refs(rows: &[CoverageRow]) -> BTreeSet<LeanRef> {
    let mut refs = BTreeSet::new();
    for row in rows {
        if is_null_cell(&row.lean_theorem) {
            continue;
        }
        for reference in split_lean_refs(&row.lean_theorem) {
            refs.insert(parse_lean_reference(reference));
        }
    }
    refs
}

fn theorem_names(source: &str) -> BTreeSet<String> {
    let mut in_block_comment = false;
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if in_block_comment {
                if trimmed.contains("-/") {
                    in_block_comment = false;
                }
                return None;
            }
            if trimmed.starts_with("/-") {
                if !trimmed.contains("-/") {
                    in_block_comment = true;
                }
                return None;
            }
            if trimmed.starts_with("--") {
                return None;
            }

            let rest = trimmed.strip_prefix("theorem ")?;
            let name = rest
                .split(|character: char| {
                    character.is_whitespace() || matches!(character, ':' | '(' | '{')
                })
                .next()
                .unwrap_or_default();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

fn collect_lean_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|err| {
        panic!(
            "expected Lean directory {} to be readable: {err}",
            dir.display()
        )
    });
    for entry in entries {
        let entry = entry.expect("Lean directory entry must be readable");
        let path = entry.path();
        if path.is_dir() {
            collect_lean_files(&path, files);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("lean") {
            files.push(path);
        }
    }
}

fn relative_lean_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or_else(|err| panic!("Lean path must sit under workspace root: {err}"))
        .to_string_lossy()
        .replace('\\', "/")
}

fn all_lean_theorems(root: &Path) -> BTreeSet<LeanRef> {
    let mut files = Vec::new();
    collect_lean_files(&root.join("lean"), &mut files);
    files.sort();

    let mut refs = BTreeSet::new();
    for path in files {
        let relative = relative_lean_path(root, &path);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("expected {} to be readable: {err}", path.display()));
        for theorem in theorem_names(&source) {
            refs.insert(LeanRef {
                path: relative.clone(),
                theorem,
            });
        }
    }
    refs
}

fn display_ref(reference: &LeanRef) -> String {
    format!("{}:{}", reference.path, reference.theorem)
}

fn log_coverage_summary(readme_rows: &BTreeSet<String>, matrix_rows: &[CoverageRow]) {
    install_test_subscriber();
    let _span = info_span!("fcp.conformance.coverage_matrix").entered();
    let lean_referenced = matrix_rows
        .iter()
        .filter(|row| !is_null_cell(&row.lean_theorem))
        .count();
    let tla_referenced = matrix_rows
        .iter()
        .filter(|row| !is_null_cell(&row.tla_spec))
        .count();
    let csp_referenced = matrix_rows
        .iter()
        .filter(|row| !is_null_cell(&row.csp_spec))
        .count();
    let no_model_explained = matrix_rows
        .iter()
        .filter(|row| !is_null_cell(&row.no_formal_model_reason))
        .count();

    info!(
        readme_rows = readme_rows.len(),
        covered_rows = matrix_rows.len(),
        lean_referenced,
        tla_referenced,
        csp_referenced,
        no_model_explained,
        "formal coverage matrix checked"
    );
    for row in matrix_rows {
        debug!(
            readme_section = %row.readme_section,
            claim = %row.claim,
            has_lean = !is_null_cell(&row.lean_theorem),
            has_tla = !is_null_cell(&row.tla_spec),
            has_csp = !is_null_cell(&row.csp_spec),
            has_no_model_reason = !is_null_cell(&row.no_formal_model_reason),
            "resolved formal coverage row"
        );
    }
}

#[test]
fn test_every_readme_status_row_covered() {
    let (readme_rows, matrix_rows) = load_inputs();
    let covered_rows = matrix_rows
        .iter()
        .map(|row| row.readme_section.clone())
        .collect::<BTreeSet<_>>();

    let uncovered = readme_rows
        .difference(&covered_rows)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        uncovered.is_empty(),
        "coverage matrix missing README rows: {}",
        uncovered
            .iter()
            .map(|row| format!("uncovered_row={row}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let extra = covered_rows
        .difference(&readme_rows)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        extra.is_empty(),
        "coverage matrix contains rows absent from README: {}",
        extra.join(", ")
    );
}

#[test]
fn test_each_row_has_one_of_lean_tla_csp_or_explicit_no_model() {
    let (_readme_rows, matrix_rows) = load_inputs();

    for row in &matrix_rows {
        let columns = [
            ("lean_theorem", row.lean_theorem.as_str()),
            ("tla_spec", row.tla_spec.as_str()),
            ("csp_spec", row.csp_spec.as_str()),
            (
                "no_formal_model_reason",
                row.no_formal_model_reason.as_str(),
            ),
        ];
        let present = columns
            .iter()
            .filter_map(|(name, cell)| (!is_null_cell(cell)).then_some(*name))
            .collect::<Vec<_>>();
        assert_eq!(
            present.len(),
            1,
            "row '{}' must have exactly one populated evidence column, got {:?}",
            row.readme_section,
            present
        );
    }
}

#[test]
fn test_referenced_lean_theorems_exist() {
    let root = workspace_root();
    let (_readme_rows, matrix_rows) = load_inputs();

    for reference in matrix_lean_refs(&matrix_rows) {
        let source_path = root.join(&reference.path);
        assert!(
            source_path.exists(),
            "referenced Lean file does not exist: {}",
            reference.path
        );
        let source = fs::read_to_string(&source_path)
            .unwrap_or_else(|err| panic!("expected {} to be readable: {err}", reference.path));
        let names = theorem_names(&source);
        assert!(
            names.contains(&reference.theorem),
            "referenced Lean theorem not found: {}",
            display_ref(&reference)
        );
    }
}

#[test]
fn test_no_orphan_lean_theorems() {
    let root = workspace_root();
    let (_readme_rows, matrix_rows) = load_inputs();
    let referenced = matrix_lean_refs(&matrix_rows);
    let discovered = all_lean_theorems(&root);
    let orphaned = discovered
        .difference(&referenced)
        .map(display_ref)
        .collect::<Vec<_>>();

    assert!(
        orphaned.is_empty(),
        "Lean theorem statements missing from coverage matrix: {}",
        orphaned.join(", ")
    );
}
