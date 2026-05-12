use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

const MATRIX_PATH: &str = "docs/formal/coverage-matrix.md";

#[derive(Debug)]
struct MatrixRow {
    claim: String,
    lean_theorem: String,
    tla_spec: String,
    csp_spec: String,
    no_formal_model_reason: String,
}

#[test]
fn test_every_readme_status_row_covered() {
    let readme_rows = readme_status_claims();
    let matrix_rows = matrix_rows();
    let matrix_claims = matrix_rows
        .iter()
        .map(|row| row.claim.as_str())
        .collect::<BTreeSet<_>>();

    for claim in &readme_rows {
        assert!(
            matrix_claims.contains(claim.as_str()),
            "uncovered_row={claim}"
        );
    }

    for claim in matrix_claims {
        assert!(
            readme_rows.contains(claim),
            "matrix contains claim not present in README status table: {claim}"
        );
    }
}

#[test]
fn test_each_row_has_one_of_lean_tla_csp_or_explicit_no_model() {
    for row in matrix_rows() {
        let occupied = [
            !is_empty_cell(&row.lean_theorem),
            !is_empty_cell(&row.tla_spec),
            !is_empty_cell(&row.csp_spec),
            !is_empty_cell(&row.no_formal_model_reason),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();

        assert_eq!(
            occupied, 1,
            "claim `{}` must have exactly one formal coverage discriminator",
            row.claim
        );
    }
}

#[test]
fn test_referenced_lean_theorems_exist() {
    for row in matrix_rows() {
        if is_empty_cell(&row.lean_theorem) {
            continue;
        }

        let (theorem, path) = parse_lean_reference(&row.lean_theorem)
            .unwrap_or_else(|| panic!("bad lean_theorem cell for `{}`", row.claim));
        let source_path = repo_root().join(path);
        let source = fs::read_to_string(&source_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", source_path.display()));
        let theorem_name = theorem
            .rsplit('.')
            .next()
            .expect("theorem reference has final segment");

        assert!(
            source.contains(&format!("theorem {theorem_name}")),
            "{} does not contain theorem {theorem_name}",
            source_path.display()
        );
    }
}

#[test]
fn test_no_orphan_lean_theorems() {
    let matrix = coverage_matrix();
    for (path, theorem) in lean_theorems() {
        assert!(
            matrix.contains(&theorem),
            "orphan_lean_theorem={theorem} source={}",
            path.display()
        );
    }
}

fn readme_status_claims() -> BTreeSet<String> {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("read README.md");
    let mut in_status_table = false;
    let mut claims = BTreeSet::new();

    for line in readme.lines() {
        if line.trim() == "| Feature | Status | What It Does | Evidence |" {
            in_status_table = true;
            continue;
        }

        if !in_status_table {
            continue;
        }

        if line.trim().is_empty() {
            break;
        }

        if !line.starts_with("| **") {
            continue;
        }

        let cells = markdown_cells(line);
        if cells.len() >= 4 {
            claims.insert(strip_bold(&cells[0]));
        }
    }

    assert!(!claims.is_empty(), "README status table yielded no claims");
    claims
}

fn matrix_rows() -> Vec<MatrixRow> {
    coverage_matrix()
        .lines()
        .filter_map(|line| {
            if !line.starts_with("| README status table |") {
                return None;
            }
            let cells = markdown_cells(line);
            assert_eq!(cells.len(), 6, "bad matrix row: {line}");
            Some(MatrixRow {
                claim: cells[1].to_owned(),
                lean_theorem: cells[2].to_owned(),
                tla_spec: cells[3].to_owned(),
                csp_spec: cells[4].to_owned(),
                no_formal_model_reason: cells[5].to_owned(),
            })
        })
        .collect()
}

fn coverage_matrix() -> String {
    fs::read_to_string(repo_root().join(MATRIX_PATH)).expect("read formal coverage matrix")
}

fn markdown_cells(line: &str) -> Vec<String> {
    line.trim_matches('|')
        .split('|')
        .map(str::trim)
        .map(ToOwned::to_owned)
        .collect()
}

fn strip_bold(cell: &str) -> String {
    cell.trim()
        .trim_start_matches("**")
        .trim_end_matches("**")
        .to_owned()
}

fn is_empty_cell(cell: &str) -> bool {
    let trimmed = cell.trim();
    trimmed.is_empty() || trimmed == "-"
}

fn parse_lean_reference(cell: &str) -> Option<(String, String)> {
    let cleaned = cell.trim().trim_matches('`');
    let (theorem, path) = cleaned.split_once(" @ ")?;
    Some((theorem.to_owned(), path.to_owned()))
}

fn lean_theorems() -> Vec<(PathBuf, String)> {
    let mut pending = vec![repo_root().join("lean")];
    let mut theorems = Vec::new();

    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
            {
                pending.push(entry.expect("read lean directory entry").path());
            }
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("lean") {
            continue;
        }

        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for line in source.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("theorem ") {
                let name = rest
                    .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '\''))
                    .next()
                    .expect("theorem name token")
                    .to_owned();
                theorems.push((path.clone(), name));
            }
        }
    }

    theorems.sort();
    theorems
}

fn repo_root() -> PathBuf {
    Path::new(&env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root ancestor")
        .to_path_buf()
}
