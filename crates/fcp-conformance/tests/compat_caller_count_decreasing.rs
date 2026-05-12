use std::fs;
use std::path::{Path, PathBuf};

const BASELINE_PREFIX: &str = "forbidden_compat_caller_baseline:";
const FORBIDDEN_CALLER_PATHS: &[&str] = &[
    concat!("fcp_core::", "compat::", "policy"),
    concat!("fcp_core::", "compat::", "evidence"),
    concat!("compat::", "policy"),
    concat!("compat::", "evidence"),
];
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".beads",
    ".rch",
    "target",
    "node_modules",
    "__pycache__",
];

#[test]
fn test_no_new_compat_callers() {
    let root = repo_root();
    let baseline = read_forbidden_caller_baseline(&root);
    let matches = forbidden_compat_matches(&root.join("crates"));

    assert!(
        matches.len() <= baseline,
        "forbidden fcp-core compat callers increased above baseline {baseline}:\n{}",
        matches.join("\n")
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("derive workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

fn read_forbidden_caller_baseline(root: &Path) -> usize {
    let inventory_path = root.join("docs/cleanup/shim_inventory.md");
    let inventory =
        fs::read_to_string(&inventory_path).expect("read docs/cleanup/shim_inventory.md");

    inventory
        .lines()
        .find_map(|line| {
            line.strip_prefix(BASELINE_PREFIX)
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .expect("inventory contains forbidden_compat_caller_baseline")
}

fn forbidden_compat_matches(root: &Path) -> Vec<String> {
    let mut matches = Vec::new();
    collect_forbidden_compat_matches(root, &mut matches);
    matches.sort();
    matches
}

fn collect_forbidden_compat_matches(path: &Path, matches: &mut Vec<String>) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };

    if metadata.is_dir() {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        if SKIP_DIRS.contains(&name) {
            return;
        }

        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            collect_forbidden_compat_matches(&entry.path(), matches);
        }
        return;
    }

    if !path.extension().is_some_and(|extension| extension == "rs") {
        return;
    }

    let Ok(source) = fs::read_to_string(path) else {
        return;
    };

    for (line_index, line) in source.lines().enumerate() {
        for forbidden in FORBIDDEN_CALLER_PATHS {
            if line.contains(forbidden) {
                matches.push(format!(
                    "{}:{} contains forbidden caller path `{forbidden}`",
                    path.display(),
                    line_index + 1
                ));
            }
        }
    }
}
