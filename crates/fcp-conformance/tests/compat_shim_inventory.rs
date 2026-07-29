//! Regression guard for the Phase I.1 compatibility-shim inventory.
//!
//! The bridge plan guessed that `fcp_core::compat::{policy,evidence}` were the
//! remaining shims. The current checkout has no such modules or callers. The
//! SDK scorecard shims have graduated to first-class SDK modules instead.

use std::fs;
use std::path::{Path, PathBuf};

const INVENTORY_DOC: &str = "docs/cleanup/shim_inventory.md";
const FCP_CORE_LIB_RS: &str = include_str!("../../fcp-core/src/lib.rs");
const FCP_SDK_ERROR_MAPPING_RS: &str = include_str!("../../fcp-sdk/src/error_mapping.rs");
const FCP_SDK_MIGRATION_RS: &str = include_str!("../../fcp-sdk/src/migration.rs");
const FCP_SDK_RUNTIME_RS: &str = include_str!("../../fcp-sdk/src/runtime.rs");
const SCORECARD_MD: &str = include_str!("../../../docs/FCP3_Transition_Scorecard.md");

const SUSPECTED_POLICY_PATH: &str = concat!("fcp_core::compat::", "policy");
const SUSPECTED_EVIDENCE_PATH: &str = concat!("fcp_core::compat::", "evidence");
const SUSPECTED_PATHS: &[&str] = &[SUSPECTED_POLICY_PATH, SUSPECTED_EVIDENCE_PATH];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn inventory_doc() -> String {
    fs::read_to_string(workspace_root().join(INVENTORY_DOC)).expect("read shim inventory")
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .map(|value| value.trim_end_matches("-->").trim())
}

fn summary_value(doc: &str, name: &str) -> usize {
    let summary_line = doc
        .lines()
        .find(|line| line.contains("compat-shim-inventory-summary:"))
        .expect("machine-readable shim inventory summary");
    field(summary_line, name)
        .unwrap_or_else(|| panic!("summary field `{name}` is present"))
        .parse()
        .unwrap_or_else(|err| panic!("summary field `{name}` parses as usize: {err}"))
}

fn row_value<'a>(doc: &'a str, row_id: &str, name: &str) -> &'a str {
    let row = doc
        .lines()
        .find(|line| line.contains("shim-row:") && line.contains(row_id))
        .unwrap_or_else(|| panic!("machine-readable row `{row_id}` is present"));
    field(row, name).unwrap_or_else(|| panic!("field `{name}` is present on `{row_id}`"))
}

fn has_core_compat_module() -> bool {
    FCP_CORE_LIB_RS.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "mod compat;"
            || trimmed == "pub mod compat;"
            || trimmed.starts_with("mod compat ")
            || trimmed.starts_with("pub mod compat ")
    })
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().and_then(|name| name.to_str());
        if matches!(file_name, Some("target" | ".git" | ".beads")) {
            continue;
        }

        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

fn rust_callers_of(paths: &[&str]) -> Vec<PathBuf> {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files);
    collect_rust_files(&root.join("connectors"), &mut files);

    files
        .into_iter()
        .filter(|path| {
            fs::read_to_string(path)
                .is_ok_and(|source| paths.iter().any(|needle| source.contains(needle)))
        })
        .map(|path| path.strip_prefix(&root).unwrap_or(&path).to_path_buf())
        .collect()
}

#[test]
fn suspected_core_compat_policy_and_evidence_shims_are_absent() {
    assert!(
        !has_core_compat_module(),
        "fcp-core must not grow a `compat` module without updating {INVENTORY_DOC}"
    );

    let callers = rust_callers_of(SUSPECTED_PATHS);
    assert!(
        callers.is_empty(),
        "no Rust source may call the absent fcp_core::compat policy/evidence \
         paths; callers: {callers:#?}"
    );

    let doc = inventory_doc();
    assert_eq!(summary_value(&doc, "suspected_core_compat_modules"), 0);
    assert_eq!(summary_value(&doc, "suspected_core_compat_callers"), 0);
    assert_eq!(
        row_value(&doc, "FCP-CORE-COMPAT-POLICY", "status"),
        "absent"
    );
    assert_eq!(
        row_value(&doc, "FCP-CORE-COMPAT-EVIDENCE", "status"),
        "absent"
    );
}

#[test]
fn scorecard_tracks_runtime_and_error_mapping_graduation() {
    assert!(
        !FCP_SDK_MIGRATION_RS.contains("pub struct ConnectorRuntime"),
        "ConnectorRuntime must not be defined in fcp-sdk/src/migration.rs after \
         flywheel_connectors-angoc.3.6"
    );
    assert!(
        FCP_SDK_RUNTIME_RS.contains("pub struct ConnectorRuntime"),
        "ConnectorRuntime must live in the first-class fcp-sdk runtime module"
    );
    assert!(
        !FCP_SDK_MIGRATION_RS.contains("pub trait ConnectorErrorMapping"),
        "ConnectorErrorMapping must not be defined in fcp-sdk/src/migration.rs \
         after flywheel_connectors-angoc.3.7"
    );
    assert!(
        FCP_SDK_ERROR_MAPPING_RS.contains("pub trait ConnectorErrorMapping"),
        "ConnectorErrorMapping must live in the first-class fcp-sdk error_mapping module"
    );
    assert!(
        SCORECARD_MD.contains("| ConnectorErrorMapping | fcp-sdk/src/error_mapping.rs |")
            && SCORECARD_MD.contains("| ConnectorRuntime | fcp-sdk/src/runtime.rs |"),
        "the FCP3 scorecard must identify the migrated SDK shim locations"
    );

    let doc = inventory_doc();
    assert_eq!(summary_value(&doc, "scorecard_active_shims"), 0);
    assert_eq!(summary_value(&doc, "scorecard_migrating_shims"), 0);
    assert!(
        doc.contains("scorecard-shim-row: id=FCP-SDK-CONNECTOR-RUNTIME")
            && doc.contains("scorecard-shim-row: id=FCP-SDK-CONNECTOR-ERROR-MAPPING"),
        "the inventory doc must carry machine-readable rows for the migrated SDK shims"
    );
    assert_eq!(
        row_value(&doc, "FCP-SDK-CONNECTOR-RUNTIME", "status"),
        "migrated"
    );
    assert_eq!(
        row_value(&doc, "FCP-SDK-CONNECTOR-ERROR-MAPPING", "status"),
        "migrated"
    );
    assert_eq!(
        row_value(&doc, "FCP-SDK-CONNECTOR-ERROR-MAPPING", "legacy_reexport"),
        "removed"
    );
}
