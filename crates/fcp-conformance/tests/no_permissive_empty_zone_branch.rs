use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fcp-conformance should live under crates/")
        .to_path_buf()
}

fn read_repo_file(path: &str) -> String {
    let full_path = repo_root().join(path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("failed to read '{}': {error}", full_path.display()))
}

fn host_binary_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os("FCP_HOST_BINARY") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(target_dir) = env::var_os("CARGO_TARGET_DIR") {
        candidates.push(
            PathBuf::from(target_dir)
                .join("debug")
                .join(format!("fcp-host{}", env::consts::EXE_SUFFIX)),
        );
    }
    candidates.push(
        repo_root()
            .join("target")
            .join("debug")
            .join(format!("fcp-host{}", env::consts::EXE_SUFFIX)),
    );
    candidates
}

fn stale_empty_zone_needles() -> Vec<&'static str> {
    vec![
        "empty + !enforce_empty -> back-compat permissive path",
        "allowed_zones` is opt-in",
        "empty set preserves a back-compat permissive branch",
    ]
}

#[test]
fn test_compiled_binary_lacks_permissive_symbol() {
    let binary = host_binary_candidates()
        .into_iter()
        .find(|candidate| candidate.exists());

    if let Some(binary) = binary {
        let bytes = fs::read(&binary).unwrap_or_else(|error| {
            panic!("failed to read host binary '{}': {error}", binary.display())
        });
        let haystack = String::from_utf8_lossy(&bytes);
        for needle in stale_empty_zone_needles() {
            assert!(
                !haystack.contains(needle),
                "compiled host binary still contains stale empty-zone permissive marker `{needle}`"
            );
        }
        return;
    }

    let source = read_repo_file("crates/fcp-host/src/bin/fcp-host.rs");
    assert!(
        source.contains("HostError::ZoneEnvelopeRequired"),
        "fallback source proof must show the zone-envelope error wired into fcp-host"
    );
}

#[test]
fn test_source_tree_lacks_pattern() {
    let files = [
        "README.md",
        "crates/fcp-host/src/admin_state.rs",
        "crates/fcp-host/src/bin/fcp-host.rs",
    ];
    for file in files {
        let source = read_repo_file(file);
        for needle in stale_empty_zone_needles() {
            assert!(
                !source.contains(needle),
                "{file} still contains stale empty-zone permissive marker `{needle}`"
            );
        }
    }

    let host_source = read_repo_file("crates/fcp-host/src/bin/fcp-host.rs");
    assert!(
        host_source.contains("require_allowed_zones_configured(&request.connector_id"),
        "fcp-host must explicitly require allowed_zones before invoke verification continues"
    );
}
