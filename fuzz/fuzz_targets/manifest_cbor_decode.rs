#![no_main]

use std::fs;
use std::path::{Component, Path, PathBuf};

use fcp_cbor::to_canonical_cbor;
use fcp_manifest::ConnectorManifest;
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Deserialize)]
struct ManifestSeed {
    manifest_vector: Option<String>,
    validate: Option<bool>,
}

fn manifests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/manifest")
}

fn safe_vector_path(root: &Path, name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    if path.components().count() != 1 {
        return None;
    }
    match path.components().next()? {
        Component::Normal(_) => Some(root.join(path)),
        _ => None,
    }
}

fn load_vector(root: &Path, name: &str) -> Option<String> {
    let path = safe_vector_path(root, name)?;
    fs::read_to_string(path).ok()
}

fn with_computed_hash(raw: &str) -> Option<String> {
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).ok()?;
    let computed = unchecked.compute_interface_hash().ok()?;
    Some(raw.replace(PLACEHOLDER_HASH, &computed.to_string()))
}

fn exercise_manifest(manifest: &ConnectorManifest, expect_valid: Option<bool>) {
    let hash = manifest.compute_interface_hash().ok();
    let validation = manifest.validate();
    if expect_valid == Some(true) {
        assert!(validation.is_ok());
    }

    if let Ok(canonical) = to_canonical_cbor(manifest)
        && let Ok(decoded) = ciborium::from_reader::<ConnectorManifest, _>(&canonical[..])
    {
        let recanonical = to_canonical_cbor(&decoded).unwrap_or_default();
        assert_eq!(canonical, recanonical);

        if let (Some(expected_hash), Ok(decoded_hash)) = (hash, decoded.compute_interface_hash()) {
            assert_eq!(expected_hash, decoded_hash);
        }

        if validation.is_ok() {
            assert!(decoded.validate().is_ok());
        } else {
            let _ = decoded.validate();
        }
    }
}

fn exercise_manifest_toml(raw: &str, expect_valid: Option<bool>) {
    let normalized = with_computed_hash(raw).unwrap_or_else(|| raw.to_string());
    if let Ok(unchecked) = ConnectorManifest::parse_str_unchecked(&normalized) {
        exercise_manifest(&unchecked, expect_valid);
    }
    let _ = ConnectorManifest::parse_str(&normalized);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(seed) = serde_json::from_slice::<ManifestSeed>(data) {
        if let Some(name) = seed.manifest_vector.as_deref()
            && let Some(raw) = load_vector(&manifests_dir(), name)
        {
            exercise_manifest_toml(&raw, seed.validate);
        }
        return;
    }

    if let Ok(raw) = std::str::from_utf8(data) {
        exercise_manifest_toml(raw, None);
    }

    if let Ok(manifest) = ciborium::from_reader::<ConnectorManifest, _>(data) {
        exercise_manifest(&manifest, None);
    }
});
