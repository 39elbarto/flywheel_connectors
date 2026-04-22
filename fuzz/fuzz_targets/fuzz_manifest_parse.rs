#![no_main]

use std::fs;
use std::path::{Component, Path, PathBuf};

use ciborium::value::Value;
use fcp_cbor::to_canonical_cbor;
use fcp_manifest::ConnectorManifest;
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";
const DEFAULT_MANIFEST_VECTOR: &str = "manifest_valid.toml";

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestParseCase {
    TruncatedCbor,
    ReorderedFields,
    DuplicateKeys,
    DeeplyNestedCapabilityTrees,
    MaliciousSignatureBlobs,
    Utf8EdgeConnectorNames,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ManifestParseSeed {
    manifest_vector: Option<String>,
    raw_manifest: Option<String>,
    validate: Option<bool>,
    case: Option<ManifestParseCase>,
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

fn base_manifest_toml(seed: &ManifestParseSeed) -> Option<String> {
    if let Some(raw) = &seed.raw_manifest {
        return Some(raw.clone());
    }
    let name = seed
        .manifest_vector
        .as_deref()
        .unwrap_or(DEFAULT_MANIFEST_VECTOR);
    load_vector(&manifests_dir(), name)
}

fn normalize_manifest(raw: &str) -> String {
    with_computed_hash(raw).unwrap_or_else(|| raw.to_string())
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
    let normalized = normalize_manifest(raw);
    if let Ok(unchecked) = ConnectorManifest::parse_str_unchecked(&normalized) {
        exercise_manifest(&unchecked, expect_valid);
    }
    let _ = ConnectorManifest::parse_str(&normalized);
}

fn exercise_manifest_cbor(bytes: &[u8], expect_valid: Option<bool>) {
    if let Ok(manifest) = ciborium::from_reader::<ConnectorManifest, _>(bytes) {
        exercise_manifest(&manifest, expect_valid);
    }
}

fn reordered_fields_manifest(raw: &str) -> String {
    let blocks = raw.split("\n\n").collect::<Vec<_>>();
    let find = |prefix: &str| -> &str {
        blocks
            .iter()
            .copied()
            .find(|block| block.starts_with(prefix))
            .unwrap_or("")
    };
    [
        find("[sandbox]"),
        find("[policy]"),
        find("[provides.operations.send_message.ai_hints]"),
        find("[manifest]"),
        find("[supply_chain]"),
        find("[connector.state]"),
        find("[capabilities]"),
        find("[signatures]"),
        find("[zones]"),
        find("[event_caps]"),
        find("[connector]"),
        find("[provides.operations.send_message]"),
    ]
    .into_iter()
    .filter(|block| !block.is_empty())
    .collect::<Vec<_>>()
    .join("\n\n")
}

fn deeply_nested_capability_manifest(raw: &str) -> String {
    let deep_capability =
        "cap.tree.branch.alpha.beta.gamma.delta.epsilon.zeta.eta.theta.iota.kappa.lambda.mu";
    raw.replace(
        r#"optional = ["media.download"]"#,
        &format!(r#"optional = ["{deep_capability}"]"#),
    )
    .replace(
        r#"capability = "telegram.send_message""#,
        &format!(r#"capability = "{deep_capability}""#),
    )
}

fn malicious_signature_manifest(raw: &str) -> String {
    let oversized_sig = format!("base64:{}!!!!", "A".repeat(8192));
    raw.replace(
        r#"sig = "base64:Zm9v""#,
        &format!(r#"sig = "{oversized_sig}""#),
    )
}

fn utf8_edge_connector_name_manifest(raw: &str) -> String {
    raw.replace(
        r#"name = "Valid Connector""#,
        r#"name = "Valid Connector 👩🏽‍🚀 é Ω 零-width‍joiner""#,
    )
}

fn duplicate_keys_cbor_bytes() -> Option<Vec<u8>> {
    let duplicate_map = Value::Map(vec![
        (Value::Text("manifest".to_string()), Value::Null),
        (Value::Text("manifest".to_string()), Value::Map(vec![])),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&duplicate_map, &mut bytes).ok()?;
    Some(bytes)
}

fn truncated_cbor_bytes(raw: &str) -> Option<Vec<u8>> {
    let normalized = normalize_manifest(raw);
    let manifest = ConnectorManifest::parse_str_unchecked(&normalized).ok()?;
    let mut bytes = to_canonical_cbor(&manifest).ok()?;
    if bytes.len() > 1 {
        bytes.truncate(bytes.len() / 2);
    } else {
        bytes.clear();
    }
    Some(bytes)
}

fn run_seed(seed: ManifestParseSeed) {
    let Some(raw) = base_manifest_toml(&seed) else {
        return;
    };

    match seed.case {
        Some(ManifestParseCase::TruncatedCbor) => {
            if let Some(bytes) = truncated_cbor_bytes(&raw) {
                exercise_manifest_cbor(&bytes, seed.validate);
            }
        }
        Some(ManifestParseCase::ReorderedFields) => {
            exercise_manifest_toml(&reordered_fields_manifest(&raw), seed.validate);
        }
        Some(ManifestParseCase::DuplicateKeys) => {
            if let Some(bytes) = duplicate_keys_cbor_bytes() {
                exercise_manifest_cbor(&bytes, seed.validate);
            }
        }
        Some(ManifestParseCase::DeeplyNestedCapabilityTrees) => {
            exercise_manifest_toml(&deeply_nested_capability_manifest(&raw), seed.validate);
        }
        Some(ManifestParseCase::MaliciousSignatureBlobs) => {
            exercise_manifest_toml(&malicious_signature_manifest(&raw), seed.validate);
        }
        Some(ManifestParseCase::Utf8EdgeConnectorNames) => {
            exercise_manifest_toml(&utf8_edge_connector_name_manifest(&raw), seed.validate);
        }
        None => {
            exercise_manifest_toml(&raw, seed.validate);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(seed) = serde_json::from_slice::<ManifestParseSeed>(data) {
        run_seed(seed);
        return;
    }

    if let Ok(raw) = std::str::from_utf8(data) {
        exercise_manifest_toml(raw, None);
    }

    exercise_manifest_cbor(data, None);
});
