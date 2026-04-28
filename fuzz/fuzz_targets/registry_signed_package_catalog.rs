#![no_main]
//! Structure-aware fuzz target for the signed-package catalog parser.
//!
//! This exercises `LocalRegistryCatalog::from_signed_package_dirs`, including
//! `manifest-signature.json`, `binary_name` path validation, binary hash checks,
//! detached signature parsing, and the valid generated-package path.

use arbitrary::{Arbitrary, Unstructured};
use base64::Engine;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_manifest::ConnectorManifest;
use fcp_registry::{
    ConnectorTarget, LocalRegistryCatalog, MANIFEST_SIGNATURE_CONTEXT, ManifestSignatureArtifact,
    REGISTRY_MANIFEST_FILENAME, REGISTRY_MANIFEST_SIGNATURE_FILENAME, manifest_signing_bytes,
    signature_message,
};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_TEXT_BYTES: usize = 64;
const MAX_BINARY_BYTES: usize = 4096;
const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Arbitrary, Debug)]
struct Input {
    connector_id: Vec<u8>,
    version_major: u8,
    version_minor: u8,
    version_patch: u8,
    binary: Vec<u8>,
    mode: u8,
    os: Vec<u8>,
    arch: Vec<u8>,
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn safe_text(bytes: &[u8], fallback: &str) -> String {
    let value: String = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_TEXT_BYTES)])
        .chars()
        .filter(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-'))
        .collect();
    if value.is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

fn safe_connector_id(bytes: &[u8]) -> String {
    let value = safe_text(bytes, "registry-fuzz");
    if value.starts_with("fcp.") {
        value
    } else {
        format!("fcp.{value}")
    }
}

fn manifest_template(connector_id: &str, version: &str) -> String {
    let raw = include_str!("../../tests/vectors/manifest/manifest_minimal.toml");
    let patched = raw
        .replace(
            r#"id = "fcp.minimal""#,
            &format!(r#"id = "{connector_id}""#),
        )
        .replace(r#"version = "0.1.0""#, &format!(r#"version = "{version}""#));
    let unchecked = ConnectorManifest::parse_str_unchecked(&patched).expect("template parses");
    let interface_hash = unchecked.compute_interface_hash().expect("interface hash");
    patched.replace(PLACEHOLDER_HASH, &interface_hash.to_string())
}

fn sign_manifest_toml(
    manifest_toml: &str,
    signing_key: &Ed25519SigningKey,
    binary_hash: &str,
) -> String {
    let manifest = ConnectorManifest::parse_str(manifest_toml).expect("manifest parses");
    let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
    let message = signature_message(&signing_bytes, binary_hash);
    let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
    format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    )
}

fn publisher_signature_section(signature: &str) -> String {
    format!(
        r#"[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{signature}"
"#,
    )
}

fn write_package(root: &Path, input: &Input) {
    let connector_id = safe_connector_id(&input.connector_id);
    let version = format!(
        "{}.{}.{}",
        input.version_major % 8,
        input.version_minor % 16,
        input.version_patch % 32
    );
    let target = ConnectorTarget {
        os: safe_text(&input.os, "linux"),
        arch: safe_text(&input.arch, "amd64"),
    };
    let binary = if input.binary.is_empty() {
        b"registry-catalog-fuzz-binary".to_vec()
    } else {
        input.binary[..input.binary.len().min(MAX_BINARY_BYTES)].to_vec()
    };
    let signing_key = Ed25519SigningKey::generate();
    let binary_hash = hash_bytes(&binary);
    let unsigned = manifest_template(&connector_id, &version);
    let signature = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
    let manifest_toml = format!("{unsigned}\n{}", publisher_signature_section(&signature));
    let signing_bytes = manifest_signing_bytes(
        &ConnectorManifest::parse_str(&unsigned).expect("unsigned manifest parses"),
    )
    .expect("signing bytes");

    let mode = input.mode % 7;
    let binary_name = match mode {
        1 => "../escaped-binary",
        2 => "/absolute-binary",
        _ => "connector-bin",
    };
    let mut artifact = ManifestSignatureArtifact {
        key_id: "pub1".to_string(),
        verifying_key: hex::encode(signing_key.verifying_key().to_bytes()),
        context: String::from_utf8_lossy(MANIFEST_SIGNATURE_CONTEXT).into_owned(),
        manifest_signing_hash: hash_bytes(&signing_bytes),
        binary_hash: binary_hash.clone(),
        signature,
        target,
        binary_name: binary_name.to_string(),
    };

    match mode {
        3 => artifact.binary_hash = hash_bytes(b"different-binary"),
        4 => artifact.context = "wrong.context".to_string(),
        5 => artifact.verifying_key = "not-hex".to_string(),
        6 => artifact.signature = "base64:AAAA".to_string(),
        _ => {}
    }

    std::fs::write(
        root.join(REGISTRY_MANIFEST_FILENAME),
        format!("{manifest_toml}\n"),
    )
    .expect("write manifest");
    if mode != 2 {
        std::fs::write(root.join("connector-bin"), &binary).expect("write binary");
    }
    std::fs::write(
        root.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&artifact).expect("signature JSON")
        ),
    )
    .expect("write signature artifact");
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };
    let Ok(temp) = tempfile::tempdir() else {
        return;
    };
    let package_dir = temp.path().join("package");
    if std::fs::create_dir(&package_dir).is_err() {
        return;
    }

    write_package(&package_dir, &input);
    let result = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir]);
    if input.mode % 7 == 0 {
        let catalog = result.expect("generated valid package should load");
        let response = catalog.connectors_response();
        assert_eq!(response.connectors.len(), 1);
        assert_eq!(
            response.connectors[0].connector_id,
            safe_connector_id(&input.connector_id)
        );
    }
});
