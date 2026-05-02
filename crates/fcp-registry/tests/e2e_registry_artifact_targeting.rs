use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_manifest::{Base64Bytes, ConnectorManifest};
use fcp_registry::{
    ConnectorTarget, LocalRegistryCatalog, ManifestSignatureArtifact,
    REGISTRY_ATTESTATION_FILENAME, REGISTRY_MANIFEST_FILENAME,
    REGISTRY_MANIFEST_SIGNATURE_FILENAME, RegistryVersionDescriptor,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tower::util::ServiceExt;
use tracing::{Level, span};

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn manifest_toml(connector_id: &str, version: &str) -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml")
        .replace(
            r#"id = "fcp.minimal""#,
            &format!(r#"id = "{connector_id}""#),
        )
        .replace(r#"version = "0.1.0""#, &format!(r#"version = "{version}""#));
    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked manifest");
    let hash = unchecked.compute_interface_hash().expect("interface hash");
    raw.replace(PLACEHOLDER_HASH, &hash.to_string())
}

fn sign_manifest_toml(
    unsigned: &str,
    signing_key: &Ed25519SigningKey,
    binary_hash: &str,
) -> Base64Bytes {
    let manifest = ConnectorManifest::parse_str(unsigned).expect("unsigned manifest parses");
    let signing_bytes = fcp_registry::manifest_signing_bytes(&manifest).expect("signing bytes");
    let message = fcp_registry::signature_message(&signing_bytes, binary_hash);
    let signature =
        signing_key.sign_with_context(fcp_registry::MANIFEST_SIGNATURE_CONTEXT, &message);
    Base64Bytes::try_from(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    ))
    .expect("base64 signature")
}

fn with_signature(unsigned: &str, sig: &Base64Bytes) -> String {
    format!(
        r#"{unsigned}

[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "registry-e2e-publisher"
sig = "{sig}"
"#,
        sig = String::from(sig.clone())
    )
}

fn write_signed_package(
    root: &Path,
    connector_id: &str,
    version: &str,
    target: ConnectorTarget,
    binary_name: &str,
    binary_bytes: &[u8],
) -> PathBuf {
    let package_dir = root.join(format!(
        "{}-{}-{}",
        connector_id.replace(':', "_"),
        version,
        target.as_string().replace('/', "_")
    ));
    std::fs::create_dir_all(&package_dir).expect("create package dir");

    let signing_key = Ed25519SigningKey::generate();
    let unsigned = manifest_toml(connector_id, version);
    let binary_hash = hash_bytes(binary_bytes);
    let signature = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
    let signed_manifest = with_signature(&unsigned, &signature);
    let signing_bytes = fcp_registry::manifest_signing_bytes(
        &ConnectorManifest::parse_str(&unsigned).expect("unsigned manifest parses"),
    )
    .expect("manifest signing bytes");
    let signature_artifact = ManifestSignatureArtifact {
        key_id: "registry-e2e-publisher".to_string(),
        verifying_key: hex::encode(signing_key.verifying_key().to_bytes()),
        context: String::from_utf8_lossy(fcp_registry::MANIFEST_SIGNATURE_CONTEXT).into_owned(),
        manifest_signing_hash: hash_bytes(&signing_bytes),
        binary_hash,
        signature: String::from(signature),
        target,
        binary_name: binary_name.to_string(),
    };

    std::fs::write(
        package_dir.join(REGISTRY_MANIFEST_FILENAME),
        signed_manifest,
    )
    .expect("write manifest");
    std::fs::write(package_dir.join(binary_name), binary_bytes).expect("write binary");
    std::fs::write(
        package_dir.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME),
        serde_json::to_string_pretty(&signature_artifact).expect("signature json"),
    )
    .expect("write signature artifact");
    std::fs::write(
        package_dir.join(REGISTRY_ATTESTATION_FILENAME),
        r#"{"predicate_type":"https://slsa.dev/provenance/v1","builder":"registry-e2e"}"#,
    )
    .expect("write attestation");

    package_dir
}

#[test]
fn e2e_registry_validates_artifacts_rejects_traversal_and_routes_cluster_target() {
    let mut phases = Vec::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let linux = ConnectorTarget {
        os: "linux".to_string(),
        arch: "amd64".to_string(),
    };
    let darwin = ConnectorTarget {
        os: "darwin".to_string(),
        arch: "arm64".to_string(),
    };

    let linux_pkg = {
        let span = span!(
            Level::INFO,
            "e2e_registry_phase",
            crate_name = "fcp-registry",
            phase = "write_signed_linux"
        );
        let _entered = span.enter();
        phases.push("write_signed_linux");
        write_signed_package(
            temp.path(),
            "fcp.registry-e2e",
            "3.2.1",
            linux.clone(),
            "registry-e2e-linux",
            b"linux-binary-e2e",
        )
    };
    let darwin_pkg = write_signed_package(
        temp.path(),
        "fcp.registry-e2e",
        "3.2.1",
        darwin,
        "registry-e2e-darwin",
        b"darwin-binary-e2e",
    );

    let catalog = {
        let span = span!(
            Level::INFO,
            "e2e_registry_phase",
            crate_name = "fcp-registry",
            phase = "validate_catalog"
        );
        let _entered = span.enter();
        phases.push("validate_catalog");
        let catalog = LocalRegistryCatalog::from_signed_package_dirs(&[
            linux_pkg.clone(),
            darwin_pkg.clone(),
        ])
        .expect("signed package catalog");
        let descriptor = catalog
            .connector_descriptor("fcp.registry-e2e")
            .expect("connector descriptor");
        assert_eq!(descriptor.latest_version, "3.2.1");
        assert_eq!(descriptor.versions[0].targets.len(), 2);
        assert!(descriptor.versions[0].targets.iter().any(|target| {
            target.target == "linux-amd64"
                && target.binary_sha256 == hash_bytes(b"linux-binary-e2e")
        }));
        assert!(descriptor.versions[0].targets.iter().any(|target| {
            target.target == "darwin-arm64"
                && target.binary_sha256 == hash_bytes(b"darwin-binary-e2e")
        }));
        catalog
    };

    {
        let span = span!(
            Level::INFO,
            "e2e_registry_phase",
            crate_name = "fcp-registry",
            phase = "path_traversal_regression"
        );
        let _entered = span.enter();
        phases.push("path_traversal_regression");
        let traversal_pkg = write_signed_package(
            temp.path(),
            "fcp.registry-traversal-e2e",
            "1.0.0",
            linux,
            "safe-binary",
            b"safe-binary",
        );
        let sig_path = traversal_pkg.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME);
        let poisoned = std::fs::read_to_string(&sig_path)
            .expect("read signature")
            .replace("safe-binary", "../escape");
        std::fs::write(sig_path, poisoned).expect("write poisoned signature");
        let err = LocalRegistryCatalog::from_signed_package_dirs(&[traversal_pkg])
            .expect_err("path traversal binary_name rejected");
        assert!(
            err.to_string().contains("path traversal"),
            "expected path traversal rejection, got {err}"
        );
    }

    {
        let span = span!(
            Level::INFO,
            "e2e_registry_phase",
            crate_name = "fcp-registry",
            phase = "route_cluster_target"
        );
        let _entered = span.enter();
        phases.push("route_cluster_target");
        let app = catalog.router();
        fcp_async_core::runtime::block_on_sync(async move {
            let release_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/connectors/fcp.registry-e2e/latest")
                        .body(Body::empty())
                        .expect("latest request"),
                )
                .await
                .expect("latest response");
            assert_eq!(release_response.status(), StatusCode::OK);
            let release_body = to_bytes(release_response.into_body(), usize::MAX)
                .await
                .expect("release body");
            let release: RegistryVersionDescriptor =
                serde_json::from_slice(&release_body).expect("release json");
            assert!(release.targets.iter().any(|target| target.target == "linux-amd64"));

            let binary_response = app
                .oneshot(
                    Request::builder()
                        .uri("/v1/connectors/fcp.registry-e2e/versions/3.2.1/targets/linux/amd64/binary")
                        .body(Body::empty())
                        .expect("binary request"),
                )
                .await
                .expect("binary response");
            assert_eq!(binary_response.status(), StatusCode::OK);
            let binary_body = to_bytes(binary_response.into_body(), usize::MAX)
                .await
                .expect("binary body");
            assert_eq!(binary_body.as_ref(), b"linux-binary-e2e");
        })
        .expect("registry router runtime");
    }

    assert_eq!(
        phases,
        [
            "write_signed_linux",
            "validate_catalog",
            "path_traversal_regression",
            "route_cluster_target"
        ]
    );
}
