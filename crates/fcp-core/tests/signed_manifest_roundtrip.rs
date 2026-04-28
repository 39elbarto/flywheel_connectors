use std::collections::BTreeMap;

use fcp_cbor::{CanonicalSerializer, SchemaId};
use fcp_core::SignedManifest;
use fcp_crypto::Ed25519SigningKey;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MinimalManifestPayload {
    connector_id: String,
    version: String,
    binary_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FullManifestPayload {
    connector_id: String,
    version: String,
    operations: BTreeMap<String, OperationPayload>,
    artifacts: Vec<ArtifactPayload>,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OperationPayload {
    risk: String,
    idempotency: String,
    capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ArtifactPayload {
    target: String,
    digest: String,
}

fn fixed_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x5A; 32]).expect("fixed signing key must parse")
}

fn manifest_schema(name: &str) -> SchemaId {
    SchemaId::new("fcp.core.tests", name, Version::new(1, 0, 0))
}

fn minimal_payload() -> MinimalManifestPayload {
    MinimalManifestPayload {
        connector_id: "com.flywheel.minimal".to_string(),
        version: "1.2.3".to_string(),
        binary_hash: "sha256:0123456789abcdef".to_string(),
    }
}

fn full_payload(operation_order: &[&str], metadata_order: &[&str]) -> FullManifestPayload {
    let mut operations = BTreeMap::new();
    for operation in operation_order {
        let payload = if *operation == "messages.send" {
            OperationPayload {
                risk: "dangerous".to_string(),
                idempotency: "strict".to_string(),
                capabilities: vec!["chat.write".to_string(), "audit.emit".to_string()],
            }
        } else if *operation == "messages.read" {
            OperationPayload {
                risk: "safe".to_string(),
                idempotency: "optional".to_string(),
                capabilities: vec!["chat.read".to_string()],
            }
        } else {
            continue;
        };
        operations.insert((*operation).to_string(), payload);
    }

    let mut metadata = BTreeMap::new();
    for key in metadata_order {
        let value = if *key == "zone" {
            "z:work"
        } else if *key == "release_channel" {
            "canary"
        } else {
            continue;
        };
        metadata.insert((*key).to_string(), value.to_string());
    }

    FullManifestPayload {
        connector_id: "com.flywheel.representative".to_string(),
        version: "2026.4.28".to_string(),
        operations,
        artifacts: vec![
            ArtifactPayload {
                target: "linux-amd64".to_string(),
                digest: "sha256:aaaaaaaaaaaaaaaa".to_string(),
            },
            ArtifactPayload {
                target: "darwin-arm64".to_string(),
                digest: "sha256:bbbbbbbbbbbbbbbb".to_string(),
            },
        ],
        metadata,
    }
}

fn assert_signed_manifest_roundtrip<T>(schema: SchemaId, payload: T)
where
    T: Clone + DeserializeOwned + Eq + std::fmt::Debug + Serialize,
{
    let signing_key = fixed_signing_key();
    let verifying_key = signing_key.verifying_key();

    let signed = SignedManifest::sign(schema.clone(), payload.clone(), &signing_key)
        .expect("sign manifest payload");
    let signed_again = SignedManifest::sign(schema.clone(), payload.clone(), &signing_key)
        .expect("sign manifest payload again");

    assert_eq!(
        signed.signature.to_bytes(),
        signed_again.signature.to_bytes()
    );

    let expected_payload_bytes =
        CanonicalSerializer::serialize(&payload, &schema).expect("canonical payload bytes");
    assert_eq!(
        signed
            .canonical_payload_bytes()
            .expect("signed canonical payload bytes"),
        expected_payload_bytes
    );

    let decoded_payload: T = CanonicalSerializer::deserialize(&expected_payload_bytes, &schema)
        .expect("payload bytes must be canonical");
    assert_eq!(decoded_payload, payload);

    signed
        .verify(&verifying_key)
        .expect("signature must verify");

    let envelope_bytes = signed
        .to_canonical_bytes()
        .expect("signed envelope canonical bytes");
    assert_eq!(
        envelope_bytes,
        signed
            .to_canonical_bytes()
            .expect("signed envelope canonical bytes again")
    );

    let roundtrip = SignedManifest::<T>::from_canonical_bytes(&envelope_bytes)
        .expect("signed envelope canonical roundtrip");
    assert_eq!(roundtrip, signed);
    roundtrip
        .verify(&verifying_key)
        .expect("roundtripped signature must verify");
    assert_eq!(
        roundtrip
            .canonical_payload_bytes()
            .expect("roundtripped payload bytes"),
        expected_payload_bytes
    );
}

#[test]
fn signed_manifest_minimal_payload_roundtrips_with_deterministic_signature() {
    assert_signed_manifest_roundtrip(manifest_schema("MinimalManifestPayload"), minimal_payload());
}

#[test]
fn signed_manifest_full_payload_roundtrips_with_deterministic_signature() {
    assert_signed_manifest_roundtrip(
        manifest_schema("FullManifestPayload"),
        full_payload(
            &["messages.send", "messages.read"],
            &["zone", "release_channel"],
        ),
    );
}

#[test]
fn signed_manifest_payload_bytes_are_canonical_for_reordered_maps() {
    let schema = manifest_schema("FullManifestPayload");
    let signing_key = fixed_signing_key();
    let forward = full_payload(
        &["messages.send", "messages.read"],
        &["zone", "release_channel"],
    );
    let reordered = full_payload(
        &["messages.read", "messages.send"],
        &["release_channel", "zone"],
    );

    let forward_signed =
        SignedManifest::sign(schema.clone(), forward, &signing_key).expect("sign forward payload");
    let reordered_signed =
        SignedManifest::sign(schema, reordered, &signing_key).expect("sign reordered payload");

    assert_eq!(
        forward_signed
            .canonical_payload_bytes()
            .expect("forward canonical payload"),
        reordered_signed
            .canonical_payload_bytes()
            .expect("reordered canonical payload")
    );
    assert_eq!(
        forward_signed.signature.to_bytes(),
        reordered_signed.signature.to_bytes()
    );
}
