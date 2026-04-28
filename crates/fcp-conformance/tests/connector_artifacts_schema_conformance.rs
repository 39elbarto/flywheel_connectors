//! `connector_artifacts` schema-namespace + arch-translation
//! conformance.
//!
//! `fcp_core::connector_artifacts` defines the canonical schemas for
//! mirrored connector manifests, binaries, and repair descriptors:
//!
//! - `ConnectorManifestObject` — the durable manifest carried in
//!   the mesh object store.
//! - `ConnectorBinaryObject` — the durable binary carried in the
//!   mesh object store.
//! - `ConnectorBinarySymbolSet` — the durable repair descriptor
//!   tying a manifest, binary, and OTI together.
//! - `connector_manifest_signing_view_schema` — the schema used
//!   when computing manifest signing bytes.
//!
//! All four MUST live under the namespace `fcp.core` at version
//! `1.0.0`, with names matching their struct names. Registry, store,
//! and install layers all key on these schema strings — drift is a
//! silent wire-format break.
//!
//! `ConnectorTarget::from_env` normalizes the architecture name so
//! a connector binary published as `linux-amd64` can be looked up
//! from a host whose process reports `x86_64`.
//!
//! `ConnectorBinaryTransmissionInfo` documents an optional
//! `payload_hash` (defaults to None) and a `serde` rule that omits
//! the field when None — relied on for forward/backward compat with
//! pre-payload-hash artifacts.

use fcp_cbor::SchemaId;
use fcp_core::{
    ConnectorBinaryObject, ConnectorBinarySymbolSet, ConnectorBinaryTransmissionInfo,
    ConnectorManifestObject, ConnectorTarget, ObjectId, connector_manifest_signing_view_schema,
};
use semver::Version;

#[test]
fn manifest_schema_uses_fcp_core_namespace_and_canonical_name_and_v1() {
    let s = ConnectorManifestObject::schema();
    assert_eq!(s.namespace, "fcp.core");
    assert_eq!(s.name, "ConnectorManifestObject");
    assert_eq!(s.version, Version::new(1, 0, 0));
}

#[test]
fn binary_schema_uses_fcp_core_namespace_and_canonical_name_and_v1() {
    let s = ConnectorBinaryObject::schema();
    assert_eq!(s.namespace, "fcp.core");
    assert_eq!(s.name, "ConnectorBinaryObject");
    assert_eq!(s.version, Version::new(1, 0, 0));
}

#[test]
fn symbol_set_schema_uses_fcp_core_namespace_and_canonical_name_and_v1() {
    let s = ConnectorBinarySymbolSet::schema();
    assert_eq!(s.namespace, "fcp.core");
    assert_eq!(s.name, "ConnectorBinarySymbolSet");
    assert_eq!(s.version, Version::new(1, 0, 0));
}

#[test]
fn manifest_signing_view_schema_lives_under_fcp_core() {
    let s = connector_manifest_signing_view_schema();
    assert_eq!(s.namespace, "fcp.core");
    assert_eq!(s.name, "ConnectorManifestSigningView");
    assert_eq!(s.version, Version::new(1, 0, 0));
}

#[test]
fn all_artifact_schemas_share_namespace_and_version() {
    // Cross-check: any drift across the four schemas would split
    // registry indexing logic.
    let schemas: [SchemaId; 4] = [
        ConnectorManifestObject::schema(),
        ConnectorBinaryObject::schema(),
        ConnectorBinarySymbolSet::schema(),
        connector_manifest_signing_view_schema(),
    ];
    for s in &schemas {
        assert_eq!(s.namespace, "fcp.core");
        assert_eq!(s.version, Version::new(1, 0, 0));
    }
}

#[test]
fn connector_target_from_env_yields_non_empty_os_and_arch() {
    let t = ConnectorTarget::from_env();
    assert!(!t.os.is_empty(), "from_env os must be non-empty");
    assert!(!t.arch.is_empty(), "from_env arch must be non-empty");
}

#[test]
fn connector_target_arch_translation_normalizes_to_canonical_names() {
    // The canonical mapping is x86_64 -> amd64, aarch64 -> arm64.
    // Other arches pass through. We can't force the arch here, but
    // we CAN assert that whatever from_env produces, the arch is one
    // of the canonical post-translation strings (or another arch
    // that simply passes through).
    let t = ConnectorTarget::from_env();
    let canonical_or_passthrough = [
        "amd64",
        "arm64", // canonical translations
        "x86",
        "powerpc",
        "powerpc64",
        "mips",
        "mips64",
        "s390x",
        "wasm32",
        "riscv64",
        "loongarch64",
    ];
    assert!(
        canonical_or_passthrough.contains(&t.arch.as_str()),
        "from_env produced an unexpected arch '{}'; the documented translation maps \
         x86_64->amd64 and aarch64->arm64, others pass through",
        t.arch
    );
    assert_ne!(
        t.arch, "x86_64",
        "x86_64 MUST be translated to 'amd64' by from_env (cross-platform binary lookup \
         contract)"
    );
    assert_ne!(
        t.arch, "aarch64",
        "aarch64 MUST be translated to 'arm64' by from_env"
    );
}

#[test]
fn connector_target_as_string_uses_os_dash_arch_format() {
    let t = ConnectorTarget {
        os: "linux".into(),
        arch: "amd64".into(),
    };
    assert_eq!(t.as_string(), "linux-amd64");
}

#[test]
fn binary_transmission_info_new_defaults_payload_hash_to_none() {
    let info = ConnectorBinaryTransmissionInfo::new(4096, 128, 1, 1, 8);
    assert!(
        info.payload_hash.is_none(),
        "ConnectorBinaryTransmissionInfo::new MUST default payload_hash to None"
    );
    assert_eq!(info.transfer_length, 4096);
    assert_eq!(info.symbol_size, 128);
}

#[test]
fn binary_transmission_info_with_payload_hash_sets_field() {
    let info =
        ConnectorBinaryTransmissionInfo::new(4096, 128, 1, 1, 8).with_payload_hash([0xAB; 32]);
    assert_eq!(info.payload_hash, Some([0xAB; 32]));
}

#[test]
fn binary_transmission_info_serde_omits_payload_hash_when_none() {
    let info = ConnectorBinaryTransmissionInfo::new(4096, 128, 1, 1, 8);
    let json = serde_json::to_string(&info).expect("serialize");
    assert!(
        !json.contains("payload_hash"),
        "payload_hash=None MUST be omitted from serialized JSON for forward compat \
         with pre-payload-hash readers; got {json}"
    );
}

#[test]
fn binary_transmission_info_serde_omits_field_consistent_with_pre_payload_hash_readers() {
    // A pre-payload-hash JSON (no payload_hash field) MUST still
    // deserialize as None.
    let json = r#"{"transfer_length":4096,"symbol_size":128,"source_blocks":1,"sub_blocks":1,"alignment":8}"#;
    let info: ConnectorBinaryTransmissionInfo =
        serde_json::from_str(json).expect("deserialize legacy form");
    assert!(
        info.payload_hash.is_none(),
        "legacy JSON without payload_hash MUST deserialize to None — backward compat \
         with pre-feature artifacts"
    );
}

#[test]
fn binary_transmission_info_serde_includes_payload_hash_when_some() {
    let info =
        ConnectorBinaryTransmissionInfo::new(4096, 128, 1, 1, 8).with_payload_hash([0xCC; 32]);
    let json = serde_json::to_string(&info).expect("serialize");
    assert!(
        json.contains("payload_hash"),
        "payload_hash=Some MUST appear in serialized JSON"
    );
    let parsed: ConnectorBinaryTransmissionInfo = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.payload_hash, Some([0xCC; 32]));
}

#[test]
fn binary_symbol_set_serde_roundtrip_preserves_all_fields() {
    let descriptor = ConnectorBinarySymbolSet {
        manifest_object_id: ObjectId::from_bytes([0x11; 32]),
        binary_object_id: ObjectId::from_bytes([0x22; 32]),
        target: ConnectorTarget {
            os: "linux".into(),
            arch: "arm64".into(),
        },
        binary_hash: "sha256:abc".into(),
        encoded_body_hash: "sha256:def".into(),
        oti: ConnectorBinaryTransmissionInfo::new(4096, 128, 1, 1, 8).with_payload_hash([0xAB; 32]),
        source_symbols: 32,
        total_symbols: 48,
        mirrored_at: 1_700_000_000,
    };
    let json = serde_json::to_string(&descriptor).expect("serialize");
    let parsed: ConnectorBinarySymbolSet = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, descriptor);
}

#[test]
fn manifest_object_serde_roundtrip() {
    let m = ConnectorManifestObject {
        manifest_toml: "name = \"telegram\"".into(),
        manifest_hash: "sha256:abc123".into(),
    };
    let json = serde_json::to_string(&m).expect("serialize");
    let parsed: ConnectorManifestObject = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, m);
}

#[test]
fn binary_object_serde_roundtrip_preserves_target_and_payload() {
    let b = ConnectorBinaryObject {
        target: ConnectorTarget {
            os: "darwin".into(),
            arch: "arm64".into(),
        },
        binary_hash: "sha256:xyz".into(),
        binary: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let json = serde_json::to_string(&b).expect("serialize");
    let parsed: ConnectorBinaryObject = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, b);
}

#[test]
fn schemas_are_distinct_per_artifact_type() {
    // Two artifacts with the same namespace+version must still be
    // distinguishable by name; otherwise registry indexing would
    // alias them.
    let manifest = ConnectorManifestObject::schema();
    let binary = ConnectorBinaryObject::schema();
    let symbol_set = ConnectorBinarySymbolSet::schema();
    let signing_view = connector_manifest_signing_view_schema();

    let names: std::collections::BTreeSet<&str> = [
        manifest.name.as_str(),
        binary.name.as_str(),
        symbol_set.name.as_str(),
        signing_view.name.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        names.len(),
        4,
        "the four artifact schemas MUST have distinct names"
    );
}
