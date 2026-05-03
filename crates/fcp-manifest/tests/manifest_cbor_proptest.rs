//! Property coverage for hostile canonical-CBOR manifest inputs.
//!
//! The cargo-fuzz target walks arbitrary bytes through the same decode path.
//! These tests pin deterministic, structured cases that used to require a
//! long fuzz run to rediscover: random CBOR bodies, schema-version tricks,
//! oversized arrays, and recursive JSON-schema-like structures.

use std::panic;

use fcp_cbor::to_canonical_cbor;
use fcp_manifest::{ConnectorManifest, ManifestError};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use serde_json::{Value, json};

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

fn base_manifest_toml(interface_hash: &str) -> String {
    format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{interface_hash}"

[connector]
id = "fcp.proptest"
name = "Proptest Connector"
version = "1.0.0"
description = "Manifest CBOR property-test fixture"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns", "proptest.op"]
optional = []
forbidden = ["system.exec"]

[provides.operations.proptest_op]
description = "Property-test operation"
capability = "proptest.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
    )
}

fn base_manifest() -> ConnectorManifest {
    let unchecked = ConnectorManifest::parse_str_unchecked(&base_manifest_toml(PLACEHOLDER_HASH))
        .expect("base manifest parses unchecked");
    let computed = unchecked
        .compute_interface_hash()
        .expect("base interface hash computes");
    ConnectorManifest::parse_str(&base_manifest_toml(&computed.to_string()))
        .expect("base manifest validates")
}

fn base_manifest_value() -> Value {
    serde_json::to_value(base_manifest()).expect("manifest serializes to JSON value")
}

fn encode_value_as_cbor(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded).expect("serde_json::Value encodes as CBOR");
    encoded
}

fn nested_array(depth: usize, width: usize) -> Value {
    let mut value = json!({"type": "string"});
    let width = width.clamp(1, 4);
    for _ in 0..depth {
        let mut next = Vec::with_capacity(width);
        next.push(value);
        next.extend(std::iter::repeat_n(json!({"type": "null"}), width - 1));
        value = Value::Array(next);
    }
    value
}

fn manifest_with_adversarial_shape(
    mode: u8,
    schema_major: u16,
    schema_minor: u16,
    schema_noise: &[u8],
    array_len: usize,
    depth: usize,
) -> Value {
    let mut manifest = base_manifest_value();
    match mode % 5 {
        0 => {
            manifest["manifest"]["schema_version"] =
                Value::String(format!("{schema_major}.{schema_minor}"));
        }
        1 => {
            manifest["manifest"]["schema_version"] =
                Value::String(String::from_utf8_lossy(schema_noise).into_owned());
        }
        2 => {
            manifest["manifest"]["protocol_features"] = Value::Array(
                (0..array_len)
                    .map(|index| Value::String(format!("feature.{index}")))
                    .collect(),
            );
        }
        3 => {
            manifest["capabilities"]["required"] = Value::Array(
                (0..array_len)
                    .map(|index| Value::String(format!("proptest.capability.{index}")))
                    .collect(),
            );
        }
        _ => {
            manifest["provides"]["operations"]["proptest_op"]["input_schema"] =
                nested_array(depth, array_len % 4 + 1);
        }
    }
    manifest
}

fn exercise_manifest_decode(bytes: &[u8]) -> Result<(), TestCaseError> {
    let decoded = panic::catch_unwind(|| ciborium::from_reader::<ConnectorManifest, _>(bytes));
    prop_assert!(decoded.is_ok(), "manifest CBOR decode panicked");

    if let Ok(manifest) = decoded.unwrap() {
        let validation = panic::catch_unwind(|| manifest.validate());
        prop_assert!(validation.is_ok(), "manifest validation panicked");
        let _typed_validation: Result<(), ManifestError> = validation.unwrap();

        let interface_hash = panic::catch_unwind(|| manifest.compute_interface_hash());
        prop_assert!(
            interface_hash.is_ok(),
            "manifest interface-hash computation panicked"
        );
        let _typed_hash: Result<_, ManifestError> = interface_hash.unwrap();

        if let Ok(canonical) = to_canonical_cbor(&manifest) {
            let reparsed = panic::catch_unwind(|| {
                ciborium::from_reader::<ConnectorManifest, _>(&canonical[..])
            });
            prop_assert!(reparsed.is_ok(), "canonical manifest reparse panicked");
            if let Ok(reparsed_manifest) = reparsed.unwrap() {
                let reencoded = panic::catch_unwind(|| to_canonical_cbor(&reparsed_manifest));
                prop_assert!(reencoded.is_ok(), "canonical manifest re-encode panicked");
            }
        }
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_manifest_cbor_bytes_never_panic_or_escape_typed_errors(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=8192),
    ) {
        exercise_manifest_decode(&bytes)?;
    }

    #[test]
    fn adversarial_manifest_shapes_never_panic_or_escape_typed_errors(
        mode in any::<u8>(),
        schema_major in 0u16..=8,
        schema_minor in 0u16..=4096,
        schema_noise in proptest::collection::vec(any::<u8>(), 0usize..=64),
        array_len in 0usize..=512,
        depth in 0usize..=80,
    ) {
        let value = manifest_with_adversarial_shape(
            mode,
            schema_major,
            schema_minor,
            &schema_noise,
            array_len,
            depth,
        );
        let bytes = encode_value_as_cbor(&value);
        exercise_manifest_decode(&bytes)?;
    }
}
