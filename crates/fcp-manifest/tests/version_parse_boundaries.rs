use std::str::FromStr;

use fcp_manifest::ConnectorManifest;
use semver::Version;

const VALID_VERSION_BOUNDARIES: &[&str] =
    &["0.0.0", "1.0.0", "0.0.1", "1.2.3-rc.1", "1.2.3+build.42"];

const INVALID_VERSION_FORMS: &[&str] = &[
    "",
    "1",
    "1.2",
    "1.2.3.4",
    "v1.2.3",
    "01.2.3",
    "1.02.3",
    "1.2.03",
    "1.2.x",
    "1.2.3-",
    "1.2.3+",
    "1.2.3-rc..1",
    "1.2.3+build..42",
    "1.2.3-01",
];

fn manifest_toml(connector_version: &str, min_mesh_version: &str) -> String {
    format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "{min_mesh_version}"
min_protocol = "fcp2-sym/2.0"
max_datagram_bytes = 1200
interface_hash = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000"

[connector]
id = "fcp.version-boundary"
name = "Version Boundary Connector"
version = "{connector_version}"
description = "Pins SemVer parsing boundaries"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"

[capabilities]
required = ["test.version"]

[provides.operations.version_check]
description = "Version boundary check"
capability = "test.version"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 128
cpu_percent = 25
wall_clock_timeout_ms = 1000
deny_exec = true
deny_ptrace = true
"#
    )
}

fn assert_version_roundtrip(version: &Version, expected_display: &str) {
    let displayed = version.to_string();
    assert_eq!(displayed, expected_display);

    let reparsed = Version::from_str(&displayed).expect("displayed version should parse");
    assert_eq!(reparsed, *version);
}

#[test]
fn semver_boundaries_roundtrip_from_str_and_display() {
    for version in VALID_VERSION_BOUNDARIES {
        let parsed = Version::from_str(version).expect("boundary version should parse");
        assert_version_roundtrip(&parsed, version);
    }
}

#[test]
fn manifest_semver_fields_roundtrip_boundary_versions() {
    for version in VALID_VERSION_BOUNDARIES {
        let manifest = ConnectorManifest::parse_str_unchecked(&manifest_toml(version, version))
            .expect("manifest SemVer fields should parse");

        assert_version_roundtrip(&manifest.connector.version, version);
        assert_version_roundtrip(&manifest.manifest.min_mesh_version, version);
    }
}

#[test]
fn semver_rejects_invalid_version_forms() {
    for version in INVALID_VERSION_FORMS {
        assert!(
            Version::from_str(version).is_err(),
            "invalid version form {version:?} unexpectedly parsed"
        );
    }
}

#[test]
fn manifest_semver_fields_reject_invalid_version_forms() {
    for version in INVALID_VERSION_FORMS {
        assert!(
            ConnectorManifest::parse_str_unchecked(&manifest_toml(version, "1.0.0")).is_err(),
            "invalid connector.version {version:?} unexpectedly parsed"
        );
        assert!(
            ConnectorManifest::parse_str_unchecked(&manifest_toml("1.0.0", version)).is_err(),
            "invalid manifest.min_mesh_version {version:?} unexpectedly parsed"
        );
    }
}
