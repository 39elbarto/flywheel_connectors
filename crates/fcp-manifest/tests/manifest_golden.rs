//! Byte-exact golden-artifact suite for `ConnectorManifest`.
//!
//! Four canonical shapes, each snapshotted as a deterministic JSON
//! projection via `insta::assert_json_snapshot!`:
//!
//!   (a) minimal — single capability, single zone, no optional sections
//!   (b) full    — multi-capability, multi-zone, every optional section
//!                 populated (`connector.state`, `rate_limits`, policy)
//!   (c) signed  — publisher signatures + threshold + registry signature
//!   (d) unsigned-accepted — `[signatures]` block omitted entirely; the
//!                 manifest must still parse+validate, establishing that
//!                 the signature section is optional at the library
//!                 boundary (host/registry layers are what gate on it)
//!
//! A fifth test pins the deterministic-encoding contract: every manifest
//! here parses+serializes to the same JSON bytes on two consecutive
//! invocations. If that property ever fails, the manifest encoder has a
//! nondeterminism bug and the failure surfaces here rather than via
//! chased-across-a-CI-retry snapshot drift.

use fcp_manifest::ConnectorManifest;
use insta::assert_json_snapshot;

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

// ───────────────────────────────────────────────────────────────────────
// Manifest fixtures
// ───────────────────────────────────────────────────────────────────────

fn minimal_manifest_toml() -> String {
    format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{PLACEHOLDER_HASH}"

[connector]
id = "fcp.golden.minimal"
name = "Minimal Golden"
version = "0.1.0"
description = "Single-capability, single-zone fixture for byte-exact goldens."
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns", "golden.ping"]
optional = []
forbidden = ["system.exec"]

[provides.operations.ping]
description = "Ping operation"
capability = "golden.ping"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
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

fn full_manifest_toml() -> String {
    format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{PLACEHOLDER_HASH}"

[connector]
id = "fcp.golden.full"
name = "Full Golden"
version = "1.2.3"
description = "Multi-capability, multi-zone fixture with every optional section populated."
archetypes = ["operational", "streaming"]
format = "native"

[connector.state]
model = "crdt"
state_schema_version = "1"
crdt_type = "or_set"
snapshot_every_updates = 1000
snapshot_every_bytes = 10485760

[zones]
home = "z:work"
allowed_sources = ["z:work", "z:private", "z:public"]
allowed_targets = ["z:work", "z:private"]
forbidden = ["z:owner"]

[capabilities]
required = ["network.dns", "golden.read", "golden.write"]
optional = ["golden.admin"]
forbidden = ["system.exec"]

[provides.operations.read]
description = "Read operation"
capability = "golden.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
input_schema = {{ type = "object", properties = {{ id = {{ type = "string" }} }}, required = ["id"] }}
output_schema = {{ type = "object" }}

[provides.operations.write]
description = "Write operation"
capability = "golden.write"
risk_level = "medium"
safety_tier = "risky"
requires_approval = "policy"
idempotency = "best_effort"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[[rate_limits.pools]]
id = "read_pool"
requests = 600
window_ms = 60000
burst = 20
unit = "requests"
enforcement = "hard"
scope = "instance"

[[rate_limits.pools]]
id = "write_pool"
requests = 120
window_ms = 60000
burst = 5
unit = "requests"
enforcement = "hard"
scope = "credential"

[signatures]
transparency_log_entry = "objectid:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

[policy]
require_transparency_log = true
require_attestation_types = ["in-toto", "reproducible-build"]
min_slsa_level = 3
trusted_builders = ["https://github.com/actions/runner"]
require_attestation_expiry = false

[sandbox]
profile = "strict"
memory_mb = 128
cpu_percent = 25
wall_clock_timeout_ms = 2000
fs_readonly_paths = ["/usr", "/etc"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
    )
}

fn signed_manifest_toml() -> String {
    // Start from the minimal shape and append a real [signatures] block
    // with two publisher signatures + a 1-of-2 threshold + a registry
    // signature. kids / sigs are plausible placeholders: the library
    // parses structure, not signature validity (that lives in the
    // registry crate).
    let base = minimal_manifest_toml();
    format!(
        r#"{base}
[signatures]
publisher_threshold = "1-of-2"

[[signatures.publisher_signatures]]
kid = "kid:publisher-alpha"
sig = "base64:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="

[[signatures.publisher_signatures]]
kid = "kid:publisher-beta"
sig = "base64:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"

[signatures.registry_signature]
kid = "kid:registry-root"
sig = "base64:UlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJS"
"#
    )
}

fn unsigned_manifest_toml() -> String {
    // The minimal fixture IS the unsigned shape — no [signatures]
    // block. We keep it as a distinct snapshot to pin the wire shape an
    // unsigned manifest serializes to: `signatures` absent from the
    // JSON projection entirely (via `skip_serializing_if = "Option::is_none"`).
    // A regression that starts emitting `"signatures": null` would flip
    // this snapshot and the diff would make the cause obvious.
    let base = minimal_manifest_toml();
    // Swap the connector id so this snapshot is not byte-identical with
    // the minimal snapshot and has its own .snap artifact.
    base.replace("fcp.golden.minimal", "fcp.golden.unsigned")
        .replace("Minimal Golden", "Unsigned Golden")
}

// ───────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────

fn with_computed_hash(raw: &str) -> String {
    // `parse_str_unchecked` accepts a placeholder hash; `compute_interface_hash`
    // returns the canonical hash over the interface-bearing sections so
    // the manifest validates under `parse_str`.
    let unchecked =
        ConnectorManifest::parse_str_unchecked(raw).expect("fixture must parse unchecked");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(PLACEHOLDER_HASH, &computed.to_string())
}

fn parse_fixture(raw: &str) -> ConnectorManifest {
    let with_hash = with_computed_hash(raw);
    ConnectorManifest::parse_str(&with_hash).expect("fixture must parse and validate")
}

// ───────────────────────────────────────────────────────────────────────
// Golden snapshots
// ───────────────────────────────────────────────────────────────────────

#[test]
fn golden_minimal_single_capability_single_zone() {
    let manifest = parse_fixture(&minimal_manifest_toml());
    assert_json_snapshot!("minimal", manifest);
}

#[test]
fn golden_full_multi_capability_multi_zone_all_optionals() {
    let manifest = parse_fixture(&full_manifest_toml());
    assert_json_snapshot!("full", manifest);
}

#[test]
fn golden_signed_publisher_threshold_plus_registry() {
    let manifest = parse_fixture(&signed_manifest_toml());
    // Sanity: the library-level parse must preserve every signature
    // structurally. Signature-validity verification is out of scope
    // for this crate; it lives in fcp-registry.
    let sigs = manifest
        .signatures
        .as_ref()
        .expect("signed fixture must carry a [signatures] section");
    assert_eq!(
        sigs.publisher_signatures.len(),
        2,
        "both publisher signatures must round-trip"
    );
    assert!(
        sigs.registry_signature.is_some(),
        "registry_signature must survive parse"
    );
    assert_json_snapshot!("signed", manifest);
}

#[test]
fn golden_unsigned_is_accepted_and_signatures_field_is_omitted() {
    let manifest = parse_fixture(&unsigned_manifest_toml());
    assert!(
        manifest.signatures.is_none(),
        "unsigned manifest must decode with signatures = None",
    );
    assert_json_snapshot!("unsigned", manifest);
}

// ───────────────────────────────────────────────────────────────────────
// Determinism guard
// ───────────────────────────────────────────────────────────────────────
//
// Every fixture MUST parse+serialize to byte-identical JSON on
// consecutive calls. If this ever fails, the manifest encoder has a
// nondeterminism bug (e.g. a HashMap iterated without sorted keys).
// The task brief says file a P1 bead on failure — surfacing it as a
// loud assertion here makes the P1 classification mechanical instead
// of discretionary.

#[test]
fn golden_encoding_is_deterministic_across_runs() {
    for (label, raw) in [
        ("minimal", minimal_manifest_toml()),
        ("full", full_manifest_toml()),
        ("signed", signed_manifest_toml()),
        ("unsigned", unsigned_manifest_toml()),
    ] {
        let a = parse_fixture(&raw);
        let b = parse_fixture(&raw);
        let aj = serde_json::to_vec(&a).expect("serialize first");
        let bj = serde_json::to_vec(&b).expect("serialize second");
        assert_eq!(
            aj, bj,
            "manifest encoding nondeterministic for fixture `{label}` \
             — file P1 bead against fcp-manifest serializer (same source \
             parsed twice produced different JSON)",
        );
    }
}
