//! No-mock integration tests for fcp-manifest.
//!
//! These tests exercise the full manifest parsing and validation pipeline
//! without any mocks or stubs, targeting coverage gaps identified in the
//! existing unit test suite.

use fcp_manifest::ConnectorManifest;

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

fn base_manifest() -> String {
    format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
max_datagram_bytes = 1200
interface_hash = "{PLACEHOLDER_HASH}"

[connector]
id = "fcp.test"
name = "Test Connector"
version = "1.0.0"
description = "A test connector"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"

[capabilities]
required = ["network.egress", "test.op"]
forbidden = ["system.exec"]

[provides.operations.test_op]
description = "Test operation"
capability = "test.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}
network_constraints = {{ host_allow = ["api.example.test"], port_allow = [443], require_sni = true }}

[sandbox]
profile = "strict"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 30000
deny_exec = true
deny_ptrace = true
"#
    )
}

fn with_computed_hash(raw: &str) -> String {
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(PLACEHOLDER_HASH, &computed.to_string())
}

fn parse_valid(toml: &str) -> ConnectorManifest {
    let with_hash = with_computed_hash(toml);
    ConnectorManifest::parse_str(&with_hash).expect("should parse and validate")
}

fn parse_err(toml: &str) -> String {
    let with_hash = with_computed_hash(toml);
    ConnectorManifest::parse_str(&with_hash)
        .expect_err("should fail validation")
        .to_string()
}

// ── EventSection tests ───────────────────────────────────────────────

#[test]
fn event_section_parses_with_all_fields() {
    let toml = base_manifest()
        + r#"
[provides.events.on_update]
description = "Fires when data updates"
streaming = true
replay = true
topic = "updates"
requires_ack = true
schema = { type = "object", required = ["id"] }
"#;
    let manifest = parse_valid(&toml);
    let event = &manifest.provides.events["on_update"];
    assert!(event.streaming);
    assert!(event.replay);
    assert_eq!(event.topic.as_deref(), Some("updates"));
    assert!(event.requires_ack);
    assert!(event.schema.is_some());
}

#[test]
fn event_section_defaults() {
    let toml = base_manifest()
        + r#"
[provides.events.on_change]
description = "Something changed"
"#;
    let manifest = parse_valid(&toml);
    let event = &manifest.provides.events["on_change"];
    assert!(!event.streaming);
    assert!(!event.replay);
    assert!(event.topic.is_none());
    assert!(!event.requires_ack);
    assert!(event.schema.is_none());
}

#[test]
fn multiple_events_parse() {
    let toml = base_manifest()
        + r#"
[provides.events.event_a]
description = "Event A"
streaming = true

[provides.events.event_b]
description = "Event B"
replay = true
"#;
    let manifest = parse_valid(&toml);
    assert_eq!(manifest.provides.events.len(), 2);
    assert!(manifest.provides.events.contains_key("event_a"));
    assert!(manifest.provides.events.contains_key("event_b"));
}

// ── EventCaps validation ─────────────────────────────────────────────

#[test]
fn event_caps_replay_only_no_buffer_ok() {
    let toml = base_manifest()
        + r"
[event_caps]
streaming = false
replay = true
min_buffer_events = 0
";
    parse_valid(&toml);
}

#[test]
fn event_caps_streaming_requires_nonzero_buffer() {
    let toml = base_manifest()
        + r"
[event_caps]
streaming = true
replay = false
min_buffer_events = 0
";
    let err = parse_err(&toml);
    assert!(err.contains("min_buffer_events"));
}

#[test]
fn event_caps_streaming_with_buffer_ok() {
    let toml = base_manifest()
        + r"
[event_caps]
streaming = true
replay = false
min_buffer_events = 100
";
    parse_valid(&toml);
}

// ── ZonesSection tests ───────────────────────────────────────────────

#[test]
fn zones_home_in_forbidden_rejected() {
    let toml = base_manifest().replace(
        "home = \"z:work\"",
        "home = \"z:work\"\nforbidden = [\"z:work\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("home zone must not be forbidden"));
}

#[test]
fn zones_with_sources_and_targets() {
    let toml = base_manifest().replace(
        "home = \"z:work\"",
        "home = \"z:work\"\nallowed_sources = [\"z:owner\", \"z:private\"]\nallowed_targets = [\"z:community\"]",
    );
    let manifest = parse_valid(&toml);
    assert_eq!(manifest.zones.allowed_sources.len(), 2);
    assert_eq!(manifest.zones.allowed_targets.len(), 1);
}

#[test]
fn zones_allow_project_wildcard_policy_selector() {
    let toml = base_manifest().replace(
        "home = \"z:work\"",
        "home = \"z:work\"\nallowed_sources = [\"z:work\", \"z:project:*\"]\nallowed_targets = [\"z:project:*\"]",
    );
    let manifest = parse_valid(&toml);
    let project_zone = "z:project:alpha".parse().expect("project zone");

    assert_eq!(manifest.zones.allowed_sources[1].as_str(), "z:project:*");
    assert!(manifest.zones.allowed_sources[1].matches(&project_zone));
    assert!(!manifest.zones.allowed_targets[0].matches(&manifest.zones.home));
}

#[test]
fn zones_reject_unsupported_wildcard_policy_selector() {
    let toml = base_manifest().replace(
        "home = \"z:work\"",
        "home = \"z:work\"\nallowed_sources = [\"z:*\"]",
    );
    let err = ConnectorManifest::parse_str_unchecked(&toml).unwrap_err();

    assert!(err.to_string().contains("unsupported zone wildcard"));
}

#[test]
fn zones_forbidden_not_containing_home_ok() {
    let toml = base_manifest().replace(
        "home = \"z:work\"",
        "home = \"z:work\"\nforbidden = [\"z:public\"]",
    );
    let manifest = parse_valid(&toml);
    assert_eq!(manifest.zones.forbidden.len(), 1);
}

// ── State model tests ────────────────────────────────────────────────

#[test]
fn state_model_singleton_writer() {
    let toml = base_manifest().replace(
        "[zones]",
        "[connector.state]\nmodel = \"singleton_writer\"\nstate_schema_version = \"1\"\n\n[zones]",
    );
    let manifest = parse_valid(&toml);
    assert!(manifest.connector.state.is_some());
}

#[test]
fn state_model_crdt_requires_crdt_type() {
    let toml = base_manifest().replace(
        "[zones]",
        "[connector.state]\nmodel = \"crdt\"\nstate_schema_version = \"1\"\n\n[zones]",
    );
    // compute_interface_hash itself calls effective_state_model, so this fails before hash
    let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
    let err = m.validate().unwrap_err().to_string();
    assert!(err.contains("crdt_type"));
}

#[test]
fn state_model_crdt_with_type_ok() {
    let toml = base_manifest().replace(
        "[zones]",
        "[connector.state]\nmodel = \"crdt\"\nstate_schema_version = \"1\"\ncrdt_type = \"lww_map\"\n\n[zones]",
    );
    parse_valid(&toml);
}

#[test]
fn state_model_crdt_with_snapshot_config() {
    let toml = base_manifest().replace(
        "[zones]",
        "[connector.state]\nmodel = \"crdt\"\nstate_schema_version = \"1\"\ncrdt_type = \"or_set\"\nsnapshot_every_updates = 1000\nsnapshot_every_bytes = 10485760\n\n[zones]",
    );
    let manifest = parse_valid(&toml);
    let state = manifest.connector.state.as_ref().unwrap();
    assert_eq!(state.snapshot_every_updates, Some(1000));
    assert_eq!(state.snapshot_every_bytes, Some(10_485_760));
}

#[test]
fn singleton_writer_flag_conflicts_with_crdt_model() {
    let toml = base_manifest()
        .replace(
            "format = \"native\"",
            "format = \"native\"\nsingleton_writer = true",
        )
        .replace(
            "[zones]",
            "[connector.state]\nmodel = \"crdt\"\nstate_schema_version = \"1\"\ncrdt_type = \"lww_map\"\n\n[zones]",
        );
    let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
    let err = m.validate().unwrap_err().to_string();
    assert!(err.contains("conflicts"));
}

#[test]
fn singleton_writer_flag_with_matching_state_ok() {
    let toml = base_manifest()
        .replace(
            "format = \"native\"",
            "format = \"native\"\nsingleton_writer = true",
        )
        .replace(
            "[zones]",
            "[connector.state]\nmodel = \"singleton_writer\"\nstate_schema_version = \"1\"\n\n[zones]",
        );
    parse_valid(&toml);
}

#[test]
fn state_model_empty_schema_version_rejected() {
    let toml = base_manifest().replace(
        "[zones]",
        "[connector.state]\nmodel = \"stateless\"\nstate_schema_version = \"  \"\n\n[zones]",
    );
    let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
    let err = m.validate().unwrap_err().to_string();
    assert!(err.contains("state_schema_version"));
}

// ── NetworkConstraints edge cases ────────────────────────────────────

#[test]
fn network_empty_host_allow_rejected() {
    let toml = base_manifest().replace("host_allow = [\"api.example.test\"]", "host_allow = []");
    let err = parse_err(&toml);
    assert!(err.contains("host_allow"));
    assert!(err.contains("must not be empty"));
}

#[test]
fn network_empty_port_allow_rejected() {
    let toml = base_manifest().replace("port_allow = [443]", "port_allow = []");
    let err = parse_err(&toml);
    assert!(err.contains("port_allow"));
    assert!(err.contains("must not be empty"));
}

#[test]
fn network_zero_connect_timeout_rejected() {
    let toml = base_manifest().replace(
        "require_sni = true",
        "require_sni = true, connect_timeout_ms = 0",
    );
    let err = parse_err(&toml);
    assert!(err.contains("timeouts must be > 0"));
}

#[test]
fn network_zero_total_timeout_rejected() {
    let toml = base_manifest().replace(
        "require_sni = true",
        "require_sni = true, total_timeout_ms = 0",
    );
    let err = parse_err(&toml);
    assert!(err.contains("timeouts must be > 0"));
}

#[test]
fn network_zero_max_response_bytes_rejected() {
    let toml = base_manifest().replace(
        "require_sni = true",
        "require_sni = true, max_response_bytes = 0",
    );
    let err = parse_err(&toml);
    assert!(err.contains("max_response_bytes"));
}

#[test]
fn network_invalid_cidr_rejected() {
    let toml = base_manifest().replace(
        "require_sni = true",
        "require_sni = true, cidr_deny = [\"not-a-cidr\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("invalid CIDR"));
}

#[test]
fn network_valid_cidr_ok() {
    let toml = base_manifest().replace(
        "require_sni = true",
        "require_sni = true, cidr_deny = [\"10.0.0.0/8\", \"172.16.0.0/12\"]",
    );
    parse_valid(&toml);
}

#[test]
fn network_trailing_dot_host_rejected() {
    let toml = base_manifest().replace(
        "host_allow = [\"api.example.test\"]",
        "host_allow = [\"api.example.test.\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("trailing dot"));
}

#[test]
fn network_empty_host_entry_rejected() {
    let toml =
        base_manifest().replace("host_allow = [\"api.example.test\"]", "host_allow = [\"\"]");
    let err = parse_err(&toml);
    assert!(err.contains("must not be empty"));
}

#[test]
fn network_non_ascii_host_rejected() {
    let toml = base_manifest().replace(
        "host_allow = [\"api.example.test\"]",
        "host_allow = [\"api.exämple.test\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("ASCII"));
}

#[test]
fn network_ip_literal_when_deny_ip_literals_true() {
    let toml = base_manifest().replace(
        "host_allow = [\"api.example.test\"]",
        "host_allow = [\"93.184.216.34\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("IP literals"));
}

#[test]
fn network_ip_literal_allowed_when_deny_ip_literals_false() {
    let toml = base_manifest().replace(
        "host_allow = [\"api.example.test\"], port_allow = [443], require_sni = true",
        "host_allow = [\"93.184.216.34\"], port_allow = [443], require_sni = true, deny_ip_literals = false",
    );
    parse_valid(&toml);
}

#[test]
fn network_valid_wildcard_host_ok() {
    let toml = base_manifest().replace(
        "host_allow = [\"api.example.test\"]",
        "host_allow = [\"*.example.test\"]",
    );
    parse_valid(&toml);
}

#[test]
fn network_multiple_wildcards_rejected() {
    let toml = base_manifest().replace(
        "host_allow = [\"api.example.test\"]",
        "host_allow = [\"*.*.example.test\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("wildcard"));
}

#[test]
fn network_mid_wildcard_rejected() {
    let toml = base_manifest().replace(
        "host_allow = [\"api.example.test\"]",
        "host_allow = [\"api.*.test\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("wildcard"));
}

#[test]
fn network_defaults_applied() {
    let toml = base_manifest();
    let manifest = parse_valid(&toml);
    let nc = manifest.provides.operations["test_op"]
        .network_constraints
        .as_ref()
        .unwrap();
    assert!(nc.deny_localhost);
    assert!(nc.deny_private_ranges);
    assert!(nc.deny_tailnet_ranges);
    assert!(nc.deny_ip_literals);
    assert!(nc.require_host_canonicalization);
    assert_eq!(nc.dns_max_ips, 16);
    assert_eq!(nc.max_redirects, 5);
    assert_eq!(nc.connect_timeout_ms, 10_000);
    assert_eq!(nc.total_timeout_ms, 60_000);
    assert_eq!(nc.max_response_bytes, 10_485_760);
}

#[test]
fn network_ip_allow_parses() {
    let toml = base_manifest().replace(
        "require_sni = true",
        "require_sni = true, ip_allow = [\"93.184.216.34\", \"::1\"], deny_ip_literals = false",
    );
    let manifest = parse_valid(&toml);
    let nc = manifest.provides.operations["test_op"]
        .network_constraints
        .as_ref()
        .unwrap();
    assert_eq!(nc.ip_allow.len(), 2);
}

#[test]
fn network_spki_pins_parse() {
    let toml = base_manifest().replace(
        "require_sni = true",
        "require_sni = true, spki_pins = [\"base64:AQID\"]",
    );
    let manifest = parse_valid(&toml);
    let nc = manifest.provides.operations["test_op"]
        .network_constraints
        .as_ref()
        .unwrap();
    assert_eq!(nc.spki_pins.len(), 1);
    assert_eq!(nc.spki_pins[0].as_bytes(), &[1, 2, 3]);
}

// ── Capability validation ────────────────────────────────────────────

#[test]
fn duplicate_capability_across_lists_rejected() {
    let toml = base_manifest().replace("optional = []", "").replace(
        "required = [\"network.egress\"]",
        "required = [\"network.egress\"]\noptional = [\"network.egress\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("duplicate capability"));
}

#[test]
fn capability_in_required_and_forbidden_rejected() {
    let toml = base_manifest().replace(
        "required = [\"network.egress\"]",
        "required = [\"network.egress\", \"system.exec\"]",
    );
    let err = parse_err(&toml);
    assert!(err.contains("duplicate capability"));
}

// ── Sandbox validation ───────────────────────────────────────────────

#[test]
fn sandbox_zero_wall_clock_timeout_rejected() {
    let toml =
        base_manifest().replace("wall_clock_timeout_ms = 30000", "wall_clock_timeout_ms = 0");
    let err = parse_err(&toml);
    assert!(err.contains("wall_clock_timeout_ms"));
}

#[test]
fn sandbox_all_profiles_parse() {
    for profile in ["strict", "strict_plus", "moderate", "permissive"] {
        let toml =
            base_manifest().replace("profile = \"strict\"", &format!("profile = \"{profile}\""));
        parse_valid(&toml);
    }
}

// ── Connector validation ─────────────────────────────────────────────

#[test]
fn empty_connector_description_rejected() {
    let toml = base_manifest().replace("description = \"A test connector\"", "description = \"\"");
    let err = parse_err(&toml);
    assert!(err.contains("connector.description"));
}

#[test]
fn empty_archetypes_rejected() {
    let toml = base_manifest().replace("archetypes = [\"operational\"]", "archetypes = []");
    let err = parse_err(&toml);
    assert!(err.contains("archetypes"));
}

#[test]
fn multiple_archetypes_ok() {
    let toml = base_manifest().replace(
        "archetypes = [\"operational\"]",
        "archetypes = [\"operational\", \"streaming\", \"knowledge\"]",
    );
    let manifest = parse_valid(&toml);
    assert_eq!(manifest.connector.archetypes.len(), 3);
}

#[test]
fn wasi_format_ok() {
    let toml = base_manifest().replace("format = \"native\"", "format = \"wasi\"");
    let manifest = parse_valid(&toml);
    assert_eq!(
        manifest.connector.format,
        fcp_manifest::ConnectorRuntimeFormat::Wasi
    );
}

// ── ManifestSection validation ───────────────────────────────────────

#[test]
fn wrong_manifest_format_rejected() {
    let toml = base_manifest().replace(
        "format = \"fcp-connector-manifest\"",
        "format = \"wrong-format\"",
    );
    let err = parse_err(&toml);
    assert!(err.contains("fcp-connector-manifest"));
}

#[test]
fn wrong_schema_major_version_rejected() {
    let toml = base_manifest().replace("schema_version = \"2.1\"", "schema_version = \"3.0\"");
    let err = parse_err(&toml);
    assert!(err.contains("schema_version"));
}

#[test]
fn zero_max_datagram_bytes_rejected() {
    let toml = base_manifest().replace("max_datagram_bytes = 1200", "max_datagram_bytes = 0");
    let err = parse_err(&toml);
    assert!(err.contains("max_datagram_bytes"));
}

// ── Operation validation ─────────────────────────────────────────────

#[test]
fn empty_operation_description_rejected() {
    let toml = base_manifest().replace("description = \"Test operation\"", "description = \"  \"");
    let err = parse_err(&toml);
    assert!(err.contains("description"));
}

#[test]
fn no_operations_rejected() {
    let toml = base_manifest()
        .replace(
            "[provides.operations.test_op]\ndescription = \"Test operation\"\ncapability = \"test.op\"\nrisk_level = \"low\"\nsafety_tier = \"safe\"\nrequires_approval = \"none\"\nidempotency = \"strict\"\ninput_schema = { type = \"object\" }\noutput_schema = { type = \"object\" }\nnetwork_constraints = { host_allow = [\"api.example.test\"], port_allow = [443], require_sni = true }",
            "",
        );
    // parse_str_unchecked should work, but validate should fail
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml);
    assert!(
        unchecked.is_err() || {
            let m = unchecked.unwrap();
            m.validate().is_err()
        }
    );
}

#[test]
fn operation_without_network_constraints_ok() {
    let toml = base_manifest().replace(
        "\nnetwork_constraints = { host_allow = [\"api.example.test\"], port_allow = [443], require_sni = true }",
        "",
    );
    let manifest = parse_valid(&toml);
    assert!(
        manifest.provides.operations["test_op"]
            .network_constraints
            .is_none()
    );
}

#[test]
fn multiple_operations_parse() {
    let toml = base_manifest()
        + r#"
[provides.operations.second_op]
description = "Second operation"
capability = "test.second"
risk_level = "high"
safety_tier = "risky"
requires_approval = "elevation_token"
idempotency = "none"
input_schema = { type = "object" }
output_schema = { type = "object" }
"#;
    let manifest = parse_valid(&toml);
    assert_eq!(manifest.provides.operations.len(), 2);
}

#[test]
fn approval_required_alias_accepted() {
    let toml = base_manifest().replace(
        "requires_approval = \"none\"",
        "requires_approval = \"approval_required\"",
    );
    let manifest = parse_valid(&toml);
    assert_eq!(
        manifest.provides.operations["test_op"].requires_approval,
        fcp_manifest::ManifestApprovalMode::ElevationToken,
    );
}

// ── Rate limit shorthand variants ────────────────────────────────────

#[test]
fn rate_limit_shorthand_per_day() {
    let toml = base_manifest().replace(
        "idempotency = \"strict\"",
        "rate_limit = \"500/day\"\nidempotency = \"strict\"",
    );
    let manifest = parse_valid(&toml);
    let rl = manifest.provides.operations["test_op"]
        .rate_limit
        .as_ref()
        .unwrap();
    assert_eq!(rl.as_inner().max, 500);
    assert_eq!(rl.as_inner().per_ms, 86_400_000);
}

#[test]
fn rate_limit_shorthand_aliases() {
    for (input, expected_ms) in [
        ("10/s", 1_000_u64),
        ("10/sec", 1_000),
        ("10/m", 60_000),
        ("10/min", 60_000),
        ("10/h", 3_600_000),
        ("10/hour", 3_600_000),
        ("10/d", 86_400_000),
        ("10/day", 86_400_000),
    ] {
        let toml = base_manifest().replace(
            "idempotency = \"strict\"",
            &format!("rate_limit = \"{input}\"\nidempotency = \"strict\""),
        );
        let manifest = parse_valid(&toml);
        let rl = manifest.provides.operations["test_op"]
            .rate_limit
            .as_ref()
            .unwrap();
        assert_eq!(
            rl.as_inner().per_ms,
            expected_ms,
            "rate_limit {input} => expected {expected_ms}ms"
        );
    }
}

// ── Rate limits section (pool declarations) ──────────────────────────

#[test]
fn rate_limits_section_with_pools() {
    let toml = base_manifest()
        + r#"
[[rate_limits.pools]]
id = "api_global"
description = "Global API rate limit"
requests = 100
window_ms = 60000

[[rate_limits.pools]]
id = "api_burst"
requests = 10
window_ms = 1000
burst = 5
unit = "requests"
enforcement = "hard"
scope = "instance"

[rate_limits.operation_pools]
test_op = ["api_global", "api_burst"]
"#;
    let manifest = parse_valid(&toml);
    let rl = manifest.rate_limits.as_ref().unwrap();
    assert_eq!(rl.pools.len(), 2);
    assert_eq!(rl.pools[0].id, "api_global");
    assert_eq!(rl.pools[1].burst, Some(5));
    assert!(rl.operation_pools.contains_key("test_op"));
}

#[test]
fn rate_limits_section_token_unit() {
    let toml = base_manifest()
        + r#"
[[rate_limits.pools]]
id = "token_pool"
requests = 100000
window_ms = 60000
unit = "tokens"
enforcement = "soft"
scope = "credential"
"#;
    let manifest = parse_valid(&toml);
    let rl = manifest.rate_limits.as_ref().unwrap();
    assert_eq!(rl.pools[0].unit.as_deref(), Some("tokens"));
    assert_eq!(rl.pools[0].enforcement.as_deref(), Some("soft"));
    assert_eq!(rl.pools[0].scope.as_deref(), Some("credential"));
}

// ── Signatures section ───────────────────────────────────────────────

#[test]
fn signatures_section_parses() {
    let toml = base_manifest()
        + r#"
[signatures]
publisher_threshold = "1-of-1"
[[signatures.publisher_signatures]]
kid = "key1"
sig = "base64:AQIDBA=="
"#;
    let manifest = parse_valid(&toml);
    let sigs = manifest.signatures.as_ref().unwrap();
    assert_eq!(sigs.publisher_signatures.len(), 1);
    assert_eq!(sigs.publisher_signatures[0].kid, "key1");
}

#[test]
fn signatures_threshold_insufficient_sigs_rejected() {
    let toml = base_manifest()
        + r#"
[signatures]
publisher_threshold = "2-of-3"
[[signatures.publisher_signatures]]
kid = "key1"
sig = "base64:AQID"
"#;
    let err = parse_err(&toml);
    assert!(err.contains("insufficient"));
}

// ── Supply chain section ─────────────────────────────────────────────

#[test]
fn supply_chain_section_parses() {
    let oid1 = "aa".repeat(32);
    let oid2 = "bb".repeat(32);
    let toml = base_manifest()
        + &format!(
            r#"
[[supply_chain.attestations]]
type = "in-toto"
object_id = "objectid:{oid1}"

[[supply_chain.attestations]]
type = "reproducible-build"
object_id = "objectid:{oid2}"
"#
        );
    let manifest = parse_valid(&toml);
    let sc = manifest.supply_chain.as_ref().unwrap();
    assert_eq!(sc.attestations.len(), 2);
}

#[test]
fn supply_chain_duplicate_object_id_rejected() {
    let oid = "cc".repeat(32);
    let toml = base_manifest()
        + &format!(
            r#"
[[supply_chain.attestations]]
type = "in-toto"
object_id = "objectid:{oid}"

[[supply_chain.attestations]]
type = "code-review"
object_id = "objectid:{oid}"
"#
        );
    let err = parse_err(&toml);
    assert!(err.contains("duplicate attestation"));
}

// ── Policy section ───────────────────────────────────────────────────

#[test]
fn policy_section_parses() {
    let toml = base_manifest()
        + r#"
[policy]
require_transparency_log = true
require_attestation_types = ["in-toto"]
min_slsa_level = 3
trusted_builders = ["github-actions"]
"#;
    let manifest = parse_valid(&toml);
    let policy = manifest.policy.as_ref().unwrap();
    assert!(policy.require_transparency_log);
    assert_eq!(policy.min_slsa_level, Some(3));
    assert_eq!(policy.trusted_builders.len(), 1);
}

#[test]
fn policy_slsa_level_boundary_0_ok() {
    let toml = base_manifest()
        + r"
[policy]
min_slsa_level = 0
";
    parse_valid(&toml);
}

#[test]
fn policy_slsa_level_boundary_4_ok() {
    let toml = base_manifest()
        + r"
[policy]
min_slsa_level = 4
";
    parse_valid(&toml);
}

#[test]
fn policy_slsa_level_5_rejected() {
    let toml = base_manifest()
        + r"
[policy]
min_slsa_level = 5
";
    let err = parse_err(&toml);
    assert!(err.contains("min_slsa_level"));
}

// ── Interface hash determinism ───────────────────────────────────────

#[test]
fn interface_hash_deterministic_across_calls() {
    let toml = base_manifest();
    let m1 = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
    let m2 = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
    let h1 = m1.compute_interface_hash().unwrap();
    let h2 = m2.compute_interface_hash().unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn interface_hash_changes_with_operation_change() {
    let toml1 = base_manifest();
    let toml2 = base_manifest().replace("risk_level = \"low\"", "risk_level = \"high\"");

    let m1 = ConnectorManifest::parse_str_unchecked(&toml1).unwrap();
    let m2 = ConnectorManifest::parse_str_unchecked(&toml2).unwrap();
    let h1 = m1.compute_interface_hash().unwrap();
    let h2 = m2.compute_interface_hash().unwrap();
    assert_ne!(h1, h2, "different risk_level should produce different hash");
}

#[test]
fn interface_hash_changes_with_capability_change() {
    let toml1 = base_manifest();
    let toml2 = base_manifest().replace(
        "required = [\"network.egress\"]",
        "required = [\"network.egress\", \"network.dns\"]",
    );

    let m1 = ConnectorManifest::parse_str_unchecked(&toml1).unwrap();
    let m2 = ConnectorManifest::parse_str_unchecked(&toml2).unwrap();
    let h1 = m1.compute_interface_hash().unwrap();
    let h2 = m2.compute_interface_hash().unwrap();
    assert_ne!(
        h1, h2,
        "different capabilities should produce different hash"
    );
}

#[test]
fn interface_hash_unaffected_by_supply_chain() {
    let oid = "dd".repeat(32);
    let toml1 = base_manifest();
    let toml2 = base_manifest()
        + &format!(
            r#"
[[supply_chain.attestations]]
type = "in-toto"
object_id = "objectid:{oid}"
"#
        );

    let m1 = ConnectorManifest::parse_str_unchecked(&toml1).unwrap();
    let m2 = ConnectorManifest::parse_str_unchecked(&toml2).unwrap();
    let h1 = m1.compute_interface_hash().unwrap();
    let h2 = m2.compute_interface_hash().unwrap();
    assert_eq!(
        h1, h2,
        "supply chain metadata should not affect interface hash"
    );
}

#[test]
fn interface_hash_unaffected_by_policy() {
    let toml1 = base_manifest();
    let toml2 = base_manifest()
        + r#"
[policy]
min_slsa_level = 3
trusted_builders = ["github-actions"]
"#;

    let m1 = ConnectorManifest::parse_str_unchecked(&toml1).unwrap();
    let m2 = ConnectorManifest::parse_str_unchecked(&toml2).unwrap();
    let h1 = m1.compute_interface_hash().unwrap();
    let h2 = m2.compute_interface_hash().unwrap();
    assert_eq!(h1, h2, "policy metadata should not affect interface hash");
}

// ── Serde roundtrip ──────────────────────────────────────────────────

#[test]
fn manifest_serde_json_roundtrip() {
    let toml = base_manifest();
    let manifest = parse_valid(&toml);
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: ConnectorManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(
        deserialized.connector.id.as_str(),
        manifest.connector.id.as_str()
    );
    assert_eq!(
        deserialized.provides.operations.len(),
        manifest.provides.operations.len()
    );
}

// ── Idempotency classes ──────────────────────────────────────────────

#[test]
fn all_idempotency_classes_parse() {
    for class in ["strict", "best_effort", "none"] {
        let toml = base_manifest().replace(
            "idempotency = \"strict\"",
            &format!("idempotency = \"{class}\""),
        );
        parse_valid(&toml);
    }
}

// ── Risk levels and safety tiers ─────────────────────────────────────

#[test]
fn all_risk_levels_parse() {
    for level in ["low", "medium", "high", "critical"] {
        let toml =
            base_manifest().replace("risk_level = \"low\"", &format!("risk_level = \"{level}\""));
        parse_valid(&toml);
    }
}

#[test]
fn all_safety_tiers_parse() {
    for tier in ["safe", "risky", "dangerous"] {
        let toml = base_manifest().replace(
            "safety_tier = \"safe\"",
            &format!("safety_tier = \"{tier}\""),
        );
        parse_valid(&toml);
    }
}

// ── AI hints ─────────────────────────────────────────────────────────

#[test]
fn ai_hints_parse() {
    let toml = base_manifest()
        + r#"
[provides.operations.test_op.ai_hints]
when_to_use = "Use when testing"
common_mistakes = ["Forgetting auth"]
"#;
    let manifest = parse_valid(&toml);
    let hints = &manifest.provides.operations["test_op"].ai_hints;
    assert_eq!(hints.when_to_use, "Use when testing");
}

// ── Protocol features ────────────────────────────────────────────────

#[test]
fn protocol_features_parse() {
    let toml = base_manifest().replace(
        "max_datagram_bytes = 1200",
        "protocol_features = [\"fcps.aead.xchacha20poly1305\", \"fcps.compress.zstd\"]\nmax_datagram_bytes = 1200",
    );
    let manifest = parse_valid(&toml);
    assert_eq!(manifest.manifest.protocol_features.len(), 2);
}

// ── Unknown fields rejected (deny_unknown_fields) ────────────────────

#[test]
fn unknown_top_level_field_rejected() {
    let toml = base_manifest() + "extra_field = true\n";
    let err = ConnectorManifest::parse_str_unchecked(&toml);
    assert!(err.is_err());
}

#[test]
fn unknown_connector_field_rejected() {
    let toml = base_manifest().replace(
        "format = \"native\"",
        "format = \"native\"\nunknown_field = 42",
    );
    let err = ConnectorManifest::parse_str_unchecked(&toml);
    assert!(err.is_err());
}

// ── parse_str vs parse_str_unchecked ─────────────────────────────────

#[test]
fn parse_str_unchecked_skips_validation() {
    // A manifest with wrong format should parse unchecked but fail validate
    let toml = base_manifest().replace("format = \"fcp-connector-manifest\"", "format = \"wrong\"");
    let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
    assert!(m.validate().is_err());
}

#[test]
fn parse_str_runs_validation() {
    let toml = base_manifest().replace("format = \"fcp-connector-manifest\"", "format = \"wrong\"");
    let with_hash = with_computed_hash(&toml);
    assert!(ConnectorManifest::parse_str(&with_hash).is_err());
}

// ── Localhost edge cases ─────────────────────────────────────────────

#[test]
fn localhost_allowed_when_deny_localhost_false() {
    let toml = base_manifest().replace(
        "host_allow = [\"api.example.test\"], port_allow = [443], require_sni = true",
        "host_allow = [\"localhost\"], port_allow = [443], require_sni = true, deny_localhost = false",
    );
    parse_valid(&toml);
}

// ── Full manifest with all optional sections ─────────────────────────

#[test]
fn full_manifest_with_all_sections() {
    let oid1 = "11".repeat(32);
    let oid2 = "22".repeat(32);
    let toml = base_manifest()
        .replace(
            "[zones]\nhome = \"z:work\"",
            "[connector.state]\nmodel = \"singleton_writer\"\nstate_schema_version = \"1\"\nmigration_hint = \"v1-to-v2\"\n\n[zones]\nhome = \"z:work\"\nallowed_sources = [\"z:owner\"]\nallowed_targets = [\"z:community\"]\nforbidden = [\"z:public\"]",
        )
        + &format!(
            r#"
[provides.events.on_data]
description = "Data event"
streaming = true

[event_caps]
streaming = true
replay = true
min_buffer_events = 5000

[[rate_limits.pools]]
id = "global"
requests = 60
window_ms = 60000

[rate_limits.operation_pools]
test_op = ["global"]

[signatures]
publisher_threshold = "1-of-1"
[[signatures.publisher_signatures]]
kid = "pub1"
sig = "base64:AQIDBA=="

[[supply_chain.attestations]]
type = "in-toto"
object_id = "objectid:{oid1}"

[[supply_chain.attestations]]
type = "code-review"
object_id = "objectid:{oid2}"

[policy]
require_transparency_log = true
require_attestation_types = ["in-toto", "code-review"]
min_slsa_level = 2
trusted_builders = ["github-actions"]
"#
        );
    let manifest = parse_valid(&toml);
    assert!(manifest.connector.state.is_some());
    assert!(manifest.event_caps.is_some());
    assert!(manifest.rate_limits.is_some());
    assert!(manifest.signatures.is_some());
    assert!(manifest.supply_chain.is_some());
    assert!(manifest.policy.is_some());
    assert!(!manifest.provides.events.is_empty());
}
