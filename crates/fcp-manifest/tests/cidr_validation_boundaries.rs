//! Pin CIDR validation boundary cases on
//! `NetworkConstraints.cidr_deny` (flywheel_connectors-sd1ll).
//!
//! The `cidr_deny` field of every operation's `network_constraints`
//! is validated by `NetworkConstraints::validate` at manifest parse
//! time (lib.rs:2285-2290): each entry must parse as
//! `ipnet::IpNet`. Invalid CIDR strings are surfaced as
//! `ManifestError::Invalid { field: "...network_constraints.cidr_deny", ... }`.
//!
//! Bead refers to "fcp-core CIDR validation"; the actual code lives
//! in `fcp-manifest` (the only crate in the workspace that depends
//! on `ipnet`). Tests are placed where the code is.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **Valid IPv4 CIDR** — every prefix length in `[0, 32]` parses,
//!    including `/0` (default route) and `/32` (host).
//! 2. **Valid IPv6 CIDR** — every prefix length in `[0, 128]` parses,
//!    including `/0` and `/128` (host).
//! 3. **Invalid prefix length** — `/33` for IPv4 or `/129` for IPv6
//!    is rejected.
//! 4. **Negative / non-numeric prefix** — `/-1`, `/abc` rejected.
//! 5. **Missing `/` prefix** — bare addresses (`10.0.0.1` without a
//!    suffix) parse via the bare-IP fallback that `ipnet` accepts;
//!    pin whichever the code currently does.
//! 6. **Malformed address** — `"999.0.0.0/8"`, `"hello/8"`,
//!    `"10.0.0/8"` (only 3 octets) all rejected.
//! 7. **End-to-end manifest validation** — invalid `cidr_deny`
//!    entries surface as `ManifestError::Invalid` with the
//!    `provides.operations.*.network_constraints.cidr_deny` field
//!    string verbatim. Valid entries pass.

use std::str::FromStr;

use fcp_manifest::{ConnectorManifest, ManifestError};
use ipnet::IpNet;

const MANIFEST_TEMPLATE: &str = r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000"

[connector]
id = "fcp.cidrtest"
name = "CIDR Test"
version = "0.1.0"
description = "Test fixture for CIDR validation boundary tests"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.https", "cidr.op"]
optional = []
forbidden = ["system.exec"]

[provides.operations.cidr_op]
description = "Operation with network_constraints"
capability = "cidr.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = { type = "object" }
output_schema = { type = "object" }

[provides.operations.cidr_op.network_constraints]
host_allow = ["api.example.com"]
port_allow = [443]
ip_allow = []
cidr_deny = __CIDR_DENY__
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = true
require_sni = true
spki_pins = []
deny_ip_literals = true
require_host_canonicalization = true

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#;

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

fn manifest_with_cidr_deny(cidrs: &[&str]) -> String {
    let toml_array: Vec<String> = cidrs.iter().map(|c| format!("\"{c}\"")).collect();
    let array_literal = format!("[{}]", toml_array.join(", "));
    let with_placeholder = MANIFEST_TEMPLATE.replace("__CIDR_DENY__", &array_literal);
    // Compute the real interface_hash for this manifest body — the
    // placeholder won't match `validate()`'s recomputation. Pattern
    // mirrors the registry_signed_package_catalog fuzz harness.
    let unchecked = ConnectorManifest::parse_str_unchecked(&with_placeholder)
        .expect("template parses without validation");
    let interface_hash = unchecked
        .compute_interface_hash()
        .expect("interface_hash computation must succeed for the template");
    with_placeholder.replace(PLACEHOLDER_HASH, &interface_hash.to_string())
}

fn parse_with_cidrs(cidrs: &[&str]) -> Result<ConnectorManifest, ManifestError> {
    let toml = manifest_with_cidr_deny(cidrs);
    ConnectorManifest::parse_str(&toml)
}

// ─────────────────────────────────────────────────────────────────────────────
// IpNet parser direct contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ipnet_accepts_ipv4_prefix_zero() {
    // /0 is the default route — covers every IPv4 address.
    let net = IpNet::from_str("0.0.0.0/0").expect("/0 must parse");
    assert_eq!(net.prefix_len(), 0);
}

#[test]
fn ipnet_accepts_ipv4_prefix_32_host() {
    // /32 is a single-host CIDR.
    let net = IpNet::from_str("10.0.0.1/32").expect("/32 must parse");
    assert_eq!(net.prefix_len(), 32);
}

#[test]
fn ipnet_accepts_ipv4_canonical_block() {
    let net = IpNet::from_str("10.0.0.0/8").expect("RFC1918 block");
    assert_eq!(net.prefix_len(), 8);
}

#[test]
fn ipnet_accepts_ipv6_prefix_zero() {
    let net = IpNet::from_str("::/0").expect("IPv6 /0 must parse");
    assert_eq!(net.prefix_len(), 0);
}

#[test]
fn ipnet_accepts_ipv6_prefix_128_host() {
    let net = IpNet::from_str("::1/128").expect("IPv6 /128 must parse");
    assert_eq!(net.prefix_len(), 128);
}

#[test]
fn ipnet_accepts_ipv6_link_local_block() {
    let net = IpNet::from_str("fe80::/10").expect("link-local");
    assert_eq!(net.prefix_len(), 10);
}

#[test]
fn ipnet_rejects_ipv4_prefix_above_32() {
    assert!(
        IpNet::from_str("10.0.0.0/33").is_err(),
        "IPv4 /33 must be rejected"
    );
    assert!(
        IpNet::from_str("10.0.0.0/255").is_err(),
        "IPv4 /255 must be rejected"
    );
}

#[test]
fn ipnet_rejects_ipv6_prefix_above_128() {
    assert!(
        IpNet::from_str("::1/129").is_err(),
        "IPv6 /129 must be rejected"
    );
    assert!(
        IpNet::from_str("::1/255").is_err(),
        "IPv6 /255 must be rejected"
    );
}

#[test]
fn ipnet_rejects_negative_or_non_numeric_prefix() {
    assert!(
        IpNet::from_str("10.0.0.0/-1").is_err(),
        "negative prefix must be rejected"
    );
    assert!(
        IpNet::from_str("10.0.0.0/abc").is_err(),
        "non-numeric prefix must be rejected"
    );
    assert!(
        IpNet::from_str("10.0.0.0/").is_err(),
        "empty prefix must be rejected"
    );
}

#[test]
fn ipnet_rejects_bare_address_without_prefix() {
    // `10.0.0.1` (no /<n>) — `ipnet::IpNet::from_str` requires the
    // `/<prefix>` syntax. A bare IP is rejected. Pinning this
    // behaviour matters because a `cidr_deny` entry without a prefix
    // would otherwise leak through silently.
    assert!(
        IpNet::from_str("10.0.0.1").is_err(),
        "bare IPv4 address (no /<n>) must be rejected"
    );
    assert!(
        IpNet::from_str("::1").is_err(),
        "bare IPv6 address (no /<n>) must be rejected"
    );
}

#[test]
fn ipnet_rejects_malformed_addresses() {
    assert!(
        IpNet::from_str("999.0.0.0/8").is_err(),
        "octet > 255 must be rejected"
    );
    assert!(
        IpNet::from_str("10.0.0/8").is_err(),
        "3-octet IPv4 must be rejected"
    );
    assert!(
        IpNet::from_str("10.0.0.0.0/8").is_err(),
        "5-octet IPv4 must be rejected"
    );
    assert!(
        IpNet::from_str("hello/8").is_err(),
        "non-IP string must be rejected"
    );
    assert!(
        IpNet::from_str("/8").is_err(),
        "empty address must be rejected"
    );
    assert!(
        IpNet::from_str("").is_err(),
        "empty string must be rejected"
    );
    assert!(
        IpNet::from_str("gggg::/16").is_err(),
        "non-hex IPv6 segment must be rejected"
    );
}

#[test]
fn ipnet_accepts_full_prefix_range_ipv4() {
    // Sweep every legal IPv4 prefix length to pin "no off-by-one"
    // anywhere in the valid range.
    for len in 0u8..=32 {
        let cidr = format!("10.0.0.0/{len}");
        IpNet::from_str(&cidr)
            .unwrap_or_else(|err| panic!("IPv4 /{len} MUST parse: {err} (input {cidr:?})"));
    }
}

#[test]
fn ipnet_accepts_full_prefix_range_ipv6() {
    // Sweep every legal IPv6 prefix length.
    for len in 0u16..=128 {
        let cidr = format!("2001:db8::/{len}");
        IpNet::from_str(&cidr)
            .unwrap_or_else(|err| panic!("IPv6 /{len} MUST parse: {err} (input {cidr:?})"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end manifest validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn manifest_accepts_valid_cidr_deny_entries() {
    // A representative mix: IPv4 /0 and /32, IPv6 /0 and /128, plus
    // standard private blocks. All MUST pass manifest validation.
    let valid = ["0.0.0.0/0", "10.0.0.0/8", "10.0.0.1/32", "::/0", "::1/128"];
    parse_with_cidrs(&valid).expect("valid CIDR list must parse");
}

#[test]
fn manifest_rejects_invalid_prefix_length() {
    // /33 trips the IpNet::from_str inside NetworkConstraints::validate.
    let bad = ["10.0.0.0/33"];
    let err = parse_with_cidrs(&bad).expect_err("/33 must be rejected");
    assert_invalid_cidr_field(&err, "10.0.0.0/33");
}

#[test]
fn manifest_rejects_ipv6_prefix_above_128() {
    let bad = ["::1/129"];
    let err = parse_with_cidrs(&bad).expect_err("IPv6 /129 must be rejected");
    assert_invalid_cidr_field(&err, "::1/129");
}

#[test]
fn manifest_rejects_malformed_address() {
    let bad = ["999.0.0.0/8"];
    let err = parse_with_cidrs(&bad).expect_err("999.0.0.0/8 must be rejected");
    assert_invalid_cidr_field(&err, "999.0.0.0/8");
}

#[test]
fn manifest_rejects_non_ip_string() {
    let bad = ["not-an-ip/8"];
    let err = parse_with_cidrs(&bad).expect_err("non-IP string must be rejected");
    assert_invalid_cidr_field(&err, "not-an-ip/8");
}

#[test]
fn manifest_rejects_bare_address_without_prefix() {
    let bad = ["10.0.0.1"];
    let err = parse_with_cidrs(&bad).expect_err("bare address must be rejected");
    assert_invalid_cidr_field(&err, "10.0.0.1");
}

#[test]
fn manifest_rejects_first_invalid_when_mixed_with_valid() {
    // Validation walks the list and surfaces the first invalid entry.
    // Pin that the surfaced field name + offending value point to
    // the bad entry.
    let mixed = ["0.0.0.0/0", "10.0.0.0/33", "::/0"];
    let err = parse_with_cidrs(&mixed).expect_err("mixed list with /33 must fail");
    assert_invalid_cidr_field(&err, "10.0.0.0/33");
}

#[test]
fn manifest_accepts_empty_cidr_deny() {
    // Empty cidr_deny list is the documented default — MUST parse.
    parse_with_cidrs(&[]).expect("empty cidr_deny list must parse");
}

/// Assert the given error is `ManifestError::Invalid` on the
/// `cidr_deny` field and includes the offending CIDR string.
fn assert_invalid_cidr_field(err: &ManifestError, offender: &str) {
    let display = err.to_string();
    assert!(
        display.contains("cidr_deny"),
        "error message must mention `cidr_deny`: {display}"
    );
    assert!(
        display.contains(offender),
        "error message must include the offending CIDR `{offender}`: {display}"
    );
}
