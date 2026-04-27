//! `McpProtocolVersion` wire-version negotiation conformance.
//!
//! `fcp_host::McpProtocolVersion` governs MCP version negotiation
//! for the host's agent endpoint. The wire-format strings
//! ("2025-03-26", "2024-11-05") are baked into serde renames and
//! must NOT drift, otherwise version negotiation between the host
//! and any third-party MCP client breaks silently with no
//! cryptographic signal — the failure surfaces as a generic
//! "unsupported protocol version" downstream.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`as_str` matches the wire-format negotiation string.** The
//!    public string is what every MCP client compares against.
//! 2. **`as_str` matches the serde rename.** Display, JSON
//!    serialization, and the version-negotiation comparison must
//!    all agree on the literal string.
//! 3. **`latest()` returns V2025_03.** Bumping latest is a
//!    deliberate cross-release coordination step, not a stealth
//!    change.
//! 4. **`supports_annotations` matrix.** V2025_03 yes, V2024_11
//!    no — pins the documented capability gate.
//! 5. **`Default == latest()`.**
//! 6. **`Display` equals `as_str`.**
//! 7. **JSON serde roundtrip preserves the wire string** — both
//!    serialization and deserialization use the rename consistently.

use fcp_host::McpProtocolVersion;

#[test]
fn v2025_03_as_str_is_2025_03_26() {
    // The wire string MUST be "2025-03-26" — anything else breaks
    // the negotiation handshake with any compliant MCP client.
    assert_eq!(McpProtocolVersion::V2025_03.as_str(), "2025-03-26");
}

#[test]
fn v2024_11_as_str_is_2024_11_05() {
    assert_eq!(McpProtocolVersion::V2024_11.as_str(), "2024-11-05");
}

#[test]
fn latest_returns_v2025_03() {
    // latest() is the default the host advertises. Bumping it is a
    // deliberate cross-release coordination step.
    assert_eq!(
        McpProtocolVersion::latest(),
        McpProtocolVersion::V2025_03,
        "latest() MUST return V2025_03; if a newer variant is added, this test must be \
         updated in the same change so the bump is intentional"
    );
}

#[test]
fn default_equals_latest() {
    assert_eq!(
        McpProtocolVersion::default(),
        McpProtocolVersion::latest(),
        "Default impl MUST delegate to latest() so newly-constructed values pick up version bumps automatically"
    );
}

#[test]
fn display_equals_as_str() {
    assert_eq!(
        format!("{}", McpProtocolVersion::V2025_03),
        McpProtocolVersion::V2025_03.as_str(),
    );
    assert_eq!(
        format!("{}", McpProtocolVersion::V2024_11),
        McpProtocolVersion::V2024_11.as_str(),
    );
}

#[test]
fn supports_annotations_is_the_documented_matrix() {
    // V2025_03 introduced tool annotations; V2024_11 did not.
    assert!(
        McpProtocolVersion::V2025_03.supports_annotations(),
        "V2025_03 MUST report supports_annotations=true (introduced in this revision)"
    );
    assert!(
        !McpProtocolVersion::V2024_11.supports_annotations(),
        "V2024_11 MUST report supports_annotations=false (predates the feature)"
    );
}

#[test]
fn json_serde_roundtrip_preserves_wire_string() {
    // The serde rename MUST match as_str. Otherwise serialization
    // and version-negotiation comparison would disagree on the
    // literal string and the host would advertise a version no
    // client recognizes.
    for version in [
        McpProtocolVersion::V2025_03,
        McpProtocolVersion::V2024_11,
    ] {
        let json = serde_json::to_string(&version).expect("serialize");
        // The serialized JSON is a quoted string equal to as_str.
        let expected = format!("\"{}\"", version.as_str());
        assert_eq!(
            json, expected,
            "JSON serialization MUST match as_str: got {json}, expected {expected}"
        );

        let parsed: McpProtocolVersion =
            serde_json::from_str(&json).expect("deserialize roundtrip");
        assert_eq!(
            parsed, version,
            "JSON deserialization MUST recover the original variant"
        );
    }
}

#[test]
fn json_deserialization_accepts_only_known_strings() {
    // A misspelled or future version string MUST fail to
    // deserialize — otherwise an attacker (or a typo) could
    // negotiate to a phantom version.
    let bogus_inputs = [
        "\"2099-99-99\"",
        "\"2025-03-26-extra\"",
        "\"v2025_03\"",
        "\"\"",
        "\"latest\"",
    ];
    for input in bogus_inputs {
        let result = serde_json::from_str::<McpProtocolVersion>(input);
        assert!(
            result.is_err(),
            "deserialization of {input:?} MUST fail; got Ok({result:?})"
        );
    }
}

#[test]
fn versions_compare_by_variant_equality() {
    // PartialEq + Eq are derived; pin that the same variant is
    // self-equal and different variants are unequal. Without this
    // version negotiation can't make decisions.
    assert_eq!(
        McpProtocolVersion::V2025_03,
        McpProtocolVersion::V2025_03
    );
    assert_eq!(
        McpProtocolVersion::V2024_11,
        McpProtocolVersion::V2024_11
    );
    assert_ne!(
        McpProtocolVersion::V2025_03,
        McpProtocolVersion::V2024_11
    );
}

#[test]
fn copy_semantics_allow_inline_use() {
    // McpProtocolVersion derives Copy — pin that it can be passed
    // by value multiple times without consuming. This matters for
    // the negotiation code which threads the version through
    // multiple decision points.
    let v = McpProtocolVersion::V2025_03;
    let _a = v;
    let _b = v;
    let _c = v.as_str();
    assert_eq!(v.as_str(), "2025-03-26");
}
