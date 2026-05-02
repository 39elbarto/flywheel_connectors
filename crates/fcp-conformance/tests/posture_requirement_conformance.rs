//! `PostureRequirement` satisfaction-predicate +
//! `PostureAttestation` validity conformance.
//!
//! `fcp_core::PostureRequirement` is the device-attestation gate
//! that policy enforcement uses to decide whether a device meets
//! the posture floor for a zone. 7 variants with documented
//! satisfaction semantics:
//!
//! - `RequireTrue` — missing attribute → FAIL (no signal = no proof)
//! - `RequireFalse` — missing attribute → PASS (documented fail-open
//!    semantics for opt-in attributes; absence is treated as "not
//!    enabled")
//! - `RequireEqual` — must be present AND equal
//! - `RequireOneOf` — must be present AND in the allowed list
//! - `RequireMinVersion` — must be present AND >= min_version
//! - `RequireMinValue` — must be present AND >= min_value
//! - `RequireMaxValue` — must be present AND <= max_value
//!
//! Plus `PostureAttestation` validity (schema = "fcp.posture.v1",
//! is_valid = not-expired AND schema-matches, is_for_node, the
//! attestation's getters).

use std::collections::HashMap;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_prelude::{
    NodeId, PostureAttestation, PostureAttributeKey, PostureAttributeValue, PostureRequirement,
};

fn empty_attestation() -> PostureAttestation {
    PostureAttestation {
        schema: PostureAttestation::SCHEMA.to_string(),
        attestation_id: "att-1".into(),
        node_id: NodeId::new("node-1"),
        attributes: HashMap::new(),
        issued_at: Utc::now() - ChronoDuration::minutes(1),
        expires_at: Utc::now() + ChronoDuration::hours(1),
        verifier_id: "verifier-1".into(),
        signature: "sig".into(),
        verifier_kid: "kid-1".into(),
    }
}

fn attestation_with(attrs: &[(PostureAttributeKey, PostureAttributeValue)]) -> PostureAttestation {
    let mut attestation = empty_attestation();
    for (k, v) in attrs {
        attestation.attributes.insert(k.clone(), v.clone());
    }
    attestation
}

#[test]
fn require_true_fails_when_attribute_is_missing() {
    let req = PostureRequirement::RequireTrue {
        attribute: PostureAttributeKey::DiskEncryption,
    };
    let attestation = empty_attestation();
    assert!(
        !req.is_satisfied_by(&attestation),
        "RequireTrue MUST fail on missing attribute (no signal = no proof)"
    );
}

#[test]
fn require_true_passes_when_attribute_is_true() {
    let req = PostureRequirement::RequireTrue {
        attribute: PostureAttributeKey::DiskEncryption,
    };
    let attestation = attestation_with(&[(
        PostureAttributeKey::DiskEncryption,
        PostureAttributeValue::Bool(true),
    )]);
    assert!(req.is_satisfied_by(&attestation));
}

#[test]
fn require_true_fails_when_attribute_is_false() {
    let req = PostureRequirement::RequireTrue {
        attribute: PostureAttributeKey::DiskEncryption,
    };
    let attestation = attestation_with(&[(
        PostureAttributeKey::DiskEncryption,
        PostureAttributeValue::Bool(false),
    )]);
    assert!(!req.is_satisfied_by(&attestation));
}

#[test]
fn require_false_passes_when_attribute_is_missing_fail_open() {
    // Documented fail-open: RequireFalse on a missing attribute
    // PASSES because absence is interpreted as "not enabled". This
    // is the deliberate asymmetry with RequireTrue. Pin the
    // semantic so a regression to fail-closed wouldn't silently
    // tighten posture requirements.
    let req = PostureRequirement::RequireFalse {
        attribute: PostureAttributeKey::DeviceManaged,
    };
    let attestation = empty_attestation();
    assert!(
        req.is_satisfied_by(&attestation),
        "RequireFalse MUST pass on missing attribute (documented fail-open semantics — \
         absence treated as 'not enabled')"
    );
}

#[test]
fn require_false_passes_when_attribute_is_false() {
    let req = PostureRequirement::RequireFalse {
        attribute: PostureAttributeKey::DeviceManaged,
    };
    let attestation = attestation_with(&[(
        PostureAttributeKey::DeviceManaged,
        PostureAttributeValue::Bool(false),
    )]);
    assert!(req.is_satisfied_by(&attestation));
}

#[test]
fn require_false_fails_when_attribute_is_true() {
    let req = PostureRequirement::RequireFalse {
        attribute: PostureAttributeKey::DeviceManaged,
    };
    let attestation = attestation_with(&[(
        PostureAttributeKey::DeviceManaged,
        PostureAttributeValue::Bool(true),
    )]);
    assert!(!req.is_satisfied_by(&attestation));
}

#[test]
fn require_equal_passes_only_on_exact_string_match() {
    let req = PostureRequirement::RequireEqual {
        attribute: PostureAttributeKey::OsType,
        value: "macos".into(),
    };
    let matched = attestation_with(&[(
        PostureAttributeKey::OsType,
        PostureAttributeValue::String("macos".into()),
    )]);
    let mismatched = attestation_with(&[(
        PostureAttributeKey::OsType,
        PostureAttributeValue::String("windows".into()),
    )]);
    let missing = empty_attestation();

    assert!(req.is_satisfied_by(&matched));
    assert!(!req.is_satisfied_by(&mismatched));
    assert!(!req.is_satisfied_by(&missing));
}

#[test]
fn require_one_of_accepts_any_listed_value() {
    let req = PostureRequirement::RequireOneOf {
        attribute: PostureAttributeKey::OsType,
        values: vec!["macos".into(), "linux".into()],
    };
    for value in ["macos", "linux"] {
        let attestation = attestation_with(&[(
            PostureAttributeKey::OsType,
            PostureAttributeValue::String(value.into()),
        )]);
        assert!(req.is_satisfied_by(&attestation), "MUST accept {value:?}");
    }
}

#[test]
fn require_one_of_rejects_unlisted_value() {
    let req = PostureRequirement::RequireOneOf {
        attribute: PostureAttributeKey::OsType,
        values: vec!["macos".into(), "linux".into()],
    };
    let attestation = attestation_with(&[(
        PostureAttributeKey::OsType,
        PostureAttributeValue::String("freebsd".into()),
    )]);
    assert!(!req.is_satisfied_by(&attestation));
}

#[test]
fn require_one_of_rejects_when_attribute_is_missing() {
    let req = PostureRequirement::RequireOneOf {
        attribute: PostureAttributeKey::OsType,
        values: vec!["macos".into()],
    };
    let attestation = empty_attestation();
    assert!(
        !req.is_satisfied_by(&attestation),
        "RequireOneOf MUST require the attribute be present (no fail-open here, unlike \
         RequireFalse)"
    );
}

#[test]
fn require_min_version_compares_semver_style() {
    let req = PostureRequirement::RequireMinVersion {
        attribute: PostureAttributeKey::OsVersion,
        min_version: "14.0.0".into(),
    };
    for (version, expected) in [
        ("14.0.0", true),
        ("14.0.1", true),
        ("14.2.5", true),
        ("15.0.0", true),
        ("13.9.9", false),
        ("13.0.0", false),
    ] {
        let attestation = attestation_with(&[(
            PostureAttributeKey::OsVersion,
            PostureAttributeValue::String(version.into()),
        )]);
        assert_eq!(
            req.is_satisfied_by(&attestation),
            expected,
            "version={version} MUST satisfy={expected} against min=14.0.0"
        );
    }
}

#[test]
fn require_min_value_compares_numeric() {
    let req = PostureRequirement::RequireMinValue {
        attribute: PostureAttributeKey::ScreenLockTimeout,
        min_value: 60,
    };
    for (value, expected) in [
        (0, false),
        (59, false),
        (60, true),
        (61, true),
        (3600, true),
    ] {
        let attestation = attestation_with(&[(
            PostureAttributeKey::ScreenLockTimeout,
            PostureAttributeValue::Number(value),
        )]);
        assert_eq!(
            req.is_satisfied_by(&attestation),
            expected,
            "value={value} MUST satisfy={expected} against min=60"
        );
    }
}

#[test]
fn require_max_value_compares_numeric() {
    let req = PostureRequirement::RequireMaxValue {
        attribute: PostureAttributeKey::ScreenLockTimeout,
        max_value: 600,
    };
    for (value, expected) in [(0, true), (600, true), (601, false), (3600, false)] {
        let attestation = attestation_with(&[(
            PostureAttributeKey::ScreenLockTimeout,
            PostureAttributeValue::Number(value),
        )]);
        assert_eq!(
            req.is_satisfied_by(&attestation),
            expected,
            "value={value} MUST satisfy={expected} against max=600"
        );
    }
}

#[test]
fn require_numeric_returns_false_for_string_value_type_mismatch() {
    // RequireMinValue applied to a string attribute MUST NOT
    // panic — it returns false (type mismatch is not satisfaction).
    let req = PostureRequirement::RequireMinValue {
        attribute: PostureAttributeKey::OsVersion,
        min_value: 60,
    };
    let attestation = attestation_with(&[(
        PostureAttributeKey::OsVersion,
        PostureAttributeValue::String("14.0.0".into()),
    )]);
    assert!(
        !req.is_satisfied_by(&attestation),
        "RequireMinValue with a String value MUST return false (no panic on type mismatch)"
    );
}

#[test]
fn attribute_returns_the_underlying_key_for_each_variant() {
    let key = PostureAttributeKey::DiskEncryption;
    let variants = [
        PostureRequirement::RequireTrue {
            attribute: key.clone(),
        },
        PostureRequirement::RequireFalse {
            attribute: key.clone(),
        },
        PostureRequirement::RequireEqual {
            attribute: key.clone(),
            value: "x".into(),
        },
        PostureRequirement::RequireOneOf {
            attribute: key.clone(),
            values: vec![],
        },
        PostureRequirement::RequireMinVersion {
            attribute: key.clone(),
            min_version: "1.0.0".into(),
        },
        PostureRequirement::RequireMinValue {
            attribute: key.clone(),
            min_value: 1,
        },
        PostureRequirement::RequireMaxValue {
            attribute: key.clone(),
            max_value: 1,
        },
    ];
    for req in variants {
        assert_eq!(
            req.attribute(),
            &key,
            "attribute() MUST return the underlying key for every variant"
        );
    }
}

#[test]
fn attestation_schema_constant_is_fcp_posture_v1() {
    assert_eq!(
        PostureAttestation::SCHEMA,
        "fcp.posture.v1",
        "PostureAttestation::SCHEMA MUST be the documented wire string — drift breaks \
         every verifier interop"
    );
}

#[test]
fn attestation_is_valid_requires_unexpired_and_correct_schema() {
    // Both must be true.
    let mut a = empty_attestation();
    assert!(
        a.is_valid(),
        "fresh attestation with correct schema is valid"
    );

    a.expires_at = Utc::now() - ChronoDuration::minutes(1);
    assert!(!a.is_valid(), "expired attestation MUST NOT be valid");

    let mut b = empty_attestation();
    b.schema = "wrong-schema".into();
    assert!(!b.is_valid(), "wrong schema MUST NOT be valid");
}

#[test]
fn attestation_is_for_node_compares_node_id() {
    let a = empty_attestation();
    assert!(a.is_for_node(&NodeId::new("node-1")));
    assert!(!a.is_for_node(&NodeId::new("node-2")));
}

#[test]
fn attestation_get_attribute_returns_value_or_none() {
    let attestation = attestation_with(&[(
        PostureAttributeKey::OsType,
        PostureAttributeValue::String("linux".into()),
    )]);
    let got = attestation.get_attribute(&PostureAttributeKey::OsType);
    assert!(matches!(
        got,
        Some(PostureAttributeValue::String(s)) if s == "linux"
    ));
    assert!(
        attestation
            .get_attribute(&PostureAttributeKey::FirewallEnabled)
            .is_none()
    );
}

#[test]
fn attribute_value_as_bool_str_number_only_match_the_corresponding_variant() {
    let b = PostureAttributeValue::Bool(true);
    let s = PostureAttributeValue::String("hi".into());
    let n = PostureAttributeValue::Number(42);

    assert_eq!(b.as_bool(), Some(true));
    assert!(b.as_str().is_none());
    assert!(b.as_number().is_none());

    assert!(s.as_bool().is_none());
    assert_eq!(s.as_str(), Some("hi"));
    assert!(s.as_number().is_none());

    assert!(n.as_bool().is_none());
    assert!(n.as_str().is_none());
    assert_eq!(n.as_number(), Some(42));
}

#[test]
fn posture_attribute_key_as_str_uses_snake_case() {
    use PostureAttributeKey::*;
    let pairs = [
        (OsType, "os_type"),
        (OsVersion, "os_version"),
        (DiskEncryption, "disk_encryption"),
        (FirewallEnabled, "firewall_enabled"),
        (ScreenLockEnabled, "screen_lock_enabled"),
        (ScreenLockTimeout, "screen_lock_timeout"),
        (AntivirusActive, "antivirus_active"),
        (DeviceManaged, "device_managed"),
        (SecureBootEnabled, "secure_boot_enabled"),
        (TpmPresent, "tpm_present"),
    ];
    for (variant, expected) in pairs {
        assert_eq!(variant.as_str(), expected);
    }
}

#[test]
fn posture_attribute_key_custom_passes_through_string() {
    let custom = PostureAttributeKey::Custom("vendor_specific_key".into());
    assert_eq!(custom.as_str(), "vendor_specific_key");
}
