//! Pin security-posture policy serde round-trips.
//!
//! There is no public `SecurityPosture` type in fcp-core. The public
//! security-posture policy surface is `PostureRequirements`: it captures the
//! posture checks a zone policy requires before accepting an attestation.

use ciborium::value::Value as CborValue;
use fcp_core::{PostureAttributeKey, PostureRequirement, PostureRequirements};
use std::fmt::Debug;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}

fn ensure_eq<T>(actual: &T, expected: &T, message: impl Into<String>) -> TestResult
where
    T: Debug + PartialEq + ?Sized,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{}: expected {expected:?}, got {actual:?}", message.into()).into())
    }
}

fn security_posture_policy() -> PostureRequirements {
    PostureRequirements::builder()
        .require_disk_encryption(true)
        .require_firewall(true)
        .require_os_min_version("14.2.0")
        .require_os_type_one_of(vec!["macos".to_string(), "linux".to_string()])
        .max_attestation_age_secs(900)
        .allow_verifier("mdm-primary")
        .allow_verifier("tailscale-posture")
        .build()
}

fn assert_security_posture_policy(decoded: &PostureRequirements) -> TestResult {
    ensure_eq(
        &decoded.max_attestation_age_secs,
        &900,
        "max attestation age drift",
    )?;
    ensure_eq(
        &decoded.allowed_verifiers,
        &vec!["mdm-primary".to_string(), "tailscale-posture".to_string()],
        "allowed verifier list drift",
    )?;
    ensure_eq(&decoded.requirements.len(), &4, "requirement count drift")?;

    match &decoded.requirements[0] {
        PostureRequirement::RequireTrue { attribute } => {
            ensure_eq(
                attribute,
                &PostureAttributeKey::DiskEncryption,
                "disk encryption attribute drift",
            )?;
        }
        other => return Err(format!("expected disk encryption requirement, got {other:?}").into()),
    }

    match &decoded.requirements[1] {
        PostureRequirement::RequireTrue { attribute } => {
            ensure_eq(
                attribute,
                &PostureAttributeKey::FirewallEnabled,
                "firewall attribute drift",
            )?;
        }
        other => return Err(format!("expected firewall requirement, got {other:?}").into()),
    }

    match &decoded.requirements[2] {
        PostureRequirement::RequireMinVersion {
            attribute,
            min_version,
        } => {
            ensure_eq(
                attribute,
                &PostureAttributeKey::OsVersion,
                "OS version attribute drift",
            )?;
            ensure_eq(min_version.as_str(), "14.2.0", "minimum OS version drift")?;
        }
        other => {
            return Err(format!("expected minimum OS version requirement, got {other:?}").into());
        }
    }

    match &decoded.requirements[3] {
        PostureRequirement::RequireOneOf { attribute, values } => {
            ensure_eq(
                attribute,
                &PostureAttributeKey::OsType,
                "OS type attribute drift",
            )?;
            ensure_eq(
                values,
                &vec!["macos".to_string(), "linux".to_string()],
                "OS allowlist drift",
            )?;
        }
        other => return Err(format!("expected OS allowlist requirement, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn security_posture_json_shape_is_pinned() -> TestResult {
    let value = serde_json::to_value(security_posture_policy())?;

    ensure_eq(
        &value,
        &serde_json::json!({
            "requirements": [
                {
                    "type": "require_true",
                    "attribute": "disk_encryption"
                },
                {
                    "type": "require_true",
                    "attribute": "firewall_enabled"
                },
                {
                    "type": "require_min_version",
                    "attribute": "os_version",
                    "min_version": "14.2.0"
                },
                {
                    "type": "require_one_of",
                    "attribute": "os_type",
                    "values": ["macos", "linux"]
                }
            ],
            "max_attestation_age_secs": 900,
            "allowed_verifiers": ["mdm-primary", "tailscale-posture"]
        }),
        "JSON security-posture shape drift",
    )?;

    Ok(())
}

#[test]
fn security_posture_json_roundtrip_preserves_policy() -> TestResult {
    let original = security_posture_policy();
    let json = serde_json::to_string(&original)?;
    let decoded: PostureRequirements = serde_json::from_str(&json)?;

    assert_security_posture_policy(&decoded)?;
    ensure_eq(
        &serde_json::to_value(&decoded)?,
        &serde_json::to_value(&original)?,
        "JSON roundtrip must preserve the security-posture wire shape",
    )?;

    Ok(())
}

#[test]
fn security_posture_cbor_roundtrip_preserves_policy() -> TestResult {
    let original = security_posture_policy();
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&original, &mut encoded)?;

    let decoded: PostureRequirements = ciborium::de::from_reader(encoded.as_slice())?;
    assert_security_posture_policy(&decoded)?;

    let mut reencoded = Vec::new();
    ciborium::ser::into_writer(&decoded, &mut reencoded)?;
    let original_value: CborValue = ciborium::de::from_reader(encoded.as_slice())?;
    let reencoded_value: CborValue = ciborium::de::from_reader(reencoded.as_slice())?;
    ensure_eq(
        &reencoded_value,
        &original_value,
        "CBOR roundtrip must preserve the security-posture wire shape",
    )?;

    Ok(())
}

#[test]
fn security_posture_defaults_roundtrip_from_minimal_json() -> TestResult {
    let decoded: PostureRequirements = serde_json::from_value(serde_json::json!({
        "requirements": []
    }))?;

    ensure(
        decoded.requirements.is_empty(),
        "requirements should default empty",
    )?;
    ensure(
        decoded.allowed_verifiers.is_empty(),
        "allowed verifiers should default empty",
    )?;
    ensure_eq(
        &decoded.max_attestation_age_secs,
        &86_400,
        "missing max_attestation_age_secs must default to 24 hours",
    )?;

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&decoded, &mut encoded)?;
    let cbor_decoded: PostureRequirements = ciborium::de::from_reader(encoded.as_slice())?;
    ensure(
        cbor_decoded.requirements.is_empty(),
        "CBOR requirements should stay empty",
    )?;
    ensure(
        cbor_decoded.allowed_verifiers.is_empty(),
        "CBOR allowed verifiers should stay empty",
    )?;
    ensure_eq(
        &cbor_decoded.max_attestation_age_secs,
        &86_400,
        "CBOR default max attestation age drift",
    )?;

    Ok(())
}
