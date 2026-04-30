//! Pin fcp-core's exported capability-scope serde vocabulary.
//!
//! No type literally named `CapabilityScope` exists in fcp-core. The capability
//! module's public scope enum is `OperationRateLimitScope`, carried by
//! `RateLimit::scope`, so this test pins its JSON and CBOR wire tags for
//! `flywheel_connectors-okv8u`.

use ciborium::Value as CborValue;
use fcp_core::OperationRateLimitScope;
use serde_json::json;
use std::error::Error;
use std::fmt::Debug;

type TestResult = Result<(), Box<dyn Error>>;

fn err(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure_eq<T>(actual: T, expected: T, context: &str) -> TestResult
where
    T: PartialEq + Debug,
{
    if actual == expected {
        Ok(())
    } else {
        Err(err(format!(
            "{context}: expected {expected:?}, got {actual:?}"
        )))
    }
}

fn ensure(condition: bool, context: impl Into<String>) -> TestResult {
    if condition { Ok(()) } else { Err(err(context)) }
}

const CAPABILITY_SCOPE_CASES: &[(OperationRateLimitScope, &str)] = &[
    (OperationRateLimitScope::PerConnector, "per_connector"),
    (OperationRateLimitScope::PerZone, "per_zone"),
    (OperationRateLimitScope::PerPrincipal, "per_principal"),
];

#[test]
fn capability_scope_json_tags_roundtrip_per_variant() -> TestResult {
    for &(scope, tag) in CAPABILITY_SCOPE_CASES {
        let value = serde_json::to_value(scope)?;
        ensure_eq(value, json!(tag), &format!("{scope:?} JSON tag"))?;

        let decoded: OperationRateLimitScope = serde_json::from_value(json!(tag))?;
        ensure_eq(decoded, scope, &format!("{scope:?} JSON roundtrip"))?;
    }

    Ok(())
}

#[test]
fn capability_scope_cbor_tags_roundtrip_per_variant() -> TestResult {
    for &(scope, tag) in CAPABILITY_SCOPE_CASES {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&scope, &mut bytes)?;

        let decoded: OperationRateLimitScope = ciborium::de::from_reader(bytes.as_slice())?;
        ensure_eq(decoded, scope, &format!("{scope:?} CBOR roundtrip"))?;

        let value: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
        match value {
            CborValue::Text(text) => ensure_eq(text, tag.to_string(), "CBOR text tag")?,
            other => {
                return Err(err(format!(
                    "{scope:?} must encode as a CBOR text tag, got {other:?}"
                )));
            }
        }
    }

    Ok(())
}

#[test]
fn capability_scope_tags_are_complete_and_distinct() -> TestResult {
    let mut tags = std::collections::BTreeSet::new();
    for &(scope, tag) in CAPABILITY_SCOPE_CASES {
        ensure(
            tags.insert(tag),
            format!("duplicate capability-scope tag for {scope:?}: {tag}"),
        )?;
    }

    ensure_eq(
        tags,
        std::collections::BTreeSet::from(["per_connector", "per_zone", "per_principal"]),
        "capability-scope tag set",
    )
}

#[test]
fn capability_scope_rejects_noncanonical_json_tags() -> TestResult {
    for bad in [
        "PerConnector",
        "per-connector",
        "PER_ZONE",
        "per_user",
        "global",
    ] {
        let result: Result<OperationRateLimitScope, _> = serde_json::from_value(json!(bad));
        ensure(
            result.is_err(),
            format!("capability scope must reject noncanonical tag `{bad}`, got {result:?}"),
        )?;
    }

    Ok(())
}
