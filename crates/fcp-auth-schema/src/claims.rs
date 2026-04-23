//! Typed capability-token claim set + canonical-CBOR serialization.
//!
//! `AuthClaims` is the single typed schema consumed by both
//! `fcp-crypto::cose::CapabilityTokenBuilder` (builder side) and
//! `fcp-core::CapabilityVerifier` (verifier side).
//!
//! ## Canonical CBOR
//!
//! [`AuthClaims::to_canonical_cbor`] produces a CBOR map where entries
//! are sorted by label integer (lowest first, negative integers sort
//! below positive per Rust `i64` ordering). This makes serialization
//! **deterministic** — two serializations of equal `AuthClaims` values
//! produce byte-identical output regardless of field-declaration order
//! or system-specific hash randomness.
//!
//! Absent optional fields and empty collections are OMITTED from the
//! encoded map. Round-trip through `to_canonical_cbor` →
//! `from_canonical_cbor` is lossless for typed fields; free-form
//! `extra` claims preserve whatever CBOR value they were decoded from.

use crate::labels::{cwt_claims, fcp2_claims};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Current schema version stamped on freshly-minted `AuthClaims`.
///
/// Verifiers reject tokens with a version outside their accepted set.
/// Policy for bumping this constant lives in
/// `docs/architecture/adr/8n0rm-claim-schema-versioning.md`.
pub const CURRENT_SCHEMA_VERSION: u16 = 1;

/// Errors produced while serializing or deserializing `AuthClaims`.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// Underlying CBOR encoder failed.
    #[error("CBOR encode error: {0}")]
    Encode(String),
    /// Underlying CBOR decoder failed.
    #[error("CBOR decode error: {0}")]
    Decode(String),
    /// Claim carried a value of an unexpected CBOR type.
    #[error("claim {label}: expected {expected}, got {got}")]
    UnexpectedType {
        /// CBOR integer label.
        label: i64,
        /// Expected type name.
        expected: &'static str,
        /// Observed type name.
        got: &'static str,
    },
    /// Timestamp value did not fit a valid `DateTime`.
    #[error("claim {label}: invalid timestamp {value}")]
    InvalidTimestamp {
        /// CBOR integer label.
        label: i64,
        /// Observed timestamp.
        value: i64,
    },
    /// Schema-version mismatch. Verifier sets this via
    /// `AuthClaims::check_schema_version` (in 8n0rm.5); serde does not
    /// enforce it during decode.
    #[error("schema_version {got} not accepted (expected {expected})")]
    UnsupportedSchemaVersion {
        /// Version present on the token.
        got: u16,
        /// Version the verifier accepts.
        expected: u16,
    },
}

/// Typed capability-token claim set.
///
/// The fields correspond 1-to-1 with CBOR integer labels in
/// `crate::labels::{cwt_claims, fcp2_claims}`. Canonical CBOR emits
/// only non-`None` and non-empty fields; see module-level docs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuthClaims {
    /// Schema version. Always emitted. Bumping is a deployment-breaking
    /// change — see the versioning ADR.
    pub schema_version: u16,

    // ── CWT standard ──────────────────────────────────────────────
    /// `iss` — issuer (text). In FCP this carries the zone id.
    pub issuer: Option<String>,
    /// `sub` — subject (text).
    pub subject: Option<String>,
    /// `aud` — audience (text).
    pub audience: Option<String>,
    /// `exp` — expiration time.
    pub expiration: Option<DateTime<Utc>>,
    /// `nbf` — not-before.
    pub not_before: Option<DateTime<Utc>>,
    /// `iat` — issued-at.
    pub issued_at: Option<DateTime<Utc>>,
    /// `cti` — token id (bytes).
    pub token_id: Option<Vec<u8>>,

    // ── FCP2 ──────────────────────────────────────────────────────
    /// Capability id the token asserts.
    pub capability_id: Option<String>,
    /// Zone scope required for use.
    pub zone_id: Option<String>,
    /// Principal on whose behalf the token is exercised.
    pub principal_id: Option<String>,
    /// Node that minted the token.
    pub issuing_node: Option<String>,
    /// Node currently holding / exercising the token.
    pub holder_node: Option<String>,
    /// Binary audience / object id.
    pub audience_binary: Option<Vec<u8>>,
    /// Object ids this grant covers.
    pub grant_object_ids: Vec<Vec<u8>>,
    /// Checkpoint identifier (bytes).
    pub checkpoint_id: Option<Vec<u8>>,
    /// Checkpoint sequence.
    pub checkpoint_seq: Option<u64>,
    /// Connector-instance binding target.
    pub instance_id: Option<String>,
    /// Delegation depth (for delegated tokens).
    pub delegation_depth: Option<u64>,
    /// Parent token id (for delegation chains).
    pub parent_token: Option<Vec<u8>>,

    /// Granted capabilities. Canonical shape; legacy `OPERATIONS`
    /// claim is not emitted by this struct and is rejected by the
    /// verifier after 8n0rm.6.
    ///
    /// Shape is opaque CBOR here so this crate does not need to
    /// depend on `fcp-core::CapabilityGrant`; the verifier
    /// deserializes the inner `Value::Map` into `CapabilityGrant`
    /// using its own typed knowledge.
    pub grants: Vec<ciborium::Value>,

    /// Resource / call constraints. Opaque CBOR for the same reason
    /// as `grants`.
    pub constraints: Option<ciborium::Value>,
}

impl AuthClaims {
    /// A fresh empty claim set stamped with [`CURRENT_SCHEMA_VERSION`].
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            ..Default::default()
        }
    }

    /// Reject claims whose `schema_version` is not in the caller's
    /// accepted set.
    ///
    /// Verifiers call this early in their pipeline so unsupported
    /// schema versions produce a clear error rather than a confusing
    /// field-level decode failure downstream.
    ///
    /// Passing a single-element `expected` slice (e.g.
    /// `&[CURRENT_SCHEMA_VERSION]`) is the normal case. During a
    /// deployment-wide version bump, pass both the old and the new
    /// (e.g. `&[1, 2]`) for one release cycle; drop the old once all
    /// issuers have rolled forward.
    ///
    /// # Errors
    /// Returns [`SchemaError::UnsupportedSchemaVersion`] when the
    /// claim set's `schema_version` is not in `expected`. The
    /// returned error's `expected` field carries the FIRST entry of
    /// the accepted set (for diagnostics; the verifier's decision
    /// was made against the full set).
    pub fn check_schema_version(&self, expected: &[u16]) -> Result<(), SchemaError> {
        if expected.contains(&self.schema_version) {
            Ok(())
        } else {
            Err(SchemaError::UnsupportedSchemaVersion {
                got: self.schema_version,
                expected: expected.first().copied().unwrap_or(CURRENT_SCHEMA_VERSION),
            })
        }
    }

    /// Serialize to canonical CBOR.
    ///
    /// Determinism: entries are sorted by CBOR integer label
    /// (ascending, so negative FCP2 labels emit before positive CWT
    /// labels). Absent / empty optional fields are OMITTED.
    ///
    /// # Errors
    /// Propagates any underlying CBOR encoder error from `ciborium`.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SchemaError> {
        let map = self.to_canonical_map();
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut bytes)
            .map_err(|e| SchemaError::Encode(e.to_string()))?;
        Ok(bytes)
    }

    /// Inverse of `to_canonical_cbor`. Accepts any CBOR map with the
    /// canonical integer labels; extra labels are silently ignored
    /// (forward-compat for minor schema additions).
    ///
    /// # Errors
    /// Propagates CBOR decoder errors and per-label type mismatches.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SchemaError> {
        let value: ciborium::Value = ciborium::from_reader(bytes)
            .map_err(|e| SchemaError::Decode(e.to_string()))?;
        let ciborium::Value::Map(entries) = value else {
            return Err(SchemaError::Decode(
                "top-level CBOR value must be a map".into(),
            ));
        };
        Self::from_map_entries(entries)
    }

    /// Produce the canonical CBOR map (sorted entries, omitted
    /// absents) as a borrowable `Vec<(Value, Value)>`.
    fn to_canonical_map(&self) -> Vec<(ciborium::Value, ciborium::Value)> {
        // BTreeMap keyed by label integer guarantees sorted iteration
        // order regardless of field declaration order.
        let mut entries: BTreeMap<i64, ciborium::Value> = BTreeMap::new();

        // CWT standard
        if let Some(iss) = &self.issuer {
            entries.insert(cwt_claims::ISS, ciborium::Value::Text(iss.clone()));
        }
        if let Some(sub) = &self.subject {
            entries.insert(cwt_claims::SUB, ciborium::Value::Text(sub.clone()));
        }
        if let Some(aud) = &self.audience {
            entries.insert(cwt_claims::AUD, ciborium::Value::Text(aud.clone()));
        }
        // chrono timestamp() returns i64 — ciborium Integer::From<i64> applies.
        if let Some(t) = self.expiration {
            entries.insert(
                cwt_claims::EXP,
                ciborium::Value::Integer(t.timestamp().into()),
            );
        }
        if let Some(t) = self.not_before {
            entries.insert(
                cwt_claims::NBF,
                ciborium::Value::Integer(t.timestamp().into()),
            );
        }
        if let Some(t) = self.issued_at {
            entries.insert(
                cwt_claims::IAT,
                ciborium::Value::Integer(t.timestamp().into()),
            );
        }
        if let Some(cti) = &self.token_id {
            entries.insert(cwt_claims::CTI, ciborium::Value::Bytes(cti.clone()));
        }

        // FCP2
        if let Some(v) = &self.capability_id {
            entries.insert(fcp2_claims::CAPABILITY_ID, ciborium::Value::Text(v.clone()));
        }
        if let Some(v) = &self.zone_id {
            entries.insert(fcp2_claims::ZONE_ID, ciborium::Value::Text(v.clone()));
        }
        if let Some(v) = &self.principal_id {
            entries.insert(fcp2_claims::PRINCIPAL_ID, ciborium::Value::Text(v.clone()));
        }
        if let Some(v) = &self.issuing_node {
            entries.insert(fcp2_claims::ISS_NODE, ciborium::Value::Text(v.clone()));
        }
        if let Some(v) = &self.holder_node {
            entries.insert(fcp2_claims::HOLDER_NODE, ciborium::Value::Text(v.clone()));
        }
        if let Some(v) = &self.audience_binary {
            entries.insert(fcp2_claims::AUD_BINARY, ciborium::Value::Bytes(v.clone()));
        }
        if !self.grant_object_ids.is_empty() {
            entries.insert(
                fcp2_claims::GRANT_OBJECT_IDS,
                ciborium::Value::Array(
                    self.grant_object_ids
                        .iter()
                        .map(|b| ciborium::Value::Bytes(b.clone()))
                        .collect(),
                ),
            );
        }
        if let Some(v) = &self.checkpoint_id {
            entries.insert(fcp2_claims::CHK_ID, ciborium::Value::Bytes(v.clone()));
        }
        if let Some(v) = self.checkpoint_seq {
            // u64 → Integer via the u64 From impl (ciborium supports it).
            entries.insert(fcp2_claims::CHK_SEQ, ciborium::Value::Integer(v.into()));
        }
        if let Some(v) = &self.instance_id {
            entries.insert(fcp2_claims::INSTANCE_ID, ciborium::Value::Text(v.clone()));
        }
        if let Some(v) = self.delegation_depth {
            // u64 → Integer via the u64 From impl.
            entries.insert(
                fcp2_claims::DELEGATION_DEPTH,
                ciborium::Value::Integer(v.into()),
            );
        }
        if let Some(v) = &self.parent_token {
            entries.insert(fcp2_claims::PARENT_TOKEN, ciborium::Value::Bytes(v.clone()));
        }
        if !self.grants.is_empty() {
            entries.insert(
                fcp2_claims::GRANTS,
                ciborium::Value::Array(self.grants.clone()),
            );
        }
        if let Some(v) = &self.constraints {
            entries.insert(fcp2_claims::CONSTRAINTS, v.clone());
        }

        // schema_version — always present
        entries.insert(
            fcp2_claims::SCHEMA_VERSION,
            ciborium::Value::Integer(i64::from(self.schema_version).into()),
        );

        // BTreeMap iterates in key order. Convert to (Integer, Value).
        entries
            .into_iter()
            .map(|(label, value)| (ciborium::Value::Integer(label.into()), value))
            .collect()
    }

    fn from_map_entries(
        entries: Vec<(ciborium::Value, ciborium::Value)>,
    ) -> Result<Self, SchemaError> {
        let mut out = Self::default();
        // default() sets schema_version=0; we overwrite if present below.
        for (k, v) in entries {
            let label = match k {
                ciborium::Value::Integer(i) => {
                    // ciborium::Value::Integer is a 128-bit container;
                    // FCP labels fit in i64. Coerce carefully.
                    let as_i128: i128 = i.into();
                    if let Ok(as_i64) = i64::try_from(as_i128) {
                        as_i64
                    } else {
                        // out-of-range label; skip (forward-compat)
                        continue;
                    }
                }
                _ => continue, // non-integer keys are not part of the schema
            };
            match label {
                // CWT standard
                cwt_claims::ISS => out.issuer = Some(expect_text(label, v)?),
                cwt_claims::SUB => out.subject = Some(expect_text(label, v)?),
                cwt_claims::AUD => out.audience = Some(expect_text(label, v)?),
                cwt_claims::EXP => out.expiration = Some(timestamp(label, v)?),
                cwt_claims::NBF => out.not_before = Some(timestamp(label, v)?),
                cwt_claims::IAT => out.issued_at = Some(timestamp(label, v)?),
                cwt_claims::CTI => out.token_id = Some(expect_bytes(label, v)?),

                // FCP2
                fcp2_claims::CAPABILITY_ID => out.capability_id = Some(expect_text(label, v)?),
                fcp2_claims::ZONE_ID => out.zone_id = Some(expect_text(label, v)?),
                fcp2_claims::PRINCIPAL_ID => out.principal_id = Some(expect_text(label, v)?),
                fcp2_claims::ISS_NODE => out.issuing_node = Some(expect_text(label, v)?),
                fcp2_claims::HOLDER_NODE => out.holder_node = Some(expect_text(label, v)?),
                fcp2_claims::AUD_BINARY => out.audience_binary = Some(expect_bytes(label, v)?),
                fcp2_claims::GRANT_OBJECT_IDS => {
                    let arr = expect_array(label, v)?;
                    let mut ids = Vec::with_capacity(arr.len());
                    for e in arr {
                        ids.push(expect_bytes(label, e)?);
                    }
                    out.grant_object_ids = ids;
                }
                fcp2_claims::CHK_ID => out.checkpoint_id = Some(expect_bytes(label, v)?),
                fcp2_claims::CHK_SEQ => out.checkpoint_seq = Some(expect_u64(label, v)?),
                fcp2_claims::INSTANCE_ID => out.instance_id = Some(expect_text(label, v)?),
                fcp2_claims::DELEGATION_DEPTH => {
                    out.delegation_depth = Some(expect_u64(label, v)?);
                }
                fcp2_claims::PARENT_TOKEN => out.parent_token = Some(expect_bytes(label, v)?),
                fcp2_claims::GRANTS => out.grants = expect_array(label, v)?,
                fcp2_claims::CONSTRAINTS => out.constraints = Some(v),
                fcp2_claims::SCHEMA_VERSION => {
                    out.schema_version = expect_u16(label, v)?;
                }

                // Unknown / deprecated labels (e.g. OPERATIONS): silently ignored here.
                // The verifier is responsible for rejecting legacy shapes (8n0rm.6).
                _ => {}
            }
        }
        Ok(out)
    }
}

// ── Decoding helpers ────────────────────────────────────────────────

fn expect_text(label: i64, v: ciborium::Value) -> Result<String, SchemaError> {
    match v {
        ciborium::Value::Text(s) => Ok(s),
        other => Err(SchemaError::UnexpectedType {
            label,
            expected: "text",
            got: value_kind(&other),
        }),
    }
}

fn expect_bytes(label: i64, v: ciborium::Value) -> Result<Vec<u8>, SchemaError> {
    match v {
        ciborium::Value::Bytes(b) => Ok(b),
        other => Err(SchemaError::UnexpectedType {
            label,
            expected: "bytes",
            got: value_kind(&other),
        }),
    }
}

fn expect_array(
    label: i64,
    v: ciborium::Value,
) -> Result<Vec<ciborium::Value>, SchemaError> {
    match v {
        ciborium::Value::Array(a) => Ok(a),
        other => Err(SchemaError::UnexpectedType {
            label,
            expected: "array",
            got: value_kind(&other),
        }),
    }
}

fn expect_u64(label: i64, v: ciborium::Value) -> Result<u64, SchemaError> {
    match v {
        ciborium::Value::Integer(i) => {
            let as_i128: i128 = i.into();
            u64::try_from(as_i128).map_err(|_| SchemaError::UnexpectedType {
                label,
                expected: "u64",
                got: "out-of-range integer",
            })
        }
        other => Err(SchemaError::UnexpectedType {
            label,
            expected: "integer",
            got: value_kind(&other),
        }),
    }
}

fn expect_u16(label: i64, v: ciborium::Value) -> Result<u16, SchemaError> {
    match v {
        ciborium::Value::Integer(i) => {
            let as_i128: i128 = i.into();
            u16::try_from(as_i128).map_err(|_| SchemaError::UnexpectedType {
                label,
                expected: "u16",
                got: "out-of-range integer",
            })
        }
        other => Err(SchemaError::UnexpectedType {
            label,
            expected: "integer",
            got: value_kind(&other),
        }),
    }
}

fn timestamp(label: i64, v: ciborium::Value) -> Result<DateTime<Utc>, SchemaError> {
    match v {
        ciborium::Value::Integer(i) => {
            let as_i128: i128 = i.into();
            let secs: i64 = i64::try_from(as_i128).map_err(|_| SchemaError::InvalidTimestamp {
                label,
                value: 0,
            })?;
            Utc.timestamp_opt(secs, 0)
                .single()
                .ok_or(SchemaError::InvalidTimestamp { label, value: secs })
        }
        other => Err(SchemaError::UnexpectedType {
            label,
            expected: "timestamp (integer)",
            got: value_kind(&other),
        }),
    }
}

const fn value_kind(v: &ciborium::Value) -> &'static str {
    match v {
        ciborium::Value::Null => "null",
        ciborium::Value::Bool(_) => "bool",
        ciborium::Value::Integer(_) => "integer",
        ciborium::Value::Float(_) => "float",
        ciborium::Value::Bytes(_) => "bytes",
        ciborium::Value::Text(_) => "text",
        ciborium::Value::Array(_) => "array",
        ciborium::Value::Map(_) => "map",
        ciborium::Value::Tag(_, _) => "tag",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single().unwrap()
    }

    #[test]
    fn empty_stamps_current_schema_version() {
        let c = AuthClaims::empty();
        assert_eq!(c.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn roundtrip_empty() {
        let c = AuthClaims::empty();
        let bytes = c.to_canonical_cbor().unwrap();
        let parsed = AuthClaims::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(c, parsed);
    }

    #[test]
    fn roundtrip_all_cwt_fields() {
        let c = AuthClaims {
            schema_version: CURRENT_SCHEMA_VERSION,
            issuer: Some("z:work".into()),
            subject: Some("subj".into()),
            audience: Some("aud".into()),
            expiration: Some(utc(2027, 6, 1)),
            not_before: Some(utc(2027, 1, 1)),
            issued_at: Some(utc(2027, 1, 1)),
            token_id: Some(vec![0xAA; 16]),
            ..AuthClaims::default()
        };
        let bytes = c.to_canonical_cbor().unwrap();
        let parsed = AuthClaims::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(c, parsed);
    }

    #[test]
    fn roundtrip_all_fcp2_fields() {
        let c = AuthClaims {
            schema_version: CURRENT_SCHEMA_VERSION,
            capability_id: Some("cap:test".into()),
            zone_id: Some("z:work".into()),
            principal_id: Some("user@example".into()),
            issuing_node: Some("node-alpha".into()),
            holder_node: Some("node-beta".into()),
            audience_binary: Some(vec![1, 2, 3]),
            grant_object_ids: vec![vec![0x10, 0x11], vec![0x20, 0x21]],
            checkpoint_id: Some(vec![0xCC; 32]),
            checkpoint_seq: Some(42),
            instance_id: Some("instance-xyz".into()),
            delegation_depth: Some(2),
            parent_token: Some(vec![0xFE, 0xED]),
            grants: vec![ciborium::Value::Text("grant-placeholder".into())],
            constraints: Some(ciborium::Value::Map(vec![(
                ciborium::Value::Text("resource_allow".into()),
                ciborium::Value::Array(vec![ciborium::Value::Text("uri:*".into())]),
            )])),
            ..AuthClaims::default()
        };
        let bytes = c.to_canonical_cbor().unwrap();
        let parsed = AuthClaims::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(c, parsed);
    }

    #[test]
    fn serialization_is_deterministic() {
        let c = AuthClaims {
            schema_version: CURRENT_SCHEMA_VERSION,
            issuer: Some("z:work".into()),
            capability_id: Some("cap:test".into()),
            zone_id: Some("z:work".into()),
            grant_object_ids: vec![vec![1], vec![2], vec![3]],
            checkpoint_seq: Some(100),
            ..AuthClaims::default()
        };
        let a = c.to_canonical_cbor().unwrap();
        let b = c.to_canonical_cbor().unwrap();
        let d = c.to_canonical_cbor().unwrap();
        assert_eq!(a, b);
        assert_eq!(b, d);
    }

    #[test]
    fn label_ordering_is_ascending_in_wire_format() {
        // The canonical map must list keys in ascending integer order.
        // Build a claims set with mixed CWT + FCP2 fields and verify
        // the decoded map's key sequence is sorted.
        let c = AuthClaims {
            schema_version: CURRENT_SCHEMA_VERSION,
            capability_id: Some("cap".into()),
            issuer: Some("iss".into()), // cwt_claims::ISS=1 (positive)
            zone_id: Some("zone".into()),
            issued_at: Some(utc(2027, 1, 1)), // IAT=6
            ..AuthClaims::default()
        };
        let bytes = c.to_canonical_cbor().unwrap();
        let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();
        let ciborium::Value::Map(entries) = value else {
            panic!("expected map at top level");
        };
        let keys: Vec<i64> = entries
            .iter()
            .filter_map(|(k, _)| match k {
                ciborium::Value::Integer(i) => {
                    let i128_v: i128 = (*i).into();
                    i64::try_from(i128_v).ok()
                }
                _ => None,
            })
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "canonical CBOR must emit keys in ascending order");
    }

    #[test]
    fn absent_optionals_are_omitted_from_wire() {
        let c = AuthClaims::empty();
        let bytes = c.to_canonical_cbor().unwrap();
        let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();
        let ciborium::Value::Map(entries) = value else {
            panic!("expected map");
        };
        // Only schema_version is present.
        assert_eq!(entries.len(), 1, "empty() must emit only schema_version, got {entries:?}");
    }

    #[test]
    fn unknown_labels_are_ignored_on_decode() {
        // Forward-compat: decoding a token that carries an extra
        // unknown integer label must not fail.
        let mut entries: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (
                ciborium::Value::Integer(fcp2_claims::SCHEMA_VERSION.into()),
                ciborium::Value::Integer(i64::from(CURRENT_SCHEMA_VERSION).into()),
            ),
            (
                ciborium::Value::Integer(fcp2_claims::CAPABILITY_ID.into()),
                ciborium::Value::Text("cap".into()),
            ),
            // Unknown label at -999_999
            (
                ciborium::Value::Integer((-999_999_i64).into()),
                ciborium::Value::Text("mystery".into()),
            ),
        ];
        entries.sort_by_key(|(k, _)| match k {
            ciborium::Value::Integer(i) => {
                let x: i128 = (*i).into();
                x
            }
            _ => 0,
        });
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(entries), &mut bytes).unwrap();
        let parsed = AuthClaims::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(parsed.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(parsed.capability_id.as_deref(), Some("cap"));
    }

    // ── 8n0rm.5: schema_version policy regression tests ─────────────────

    #[test]
    fn check_schema_version_accepts_current() {
        let c = AuthClaims::empty();
        assert!(c.check_schema_version(&[CURRENT_SCHEMA_VERSION]).is_ok());
    }

    #[test]
    fn check_schema_version_rejects_unsupported() {
        let c = AuthClaims {
            schema_version: 999,
            ..AuthClaims::default()
        };
        let err = c.check_schema_version(&[CURRENT_SCHEMA_VERSION]).unwrap_err();
        assert!(
            matches!(
                err,
                SchemaError::UnsupportedSchemaVersion {
                    got: 999,
                    expected: CURRENT_SCHEMA_VERSION,
                }
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn check_schema_version_accepts_multi_version_window() {
        // During a deployment-wide bump, verifiers accept old + new.
        let c = AuthClaims {
            schema_version: 1,
            ..AuthClaims::default()
        };
        assert!(c.check_schema_version(&[1, 2]).is_ok());
        let c2 = AuthClaims {
            schema_version: 2,
            ..AuthClaims::default()
        };
        assert!(c2.check_schema_version(&[1, 2]).is_ok());
    }

    #[test]
    fn schema_version_zero_is_not_valid_as_current() {
        // Sanity: CURRENT_SCHEMA_VERSION must be > 0 so that a
        // claim-set constructed with ::default() (which leaves
        // schema_version=0) cannot pass verification by accident.
        assert!(CURRENT_SCHEMA_VERSION > 0);
    }

    #[test]
    fn type_mismatch_surfaces_helpful_error() {
        // Capability id stored as Bytes instead of Text → UnexpectedType
        let entries = vec![
            (
                ciborium::Value::Integer(fcp2_claims::SCHEMA_VERSION.into()),
                ciborium::Value::Integer(i64::from(CURRENT_SCHEMA_VERSION).into()),
            ),
            (
                ciborium::Value::Integer(fcp2_claims::CAPABILITY_ID.into()),
                ciborium::Value::Bytes(vec![0x01]),
            ),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(entries), &mut bytes).unwrap();
        let err = AuthClaims::from_canonical_cbor(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                SchemaError::UnexpectedType {
                    label: -65537,
                    expected: "text",
                    ..
                }
            ),
            "got: {err:?}"
        );
    }
}
