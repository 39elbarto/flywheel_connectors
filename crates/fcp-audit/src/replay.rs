//! Predicate-trace reconstruction for capability-token audit replay.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::AuditEntry;

/// Default replay lookback window: seven days.
pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

const TOKEN_HASH_PREFIX: &str = "blake3:";
const DEFAULT_EVALUATOR_VERSION: &str = "0.0.0";
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "secret",
    "token",
    "password",
    "credential",
    "private_key",
    "api_key",
    "service_account",
];

/// Reconstructed predicate trace for one capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateTrace {
    /// Redaction-safe BLAKE3 hash of the input token.
    pub token_hash: String,
    /// Final capability-decision verdict inferred from predicate steps.
    pub final_verdict: FinalVerdict,
    /// Number of predicate steps in `trace`.
    pub total_steps: usize,
    /// Reconstructed latency in microseconds.
    pub total_latency_us: u64,
    /// Audit-chain sequence span used as witness evidence.
    pub audit_chain_range: AuditChainRange,
    /// Ordered predicate-evaluation steps.
    pub trace: Vec<PredicateStep>,
}

/// Inclusive audit-chain sequence range used by a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainRange {
    /// First audit-chain sequence number consulted.
    pub start_seq: u64,
    /// Last audit-chain sequence number consulted.
    pub end_seq: u64,
}

/// One predicate-evaluation step reconstructed from audit-chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateStep {
    /// Stable predicate or rule identifier.
    pub rule_name: String,
    /// Redacted predicate inputs.
    pub inputs_json: Value,
    /// Boolean predicate result.
    pub output: bool,
    /// Audit-chain sequence numbers that witness this step.
    pub witness_chain_indices: Vec<u64>,
    /// Evaluator version captured by the audit source.
    pub evaluator_version: String,
}

/// Final decision represented by a capability predicate trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalVerdict {
    /// Every predicate step accepted the token.
    Accepted,
    /// A non-revocation predicate rejected the token.
    RejectedPredicate,
    /// The token was rejected because revocation evidence was present.
    RejectedRevocation,
    /// The token was rejected because it had expired.
    RejectedExpired,
}

/// Errors that can occur while reconstructing a predicate trace.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReplayError {
    /// Requested window exceeds the default cap and the caller did not confirm.
    #[error(
        "replay window {since_secs}s exceeds default cap {max_secs}s; pass --confirm to continue"
    )]
    WideWindowRequiresConfirm {
        /// Requested lookback window in seconds.
        since_secs: u64,
        /// Default unconfirmed lookback cap in seconds.
        max_secs: u64,
    },
    /// No matching audit entries were found.
    #[error("capability token {token_hash} has no audit-chain entries in the requested window")]
    TokenNotFoundInAuditChain {
        /// Redaction-safe BLAKE3 hash of the requested token.
        token_hash: String,
    },
    /// The audit chain could not be read.
    #[error("audit chain unavailable: {0}")]
    AuditChainUnavailable(String),
    /// Matching entries were present but unusable as predicate evidence.
    #[error("audit chain corrupted: {0}")]
    AuditChainCorrupted(String),
}

/// Return the redaction-safe capability-token hash used by replay outputs.
#[must_use]
pub fn token_hash(token: &str) -> String {
    format!(
        "{TOKEN_HASH_PREFIX}{}",
        blake3::hash(token.as_bytes()).to_hex()
    )
}

/// Reconstruct a predicate trace from the default audit source.
///
/// This currently uses the same reconstruction contract as the entry-backed
/// helper, but the default durable audit-chain walker is not wired here yet.
/// Callers with captured evidence should use
/// [`reconstruct_predicate_trace_from_entries`].
///
/// # Errors
///
/// Returns [`ReplayError::WideWindowRequiresConfirm`] when `since` exceeds the
/// seven-day cap without confirmation, and
/// [`ReplayError::TokenNotFoundInAuditChain`] until a default audit-chain source
/// is configured.
pub fn reconstruct_predicate_trace(
    token: &str,
    since: Duration,
    confirm: bool,
) -> Result<PredicateTrace, ReplayError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    reconstruct_predicate_trace_from_entries(token, since, confirm, now_unix, &[])
}

/// Reconstruct a predicate trace from captured audit entries.
///
/// # Errors
///
/// Returns [`ReplayError::WideWindowRequiresConfirm`] when `since` exceeds the
/// seven-day cap without confirmation, [`ReplayError::TokenNotFoundInAuditChain`]
/// when the window has no matching entries, or
/// [`ReplayError::AuditChainCorrupted`] when matching entries lack usable
/// predicate-step evidence.
pub fn reconstruct_predicate_trace_from_entries(
    token: &str,
    since: Duration,
    confirm: bool,
    now_unix: u64,
    entries: &[AuditEntry],
) -> Result<PredicateTrace, ReplayError> {
    let since_secs = since.as_secs();
    enforce_window(since_secs, confirm)?;

    let token_hash = token_hash(token);
    let cutoff = now_unix.saturating_sub(since_secs);
    let mut selected = entries
        .iter()
        .filter(|entry| {
            entry.occurred_at >= cutoff && entry_mentions_token(entry, token, &token_hash)
        })
        .collect::<Vec<_>>();

    selected.sort_by_key(|entry| (entry.seq, entry.occurred_at, entry.id.as_str()));

    if selected.is_empty() {
        return Err(ReplayError::TokenNotFoundInAuditChain { token_hash });
    }

    let mut trace = Vec::new();
    let mut explicit_latency_us = 0_u64;
    let mut saw_explicit_latency = false;
    let mut explicit_verdict = None;

    for entry in &selected {
        if let Some(latency_us) = metadata_u64(&entry.metadata, &["latency_us", "duration_us"]) {
            explicit_latency_us = explicit_latency_us.saturating_add(latency_us);
            saw_explicit_latency = true;
        }
        if let Some(verdict) = metadata_verdict(&entry.metadata) {
            explicit_verdict = Some(verdict);
        }
        trace.extend(predicate_steps_from_entry(entry, token)?);
    }

    if trace.is_empty() {
        return Err(ReplayError::AuditChainCorrupted(
            "matched token entries contained no predicate trace steps".to_owned(),
        ));
    }

    let audit_chain_range = chain_range(&trace).ok_or_else(|| {
        ReplayError::AuditChainCorrupted(
            "predicate trace did not include witness chain indices".to_owned(),
        )
    })?;
    let total_latency_us = if saw_explicit_latency {
        explicit_latency_us
    } else {
        reconstructed_latency_us(&selected)
    };
    let final_verdict = explicit_verdict.unwrap_or_else(|| infer_final_verdict(&trace));

    Ok(PredicateTrace {
        token_hash,
        final_verdict,
        total_steps: trace.len(),
        total_latency_us,
        audit_chain_range,
        trace,
    })
}

const fn enforce_window(since_secs: u64, confirm: bool) -> Result<(), ReplayError> {
    if since_secs > DEFAULT_REPLAY_WINDOW_SECS && !confirm {
        return Err(ReplayError::WideWindowRequiresConfirm {
            since_secs,
            max_secs: DEFAULT_REPLAY_WINDOW_SECS,
        });
    }
    Ok(())
}

fn entry_mentions_token(entry: &AuditEntry, raw_token: &str, token_hash: &str) -> bool {
    entry.metadata.iter().any(|(key, value)| {
        (is_token_hash_key(key) && scalar_string(value).is_some_and(|actual| actual == token_hash))
            || (is_token_identity_key(key)
                && scalar_string(value).is_some_and(|actual| actual == raw_token))
            || value_contains_string(value, token_hash)
            || value_contains_string(value, raw_token)
    })
}

fn is_token_hash_key(key: &str) -> bool {
    matches!(
        key,
        "token_hash" | "capability_token_hash" | "capability_hash" | "capability_token_digest"
    )
}

fn is_token_identity_key(key: &str) -> bool {
    matches!(key, "token_id" | "capability_token_id" | "jti")
}

fn value_contains_string(value: &Value, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    match value {
        Value::String(value) => value.contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_string(value, needle)),
        Value::Object(object) => object
            .values()
            .any(|value| value_contains_string(value, needle)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn predicate_steps_from_entry(
    entry: &AuditEntry,
    raw_token: &str,
) -> Result<Vec<PredicateStep>, ReplayError> {
    if let Some(trace) = entry
        .metadata
        .get("predicate_trace")
        .or_else(|| entry.metadata.get("trace"))
        .and_then(Value::as_array)
    {
        return trace
            .iter()
            .map(|value| predicate_step_from_value(value, entry.seq, raw_token))
            .collect();
    }

    direct_predicate_step(entry, raw_token).map_or_else(|| Ok(Vec::new()), |step| Ok(vec![step]))
}

fn predicate_step_from_value(
    value: &Value,
    fallback_seq: u64,
    raw_token: &str,
) -> Result<PredicateStep, ReplayError> {
    let Some(object) = value.as_object() else {
        return Err(ReplayError::AuditChainCorrupted(
            "predicate_trace entries must be JSON objects".to_owned(),
        ));
    };
    let rule_name =
        object_string(object, &["rule_name", "predicate", "name"]).ok_or_else(|| {
            ReplayError::AuditChainCorrupted(
                "predicate_trace entry is missing rule_name".to_owned(),
            )
        })?;
    let output = object_bool(object, &["output", "result", "allowed"]).ok_or_else(|| {
        ReplayError::AuditChainCorrupted(format!(
            "predicate_trace entry `{rule_name}` is missing boolean output"
        ))
    })?;
    let inputs_json = object
        .get("inputs_json")
        .or_else(|| object.get("inputs"))
        .or_else(|| object.get("input"))
        .map_or_else(|| json!({}), |value| redact_inputs(value, raw_token));
    let witness_chain_indices = object_witness_indices(object, fallback_seq);
    let evaluator_version = object_string(object, &["evaluator_version", "version"])
        .unwrap_or_else(|| DEFAULT_EVALUATOR_VERSION.to_owned());

    Ok(PredicateStep {
        rule_name,
        inputs_json,
        output,
        witness_chain_indices,
        evaluator_version,
    })
}

fn direct_predicate_step(entry: &AuditEntry, raw_token: &str) -> Option<PredicateStep> {
    let rule_name = metadata_string(&entry.metadata, &["rule_name", "predicate", "name"])?;
    let output = metadata_bool(&entry.metadata, &["output", "result", "allowed"])?;
    let inputs_json = entry
        .metadata
        .get("inputs_json")
        .or_else(|| entry.metadata.get("inputs"))
        .or_else(|| entry.metadata.get("input"))
        .map_or_else(|| json!({}), |value| redact_inputs(value, raw_token));
    let witness_chain_indices = metadata_witness_indices(&entry.metadata, entry.seq);
    let evaluator_version = metadata_string(&entry.metadata, &["evaluator_version", "version"])
        .unwrap_or_else(|| DEFAULT_EVALUATOR_VERSION.to_owned());

    Some(PredicateStep {
        rule_name,
        inputs_json,
        output,
        witness_chain_indices,
        evaluator_version,
    })
}

fn redact_inputs(value: &Value, raw_token: &str) -> Value {
    redact_value(value, raw_token, None)
}

fn redact_value(value: &Value, raw_token: &str, key: Option<&str>) -> Value {
    if key.is_some_and(is_sensitive_key) {
        return redaction_marker(redacted_len(value));
    }

    match value {
        Value::String(value) if !raw_token.is_empty() && value.contains(raw_token) => {
            redaction_marker(value.len())
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| redact_value(value, raw_token, None))
                .collect(),
        ),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), redact_value(value, raw_token, Some(key))))
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

fn redaction_marker(len: usize) -> Value {
    json!({ "<redacted>": { "len": len } })
}

fn redacted_len(value: &Value) -> usize {
    value
        .as_str()
        .map_or_else(|| value.to_string().len(), str::len)
}

fn metadata_string(metadata: &MapLike, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        metadata
            .get(*key)
            .and_then(scalar_string)
            .map(str::to_owned)
    })
}

fn metadata_bool(metadata: &MapLike, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| metadata.get(*key).and_then(scalar_bool))
}

fn metadata_u64(metadata: &MapLike, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| metadata.get(*key).and_then(Value::as_u64))
}

fn metadata_verdict(metadata: &MapLike) -> Option<FinalVerdict> {
    metadata
        .get("final_verdict")
        .or_else(|| metadata.get("verdict"))
        .and_then(scalar_string)
        .and_then(parse_final_verdict)
}

type MapLike = std::collections::BTreeMap<String, Value>;

fn object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_string).map(str::to_owned))
}

fn object_bool(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_bool))
}

fn scalar_string(value: &Value) -> Option<&str> {
    value.as_str()
}

fn scalar_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) if value.eq_ignore_ascii_case("true") => Some(true),
        Value::String(value) if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn object_witness_indices(object: &Map<String, Value>, fallback_seq: u64) -> Vec<u64> {
    object
        .get("witness_chain_indices")
        .or_else(|| object.get("witness_seq"))
        .and_then(witness_indices)
        .filter(|indices| !indices.is_empty())
        .unwrap_or_else(|| vec![fallback_seq])
}

fn metadata_witness_indices(metadata: &MapLike, fallback_seq: u64) -> Vec<u64> {
    metadata
        .get("witness_chain_indices")
        .or_else(|| metadata.get("witness_seq"))
        .and_then(witness_indices)
        .filter(|indices| !indices.is_empty())
        .unwrap_or_else(|| vec![fallback_seq])
}

fn witness_indices(value: &Value) -> Option<Vec<u64>> {
    match value {
        Value::Number(number) => number.as_u64().map(|value| vec![value]),
        Value::Array(values) => Some(values.iter().filter_map(Value::as_u64).collect()),
        _ => None,
    }
}

fn chain_range(trace: &[PredicateStep]) -> Option<AuditChainRange> {
    let mut iter = trace
        .iter()
        .flat_map(|step| step.witness_chain_indices.iter().copied());
    let first = iter.next()?;
    let (start_seq, end_seq) = iter.fold((first, first), |(min, max), seq| {
        (min.min(seq), max.max(seq))
    });
    Some(AuditChainRange { start_seq, end_seq })
}

const fn reconstructed_latency_us(selected: &[&AuditEntry]) -> u64 {
    let Some(first) = selected.first() else {
        return 0;
    };
    let Some(last) = selected.last() else {
        return 0;
    };
    last.occurred_at
        .saturating_sub(first.occurred_at)
        .saturating_mul(1_000_000)
}

fn infer_final_verdict(trace: &[PredicateStep]) -> FinalVerdict {
    let Some(rejection) = trace.iter().rev().find(|step| !step.output) else {
        return FinalVerdict::Accepted;
    };

    let rule = rejection.rule_name.to_ascii_lowercase();
    if rule.contains("revocation") || rule.contains("revoked") {
        FinalVerdict::RejectedRevocation
    } else if rule.contains("expiry") || rule.contains("expired") || rule.contains("expiration") {
        FinalVerdict::RejectedExpired
    } else {
        FinalVerdict::RejectedPredicate
    }
}

fn parse_final_verdict(value: &str) -> Option<FinalVerdict> {
    match value {
        "accepted" => Some(FinalVerdict::Accepted),
        "rejected_predicate" => Some(FinalVerdict::RejectedPredicate),
        "rejected_revocation" => Some(FinalVerdict::RejectedRevocation),
        "rejected_expired" => Some(FinalVerdict::RejectedExpired),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::{AuditEntry, AuditEntryBuilder, event_types};

    use super::{
        DEFAULT_REPLAY_WINDOW_SECS, FinalVerdict, ReplayError,
        reconstruct_predicate_trace_from_entries, token_hash,
    };

    const NOW: u64 = 1_700_000_100;
    const TOKEN: &str = "cap-token-secret";

    fn entry(seq: u64, metadata: Vec<(&str, Value)>) -> AuditEntry {
        metadata
            .into_iter()
            .fold(
                AuditEntryBuilder::new()
                    .id(format!("entry-{seq}"))
                    .event_type(event_types::CAPABILITY_INVOKE)
                    .actor("user:alice")
                    .zone_id("z:work")
                    .seq(seq)
                    .occurred_at(NOW - 10 + seq),
                |builder, (key, value)| builder.meta(key, value),
            )
            .build()
            .expect("audit entry builds")
    }

    fn replay(entries: &[AuditEntry]) -> Result<super::PredicateTrace, ReplayError> {
        reconstruct_predicate_trace_from_entries(
            TOKEN,
            std::time::Duration::from_secs(DEFAULT_REPLAY_WINDOW_SECS),
            false,
            NOW,
            entries,
        )
    }

    #[test]
    fn reconstructs_accepted_trace() {
        let hash = token_hash(TOKEN);
        let entries = vec![
            entry(
                1,
                vec![
                    ("token_hash", json!(hash)),
                    ("rule_name", json!("zone_match")),
                    (
                        "inputs_json",
                        json!({"src_zone": "z:work", "dst_zone": "z:work"}),
                    ),
                    ("output", json!(true)),
                    ("latency_us", json!(100)),
                    ("evaluator_version", json!("1.2.0")),
                ],
            ),
            entry(
                2,
                vec![
                    ("token_id", json!(TOKEN)),
                    ("rule_name", json!("capability_token_signature_verify")),
                    ("inputs_json", json!({"alg": "ed25519"})),
                    ("output", json!(true)),
                    ("latency_us", json!(145)),
                    ("evaluator_version", json!("1.2.0")),
                ],
            ),
        ];

        let trace = replay(&entries).expect("trace reconstructs");

        assert_eq!(trace.token_hash, token_hash(TOKEN));
        assert_eq!(trace.final_verdict, FinalVerdict::Accepted);
        assert_eq!(trace.total_steps, 2);
        assert_eq!(trace.total_latency_us, 245);
        assert_eq!(trace.audit_chain_range.start_seq, 1);
        assert_eq!(trace.audit_chain_range.end_seq, 2);
    }

    #[test]
    fn infers_revocation_and_expiry_rejections() {
        let revoked = vec![entry(
            1,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!("revocation_check")),
                ("output", json!(false)),
            ],
        )];
        let expired = vec![entry(
            2,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!("expiry_check")),
                ("output", json!(false)),
            ],
        )];

        assert_eq!(
            replay(&revoked).expect("revoked trace").final_verdict,
            FinalVerdict::RejectedRevocation
        );
        assert_eq!(
            replay(&expired).expect("expired trace").final_verdict,
            FinalVerdict::RejectedExpired
        );
    }

    #[test]
    fn unknown_token_returns_not_found() {
        let entries = vec![entry(
            1,
            vec![
                ("token_hash", json!(token_hash("different-token"))),
                ("rule_name", json!("zone_match")),
                ("output", json!(true)),
            ],
        )];

        let error = replay(&entries).expect_err("unknown token must fail");

        assert!(matches!(
            error,
            ReplayError::TokenNotFoundInAuditChain { .. }
        ));
    }

    #[test]
    fn wide_window_requires_confirmation() {
        let error = reconstruct_predicate_trace_from_entries(
            TOKEN,
            std::time::Duration::from_secs(DEFAULT_REPLAY_WINDOW_SECS + 1),
            false,
            NOW,
            &[],
        )
        .expect_err("wide replay must require confirm");

        assert!(matches!(
            error,
            ReplayError::WideWindowRequiresConfirm { .. }
        ));
    }

    #[test]
    fn redacts_secret_inputs_and_raw_token() {
        let entries = vec![entry(
            1,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!("credential_scope")),
                (
                    "inputs_json",
                    json!({
                        "service_account_key": "abcdef",
                        "request": format!("Bearer {TOKEN}"),
                        "safe": "visible"
                    }),
                ),
                ("output", json!(true)),
            ],
        )];

        let trace = replay(&entries).expect("trace reconstructs");
        let serialized = serde_json::to_string(&trace).expect("trace serializes");

        assert!(!serialized.contains(TOKEN));
        assert!(!serialized.contains("abcdef"));
        assert!(serialized.contains("visible"));
        assert!(serialized.contains("<redacted>"));
    }
}
