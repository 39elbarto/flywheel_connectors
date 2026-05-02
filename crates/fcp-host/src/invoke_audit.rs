//! Live `/rpc/invoke` hash-linked audit chain (br-mvax3).
//!
//! VioletPine's reality-check audit (br-mvax3) found that the README
//! advertises a "hash-linked audit event on every invoke" but the
//! production `/rpc/invoke` path only ever recorded a flat
//! `ReceiptSummary` (and only when the connector chose to return a
//! `receipt_id`). When the connector failed, denied preflight, or
//! returned no receipt, the chain claim was a lie.
//!
//! This module wires a per-host, per-zone hash-linked audit chain to
//! the four invoke phases — preflight allow, preflight deny, dispatch
//! result, dispatch error — so the README claim becomes literally true.
//!
//! ## Wire form
//!
//! Each appended event is an [`fcp_audit::AuditEntry`] with:
//! - `event_type`: one of [`event_types`].
//! - `seq`: monotonic per zone.
//! - `prev`: the previous entry's canonical id, hash-linked.
//! - `zone_id` / `connector_id` / `operation_id` / `correlation_id`:
//!   populated from the invoke request so an operator tracing a
//!   request can find every related audit row.
//! - `metadata`: phase-specific (see [`InvokePhase`]).
//!
//! The id is the BLAKE3 hash of the canonical CBOR of the entry
//! payload — same derivation `fcp_audit::AuditEntry::computed_id` uses,
//! so chain verification via the existing `verify_chain` helpers
//! continues to work without modification.
//!
//! ## Storage
//!
//! In-memory only for now (per-process). The shape is intentionally
//! retainable behind a trait so a future durable backend can be
//! swapped in without touching the call sites.

use std::collections::HashMap;
use std::sync::Mutex;

use fcp_audit::{AuditEntry, AuditEntryBuilder, AuditError, Severity};
use serde_json::json;

/// Event type strings for invoke-chain audit entries.
pub mod event_types {
    /// Emitted after preflight (zone, capability, revocation) PASSES,
    /// before the connector subprocess is dispatched.
    pub const INVOKE_ALLOW: &str = "invoke.allow";
    /// Emitted when preflight DENIES the request — the connector is
    /// never dispatched.
    pub const INVOKE_DENY: &str = "invoke.deny";
    /// Emitted after the connector returns successfully.
    pub const INVOKE_RESULT: &str = "invoke.result";
    /// Emitted when the registry/dispatcher returns an error before or
    /// during connector execution.
    pub const INVOKE_ERROR: &str = "invoke.error";
}

/// Phase-specific payload for an invoke audit append.
#[derive(Debug, Clone)]
pub enum InvokePhase {
    /// Preflight passed. Emitted before connector dispatch.
    PreflightAllow,
    /// Preflight denied. Connector never dispatched.
    PreflightDeny {
        /// Operator-readable reason (sanitized).
        reason: String,
    },
    /// Dispatch returned a response.
    DispatchResult {
        /// Receipt id returned by the connector, if any.
        receipt_id: Option<String>,
        /// `true` if the dispatch's status was `Ok`.
        success: bool,
        /// Wall-clock duration from request enter to dispatch return.
        duration_ms: u64,
    },
    /// Dispatch failed before returning a response.
    DispatchError {
        /// Sanitized error message.
        error: String,
        /// Wall-clock duration from request enter to dispatch failure.
        duration_ms: u64,
    },
}

impl InvokePhase {
    fn event_type(&self) -> &'static str {
        match self {
            Self::PreflightAllow => event_types::INVOKE_ALLOW,
            Self::PreflightDeny { .. } => event_types::INVOKE_DENY,
            Self::DispatchResult { .. } => event_types::INVOKE_RESULT,
            Self::DispatchError { .. } => event_types::INVOKE_ERROR,
        }
    }

    fn severity(&self) -> Severity {
        match self {
            Self::PreflightAllow => Severity::Info,
            Self::PreflightDeny { .. } => Severity::Warning,
            Self::DispatchResult { success, .. } => {
                if *success {
                    Severity::Info
                } else {
                    Severity::Warning
                }
            }
            Self::DispatchError { .. } => Severity::Error,
        }
    }

    fn into_metadata(self) -> Vec<(String, serde_json::Value)> {
        match self {
            Self::PreflightAllow => vec![],
            Self::PreflightDeny { reason } => vec![("reason".into(), json!(reason))],
            Self::DispatchResult {
                receipt_id,
                success,
                duration_ms,
            } => {
                let mut meta = vec![
                    ("success".into(), json!(success)),
                    ("duration_ms".into(), json!(duration_ms)),
                ];
                if let Some(id) = receipt_id {
                    meta.push(("receipt_id".into(), json!(id)));
                }
                meta
            }
            Self::DispatchError {
                error,
                duration_ms,
            } => vec![
                ("error".into(), json!(error)),
                ("duration_ms".into(), json!(duration_ms)),
            ],
        }
    }
}

/// Stable context carried across the four invoke phases for one
/// request.
#[derive(Debug, Clone)]
pub struct InvokeAuditContext {
    /// Zone the request targets — partitions the chain.
    pub zone_id: String,
    /// Authenticated principal that issued the request.
    pub actor: String,
    /// Connector id being invoked.
    pub connector_id: String,
    /// Connector operation name.
    pub operation: String,
    /// Server-assigned request id (also used as `operation_id` on the
    /// audit entry).
    pub operation_id: String,
    /// Optional client-supplied correlation id for tracing.
    pub correlation_id: Option<String>,
    /// Wall-clock when the request entered the host (Unix seconds).
    pub occurred_at: u64,
}

#[derive(Debug, Default)]
struct ZoneChain {
    last_seq: Option<u64>,
    last_id: Option<String>,
    entries: Vec<AuditEntry>,
}

/// Per-host hash-linked invoke audit chain.
///
/// Partitioned by zone — each zone has its own monotonic `seq` and
/// `prev`-linked chain so two zones cannot interfere with each other's
/// hash linkage. Cheap to construct, cheap to clone (via `Arc`).
#[derive(Debug, Default)]
pub struct InvokeAuditChain {
    chains: Mutex<HashMap<String, ZoneChain>>,
}

impl InvokeAuditChain {
    /// Construct an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a phase event for `ctx` and return the resulting entry.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if canonical-CBOR encoding of the entry
    /// payload fails (cannot happen for normal field values).
    pub fn append(
        &self,
        ctx: &InvokeAuditContext,
        phase: InvokePhase,
    ) -> Result<AuditEntry, AuditError> {
        let event_type = phase.event_type();
        let severity = phase.severity();
        let metadata = phase.into_metadata();

        // Hold the lock for the whole append so seq + prev stay
        // monotonic against concurrent invokes.
        let mut chains = self
            .chains
            .lock()
            .expect("InvokeAuditChain mutex poisoned — host process is in a bad state");
        let zone = chains.entry(ctx.zone_id.clone()).or_default();

        let next_seq = zone.last_seq.map_or(0u64, |s| s.saturating_add(1));
        let prev = zone.last_id.clone();

        let mut builder = AuditEntryBuilder::new()
            .event_type(event_type)
            .severity(severity)
            .actor(&ctx.actor)
            .zone_id(&ctx.zone_id)
            .seq(next_seq)
            .occurred_at(ctx.occurred_at)
            .connector_id(&ctx.connector_id)
            .operation_id(&ctx.operation_id)
            .meta("operation", json!(ctx.operation));
        if let Some(p) = prev {
            builder = builder.prev(p);
        }
        if let Some(cid) = ctx.correlation_id.clone() {
            builder = builder.correlation_id(cid);
        }
        for (k, v) in metadata {
            builder = builder.meta(k, v);
        }

        // Compute the canonical id ourselves so the entry's `id` field
        // matches `computed_id` — required for downstream chain
        // verification via `fcp_audit::verify_chain`.
        // We need a temporary entry with placeholder id to compute the
        // canonical id (id is excluded from the canonical bytes), then
        // rebuild with the real id.
        let provisional = builder
            .clone()
            .id("__provisional__")
            .build()
            .map_err(|e| AuditError::SerializationError(format!("invoke audit build: {e}")))?;
        let real_id = provisional.computed_id()?;
        let entry = builder
            .id(real_id.clone())
            .build()
            .map_err(|e| AuditError::SerializationError(format!("invoke audit build: {e}")))?;

        zone.last_seq = Some(next_seq);
        zone.last_id = Some(real_id);
        zone.entries.push(entry.clone());

        Ok(entry)
    }

    /// Snapshot of the entries appended for `zone_id`. Empty if the
    /// zone has had no invokes yet.
    #[must_use]
    pub fn entries_for_zone(&self, zone_id: &str) -> Vec<AuditEntry> {
        self.chains
            .lock()
            .expect("InvokeAuditChain mutex poisoned")
            .get(zone_id)
            .map(|c| c.entries.clone())
            .unwrap_or_default()
    }

    /// Number of entries appended for `zone_id`.
    #[must_use]
    pub fn len_for_zone(&self, zone_id: &str) -> usize {
        self.chains
            .lock()
            .expect("InvokeAuditChain mutex poisoned")
            .get(zone_id)
            .map_or(0, |c| c.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(zone: &str, op_id: &str) -> InvokeAuditContext {
        InvokeAuditContext {
            zone_id: zone.into(),
            actor: "agent:test".into(),
            connector_id: "github".into(),
            operation: "list_repos".into(),
            operation_id: op_id.into(),
            correlation_id: Some("cid-42".into()),
            occurred_at: 1_700_000_000,
        }
    }

    #[test]
    fn invoke_audit_chain_single_append_is_genesis() {
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();
        assert!(entry.is_genesis(), "first entry must be genesis (seq 0, no prev)");
        assert_eq!(entry.event_type, event_types::INVOKE_ALLOW);
        assert_eq!(entry.severity, Severity::Info);
        assert_eq!(entry.zone_id, "z:work");
    }

    #[test]
    fn invoke_audit_chain_consecutive_appends_hash_link() {
        // br-mvax3: the README claim is "hash-linked audit chain". The
        // second entry MUST `follow` the first via prev = first.id and
        // seq = first.seq + 1.
        let chain = InvokeAuditChain::new();
        let first = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();
        let second = chain
            .append(
                &ctx("z:work", "op-1"),
                InvokePhase::DispatchResult {
                    receipt_id: Some("rcpt-1".into()),
                    success: true,
                    duration_ms: 42,
                },
            )
            .unwrap();
        assert!(
            second.follows(&first),
            "second entry must hash-link to first: prev={:?} expected_prev={:?}, seq={} expected_seq={}",
            second.prev, Some(&first.id), second.seq, first.seq + 1
        );
        assert_eq!(second.event_type, event_types::INVOKE_RESULT);
    }

    #[test]
    fn invoke_audit_chain_zone_isolation() {
        // Two zones must each have their own seq=0 genesis entry —
        // they cannot interfere with each other's hash linkage.
        let chain = InvokeAuditChain::new();
        let work = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();
        let home = chain
            .append(&ctx("z:home", "op-2"), InvokePhase::PreflightAllow)
            .unwrap();
        assert!(work.is_genesis());
        assert!(home.is_genesis());
        assert_eq!(work.zone_id, "z:work");
        assert_eq!(home.zone_id, "z:home");
        assert_eq!(chain.len_for_zone("z:work"), 1);
        assert_eq!(chain.len_for_zone("z:home"), 1);
    }

    #[test]
    fn invoke_audit_chain_deny_appends_with_warning_severity() {
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(
                &ctx("z:work", "op-1"),
                InvokePhase::PreflightDeny {
                    reason: "capability not granted".into(),
                },
            )
            .unwrap();
        assert_eq!(entry.event_type, event_types::INVOKE_DENY);
        assert_eq!(entry.severity, Severity::Warning);
        assert_eq!(
            entry.metadata.get("reason").and_then(|v| v.as_str()),
            Some("capability not granted")
        );
    }

    #[test]
    fn invoke_audit_chain_dispatch_error_carries_message() {
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(
                &ctx("z:work", "op-1"),
                InvokePhase::DispatchError {
                    error: "connector subprocess crashed".into(),
                    duration_ms: 17,
                },
            )
            .unwrap();
        assert_eq!(entry.event_type, event_types::INVOKE_ERROR);
        assert_eq!(entry.severity, Severity::Error);
        assert_eq!(
            entry.metadata.get("error").and_then(|v| v.as_str()),
            Some("connector subprocess crashed")
        );
        assert_eq!(
            entry.metadata.get("duration_ms").and_then(|v| v.as_u64()),
            Some(17)
        );
    }

    #[test]
    fn invoke_audit_chain_id_is_canonical_recomputable() {
        // br-mvax3: the entry's id MUST match its computed_id (BLAKE3
        // of canonical CBOR of the payload). This is what makes the
        // hash chain verifiable by downstream tooling.
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();
        let recomputed = entry
            .computed_id()
            .expect("computed_id must succeed for a well-formed entry");
        assert_eq!(
            entry.id, recomputed,
            "stored id must match computed_id so the chain is verifiable"
        );
    }

    #[test]
    fn invoke_audit_chain_full_request_lifecycle_produces_chain_of_two_links() {
        // br-mvax3 acceptance: a full successful invoke produces TWO
        // events — allow + result — both linked.
        let chain = InvokeAuditChain::new();
        let c = ctx("z:work", "op-99");
        chain.append(&c, InvokePhase::PreflightAllow).unwrap();
        chain
            .append(
                &c,
                InvokePhase::DispatchResult {
                    receipt_id: Some("rcpt-99".into()),
                    success: true,
                    duration_ms: 100,
                },
            )
            .unwrap();

        let entries = chain.entries_for_zone("z:work");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_genesis());
        assert!(entries[1].follows(&entries[0]));
        assert_eq!(entries[0].event_type, event_types::INVOKE_ALLOW);
        assert_eq!(entries[1].event_type, event_types::INVOKE_RESULT);
        // Both share the operation_id so an operator can correlate.
        assert_eq!(entries[0].operation_id.as_deref(), Some("op-99"));
        assert_eq!(entries[1].operation_id.as_deref(), Some("op-99"));
    }

    #[test]
    fn invoke_audit_chain_denied_request_still_produces_event() {
        // br-mvax3 acceptance: even when preflight denies, an event
        // must be appended — the README "every operation" claim.
        let chain = InvokeAuditChain::new();
        let c = ctx("z:work", "op-deny");
        chain
            .append(
                &c,
                InvokePhase::PreflightDeny {
                    reason: "out of zone".into(),
                },
            )
            .unwrap();
        let entries = chain.entries_for_zone("z:work");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, event_types::INVOKE_DENY);
    }

    #[test]
    fn invoke_audit_chain_failed_dispatch_with_no_receipt_still_appends() {
        // br-mvax3 acceptance: the previous bug was that connectors
        // returning no receipt_id silently produced ZERO audit events.
        // The DispatchError phase must always append.
        let chain = InvokeAuditChain::new();
        let c = ctx("z:work", "op-bad");
        chain.append(&c, InvokePhase::PreflightAllow).unwrap();
        chain
            .append(
                &c,
                InvokePhase::DispatchError {
                    error: "boom".into(),
                    duration_ms: 5,
                },
            )
            .unwrap();
        let entries = chain.entries_for_zone("z:work");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].event_type, event_types::INVOKE_ERROR);
        assert!(entries[1].follows(&entries[0]));
    }
}
