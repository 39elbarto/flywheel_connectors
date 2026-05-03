//! Live `/rpc/invoke` hash-linked audit chain (br-mvax3).
//!
//! A reality-check audit (br-mvax3) found that the README advertises
//! a "hash-linked audit event on every invoke" but the
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
use std::sync::{Arc, Mutex, RwLock};

use fcp_audit::{AuditEntry, AuditEntryBuilder, AuditError, Severity};
use serde_json::json;

/// Defence-in-depth bound on the optimistic-CAS retry loop.
///
/// Sized so that even with thousands of concurrent same-zone appenders
/// the natural happy path completes well under the bound; hitting it
/// indicates pathological per-zone writer overload (operator response:
/// scale the writer fan-in or shard the per-zone Mutex).
pub const CAS_RETRY_BUDGET: usize = 64;

/// Number of stale-head CAS attempts after which production append
/// switches to a deterministic serialized commit for the current
/// event.
///
/// The optimistic path remains the hot path for uncontended and
/// lightly-contended zones. Under a same-zone storm, repeatedly
/// rebuilding canonical CBOR against stale heads burns CPU and can
/// exhaust [`CAS_RETRY_BUDGET`]. The serialized fallback pays one
/// short critical section for one event, using the fresh chain head
/// already protected by the zone mutex. That preserves chain
/// semantics while guaranteeing progress before the defensive retry
/// budget trips.
pub const SERIALIZED_COMMIT_FALLBACK_ATTEMPTS: usize = 8;

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
    const fn event_type(&self) -> &'static str {
        match self {
            Self::PreflightAllow => event_types::INVOKE_ALLOW,
            Self::PreflightDeny { .. } => event_types::INVOKE_DENY,
            Self::DispatchResult { .. } => event_types::INVOKE_RESULT,
            Self::DispatchError { .. } => event_types::INVOKE_ERROR,
        }
    }

    const fn severity(&self) -> Severity {
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
            Self::DispatchError { error, duration_ms } => vec![
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
/// hash linkage.
///
/// # Concurrency model (br-uwlj5)
///
/// Two-layer locking, sharded by zone:
///
/// - **Outer `RwLock<HashMap<String, Arc<Mutex<ZoneChain>>>>`** —
///   read-locked on the hot path to look up the per-zone Mutex
///   (multiple zones can be looked up concurrently); write-locked
///   only on the COLD path that inserts a new zone (rare, dominated
///   by the lifetime of the host).
/// - **Inner per-zone `Mutex<ZoneChain>`** — held only for the
///   short bookkeeping window: snapshot `(last_seq, last_id)` →
///   drop → encode canonical CBOR + compute id OUTSIDE the lock →
///   re-lock + CAS-style verify the head still matches the
///   snapshot → push.
///
/// Net effect: N concurrent invokes targeting N distinct zones run
/// in parallel (each on its own per-zone Mutex). Same-zone invokes
/// still serialise on the per-zone Mutex but pay only the
/// constant-time bookkeeping cost inside the lock — the dominant
/// canonical-CBOR + BLAKE3 work happens lock-free, with an
/// optimistic-CAS retry on the rare case where another append to
/// the same zone landed between snapshot and commit.
///
/// Pre-uwlj5 design used a single global `Mutex<HashMap<...>>`
/// holding canonical CBOR + BLAKE3 inside the critical section —
/// throughput bottleneck on the per-`/rpc/invoke` audit hot path.
#[derive(Debug, Default)]
pub struct InvokeAuditChain {
    /// Outer map of per-zone chain handles. Read-locked on the
    /// hot path; write-locked only when a new zone is first
    /// observed.
    chains: RwLock<HashMap<String, Arc<Mutex<ZoneChain>>>>,
}

impl InvokeAuditChain {
    /// Construct an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get-or-insert the per-zone handle. Optimised for the
    /// already-present case (single read-lock, no allocation).
    fn zone_handle(&self, zone_id: &str) -> Arc<Mutex<ZoneChain>> {
        // Fast path: zone already present, single read-lock.
        if let Some(handle) = self
            .chains
            .read()
            .expect("InvokeAuditChain outer rwlock poisoned")
            .get(zone_id)
        {
            return Arc::clone(handle);
        }
        // Slow path: insert under the write lock. Re-check after
        // upgrading because another writer may have raced us in.
        let mut chains = self
            .chains
            .write()
            .expect("InvokeAuditChain outer rwlock poisoned");
        Arc::clone(
            chains
                .entry(zone_id.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(ZoneChain::default()))),
        )
    }

    /// Append a phase event for `ctx` and return the resulting entry.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if canonical-CBOR encoding of the entry
    /// payload fails (cannot happen for normal field values), or
    /// [`AuditError::ContentionExhausted`] if the optimistic-CAS retry
    /// budget [`CAS_RETRY_BUDGET`] is exceeded under per-zone writer
    /// overload.
    pub fn append(
        &self,
        ctx: &InvokeAuditContext,
        phase: InvokePhase,
    ) -> Result<AuditEntry, AuditError> {
        self.append_with_contention_policy(
            ctx,
            phase,
            CAS_RETRY_BUDGET,
            Some(SERIALIZED_COMMIT_FALLBACK_ATTEMPTS),
        )
    }

    /// Same as [`Self::append`] but with a caller-supplied CAS retry
    /// budget and no serialized fallback. Production callers should
    /// always use [`Self::append`] (which passes
    /// [`CAS_RETRY_BUDGET`] and enables
    /// [`SERIALIZED_COMMIT_FALLBACK_ATTEMPTS`]). This entry point
    /// exists so regression tests and benchmarks can drive the
    /// retry-only bound deterministically instead of trying to
    /// construct a real pathological storm.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if canonical-CBOR encoding of the entry
    /// payload fails, or [`AuditError::ContentionExhausted`] if the
    /// supplied retry budget is exceeded under same-zone contention.
    pub fn append_with_retry_budget(
        &self,
        ctx: &InvokeAuditContext,
        phase: InvokePhase,
        retry_budget: usize,
    ) -> Result<AuditEntry, AuditError> {
        self.append_with_contention_policy(ctx, phase, retry_budget, None)
    }

    fn append_with_contention_policy(
        &self,
        ctx: &InvokeAuditContext,
        phase: InvokePhase,
        retry_budget: usize,
        serialized_fallback_after: Option<usize>,
    ) -> Result<AuditEntry, AuditError> {
        let event_type = phase.event_type();
        let severity = phase.severity();
        let metadata = phase.into_metadata();

        // Build the immutable parts of the entry once; only seq +
        // prev change between retries.
        let base_builder = AuditEntryBuilder::new()
            .event_type(event_type)
            .severity(severity)
            .actor(&ctx.actor)
            .zone_id(&ctx.zone_id)
            .occurred_at(ctx.occurred_at)
            .connector_id(&ctx.connector_id)
            .operation_id(&ctx.operation_id)
            .meta("operation", json!(ctx.operation));
        let base_builder = if let Some(cid) = ctx.correlation_id.clone() {
            base_builder.correlation_id(cid)
        } else {
            base_builder
        };
        let base_builder = metadata
            .into_iter()
            .fold(base_builder, |b, (k, v)| b.meta(k, v));

        let zone = self.zone_handle(&ctx.zone_id);

        // br-uwlj5 optimistic-CAS retry loop. Constant in practice:
        // contention only happens when N appends to the SAME zone
        // race, which is bounded by per-zone request rate.
        let mut attempts: usize = 0;
        loop {
            attempts = attempts.saturating_add(1);
            // 1. Snapshot (last_seq, last_id) under the per-zone
            //    Mutex — short critical section, no allocation
            //    beyond the optional String clone of last_id.
            let (next_seq, prev_snapshot) = {
                let z = zone.lock().expect("InvokeAuditChain zone mutex poisoned");
                (
                    z.last_seq.map_or(0u64, |s| s.saturating_add(1)),
                    z.last_id.clone(),
                )
            };

            // 2. Build entry + encode canonical + hash OUTSIDE
            //    any lock. This is the dominant cost; running it
            //    lock-free is the load-bearing perf win.
            let mut builder = base_builder.clone().seq(next_seq);
            if let Some(p) = prev_snapshot {
                builder = builder.prev(p);
            }
            let entry = builder
                .build_with_computed_id()
                .map_err(|e| AuditError::SerializationError(format!("invoke audit build: {e}")))?;
            let real_id = entry.id.clone();

            // 3. Re-lock + CAS commit. If another append landed
            //    on this zone between (1) and (3), our prev /
            //    seq snapshot is stale — retry with the fresh
            //    head. In the uncontended case (different zones
            //    or sequential same-zone) this loop runs once.
            {
                let mut z = zone.lock().expect("InvokeAuditChain zone mutex poisoned");
                if z.last_id.as_deref() == entry.prev.as_deref() {
                    z.last_seq = Some(next_seq);
                    z.last_id = Some(real_id);
                    z.entries.push(entry.clone());
                    drop(z);
                    return Ok(entry);
                }
                // Else: another writer raced us; retry with the
                // fresh head. Drop the lock and loop.
            }

            // Same-zone storms can make every lock-free build race a
            // fresher head. Once that pattern is visible, switch this
            // one event to a serialized commit: take the fresh head
            // under the zone mutex, build the entry once, and append
            // immediately. This is equivalent to a successful retry
            // whose snapshot cannot go stale because the snapshot and
            // commit happen in the same critical section.
            if serialized_fallback_after.is_some_and(|fallback_after| attempts >= fallback_after) {
                return Self::append_serialized(&zone, &base_builder);
            }

            // Defence in depth against pathological retry storms
            // (should be impossible without thousands of concurrent
            // same-zone appenders): bail with an error after a
            // reasonable bound rather than spinning forever.
            //
            // br-1a73y: bail with the contention-specific variant so
            // operator telemetry attributes the failure to per-zone
            // writer overload (correct response: scale or shard the
            // per-zone Mutex) rather than to a serialisation /
            // canonicalisation bug (which is what the previous
            // `SerializationError` taxonomy implied).
            if attempts > retry_budget {
                return Err(AuditError::ContentionExhausted {
                    zone_id: ctx.zone_id.clone(),
                    attempts,
                });
            }
        }
    }

    fn append_serialized(
        zone: &Arc<Mutex<ZoneChain>>,
        base_builder: &AuditEntryBuilder,
    ) -> Result<AuditEntry, AuditError> {
        let mut z = zone.lock().expect("InvokeAuditChain zone mutex poisoned");
        let next_seq = z.last_seq.map_or(0u64, |s| s.saturating_add(1));
        let mut builder = base_builder.clone().seq(next_seq);
        if let Some(prev) = z.last_id.clone() {
            builder = builder.prev(prev);
        }
        let entry = builder
            .build_with_computed_id()
            .map_err(|e| AuditError::SerializationError(format!("invoke audit build: {e}")))?;
        z.last_seq = Some(next_seq);
        z.last_id = Some(entry.id.clone());
        z.entries.push(entry.clone());
        drop(z);
        Ok(entry)
    }

    /// Snapshot of the entries appended for `zone_id`. Empty if the
    /// zone has had no invokes yet.
    ///
    /// # Panics
    ///
    /// Panics if the chain map or per-zone chain mutex has been poisoned.
    #[must_use]
    pub fn entries_for_zone(&self, zone_id: &str) -> Vec<AuditEntry> {
        let Some(handle) = self
            .chains
            .read()
            .expect("InvokeAuditChain outer rwlock poisoned")
            .get(zone_id)
            .cloned()
        else {
            return Vec::new();
        };
        handle
            .lock()
            .expect("InvokeAuditChain zone mutex poisoned")
            .entries
            .clone()
    }

    /// Number of entries appended for `zone_id`.
    ///
    /// # Panics
    ///
    /// Panics if the chain map or per-zone chain mutex has been poisoned.
    #[must_use]
    pub fn len_for_zone(&self, zone_id: &str) -> usize {
        let Some(handle) = self
            .chains
            .read()
            .expect("InvokeAuditChain outer rwlock poisoned")
            .get(zone_id)
            .cloned()
        else {
            return 0;
        };
        handle
            .lock()
            .expect("InvokeAuditChain zone mutex poisoned")
            .entries
            .len()
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
        assert!(
            entry.is_genesis(),
            "first entry must be genesis (seq 0, no prev)"
        );
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
            second.prev,
            Some(&first.id),
            second.seq,
            first.seq + 1
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

    // ── br-uwlj5: per-zone sharding regressions ──────────────────────

    #[test]
    fn invoke_audit_chain_concurrent_appends_to_distinct_zones_do_not_serialise() {
        // br-uwlj5: under per-zone sharding, two threads appending to
        // different zones MUST be able to land their entries
        // independently of each other's lock state. The pre-uwlj5
        // single-Mutex design would force one thread to wait on the
        // other's canonical-CBOR + BLAKE3 critical section.
        //
        // Functional check: spawn N threads each appending APPENDS_PER
        // events to a unique zone, then assert every chain has the
        // expected length and each entry's prev hash-links to the
        // previous one. Concurrency-safety + zone isolation in one
        // test.
        use std::thread;

        const ZONES: usize = 8;
        const APPENDS_PER: usize = 32;

        let chain = std::sync::Arc::new(InvokeAuditChain::new());
        let mut handles = Vec::with_capacity(ZONES);
        for z in 0..ZONES {
            let chain_arc = std::sync::Arc::clone(&chain);
            handles.push(thread::spawn(move || {
                let zone_id = format!("z:zone-{z}");
                for i in 0..APPENDS_PER {
                    let c = InvokeAuditContext {
                        zone_id: zone_id.clone(),
                        actor: format!("agent:t-{z}"),
                        connector_id: "github".into(),
                        operation: "list_repos".into(),
                        operation_id: format!("op-{z}-{i}"),
                        correlation_id: None,
                        occurred_at: 1_700_000_000 + i as u64,
                    };
                    chain_arc
                        .append(&c, InvokePhase::PreflightAllow)
                        .expect("append must not fail under per-zone sharding");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        // Each zone got APPENDS_PER entries, each correctly hash-linked.
        for z in 0..ZONES {
            let zone_id = format!("z:zone-{z}");
            let entries = chain.entries_for_zone(&zone_id);
            assert_eq!(
                entries.len(),
                APPENDS_PER,
                "zone {zone_id} must have {APPENDS_PER} entries"
            );
            assert!(
                entries[0].is_genesis(),
                "zone {zone_id}: entry 0 is genesis"
            );
            for i in 1..entries.len() {
                assert!(
                    entries[i].follows(&entries[i - 1]),
                    "zone {zone_id}: entry {i} must hash-link to entry {}: prev={:?} expected={:?}, seq={} expected={}",
                    i - 1,
                    entries[i].prev,
                    Some(&entries[i - 1].id),
                    entries[i].seq,
                    entries[i - 1].seq + 1,
                );
            }
        }
    }

    #[test]
    fn invoke_audit_chain_concurrent_same_zone_appends_preserve_chain_integrity() {
        // br-uwlj5: same-zone appends still serialise on the per-zone
        // Mutex, but the optimistic-CAS retry pattern means concurrent
        // appenders DO retry and DO produce a correctly hash-linked
        // chain. This test pins the property: N threads × M appends to
        // ONE zone produces N×M entries with monotonic seq and
        // pairwise prev-link.
        use std::thread;

        const THREADS: usize = 8;
        const APPENDS_PER: usize = 16;

        let chain = std::sync::Arc::new(InvokeAuditChain::new());
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let chain_arc = std::sync::Arc::clone(&chain);
            handles.push(thread::spawn(move || {
                for i in 0..APPENDS_PER {
                    let c = InvokeAuditContext {
                        zone_id: "z:contended".into(),
                        actor: format!("agent:t-{t}"),
                        connector_id: "github".into(),
                        operation: "list_repos".into(),
                        operation_id: format!("op-{t}-{i}"),
                        correlation_id: None,
                        occurred_at: 1_700_000_000,
                    };
                    chain_arc
                        .append(&c, InvokePhase::PreflightAllow)
                        .expect("same-zone append must succeed via CAS retry");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        let entries = chain.entries_for_zone("z:contended");
        assert_eq!(entries.len(), THREADS * APPENDS_PER);
        // Monotonic seq: 0, 1, 2, ..., THREADS*APPENDS_PER - 1.
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq, i as u64, "monotonic seq broken at index {i}");
        }
        // Pairwise hash links.
        assert!(entries[0].is_genesis());
        for i in 1..entries.len() {
            assert!(
                entries[i].follows(&entries[i - 1]),
                "entry {i} must hash-link under contention"
            );
        }
    }

    #[test]
    fn invoke_audit_chain_same_zone_storm_uses_serialized_fallback_without_dropping_events() {
        // evxvv.8: the retry-only CAS path can exhaust its defensive
        // retry budget under modest same-zone storms. Production
        // append keeps the optimistic path for ordinary traffic but
        // falls back to one serialized commit once stale-head retries
        // show that this event is racing a hot zone. The observable
        // contract is unchanged: every append lands exactly once, seq
        // is monotonic, and prev hash-links to the prior entry.
        use std::thread;

        const THREADS: usize = 64;
        const APPENDS_PER: usize = 16;

        let chain = std::sync::Arc::new(InvokeAuditChain::new());
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let chain_arc = std::sync::Arc::clone(&chain);
            handles.push(thread::spawn(move || {
                for i in 0..APPENDS_PER {
                    let c = InvokeAuditContext {
                        zone_id: "z:storm".into(),
                        actor: format!("agent:t-{t}"),
                        connector_id: "github".into(),
                        operation: "list_repos".into(),
                        operation_id: format!("op-{t}-{i}"),
                        correlation_id: None,
                        occurred_at: 1_700_000_000,
                    };
                    chain_arc
                        .append(&c, InvokePhase::PreflightAllow)
                        .expect("serialized fallback must prevent same-zone audit loss");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        let entries = chain.entries_for_zone("z:storm");
        assert_eq!(entries.len(), THREADS * APPENDS_PER);
        assert!(entries[0].is_genesis());
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.seq, i as u64, "monotonic seq broken at index {i}");
            if i > 0 {
                assert!(
                    entry.follows(&entries[i - 1]),
                    "entry {i} must hash-link after serialized fallback"
                );
            }
        }
    }

    /// br-1a73y: when the optimistic-CAS retry budget is exhausted
    /// the bail MUST surface as `AuditError::ContentionExhausted`
    /// (not the misleading `SerializationError` the prior taxonomy
    /// used). This regression drives the bail deterministically by
    /// passing a tiny `retry_budget` and racing many concurrent
    /// appenders on a single zone — at least one appender will be
    /// out-CAS'd more times than the budget allows.
    #[test]
    fn br_1a73y_cas_retry_budget_exhaustion_returns_contention_exhausted_variant() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        // Tiny retry budget so even modest contention trips it.
        const RETRY_BUDGET: usize = 1;
        const THREADS: usize = 32;
        const APPENDS_PER: usize = 8;

        let chain = StdArc::new(InvokeAuditChain::new());
        let contention_failures = StdArc::new(AtomicUsize::new(0));
        let unexpected_errors = StdArc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let chain_arc = StdArc::clone(&chain);
            let failures = StdArc::clone(&contention_failures);
            let unexpected = StdArc::clone(&unexpected_errors);
            handles.push(thread::spawn(move || {
                for i in 0..APPENDS_PER {
                    let c = InvokeAuditContext {
                        zone_id: "z:contention-storm".into(),
                        actor: format!("agent:t-{t}"),
                        connector_id: "github".into(),
                        operation: "list_repos".into(),
                        operation_id: format!("op-{t}-{i}"),
                        correlation_id: None,
                        occurred_at: 1_700_000_000,
                    };
                    match chain_arc.append_with_retry_budget(
                        &c,
                        InvokePhase::PreflightAllow,
                        RETRY_BUDGET,
                    ) {
                        Ok(_) => {}
                        Err(AuditError::ContentionExhausted { zone_id, attempts }) => {
                            failures.fetch_add(1, Ordering::SeqCst);
                            // Operator-diagnostic fields populated.
                            assert_eq!(zone_id, "z:contention-storm");
                            assert!(
                                attempts > RETRY_BUDGET,
                                "ContentionExhausted must report attempts > budget"
                            );
                        }
                        Err(_) => {
                            unexpected.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        let total = contention_failures.load(Ordering::SeqCst);
        assert_eq!(
            unexpected_errors.load(Ordering::SeqCst),
            0,
            "br-1a73y: expected only Ok or ContentionExhausted; any other variant means the bail \
             returned the wrong taxonomy and operator telemetry will mis-route"
        );
        assert!(
            total > 0,
            "br-1a73y: with RETRY_BUDGET={RETRY_BUDGET} and {THREADS} threads racing on one \
             zone, the test scenario must trip the bail at least once — got 0. If this \
             flakes, raise THREADS or APPENDS_PER, do NOT raise RETRY_BUDGET above 1 \
             (the test is asserting that the bail returns the right variant when it \
             fires, not that it must always fire)"
        );
    }
}
