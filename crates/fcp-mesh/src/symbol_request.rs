//! Symbol request handling with admission control and targeted repair.
//!
//! This module implements the NORMATIVE symbol request handling from
//! `FCP_Specification_V2.md`, including:
//!
//! - [`SymbolRequestHandler`] - Validates and processes bounded symbol requests
//! - [`SymbolResponseBuilder`] - Builds bounded responses with targeted repair
//! - [`TargetedRepairEngine`] - Uses missing hints for efficient repair
//!
//! # Overview
//!
//! Symbol request handling enforces:
//! - Bounded requests (max_symbols and/or missing-hint proof-of-need)
//! - Anti-amplification rules for unauthenticated peers
//! - Admission control integration (bytes + CPU + inflight decodes)
//! - Stop conditions via SymbolAck
//!
//! # Anti-Amplification Rule (NORMATIVE)
//!
//! `MeshNodes` MUST NOT send more than N symbols in response to a request unless:
//! 1. The requester is authenticated (session MAC or node signature), AND
//! 2. The request includes a bounded missing-hint or proof-of-need

#![forbid(unsafe_code)]

use crate::admission::{AdmissionController, AdmissionError};
use fcp_core::{ObjectId, ZoneId, ZoneKeyId};
use fcp_protocol::{
    DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, DecodeStatus, MAX_MISSING_HINT_ENTRIES, SymbolAck,
    SymbolRequest,
};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::{debug, info, warn};

// ============================================================================
// Constants
// ============================================================================

/// Default maximum response symbols for unauthenticated requests (NORMATIVE).
pub const DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED: u32 = 32;

/// Default maximum response symbols for authenticated requests (NORMATIVE).
pub const DEFAULT_RESPONSE_LIMIT_AUTHENTICATED: u32 = 1000;

/// Default minimum symbols to send even without proof-of-need (bootstrap).
pub const DEFAULT_MIN_BOOTSTRAP_SYMBOLS: u32 = 8;

// ============================================================================
// Error Types
// ============================================================================

/// Symbol request handling errors.
#[derive(Debug, Error)]
pub enum SymbolRequestError {
    /// Request validation failed.
    #[error("invalid request: {reason}")]
    InvalidRequest { reason: String },

    /// Request exceeded bounds.
    #[error("request exceeds bounds: requested {requested}, max {max_allowed}")]
    BoundsExceeded { requested: u32, max_allowed: u32 },

    /// Missing hint exceeds maximum entries.
    #[error("missing hint exceeds limit: {count} entries, max {max}")]
    HintTooLarge { count: usize, max: usize },

    /// Admission control rejected the request.
    #[error("admission control rejected: {0}")]
    AdmissionRejected(#[from] AdmissionError),

    /// Object not found.
    #[error("object not found: {object_id}")]
    ObjectNotFound { object_id: String },

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Request for completed transfer.
    #[error("transfer already complete for object {object_id}")]
    AlreadyComplete { object_id: String },
}

// ============================================================================
// Request Validation Result
// ============================================================================

/// Result of validating a symbol request.
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    /// The validated request.
    pub request: SymbolRequest,
    /// Whether the requester is authenticated.
    pub is_authenticated: bool,
    /// Maximum symbols allowed in response (computed from policy).
    pub max_response_symbols: u32,
    /// Whether the request has proof-of-need.
    pub has_proof_of_need: bool,
}

// ============================================================================
// Symbol Response
// ============================================================================

/// Response to a symbol request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolResponse {
    /// Object ID being responded to.
    pub object_id: ObjectId,
    /// Zone ID.
    pub zone_id: ZoneId,
    /// Zone key ID.
    pub zone_key_id: ZoneKeyId,
    /// ESIs of symbols being sent.
    pub symbol_esis: Vec<u32>,
    /// Whether this completes the transfer.
    pub is_final: bool,
    /// Response was limited by bounds.
    pub was_bounded: bool,
}

impl SymbolResponse {
    /// Number of symbols in this response.
    #[must_use]
    pub fn symbol_count(&self) -> u32 {
        u32::try_from(self.symbol_esis.len()).unwrap_or(u32::MAX)
    }
}

// ============================================================================
// Symbol Request Handler
// ============================================================================

/// Handler for symbol requests with admission control.
///
/// Validates incoming requests, enforces bounds, and coordinates with
/// admission control to prevent DoS attacks.
pub struct SymbolRequestHandler {
    /// Policy configuration.
    policy: SymbolRequestPolicy,
    /// Active transfers (object_id -> transfer state).
    active_transfers: HashMap<ObjectId, TransferState>,
    /// Completed transfers awaiting SymbolAck (object_id -> timestamp_ms).
    completed_awaiting_ack: HashMap<ObjectId, u64>,
    /// Completed transfers (SymbolAck received) (object_id -> timestamp_ms).
    completed_transfers: HashMap<ObjectId, u64>,
}

/// Policy for symbol request handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRequestPolicy {
    /// Max response symbols for unauthenticated requests.
    pub max_unauthenticated_response: u32,
    /// Max response symbols for authenticated requests.
    pub max_authenticated_response: u32,
    /// Min symbols to send without proof-of-need (bootstrap mode).
    pub min_bootstrap_symbols: u32,
    /// Whether to require proof-of-need for large requests.
    pub require_proof_of_need_above: u32,
    /// Whether to allow unauthenticated requests at all.
    pub allow_unauthenticated: bool,
    /// Timeout for stale transfer state in milliseconds (default: 1 hour).
    pub transfer_state_ttl_ms: u64,
}

impl Default for SymbolRequestPolicy {
    fn default() -> Self {
        Self {
            max_unauthenticated_response: DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED,
            max_authenticated_response: DEFAULT_RESPONSE_LIMIT_AUTHENTICATED,
            min_bootstrap_symbols: DEFAULT_MIN_BOOTSTRAP_SYMBOLS,
            require_proof_of_need_above: 100, // Require hints for large requests
            allow_unauthenticated: true,      // Zone can override
            transfer_state_ttl_ms: 3_600_000, // 1 hour
        }
    }
}

/// State for an active transfer.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for full MeshNode handler implementation
struct TransferState {
    /// Object ID.
    object_id: ObjectId,
    /// Total symbols needed for decode.
    total_needed: u32,
    /// ESIs already sent.
    sent_esis: HashSet<u32>,
    /// Last decode status received.
    last_status: Option<DecodeStatusSummary>,
    /// Whether we've been told to stop.
    stopped: bool,
    /// Last activity timestamp (ms).
    last_activity: u64,
}

/// Summary of a decode status for tracking.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for full MeshNode handler implementation
struct DecodeStatusSummary {
    /// Unique symbols received.
    received_unique: u32,
    /// Symbols still needed.
    needed: u32,
    /// Is decode complete.
    complete: bool,
}

impl SymbolRequestHandler {
    /// Create a new handler with the given policy.
    #[must_use]
    pub fn new(policy: SymbolRequestPolicy) -> Self {
        Self {
            policy,
            active_transfers: HashMap::new(),
            completed_awaiting_ack: HashMap::new(),
            completed_transfers: HashMap::new(),
        }
    }

    /// Create a handler with default policy.
    #[must_use]
    pub fn with_default_policy() -> Self {
        Self::new(SymbolRequestPolicy::default())
    }

    /// Validate an incoming symbol request.
    ///
    /// # Errors
    ///
    /// Returns `SymbolRequestError` if the request is invalid or exceeds bounds.
    pub fn validate_request(
        &self,
        request: &SymbolRequest,
        is_authenticated: bool,
        admission: &mut AdmissionController,
        peer: &NodeId,
        now_ms: u64,
        symbol_size: u16,
    ) -> Result<ValidatedRequest, SymbolRequestError> {
        // Check if unauthenticated requests are allowed
        if !is_authenticated && !self.policy.allow_unauthenticated {
            return Err(SymbolRequestError::AdmissionRejected(
                AdmissionError::AuthenticationRequired,
            ));
        }

        if request.zone_id != request.header.zone_id {
            return Err(SymbolRequestError::InvalidRequest {
                reason: "request zone_id does not match header zone_id".to_string(),
            });
        }

        // Validate hint bounds
        if let Some(ref hints) = request.missing_hint {
            if hints.len() > MAX_MISSING_HINT_ENTRIES {
                return Err(SymbolRequestError::HintTooLarge {
                    count: hints.len(),
                    max: MAX_MISSING_HINT_ENTRIES,
                });
            }
            if hints.len() > request.max_symbols as usize {
                return Err(SymbolRequestError::InvalidRequest {
                    reason: "missing hint exceeds max_symbols".to_string(),
                });
            }
        }

        // Compute maximum allowed response
        let base_limit = if is_authenticated {
            self.policy.max_authenticated_response
        } else {
            self.policy.max_unauthenticated_response
        };

        // Request's max_symbols bounds the response
        let max_response_symbols = request.max_symbols.min(base_limit);

        // For unauthenticated requests, enforce stricter limits
        if !is_authenticated && request.max_symbols > DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED {
            warn!(
                peer = %peer,
                requested = request.max_symbols,
                limit = DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED,
                "unauthenticated request exceeds limit"
            );
            return Err(SymbolRequestError::BoundsExceeded {
                requested: request.max_symbols,
                max_allowed: DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED,
            });
        }

        // Check admission control
        let estimated_response_bytes = u64::from(max_response_symbols) * u64::from(symbol_size);
        admission.check_admission(
            peer,
            estimated_response_bytes,
            max_response_symbols,
            is_authenticated,
            now_ms,
        )?;

        // Check anti-amplification for large requests
        let has_proof_of_need = request.has_proof_of_need();
        if max_response_symbols > self.policy.require_proof_of_need_above
            && !has_proof_of_need
            && !is_authenticated
        {
            warn!(
                peer = %peer,
                requested = max_response_symbols,
                "large unauthenticated request without proof-of-need"
            );
            return Err(SymbolRequestError::AdmissionRejected(
                AdmissionError::ProofOfNeedRequired,
            ));
        }

        debug!(
            peer = %peer,
            object_id = %hex::encode(request.object_id.as_bytes()),
            max_symbols = max_response_symbols,
            has_proof = has_proof_of_need,
            authenticated = is_authenticated,
            "validated symbol request"
        );

        Ok(ValidatedRequest {
            request: request.clone(),
            is_authenticated,
            max_response_symbols,
            has_proof_of_need,
        })
    }

    /// Process a decode status update from a peer.
    ///
    /// Updates transfer state based on receiver feedback.
    pub fn process_decode_status(&mut self, status: &DecodeStatus, now_ms: u64) {
        let summary = DecodeStatusSummary {
            received_unique: status.received_unique,
            needed: status.needed,
            complete: status.complete,
        };

        if status.complete {
            info!(
                object_id = %hex::encode(status.object_id.as_bytes()),
                received = status.received_unique,
                "decode complete, awaiting SymbolAck"
            );
            self.completed_awaiting_ack
                .insert(status.object_id.clone(), now_ms);
        }

        if let Some(state) = self.active_transfers.get_mut(&status.object_id) {
            state.last_status = Some(summary);
            state.last_activity = now_ms;
            if status.complete {
                state.stopped = true;
            }
        }
    }

    /// Track symbols sent for a request (starts or updates transfer state).
    pub fn track_transfer(
        &mut self,
        request: &SymbolRequest,
        sent_esis: impl IntoIterator<Item = u32>,
        now_ms: u64,
    ) {
        let state = self
            .active_transfers
            .entry(request.object_id)
            .or_insert_with(|| TransferState {
                object_id: request.object_id,
                total_needed: request.max_symbols,
                sent_esis: HashSet::new(),
                last_status: None,
                stopped: false,
                last_activity: now_ms,
            });

        state.last_activity = now_ms;
        state.total_needed = state.total_needed.max(request.max_symbols);
        state.sent_esis.extend(sent_esis);
    }

    /// Process a symbol acknowledgment (stop condition).
    ///
    /// Stops sending symbols for the acknowledged object.
    pub fn process_symbol_ack(&mut self, ack: &SymbolAck, now_ms: u64) {
        info!(
            object_id = %hex::encode(ack.object_id.as_bytes()),
            reason = ?ack.reason,
            final_count = ack.final_symbol_count,
            "received SymbolAck, stopping transfer"
        );

        self.completed_awaiting_ack.remove(&ack.object_id);
        self.completed_transfers.insert(ack.object_id, now_ms);

        if let Some(state) = self.active_transfers.get_mut(&ack.object_id) {
            state.stopped = true;
            state.last_activity = now_ms;
        }

        // Can clean up transfer state
        self.active_transfers.remove(&ack.object_id);
    }

    /// Check if a transfer should stop.
    #[must_use]
    pub fn should_stop(&self, object_id: &ObjectId) -> bool {
        if self.completed_transfers.contains_key(object_id) {
            return true;
        }
        self.active_transfers
            .get(object_id)
            .is_some_and(|s| s.stopped)
    }

    /// Prune stale transfer state.
    ///
    /// Removes active and completed transfers that have exceeded the TTL.
    /// Returns the count of removed entries (active + completed).
    pub fn prune_stale_state(&mut self, now_ms: u64) -> usize {
        let ttl = self.policy.transfer_state_ttl_ms;
        let expired_threshold = now_ms.saturating_sub(ttl);
        let mut removed = 0;

        self.active_transfers.retain(|_, state| {
            let keep = state.last_activity >= expired_threshold;
            if !keep {
                removed += 1;
            }
            keep
        });

        self.completed_awaiting_ack.retain(|_, timestamp| {
            let keep = *timestamp >= expired_threshold;
            if !keep {
                removed += 1;
            }
            keep
        });

        self.completed_transfers.retain(|_, timestamp| {
            let keep = *timestamp >= expired_threshold;
            if !keep {
                removed += 1;
            }
            keep
        });

        if removed > 0 {
            debug!(removed, "pruned stale transfer state");
        }
        removed
    }

    /// Get the policy.
    #[must_use]
    pub const fn policy(&self) -> &SymbolRequestPolicy {
        &self.policy
    }

    /// Get active transfer count.
    #[must_use]
    pub fn active_transfer_count(&self) -> usize {
        self.active_transfers.len()
    }
}

// ============================================================================
// Targeted Repair Engine
// ============================================================================

/// Engine for targeted repair using missing hints.
///
/// When a peer provides specific ESIs they need, this engine ensures
/// we send exactly those symbols rather than flooding redundant data.
pub struct TargetedRepairEngine {
    /// Available symbols per object (ESI -> available).
    available_symbols: HashMap<ObjectId, HashSet<u32>>,
}

impl TargetedRepairEngine {
    /// Create a new repair engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available_symbols: HashMap::new(),
        }
    }

    /// Register available symbols for an object.
    pub fn register_available(&mut self, object_id: ObjectId, esis: impl IntoIterator<Item = u32>) {
        let set = self
            .available_symbols
            .entry(object_id)
            .or_insert_with(HashSet::new);
        set.extend(esis);
    }

    /// Select symbols to send based on request and availability.
    ///
    /// If the request has a missing_hint, prioritizes those ESIs.
    /// Otherwise, selects available symbols up to the limit.
    #[must_use]
    pub fn select_symbols(
        &self,
        request: &ValidatedRequest,
        already_sent: &HashSet<u32>,
    ) -> Vec<u32> {
        let available = match self.available_symbols.get(&request.request.object_id) {
            Some(set) => set,
            None => return vec![],
        };

        let limit = request
            .max_response_symbols
            .saturating_add(1)
            .try_into()
            .unwrap_or(usize::MAX);

        // If we have a missing hint, prioritize those
        if let Some(ref hints) = request.request.missing_hint {
            let mut seen = HashSet::new();
            let mut selected = Vec::new();
            for esi in hints.iter().copied() {
                if selected.len() >= limit {
                    break;
                }
                if !seen.insert(esi) {
                    continue;
                }
                if available.contains(&esi) && !already_sent.contains(&esi) {
                    selected.push(esi);
                }
            }

            // If we have room and the hint didn't fill it, add more
            if selected.len() < limit {
                let remaining = limit - selected.len();
                let hint_set: HashSet<_> = hints.iter().copied().collect();
                let mut additional: Vec<_> = available
                    .iter()
                    .filter(|esi| !hint_set.contains(esi) && !already_sent.contains(esi))
                    .copied()
                    .collect();
                additional.sort_unstable();
                additional.truncate(remaining);
                selected.extend(additional);
            }

            debug!(
                object_id = %hex::encode(request.request.object_id.as_bytes()),
                requested_hints = hints.len(),
                selected = selected.len(),
                "targeted repair: selected symbols from hints"
            );

            selected
        } else {
            // No hints, select any available symbols
            let mut candidates: Vec<u32> = available
                .iter()
                .filter(|esi| !already_sent.contains(esi))
                .copied()
                .collect();
            candidates.sort_unstable();
            candidates.truncate(limit);
            candidates
        }
    }

    /// Remove an object from tracking.
    pub fn remove_object(&mut self, object_id: &ObjectId) {
        self.available_symbols.remove(object_id);
    }
}

impl Default for TargetedRepairEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Symbol Response Builder
// ============================================================================

/// Builder for bounded symbol responses.
pub struct SymbolResponseBuilder {
    /// Object ID.
    object_id: ObjectId,
    /// Zone ID.
    zone_id: ZoneId,
    /// Zone key ID.
    zone_key_id: ZoneKeyId,
    /// Maximum symbols to include.
    max_symbols: u32,
    /// Selected ESIs.
    selected_esis: Vec<u32>,
    /// Whether response was limited by bounds.
    was_bounded: bool,
}

impl SymbolResponseBuilder {
    /// Create a new response builder.
    #[must_use]
    pub fn new(
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        max_symbols: u32,
    ) -> Self {
        Self {
            object_id,
            zone_id,
            zone_key_id,
            max_symbols,
            selected_esis: Vec::new(),
            was_bounded: false,
        }
    }

    /// Add symbols from the targeted repair engine.
    pub fn add_from_repair_engine(
        mut self,
        engine: &TargetedRepairEngine,
        request: &ValidatedRequest,
        already_sent: &HashSet<u32>,
    ) -> Self {
        let selected = engine.select_symbols(request, already_sent);
        let available_count = selected.len();

        // Apply bounds
        let limited: Vec<_> = selected
            .into_iter()
            .take(self.max_symbols as usize)
            .collect();

        self.was_bounded = limited.len() < available_count;
        self.selected_esis = limited;
        self
    }

    /// Build the response.
    #[must_use]
    pub fn build(self, total_available: u32, already_sent: usize) -> SymbolResponse {
        let sent_count = self.selected_esis.len() as u32;
        let already_sent = u32::try_from(already_sent).unwrap_or(u32::MAX);
        let total_sent = sent_count.saturating_add(already_sent);
        let is_final = total_sent >= total_available || self.selected_esis.is_empty();

        SymbolResponse {
            object_id: self.object_id,
            zone_id: self.zone_id,
            zone_key_id: self.zone_key_id,
            symbol_esis: self.selected_esis,
            is_final,
            was_bounded: self.was_bounded,
        }
    }
}

// ============================================================================
// Metrics
// ============================================================================

/// Metrics for symbol request handling.
#[derive(Debug, Default, Clone)]
pub struct SymbolRequestMetrics {
    /// Total requests received.
    pub requests_received: u64,
    /// Requests validated successfully.
    pub requests_validated: u64,
    /// Requests rejected by bounds.
    pub requests_rejected_bounds: u64,
    /// Requests rejected by admission control.
    pub requests_rejected_admission: u64,
    /// Total symbols sent in responses.
    pub symbols_sent: u64,
    /// Responses that used targeted repair.
    pub targeted_repairs: u64,
    /// SymbolAcks received.
    pub acks_received: u64,
}

impl SymbolRequestMetrics {
    /// Record a validated request.
    pub fn record_validated(&mut self) {
        self.requests_received += 1;
        self.requests_validated += 1;
    }

    /// Record a bounds rejection.
    pub fn record_bounds_rejection(&mut self) {
        self.requests_received += 1;
        self.requests_rejected_bounds += 1;
    }

    /// Record an admission rejection.
    pub fn record_admission_rejection(&mut self) {
        self.requests_received += 1;
        self.requests_rejected_admission += 1;
    }

    /// Record symbols sent.
    pub fn record_symbols_sent(&mut self, count: u32, was_targeted: bool) {
        self.symbols_sent += u64::from(count);
        if was_targeted {
            self.targeted_repairs += 1;
        }
    }

    /// Record a SymbolAck.
    pub fn record_ack(&mut self) {
        self.acks_received += 1;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_cbor::SchemaId;
    use fcp_core::{ObjectHeader, Provenance};
    use fcp_protocol::SymbolAckReason;
    use semver::Version;

    fn test_zone_id() -> ZoneId {
        "z:test-zone".parse().expect("zone parse")
    }

    fn test_zone_id_alt() -> ZoneId {
        "z:alt-zone".parse().expect("zone parse")
    }

    fn test_object_header() -> ObjectHeader {
        let zone_id = test_zone_id();
        ObjectHeader {
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_symbol_request(max_symbols: u32, hint: Option<Vec<u32>>) -> SymbolRequest {
        let zone_id = test_zone_id();
        let mut req = SymbolRequest::new(
            test_object_header(),
            ObjectId::from_bytes([0x11; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            max_symbols,
            0,
        );
        if let Some(h) = hint {
            req = req.with_missing_hint(h);
        }
        req
    }

    #[test]
    fn validate_authenticated_request() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-auth");

        let request = test_symbol_request(100, None);
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(result.is_ok());
        let validated = result.unwrap();
        assert!(validated.is_authenticated);
        assert_eq!(validated.max_response_symbols, 100);
        assert!(!validated.has_proof_of_need);
    }

    #[test]
    fn reject_zone_id_mismatch() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-zone-mismatch");

        let header = test_object_header();
        let request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0x11; 32]),
            test_zone_id_alt(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            10,
            0,
        );

        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);
        assert!(matches!(
            result,
            Err(SymbolRequestError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn validate_unauthenticated_request_bounded() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        admission.set_authenticated(&NodeId::new("peer-unauth"), false, 0);

        // Use a lenient policy for unauthenticated requests
        let mut policy = crate::admission::AdmissionPolicy::default();
        policy.require_authenticated_requests = false;
        let mut admission = AdmissionController::new(policy);

        let peer = NodeId::new("peer-unauth");

        // Request within unauthenticated limit should succeed
        let request = test_symbol_request(DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, None);
        let result = handler.validate_request(&request, false, &mut admission, &peer, 0, 64);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_unauthenticated_over_limit() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut policy = crate::admission::AdmissionPolicy::default();
        policy.require_authenticated_requests = false;
        let mut admission = AdmissionController::new(policy);

        let peer = NodeId::new("peer-over");

        // Request exceeding unauthenticated limit should fail
        let request = test_symbol_request(DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1, None);
        let result = handler.validate_request(&request, false, &mut admission, &peer, 0, 64);
        assert!(matches!(
            result,
            Err(SymbolRequestError::BoundsExceeded { .. })
        ));
    }

    #[test]
    fn validate_request_with_proof_of_need() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-pon");

        let request = test_symbol_request(50, Some(vec![1, 2, 3, 4, 5]));
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(result.is_ok());
        let validated = result.unwrap();
        assert!(validated.has_proof_of_need);
    }

    #[test]
    fn reject_hint_too_large() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-large-hint");

        let request = test_symbol_request(50, Some(vec![0; MAX_MISSING_HINT_ENTRIES + 1]));
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(matches!(
            result,
            Err(SymbolRequestError::HintTooLarge { .. })
        ));
    }

    #[test]
    fn reject_hint_exceeding_max_symbols() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-hint-max");

        let request = test_symbol_request(2, Some(vec![1, 2, 3]));
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(matches!(
            result,
            Err(SymbolRequestError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn targeted_repair_selects_from_hints() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        // Register available symbols
        engine.register_available(object_id.clone(), 0..100);

        let request = ValidatedRequest {
            request: test_symbol_request(10, Some(vec![5, 10, 15, 20, 25])),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: true,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());

        // Should select the hinted ESIs first
        assert!(selected.contains(&5));
        assert!(selected.contains(&10));
        assert!(selected.contains(&15));
        assert!(selected.contains(&20));
        assert!(selected.contains(&25));
    }

    #[test]
    fn targeted_repair_respects_already_sent() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..50);

        let request = ValidatedRequest {
            request: test_symbol_request(10, Some(vec![5, 10, 15])),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: true,
        };

        // Mark some as already sent
        let already_sent: HashSet<_> = vec![5, 10].into_iter().collect();
        let selected = engine.select_symbols(&request, &already_sent);

        // Should not re-select already sent
        assert!(!selected.contains(&5));
        assert!(!selected.contains(&10));
        assert!(selected.contains(&15));
    }

    #[test]
    fn targeted_repair_dedups_hints_and_orders_additional() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..20);

        let request = ValidatedRequest {
            request: test_symbol_request(4, Some(vec![10, 5, 10, 3])),
            is_authenticated: true,
            max_response_symbols: 4,
            has_proof_of_need: true,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());

        assert_eq!(selected, vec![10, 5, 3, 0, 1]);
    }

    #[test]
    fn targeted_repair_is_deterministic_without_hints() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..10);

        let request = ValidatedRequest {
            request: test_symbol_request(5, None),
            is_authenticated: true,
            max_response_symbols: 5,
            has_proof_of_need: false,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());

        assert_eq!(selected, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn process_symbol_ack_stops_transfer() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        // Initially not stopped
        assert!(!handler.should_stop(&object_id));

        // Process ack
        let ack = SymbolAck::new(
            test_object_header(),
            object_id.clone(),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            SymbolAckReason::Complete,
            500,
        );

        handler.process_symbol_ack(&ack, 0);

        // Transfer state should be removed
        assert_eq!(handler.active_transfer_count(), 0);
    }

    #[test]
    fn response_builder_respects_bounds() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let zone_id = test_zone_id();

        engine.register_available(object_id.clone(), 0..1000);

        let request = ValidatedRequest {
            request: test_symbol_request(50, None),
            is_authenticated: true,
            max_response_symbols: 50,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            25, // Builder limit smaller than request limit (50) to force bounding
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(1000, 0);

        // Should be bounded to 25
        assert_eq!(response.symbol_count(), 25);
        assert!(response.was_bounded);
        assert!(!response.is_final); // More available
    }

    #[test]
    fn response_builder_marks_bounded_when_request_limit_hits() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let zone_id = test_zone_id();

        engine.register_available(object_id.clone(), 0..100);

        let request = ValidatedRequest {
            request: test_symbol_request(10, None),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            request.max_response_symbols,
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(100, 0);

        assert_eq!(response.symbol_count(), 10);
        assert!(response.was_bounded);
        assert!(!response.is_final);
    }

    #[test]
    fn response_builder_marks_final_when_all_symbols_sent() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let zone_id = test_zone_id();

        engine.register_available(object_id.clone(), 0..2);

        let request = ValidatedRequest {
            request: test_symbol_request(1, None),
            is_authenticated: true,
            max_response_symbols: 1,
            has_proof_of_need: false,
        };

        let already_sent: HashSet<_> = vec![0].into_iter().collect();
        let response = SymbolResponseBuilder::new(
            object_id,
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            request.max_response_symbols,
        )
        .add_from_repair_engine(&engine, &request, &already_sent)
        .build(2, already_sent.len());

        assert_eq!(response.symbol_count(), 1);
        assert!(response.is_final);
    }

    #[test]
    fn decode_status_complete_stops_transfer() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        // Start a transfer
        let request = test_symbol_request(50, None);
        handler.track_transfer(&request, 0..10, 0);
        assert_eq!(handler.active_transfer_count(), 1);

        // Process decode status marking transfer complete
        let status = DecodeStatus {
            header: test_object_header(),
            object_id: object_id.clone(),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1000,
            received_unique: 50,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        handler.process_decode_status(&status, 0);

        // Transfer should be stopped
        assert!(handler.should_stop(&object_id));
    }

    #[test]
    fn track_transfer_accumulates_sent_esis() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let request = test_symbol_request(100, None);

        handler.track_transfer(&request, 0..5, 0);
        assert_eq!(handler.active_transfer_count(), 1);

        // Track more symbols for the same object
        handler.track_transfer(&request, 5..10, 0);
        assert_eq!(handler.active_transfer_count(), 1); // Same transfer
    }

    #[test]
    fn should_stop_after_ack() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        // Initially not stopped
        assert!(!handler.should_stop(&object_id));

        // Start tracking then ack
        let request = test_symbol_request(50, None);
        handler.track_transfer(&request, 0..5, 0);

        let ack = SymbolAck::new(
            test_object_header(),
            object_id.clone(),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            SymbolAckReason::Complete,
            5,
        );
        handler.process_symbol_ack(&ack, 0);

        // Should stop and be fully cleaned up
        assert!(handler.should_stop(&object_id));
        assert_eq!(handler.active_transfer_count(), 0);
    }

    #[test]
    fn policy_disallow_unauthenticated_rejects() {
        let policy = SymbolRequestPolicy {
            allow_unauthenticated: false,
            ..SymbolRequestPolicy::default()
        };
        let handler = SymbolRequestHandler::new(policy);
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-no-auth");

        let request = test_symbol_request(10, None);
        let result = handler.validate_request(&request, false, &mut admission, &peer, 0, 64);
        assert!(matches!(
            result,
            Err(SymbolRequestError::AdmissionRejected(_))
        ));
    }

    #[test]
    fn targeted_repair_remove_object() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..10);

        let request = ValidatedRequest {
            request: test_symbol_request(10, None),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: false,
        };

        // Should have symbols
        let selected = engine.select_symbols(&request, &HashSet::new());
        assert!(!selected.is_empty());

        // Remove and verify gone
        engine.remove_object(&object_id);
        let selected = engine.select_symbols(&request, &HashSet::new());
        assert!(selected.is_empty());
    }

    #[test]
    fn response_builder_empty_availability() {
        let engine = TargetedRepairEngine::new(); // No symbols registered
        let object_id = ObjectId::from_bytes([0x11; 32]);

        let request = ValidatedRequest {
            request: test_symbol_request(50, None),
            is_authenticated: true,
            max_response_symbols: 50,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            50,
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(0, 0);

        assert_eq!(response.symbol_count(), 0);
        assert!(response.is_final);
    }

    #[test]
    fn authenticated_request_bounded_by_request_max() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-bounded");

        // Request max_symbols (50) < policy max (1000)
        let request = test_symbol_request(50, None);
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        let validated = result.unwrap();
        // Should be bounded to the request's max, not the policy's max
        assert_eq!(validated.max_response_symbols, 50);
    }

    #[test]
    fn metrics_tracking() {
        let mut metrics = SymbolRequestMetrics::default();

        metrics.record_validated();
        metrics.record_validated();
        metrics.record_bounds_rejection();
        metrics.record_symbols_sent(100, true);
        metrics.record_ack();

        assert_eq!(metrics.requests_received, 3);
        assert_eq!(metrics.requests_validated, 2);
        assert_eq!(metrics.requests_rejected_bounds, 1);
        assert_eq!(metrics.symbols_sent, 100);
        assert_eq!(metrics.targeted_repairs, 1);
        assert_eq!(metrics.acks_received, 1);
    }
}
