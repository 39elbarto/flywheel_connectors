//! Admission control for FCP2 mesh nodes.
//!
//! This module implements the NORMATIVE admission control requirements from
//! `FCP_Specification_V2.md` §8.4, including:
//!
//! - [`PeerBudget`] - Per-peer resource limits
//! - [`AdmissionPolicy`] - Policy configuration
//! - [`ObjectAdmissionPolicy`] - Quarantine policy for unknown objects
//! - [`AdmissionController`] - Runtime admission enforcement
//!
//! # Overview
//!
//! `MeshNodes` MUST implement admission control for:
//! - Per-peer inbound bytes/symbols
//! - Failed decrypt/MAC counters
//! - Bounded concurrent decodes
//! - Bounded gossip reconciliation work
//!
//! # Anti-Amplification Rule (NORMATIVE)
//!
//! `MeshNodes` MUST NOT send more than `N` symbols in response to a request unless:
//! 1. The requester is authenticated (session MAC or node signature), AND
//! 2. The request includes a bounded missing-hint or proof-of-need
//!
//! # Example
//!
//! ```rust
//! use fcp_mesh::admission::{AdmissionController, AdmissionPolicy, PeerBudget};
//! use fcp_tailscale::NodeId;
//!
//! let policy = AdmissionPolicy::default();
//! let mut controller = AdmissionController::new(policy);
//!
//! let peer = NodeId::new("node-12345");
//!
//! // Check if a peer can send bytes
//! match controller.check_bytes(&peer, 1024, 1000) {
//!     Ok(()) => println!("Allowed"),
//!     Err(e) => println!("Rejected: {:?}", e),
//! }
//! ```

#![forbid(unsafe_code)]

use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ============================================================================
// Constants (NORMATIVE defaults from spec §8.4)
// ============================================================================

/// Default max bytes per minute per peer (64 MB/min).
pub const DEFAULT_MAX_BYTES_PER_MIN: u64 = 64 * 1024 * 1024;

/// Default max symbols per minute per peer.
pub const DEFAULT_MAX_SYMBOLS_PER_MIN: u32 = 200_000;

/// Default max failed auth attempts per minute per peer.
pub const DEFAULT_MAX_FAILED_AUTH_PER_MIN: u32 = 100;

/// Default max concurrent decode operations per peer.
pub const DEFAULT_MAX_INFLIGHT_DECODES: u32 = 32;

/// Default max decode CPU milliseconds per minute per peer.
pub const DEFAULT_MAX_DECODE_CPU_MS_PER_MIN: u64 = 5_000;

/// Default anti-amplification factor (response symbols <= N * request symbols).
pub const DEFAULT_AMPLIFICATION_FACTOR: u32 = 10;

/// Default quarantine storage per zone (256 MB).
pub const DEFAULT_MAX_QUARANTINE_BYTES_PER_ZONE: u64 = 256 * 1024 * 1024;

/// Default max quarantined objects per zone.
pub const DEFAULT_MAX_QUARANTINE_OBJECTS_PER_ZONE: u32 = 100_000;

/// Default TTL for quarantined objects (1 hour).
pub const DEFAULT_QUARANTINE_TTL_SECS: u64 = 3600;

// ============================================================================
// Error Types
// ============================================================================

/// Admission control rejection reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionError {
    /// Peer exceeded bytes per minute budget.
    ByteBudgetExceeded {
        /// Current usage in bytes.
        current: u64,
        /// Maximum allowed bytes per minute.
        limit: u64,
        /// Suggested retry delay.
        retry_after: Duration,
    },

    /// Peer exceeded symbols per minute budget.
    SymbolBudgetExceeded {
        /// Current usage in symbols.
        current: u32,
        /// Maximum allowed symbols per minute.
        limit: u32,
        /// Suggested retry delay.
        retry_after: Duration,
    },

    /// Peer exceeded failed auth attempts budget.
    AuthFailureBudgetExceeded {
        /// Current failure count.
        current: u32,
        /// Maximum allowed failures per minute.
        limit: u32,
        /// Suggested retry delay.
        retry_after: Duration,
    },

    /// Peer exceeded concurrent decode limit.
    DecodeCapacityExceeded {
        /// Current inflight decodes.
        current: u32,
        /// Maximum allowed concurrent decodes.
        limit: u32,
    },

    /// Peer exceeded decode CPU budget.
    DecodeCpuBudgetExceeded {
        /// Current CPU usage in milliseconds.
        current_ms: u64,
        /// Maximum allowed CPU milliseconds per minute.
        limit_ms: u64,
        /// Suggested retry delay.
        retry_after: Duration,
    },

    /// Request would violate anti-amplification rule.
    AmplificationViolation {
        /// Request size in symbols.
        request_symbols: u32,
        /// Proposed response size in symbols.
        response_symbols: u32,
        /// Maximum allowed amplification factor.
        max_factor: u32,
    },

    /// Request requires authentication but peer is unauthenticated.
    AuthenticationRequired,

    /// Request requires proof-of-need but none provided.
    ProofOfNeedRequired,

    /// Object is quarantined and not reachable from frontier.
    ObjectQuarantined {
        /// The quarantined object ID (as hex string for serialization).
        object_id: String,
    },

    /// Object cannot be promoted - not reachable from zone frontier.
    NotReachable {
        /// The object ID (as hex string).
        object_id: String,
    },

    /// Quarantine storage quota exceeded.
    QuarantineQuotaExceeded {
        /// Current quarantine bytes.
        current_bytes: u64,
        /// Maximum quarantine bytes.
        limit_bytes: u64,
    },
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ByteBudgetExceeded { current, limit, .. } => {
                write!(
                    f,
                    "byte budget exceeded: {current} bytes used of {limit} bytes/min limit"
                )
            }
            Self::SymbolBudgetExceeded { current, limit, .. } => {
                write!(
                    f,
                    "symbol budget exceeded: {current} symbols used of {limit} symbols/min limit"
                )
            }
            Self::AuthFailureBudgetExceeded { current, limit, .. } => {
                write!(
                    f,
                    "auth failure budget exceeded: {current} failures of {limit}/min limit"
                )
            }
            Self::DecodeCapacityExceeded { current, limit } => {
                write!(
                    f,
                    "decode capacity exceeded: {current} inflight of {limit} max"
                )
            }
            Self::DecodeCpuBudgetExceeded {
                current_ms,
                limit_ms,
                ..
            } => {
                write!(
                    f,
                    "decode CPU budget exceeded: {current_ms}ms used of {limit_ms}ms/min limit"
                )
            }
            Self::AmplificationViolation {
                request_symbols,
                response_symbols,
                max_factor,
            } => {
                write!(
                    f,
                    "amplification violation: response {response_symbols} symbols > \
                     {max_factor}x request {request_symbols} symbols"
                )
            }
            Self::AuthenticationRequired => write!(f, "authentication required for this request"),
            Self::ProofOfNeedRequired => write!(f, "proof-of-need required for this request"),
            Self::ObjectQuarantined { object_id } => {
                write!(f, "object {object_id} is quarantined")
            }
            Self::NotReachable { object_id } => {
                write!(f, "object {object_id} not reachable from zone frontier")
            }
            Self::QuarantineQuotaExceeded {
                current_bytes,
                limit_bytes,
            } => {
                write!(
                    f,
                    "quarantine quota exceeded: {current_bytes} bytes of {limit_bytes} limit"
                )
            }
        }
    }
}

impl std::error::Error for AdmissionError {}

impl AdmissionError {
    /// Returns the suggested retry delay, if applicable.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::ByteBudgetExceeded { retry_after, .. }
            | Self::SymbolBudgetExceeded { retry_after, .. }
            | Self::AuthFailureBudgetExceeded { retry_after, .. }
            | Self::DecodeCpuBudgetExceeded { retry_after, .. } => Some(*retry_after),
            _ => None,
        }
    }

    /// Returns true if the error indicates the request can be retried later.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ByteBudgetExceeded { .. }
                | Self::SymbolBudgetExceeded { .. }
                | Self::AuthFailureBudgetExceeded { .. }
                | Self::DecodeCapacityExceeded { .. }
                | Self::DecodeCpuBudgetExceeded { .. }
        )
    }

    /// Returns the FCP error code for this admission error.
    ///
    /// Error codes follow the FCP-6xxx range for resource errors.
    #[must_use]
    pub const fn error_code(&self) -> u32 {
        match self {
            Self::ByteBudgetExceeded { .. } => 6001,
            Self::SymbolBudgetExceeded { .. } => 6002,
            Self::AuthFailureBudgetExceeded { .. } => 6003,
            Self::DecodeCapacityExceeded { .. } => 6004,
            Self::DecodeCpuBudgetExceeded { .. } => 6005,
            Self::AmplificationViolation { .. } => 6010,
            Self::AuthenticationRequired => 6011,
            Self::ProofOfNeedRequired => 6012,
            Self::ObjectQuarantined { .. } => 6020,
            Self::NotReachable { .. } => 6021,
            Self::QuarantineQuotaExceeded { .. } => 6022,
        }
    }
}

// ============================================================================
// Budget and Policy Types (NORMATIVE)
// ============================================================================

/// Per-peer resource budget (NORMATIVE).
///
/// Defines the maximum resource consumption allowed per peer per minute.
/// These limits prevent any single peer from exhausting node resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBudget {
    /// Maximum bytes per minute from this peer.
    pub max_bytes_per_min: u64,

    /// Maximum symbols per minute from this peer.
    pub max_symbols_per_min: u32,

    /// Maximum failed auth attempts per minute before blocking.
    pub max_failed_auth_per_min: u32,

    /// Maximum concurrent decode operations.
    pub max_inflight_decodes: u32,

    /// Maximum decode CPU milliseconds per minute.
    pub max_decode_cpu_ms_per_min: u64,
}

impl Default for PeerBudget {
    fn default() -> Self {
        Self {
            max_bytes_per_min: DEFAULT_MAX_BYTES_PER_MIN,
            max_symbols_per_min: DEFAULT_MAX_SYMBOLS_PER_MIN,
            max_failed_auth_per_min: DEFAULT_MAX_FAILED_AUTH_PER_MIN,
            max_inflight_decodes: DEFAULT_MAX_INFLIGHT_DECODES,
            max_decode_cpu_ms_per_min: DEFAULT_MAX_DECODE_CPU_MS_PER_MIN,
        }
    }
}

impl PeerBudget {
    /// Create a new peer budget with custom limits.
    #[must_use]
    pub const fn new(
        max_bytes_per_min: u64,
        max_symbols_per_min: u32,
        max_failed_auth_per_min: u32,
        max_inflight_decodes: u32,
        max_decode_cpu_ms_per_min: u64,
    ) -> Self {
        Self {
            max_bytes_per_min,
            max_symbols_per_min,
            max_failed_auth_per_min,
            max_inflight_decodes,
            max_decode_cpu_ms_per_min,
        }
    }

    /// Create a restrictive budget for untrusted peers.
    #[must_use]
    pub const fn restrictive() -> Self {
        Self {
            max_bytes_per_min: 1024 * 1024, // 1MB/min
            max_symbols_per_min: 10_000,    // 10k/min
            max_failed_auth_per_min: 10,    // 10/min
            max_inflight_decodes: 4,        // 4 concurrent
            max_decode_cpu_ms_per_min: 500, // 500ms/min
        }
    }

    /// Create a permissive budget for trusted peers.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            max_bytes_per_min: 512 * 1024 * 1024, // 512MB/min
            max_symbols_per_min: 1_000_000,       // 1M/min
            max_failed_auth_per_min: 1000,        // 1000/min
            max_inflight_decodes: 128,            // 128 concurrent
            max_decode_cpu_ms_per_min: 60_000,    // 60s/min
        }
    }
}

/// Admission policy configuration (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    /// Per-peer resource budget.
    pub per_peer: PeerBudget,

    /// If true, unauthenticated `SymbolRequest` is rejected.
    /// Default: true (except for `z:public` ingress zones).
    pub require_authenticated_requests: bool,

    /// Maximum amplification factor for responses.
    /// Response symbols must be <= this factor * request symbols.
    pub max_amplification_factor: u32,

    /// If true, responses to unauthenticated requests are rate-limited
    /// more aggressively.
    pub strict_unauthenticated_limits: bool,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            per_peer: PeerBudget::default(),
            require_authenticated_requests: true,
            max_amplification_factor: DEFAULT_AMPLIFICATION_FACTOR,
            strict_unauthenticated_limits: true,
        }
    }
}

impl AdmissionPolicy {
    /// Create a policy for public ingress zones.
    ///
    /// Public zones allow unauthenticated requests but apply stricter
    /// rate limits and anti-amplification rules.
    #[must_use]
    pub const fn public_ingress() -> Self {
        Self {
            per_peer: PeerBudget::restrictive(),
            require_authenticated_requests: false,
            max_amplification_factor: 2, // Very restrictive for public
            strict_unauthenticated_limits: true,
        }
    }

    /// Create a policy for trusted mesh peers.
    #[must_use]
    pub const fn trusted_mesh() -> Self {
        Self {
            per_peer: PeerBudget::permissive(),
            require_authenticated_requests: true,
            max_amplification_factor: 100,
            strict_unauthenticated_limits: false,
        }
    }
}

/// Object admission classification (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectAdmissionClass {
    /// Unknown provenance, bounded retention, not gossiped.
    Quarantined,
    /// Verified reachable, normal retention, gossiped.
    Admitted,
}

/// Object admission policy (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectAdmissionPolicy {
    /// Maximum quarantine storage per zone in bytes.
    pub max_quarantine_bytes_per_zone: u64,

    /// Maximum quarantined objects per zone.
    pub max_quarantine_objects_per_zone: u32,

    /// TTL for quarantined objects before eviction.
    pub quarantine_ttl_secs: u64,

    /// Whether to require schema validation on promotion.
    pub require_schema_validation: bool,
}

impl Default for ObjectAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_quarantine_bytes_per_zone: DEFAULT_MAX_QUARANTINE_BYTES_PER_ZONE,
            max_quarantine_objects_per_zone: DEFAULT_MAX_QUARANTINE_OBJECTS_PER_ZONE,
            quarantine_ttl_secs: DEFAULT_QUARANTINE_TTL_SECS,
            require_schema_validation: true,
        }
    }
}

// ============================================================================
// Runtime Tracking
// ============================================================================

/// Per-peer usage tracker.
///
/// Tracks resource consumption per peer within a sliding time window.
#[derive(Debug, Clone)]
pub struct PeerUsage {
    /// Bytes received in current window.
    pub bytes_in_window: u64,
    /// Symbols received in current window.
    pub symbols_in_window: u32,
    /// Failed auth attempts in current window.
    pub failed_auth_in_window: u32,
    /// Currently inflight decode operations.
    pub inflight_decodes: u32,
    /// Decode CPU milliseconds in current window.
    pub decode_cpu_ms_in_window: u64,
    /// Window start timestamp (ms since epoch).
    pub window_start_ms: u64,
    /// Whether peer is currently authenticated.
    pub is_authenticated: bool,
}

impl PeerUsage {
    /// Create a new usage tracker starting at the given timestamp.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            bytes_in_window: 0,
            symbols_in_window: 0,
            failed_auth_in_window: 0,
            inflight_decodes: 0,
            decode_cpu_ms_in_window: 0,
            window_start_ms: now_ms,
            is_authenticated: false,
        }
    }

    /// Check if the window has expired and reset if needed.
    const fn maybe_reset_window(&mut self, now_ms: u64) {
        const WINDOW_MS: u64 = 60_000; // 1 minute window
        if now_ms.saturating_sub(self.window_start_ms) >= WINDOW_MS {
            self.bytes_in_window = 0;
            self.symbols_in_window = 0;
            self.failed_auth_in_window = 0;
            self.decode_cpu_ms_in_window = 0;
            self.window_start_ms = now_ms;
        }
    }

    /// Calculate time remaining in current window.
    #[must_use]
    const fn time_until_window_reset(&self, now_ms: u64) -> Duration {
        const WINDOW_MS: u64 = 60_000;
        let elapsed = now_ms.saturating_sub(self.window_start_ms);
        let remaining = WINDOW_MS.saturating_sub(elapsed);
        Duration::from_millis(remaining)
    }
}

// ============================================================================
// Admission Controller
// ============================================================================

/// Admission controller for mesh node traffic.
///
/// Enforces per-peer resource budgets and anti-amplification rules
/// as specified in `FCP_Specification_V2.md` §8.4.
#[derive(Debug)]
pub struct AdmissionController {
    /// Admission policy configuration.
    policy: AdmissionPolicy,
    /// Per-peer usage tracking.
    peer_usage: HashMap<NodeId, PeerUsage>,
}

impl AdmissionController {
    /// Create a new admission controller with the given policy.
    #[must_use]
    pub fn new(policy: AdmissionPolicy) -> Self {
        Self {
            policy,
            peer_usage: HashMap::new(),
        }
    }

    /// Create an admission controller with default policy.
    #[must_use]
    pub fn with_default_policy() -> Self {
        Self::new(AdmissionPolicy::default())
    }

    /// Get or create usage tracker for a peer.
    fn get_or_create_usage(&mut self, peer: &NodeId, now_ms: u64) -> &mut PeerUsage {
        self.peer_usage
            .entry(peer.clone())
            .or_insert_with(|| PeerUsage::new(now_ms))
    }

    fn effective_byte_limit(&self, is_authenticated: bool) -> u64 {
        if !is_authenticated && self.policy.strict_unauthenticated_limits {
            let restrictive = PeerBudget::restrictive();
            self.policy
                .per_peer
                .max_bytes_per_min
                .min(restrictive.max_bytes_per_min)
        } else {
            self.policy.per_peer.max_bytes_per_min
        }
    }

    fn effective_symbol_limit(&self, is_authenticated: bool) -> u32 {
        if !is_authenticated && self.policy.strict_unauthenticated_limits {
            let restrictive = PeerBudget::restrictive();
            self.policy
                .per_peer
                .max_symbols_per_min
                .min(restrictive.max_symbols_per_min)
        } else {
            self.policy.per_peer.max_symbols_per_min
        }
    }

    fn check_bytes_with_limit(
        &mut self,
        peer: &NodeId,
        bytes: u64,
        now_ms: u64,
        limit: u64,
    ) -> Result<(), AdmissionError> {
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.maybe_reset_window(now_ms);

        let new_total = usage.bytes_in_window.saturating_add(bytes);
        if new_total > limit {
            return Err(AdmissionError::ByteBudgetExceeded {
                current: usage.bytes_in_window,
                limit,
                retry_after: usage.time_until_window_reset(now_ms),
            });
        }

        Ok(())
    }

    fn check_symbols_with_limit(
        &mut self,
        peer: &NodeId,
        symbols: u32,
        now_ms: u64,
        limit: u32,
    ) -> Result<(), AdmissionError> {
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.maybe_reset_window(now_ms);

        let new_total = usage.symbols_in_window.saturating_add(symbols);
        if new_total > limit {
            return Err(AdmissionError::SymbolBudgetExceeded {
                current: usage.symbols_in_window,
                limit,
                retry_after: usage.time_until_window_reset(now_ms),
            });
        }

        Ok(())
    }

    /// Check if peer can send the given number of bytes (NORMATIVE).
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::ByteBudgetExceeded` if the peer has exceeded
    /// their byte budget for the current window.
    pub fn check_bytes(
        &mut self,
        peer: &NodeId,
        bytes: u64,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        let limit = self.policy.per_peer.max_bytes_per_min;
        self.check_bytes_with_limit(peer, bytes, now_ms, limit)
    }

    /// Record bytes received from peer.
    pub fn record_bytes(&mut self, peer: &NodeId, bytes: u64, now_ms: u64) {
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.maybe_reset_window(now_ms);
        usage.bytes_in_window = usage.bytes_in_window.saturating_add(bytes);
    }

    /// Check if peer can send the given number of symbols (NORMATIVE).
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::SymbolBudgetExceeded` if the peer has exceeded
    /// their symbol budget for the current window.
    pub fn check_symbols(
        &mut self,
        peer: &NodeId,
        symbols: u32,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        let limit = self.policy.per_peer.max_symbols_per_min;
        self.check_symbols_with_limit(peer, symbols, now_ms, limit)
    }

    /// Record symbols received from peer.
    pub fn record_symbols(&mut self, peer: &NodeId, symbols: u32, now_ms: u64) {
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.maybe_reset_window(now_ms);
        usage.symbols_in_window = usage.symbols_in_window.saturating_add(symbols);
    }

    /// Record a failed authentication attempt (NORMATIVE).
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::AuthFailureBudgetExceeded` if the peer has
    /// exceeded their auth failure budget for the current window.
    pub fn record_auth_failure(
        &mut self,
        peer: &NodeId,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        // Copy limit before mutable borrow
        let limit = self.policy.per_peer.max_failed_auth_per_min;
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.maybe_reset_window(now_ms);

        usage.failed_auth_in_window = usage.failed_auth_in_window.saturating_add(1);

        if usage.failed_auth_in_window > limit {
            return Err(AdmissionError::AuthFailureBudgetExceeded {
                current: usage.failed_auth_in_window,
                limit,
                retry_after: usage.time_until_window_reset(now_ms),
            });
        }

        Ok(())
    }

    /// Try to acquire a decode slot (NORMATIVE).
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::DecodeCapacityExceeded` if the peer has
    /// too many concurrent decode operations.
    pub fn try_acquire_decode(&mut self, peer: &NodeId, now_ms: u64) -> Result<(), AdmissionError> {
        // Copy limit before mutable borrow
        let limit = self.policy.per_peer.max_inflight_decodes;
        let usage = self.get_or_create_usage(peer, now_ms);

        if usage.inflight_decodes >= limit {
            return Err(AdmissionError::DecodeCapacityExceeded {
                current: usage.inflight_decodes,
                limit,
            });
        }

        usage.inflight_decodes += 1;
        Ok(())
    }

    /// Release a decode slot.
    pub fn release_decode(&mut self, peer: &NodeId, now_ms: u64) {
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.inflight_decodes = usage.inflight_decodes.saturating_sub(1);
    }

    /// Record decode CPU usage (NORMATIVE).
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::DecodeCpuBudgetExceeded` if the peer has
    /// exceeded their CPU budget for the current window.
    pub fn record_decode_cpu(
        &mut self,
        peer: &NodeId,
        cpu_ms: u64,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        // Copy limit before mutable borrow
        let limit_ms = self.policy.per_peer.max_decode_cpu_ms_per_min;
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.maybe_reset_window(now_ms);

        usage.decode_cpu_ms_in_window = usage.decode_cpu_ms_in_window.saturating_add(cpu_ms);

        if usage.decode_cpu_ms_in_window > limit_ms {
            return Err(AdmissionError::DecodeCpuBudgetExceeded {
                current_ms: usage.decode_cpu_ms_in_window,
                limit_ms,
                retry_after: usage.time_until_window_reset(now_ms),
            });
        }

        Ok(())
    }

    /// Check anti-amplification rule (NORMATIVE).
    ///
    /// Ensures response size does not exceed the allowed amplification factor.
    ///
    /// # Arguments
    ///
    /// * `peer` - The requesting peer
    /// * `request_symbols` - Number of symbols in the request
    /// * `response_symbols` - Proposed number of symbols in response
    /// * `is_authenticated` - Whether the peer is authenticated
    /// * `has_proof_of_need` - Whether the request includes proof-of-need
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::AmplificationViolation` if the response would
    /// exceed the allowed amplification factor.
    pub const fn check_amplification(
        &self,
        _peer: &NodeId,
        request_symbols: u32,
        response_symbols: u32,
        is_authenticated: bool,
        has_proof_of_need: bool,
    ) -> Result<(), AdmissionError> {
        // Authenticated peers with proof-of-need can receive larger responses
        if is_authenticated && has_proof_of_need {
            return Ok(());
        }

        // For unauthenticated peers, enforce strict amplification limit
        let max_response = request_symbols.saturating_mul(self.policy.max_amplification_factor);
        if response_symbols > max_response {
            return Err(AdmissionError::AmplificationViolation {
                request_symbols,
                response_symbols,
                max_factor: self.policy.max_amplification_factor,
            });
        }

        Ok(())
    }

    /// Check if authentication is required for a request (NORMATIVE).
    ///
    /// # Errors
    ///
    /// Returns `AdmissionError::AuthenticationRequired` if the policy requires
    /// authentication and the peer is not authenticated.
    pub const fn check_authentication_required(
        &self,
        is_authenticated: bool,
    ) -> Result<(), AdmissionError> {
        if self.policy.require_authenticated_requests && !is_authenticated {
            return Err(AdmissionError::AuthenticationRequired);
        }
        Ok(())
    }

    /// Combined admission check (NORMATIVE).
    ///
    /// Performs all admission checks for an incoming request:
    /// 1. Authentication requirement
    /// 2. Byte budget
    /// 3. Symbol budget
    ///
    /// # Errors
    ///
    /// Returns the first admission error encountered, if any.
    pub fn check_admission(
        &mut self,
        peer: &NodeId,
        bytes: u64,
        symbols: u32,
        is_authenticated: bool,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        self.check_authentication_required(is_authenticated)?;
        let byte_limit = self.effective_byte_limit(is_authenticated);
        let symbol_limit = self.effective_symbol_limit(is_authenticated);
        self.check_bytes_with_limit(peer, bytes, now_ms, byte_limit)?;
        self.check_symbols_with_limit(peer, symbols, now_ms, symbol_limit)?;
        Ok(())
    }

    /// Record authenticated status for a peer.
    pub fn set_authenticated(&mut self, peer: &NodeId, authenticated: bool, now_ms: u64) {
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.is_authenticated = authenticated;
    }

    /// Check if a peer is currently authenticated.
    #[must_use]
    pub fn is_authenticated(&self, peer: &NodeId) -> bool {
        self.peer_usage
            .get(peer)
            .is_some_and(|u| u.is_authenticated)
    }

    /// Get current usage for a peer (for metrics/debugging).
    #[must_use]
    pub fn get_usage(&self, peer: &NodeId) -> Option<&PeerUsage> {
        self.peer_usage.get(peer)
    }

    /// Get the current policy.
    #[must_use]
    pub const fn policy(&self) -> &AdmissionPolicy {
        &self.policy
    }

    /// Update the policy.
    pub const fn set_policy(&mut self, policy: AdmissionPolicy) {
        self.policy = policy;
    }

    /// Remove stale peer entries older than the given threshold.
    ///
    /// Call periodically to prevent unbounded memory growth.
    pub fn gc_stale_peers(&mut self, now_ms: u64, stale_threshold_ms: u64) {
        self.peer_usage
            .retain(|_, usage| now_ms.saturating_sub(usage.window_start_ms) < stale_threshold_ms);
    }

    /// Get the number of tracked peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peer_usage.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> NodeId {
        NodeId::new("test-peer-123")
    }

    #[test]
    fn peer_budget_defaults() {
        let budget = PeerBudget::default();
        assert_eq!(budget.max_bytes_per_min, 64 * 1024 * 1024);
        assert_eq!(budget.max_symbols_per_min, 200_000);
        assert_eq!(budget.max_failed_auth_per_min, 100);
        assert_eq!(budget.max_inflight_decodes, 32);
        assert_eq!(budget.max_decode_cpu_ms_per_min, 5_000);
    }

    #[test]
    fn admission_policy_defaults() {
        let policy = AdmissionPolicy::default();
        assert!(policy.require_authenticated_requests);
        assert_eq!(policy.max_amplification_factor, 10);
        assert!(policy.strict_unauthenticated_limits);
    }

    #[test]
    fn strict_unauthenticated_limits_apply_to_bytes() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 10 * 1024 * 1024,
                ..PeerBudget::default()
            },
            require_authenticated_requests: false,
            strict_unauthenticated_limits: true,
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        let result = controller.check_admission(&peer, 2 * 1024 * 1024, 1, false, 0);
        assert!(matches!(
            result,
            Err(AdmissionError::ByteBudgetExceeded { .. })
        ));

        assert!(
            controller
                .check_admission(&peer, 2 * 1024 * 1024, 1, true, 0)
                .is_ok()
        );
    }

    #[test]
    fn strict_unauthenticated_limits_apply_to_symbols() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_symbols_per_min: 50_000,
                ..PeerBudget::default()
            },
            require_authenticated_requests: false,
            strict_unauthenticated_limits: true,
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        let result = controller.check_admission(&peer, 0, 20_000, false, 0);
        assert!(matches!(
            result,
            Err(AdmissionError::SymbolBudgetExceeded { .. })
        ));
    }

    #[test]
    fn check_bytes_under_limit() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        // Should succeed under limit
        assert!(controller.check_bytes(&peer, 1024, 0).is_ok());
        controller.record_bytes(&peer, 1024, 0);

        // Should still succeed
        assert!(controller.check_bytes(&peer, 1024, 0).is_ok());
    }

    #[test]
    fn check_bytes_over_limit() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // Record some bytes
        controller.record_bytes(&peer, 500, 0);

        // Should fail - would exceed limit
        let result = controller.check_bytes(&peer, 600, 0);
        assert!(matches!(
            result,
            Err(AdmissionError::ByteBudgetExceeded { .. })
        ));
    }

    #[test]
    fn check_bytes_window_reset() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // Use up budget at t=0
        controller.record_bytes(&peer, 1000, 0);
        assert!(controller.check_bytes(&peer, 100, 0).is_err());

        // After window reset (60s later), should succeed again
        assert!(controller.check_bytes(&peer, 100, 60_001).is_ok());
    }

    #[test]
    fn check_symbols_over_limit() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_symbols_per_min: 100,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        controller.record_symbols(&peer, 90, 0);
        let result = controller.check_symbols(&peer, 20, 0);
        assert!(matches!(
            result,
            Err(AdmissionError::SymbolBudgetExceeded { .. })
        ));
    }

    #[test]
    fn auth_failure_tracking() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_failed_auth_per_min: 3,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // First 3 failures should be recorded
        assert!(controller.record_auth_failure(&peer, 0).is_ok());
        assert!(controller.record_auth_failure(&peer, 0).is_ok());
        assert!(controller.record_auth_failure(&peer, 0).is_ok());

        // 4th failure should exceed budget
        let result = controller.record_auth_failure(&peer, 0);
        assert!(matches!(
            result,
            Err(AdmissionError::AuthFailureBudgetExceeded { .. })
        ));
    }

    #[test]
    fn decode_capacity() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_inflight_decodes: 2,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // Acquire 2 slots
        assert!(controller.try_acquire_decode(&peer, 0).is_ok());
        assert!(controller.try_acquire_decode(&peer, 0).is_ok());

        // 3rd should fail
        assert!(matches!(
            controller.try_acquire_decode(&peer, 0),
            Err(AdmissionError::DecodeCapacityExceeded { .. })
        ));

        // Release one
        controller.release_decode(&peer, 0);

        // Should succeed now
        assert!(controller.try_acquire_decode(&peer, 0).is_ok());
    }

    #[test]
    fn anti_amplification_unauthenticated() {
        let controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        // 10x amplification should be allowed (default factor)
        assert!(
            controller
                .check_amplification(&peer, 10, 100, false, false)
                .is_ok()
        );

        // 11x should fail
        assert!(matches!(
            controller.check_amplification(&peer, 10, 110, false, false),
            Err(AdmissionError::AmplificationViolation { .. })
        ));
    }

    #[test]
    fn anti_amplification_authenticated_with_proof() {
        let controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        // Authenticated with proof-of-need bypasses amplification limit
        assert!(
            controller
                .check_amplification(&peer, 1, 1000, true, true)
                .is_ok()
        );
    }

    #[test]
    fn authentication_required() {
        let controller = AdmissionController::with_default_policy();

        // Default policy requires auth
        assert!(matches!(
            controller.check_authentication_required(false),
            Err(AdmissionError::AuthenticationRequired)
        ));

        assert!(controller.check_authentication_required(true).is_ok());
    }

    #[test]
    fn authentication_not_required_for_public() {
        let controller = AdmissionController::new(AdmissionPolicy::public_ingress());

        // Public policy doesn't require auth
        assert!(controller.check_authentication_required(false).is_ok());
    }

    #[test]
    fn combined_admission_check() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        // Unauthenticated should fail
        assert!(matches!(
            controller.check_admission(&peer, 100, 10, false, 0),
            Err(AdmissionError::AuthenticationRequired)
        ));

        // Authenticated should succeed
        assert!(controller.check_admission(&peer, 100, 10, true, 0).is_ok());
    }

    #[test]
    fn gc_stale_peers() {
        let mut controller = AdmissionController::with_default_policy();

        // Add some peers at different times
        controller.record_bytes(&NodeId::new("peer-1"), 100, 0);
        controller.record_bytes(&NodeId::new("peer-2"), 100, 50_000);
        controller.record_bytes(&NodeId::new("peer-3"), 100, 100_000);

        assert_eq!(controller.peer_count(), 3);

        // GC with threshold that removes peer-1
        controller.gc_stale_peers(100_000, 60_000);
        assert_eq!(controller.peer_count(), 2);
    }

    #[test]
    fn error_codes() {
        let err = AdmissionError::ByteBudgetExceeded {
            current: 100,
            limit: 50,
            retry_after: Duration::from_secs(30),
        };
        assert_eq!(err.error_code(), 6001);
        assert!(err.is_retryable());
        assert!(err.retry_after().is_some());

        let err = AdmissionError::AuthenticationRequired;
        assert_eq!(err.error_code(), 6011);
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn peer_budget_variants() {
        let restrictive = PeerBudget::restrictive();
        let permissive = PeerBudget::permissive();
        let default = PeerBudget::default();

        // Restrictive should be most limited
        assert!(restrictive.max_bytes_per_min < default.max_bytes_per_min);
        assert!(restrictive.max_symbols_per_min < default.max_symbols_per_min);

        // Permissive should be most generous
        assert!(permissive.max_bytes_per_min > default.max_bytes_per_min);
        assert!(permissive.max_symbols_per_min > default.max_symbols_per_min);
    }

    #[test]
    fn object_admission_policy_defaults() {
        let policy = ObjectAdmissionPolicy::default();
        assert_eq!(policy.max_quarantine_bytes_per_zone, 256 * 1024 * 1024);
        assert_eq!(policy.max_quarantine_objects_per_zone, 100_000);
        assert_eq!(policy.quarantine_ttl_secs, 3600);
        assert!(policy.require_schema_validation);
    }
}
