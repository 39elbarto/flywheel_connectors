//! Admission control for FCP mesh nodes.
//!
//! This module implements the NORMATIVE admission control requirements from
//! `FCP_Specification_V3.md` §11.7.1 (Admission Control and DoS Resistance), including:
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
/// Tracks resource consumption per peer using a sliding-window counter
/// with a weighted moving average over two adjacent windows. At any
/// instant `t` within the current window, the "effective" usage is
///
/// ```text
///   effective = prev_window * (WINDOW_MS - elapsed_in_current) / WINDOW_MS
///             + current_window
/// ```
///
/// so limits are enforced against a rolling 60-second window, not a
/// fixed calendar window. This eliminates the window-boundary burst
/// vulnerability where a peer could send up to 2× its per-minute
/// budget by scheduling traffic at the tail of window N and the head
/// of window N+1.
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
    /// Bytes received in the immediately-previous window (used for
    /// sliding-window weighting).
    pub prev_bytes_in_window: u64,
    /// Symbols received in the immediately-previous window.
    pub prev_symbols_in_window: u32,
    /// Failed auth attempts in the immediately-previous window.
    pub prev_failed_auth_in_window: u32,
    /// Decode CPU milliseconds in the immediately-previous window.
    pub prev_decode_cpu_ms_in_window: u64,
    /// Current window start timestamp (ms since epoch). The previous
    /// window occupies `[window_start_ms - WINDOW_MS, window_start_ms)`.
    pub window_start_ms: u64,
    /// Whether peer is currently authenticated.
    pub is_authenticated: bool,
}

/// Sliding-window duration (1 minute, matching per-minute budgets).
const WINDOW_MS: u64 = 60_000;

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
            prev_bytes_in_window: 0,
            prev_symbols_in_window: 0,
            prev_failed_auth_in_window: 0,
            prev_decode_cpu_ms_in_window: 0,
            window_start_ms: now_ms,
            is_authenticated: false,
        }
    }

    /// Advance the sliding window if enough time has elapsed. Rolls
    /// the current accumulators into `prev_*` when one window has
    /// passed, or zeroes both halves if two or more windows have
    /// passed (the previous window is then too old to contribute).
    const fn maybe_reset_window(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.window_start_ms);
        if elapsed >= WINDOW_MS.saturating_mul(2) {
            // Both the previous and current accumulators are stale.
            self.bytes_in_window = 0;
            self.symbols_in_window = 0;
            self.failed_auth_in_window = 0;
            self.decode_cpu_ms_in_window = 0;
            self.prev_bytes_in_window = 0;
            self.prev_symbols_in_window = 0;
            self.prev_failed_auth_in_window = 0;
            self.prev_decode_cpu_ms_in_window = 0;
            self.window_start_ms = now_ms;
        } else if elapsed >= WINDOW_MS {
            // Slide one window forward: current becomes previous.
            self.prev_bytes_in_window = self.bytes_in_window;
            self.prev_symbols_in_window = self.symbols_in_window;
            self.prev_failed_auth_in_window = self.failed_auth_in_window;
            self.prev_decode_cpu_ms_in_window = self.decode_cpu_ms_in_window;
            self.bytes_in_window = 0;
            self.symbols_in_window = 0;
            self.failed_auth_in_window = 0;
            self.decode_cpu_ms_in_window = 0;
            self.window_start_ms = self.window_start_ms.saturating_add(WINDOW_MS);
        }
    }

    /// Return the weight (0..=WINDOW_MS) applied to the previous
    /// window's counters when computing the effective sliding-window
    /// usage.
    const fn prev_window_weight(&self, now_ms: u64) -> u64 {
        let elapsed = now_ms.saturating_sub(self.window_start_ms);
        // `u64::min` calls `Ord::min`, which isn't stable as a const trait
        // method yet (rust-lang #143874). Inline the comparison so this
        // function and its const callers continue to compile.
        let clamped = if elapsed < WINDOW_MS { elapsed } else { WINDOW_MS };
        WINDOW_MS.saturating_sub(clamped)
    }

    /// Return the effective bytes used in the trailing sliding window.
    #[must_use]
    pub const fn effective_bytes_in_window(&self, now_ms: u64) -> u64 {
        let weight = self.prev_window_weight(now_ms);
        // prev * weight / WINDOW_MS + current
        let weighted_prev = self
            .prev_bytes_in_window
            .saturating_mul(weight)
            / WINDOW_MS;
        weighted_prev.saturating_add(self.bytes_in_window)
    }

    /// Return the effective symbol count in the trailing sliding window.
    #[must_use]
    pub const fn effective_symbols_in_window(&self, now_ms: u64) -> u32 {
        let weight = self.prev_window_weight(now_ms);
        // Use u64 arithmetic to avoid u32 overflow, then clamp.
        let weighted_prev =
            (self.prev_symbols_in_window as u64).saturating_mul(weight) / WINDOW_MS;
        let weighted_prev_u32 = if weighted_prev > u32::MAX as u64 {
            u32::MAX
        } else {
            weighted_prev as u32
        };
        weighted_prev_u32.saturating_add(self.symbols_in_window)
    }

    /// Return the effective failed-auth count in the trailing sliding window.
    #[must_use]
    pub const fn effective_failed_auth_in_window(&self, now_ms: u64) -> u32 {
        let weight = self.prev_window_weight(now_ms);
        let weighted_prev =
            (self.prev_failed_auth_in_window as u64).saturating_mul(weight) / WINDOW_MS;
        let weighted_prev_u32 = if weighted_prev > u32::MAX as u64 {
            u32::MAX
        } else {
            weighted_prev as u32
        };
        weighted_prev_u32.saturating_add(self.failed_auth_in_window)
    }

    /// Return the effective decode-CPU milliseconds in the trailing
    /// sliding window.
    #[must_use]
    pub const fn effective_decode_cpu_ms_in_window(&self, now_ms: u64) -> u64 {
        let weight = self.prev_window_weight(now_ms);
        let weighted_prev = self
            .prev_decode_cpu_ms_in_window
            .saturating_mul(weight)
            / WINDOW_MS;
        weighted_prev.saturating_add(self.decode_cpu_ms_in_window)
    }

    /// Calculate time remaining until the sliding window drains enough
    /// to make a budget decision stable.
    #[must_use]
    const fn time_until_window_reset(&self, now_ms: u64) -> Duration {
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
/// as specified in `FCP_Specification_V3.md` §11.7.1.
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
    ///
    /// Uses the raw entry API on Rust nightly to avoid cloning the `NodeId(String)`
    /// key on the hot path. Only clones once for first-time peer insertion.
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
        // L2-09 fix: use the sliding-window effective count (prev
        // window weighted by time remaining in current window) so a
        // peer cannot burst up to 2× its budget by scheduling traffic
        // at the seam between two fixed 60-second windows.
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.maybe_reset_window(now_ms);

        let effective = usage.effective_bytes_in_window(now_ms);
        let new_total = effective.saturating_add(bytes);
        if new_total > limit {
            return Err(AdmissionError::ByteBudgetExceeded {
                current: effective,
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
        // L2-09 fix: sliding-window effective count, see
        // check_bytes_with_limit for rationale.
        let usage = self.get_or_create_usage(peer, now_ms);
        usage.maybe_reset_window(now_ms);

        let effective = usage.effective_symbols_in_window(now_ms);
        let new_total = effective.saturating_add(symbols);
        if new_total > limit {
            return Err(AdmissionError::SymbolBudgetExceeded {
                current: effective,
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

        let effective = usage.effective_failed_auth_in_window(now_ms);
        if effective > limit {
            return Err(AdmissionError::AuthFailureBudgetExceeded {
                current: effective,
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

        let effective_ms = usage.effective_decode_cpu_ms_in_window(now_ms);
        if effective_ms > limit_ms {
            return Err(AdmissionError::DecodeCpuBudgetExceeded {
                current_ms: effective_ms,
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
    /// **Important:** This method only _checks_ whether the request would be
    /// admitted. After processing, callers must debit the budget via
    /// [`record_bytes`](Self::record_bytes) and
    /// [`record_symbols`](Self::record_symbols).
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
        self.peer_usage.retain(|_, usage| {
            usage.inflight_decodes > 0
                || now_ms.saturating_sub(usage.window_start_ms) < stale_threshold_ms
        });
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

        // Sliding window: two full windows after the peer exhausted
        // its budget, the previous window has drained completely and
        // fresh traffic succeeds again.
        assert!(controller.check_bytes(&peer, 100, 120_001).is_ok());

        // Immediately after the slide (t=60_001), the previous
        // window still weighs in heavily so the limit is still
        // enforced against the rolling 60-second total. This is the
        // regression-proof end of the L2-09 fix: fixed-window reset
        // would have accepted 100 bytes here.
        let mut controller2 = AdmissionController::new(AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        });
        controller2.record_bytes(&peer, 1000, 0);
        assert!(controller2.check_bytes(&peer, 100, 60_001).is_err());
    }

    #[test]
    fn sliding_window_rejects_window_boundary_burst() {
        // Regression test for the L2-09 burst vulnerability: a peer
        // that pushes the full per-minute budget at the END of window
        // N and then attempts to immediately push it again at the
        // START of window N+1 must not succeed, because the trailing
        // 60-second window would exceed 2× the budget.
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // Near the end of window N, the peer records its full budget.
        controller.record_bytes(&peer, 1000, 59_000);

        // One and a half seconds later (now in window N+1 after
        // slide), the trailing 60-second window still contains most
        // of that traffic. A full second budget must be rejected.
        assert!(controller.check_bytes(&peer, 1000, 60_500).is_err());

        // Even a small request that pushes the effective total past
        // the limit must be rejected.
        assert!(controller.check_bytes(&peer, 10, 60_500).is_err());
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

        // peer-4 has an active decode
        controller.record_bytes(&NodeId::new("peer-4"), 100, 0);
        controller
            .try_acquire_decode(&NodeId::new("peer-4"), 0)
            .unwrap();

        assert_eq!(controller.peer_count(), 4);

        // GC with threshold that removes peer-1 and would remove peer-4 if it weren't for the active decode
        controller.gc_stale_peers(100_000, 60_000);
        assert_eq!(controller.peer_count(), 3);
        assert!(controller.get_usage(&NodeId::new("peer-1")).is_none());
        assert!(controller.get_usage(&NodeId::new("peer-4")).is_some());
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

    // --- New tests below ---

    #[test]
    fn peer_budget_new_constructor() {
        let budget = PeerBudget::new(100, 200, 300, 400, 5000);
        assert_eq!(budget.max_bytes_per_min, 100);
        assert_eq!(budget.max_symbols_per_min, 200);
        assert_eq!(budget.max_failed_auth_per_min, 300);
        assert_eq!(budget.max_inflight_decodes, 400);
        assert_eq!(budget.max_decode_cpu_ms_per_min, 5000);
    }

    #[test]
    fn peer_budget_serde_roundtrip() {
        let budget = PeerBudget::default();
        let json = serde_json::to_string(&budget).unwrap();
        let deserialized: PeerBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, deserialized);
    }

    #[test]
    fn admission_policy_trusted_mesh() {
        let policy = AdmissionPolicy::trusted_mesh();
        assert!(policy.require_authenticated_requests);
        assert_eq!(policy.max_amplification_factor, 100);
        assert!(!policy.strict_unauthenticated_limits);
        assert_eq!(policy.per_peer, PeerBudget::permissive());
    }

    #[test]
    fn admission_policy_public_ingress() {
        let policy = AdmissionPolicy::public_ingress();
        assert!(!policy.require_authenticated_requests);
        assert_eq!(policy.max_amplification_factor, 2);
        assert!(policy.strict_unauthenticated_limits);
        assert_eq!(policy.per_peer, PeerBudget::restrictive());
    }

    #[test]
    fn admission_policy_serde_roundtrip() {
        let policy = AdmissionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: AdmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn object_admission_class_serde_roundtrip() {
        let quarantined = ObjectAdmissionClass::Quarantined;
        let json = serde_json::to_string(&quarantined).unwrap();
        assert_eq!(json, "\"quarantined\"");
        let deserialized: ObjectAdmissionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, quarantined);

        let admitted = ObjectAdmissionClass::Admitted;
        let json = serde_json::to_string(&admitted).unwrap();
        assert_eq!(json, "\"admitted\"");
    }

    #[test]
    fn object_admission_class_debug_clone_copy_eq_hash() {
        let a = ObjectAdmissionClass::Quarantined;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(a, ObjectAdmissionClass::Admitted);

        let s = format!("{a:?}");
        assert!(s.contains("Quarantined"));

        // Hash: can be used as HashMap key
        let mut map = std::collections::HashMap::new();
        map.insert(a, "test");
        assert_eq!(map.get(&ObjectAdmissionClass::Quarantined), Some(&"test"));
    }

    #[test]
    fn object_admission_policy_serde_roundtrip() {
        let policy = ObjectAdmissionPolicy {
            max_quarantine_bytes_per_zone: 1024,
            max_quarantine_objects_per_zone: 50,
            quarantine_ttl_secs: 120,
            require_schema_validation: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: ObjectAdmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn peer_usage_new() {
        let usage = PeerUsage::new(1000);
        assert_eq!(usage.bytes_in_window, 0);
        assert_eq!(usage.symbols_in_window, 0);
        assert_eq!(usage.failed_auth_in_window, 0);
        assert_eq!(usage.inflight_decodes, 0);
        assert_eq!(usage.decode_cpu_ms_in_window, 0);
        assert_eq!(usage.window_start_ms, 1000);
        assert!(!usage.is_authenticated);
    }

    #[test]
    fn peer_usage_debug_and_clone() {
        let usage = PeerUsage::new(0);
        let cloned = usage.clone();
        assert_eq!(cloned.window_start_ms, 0);
        let s = format!("{usage:?}");
        assert!(s.contains("PeerUsage"));
    }

    #[test]
    fn admission_error_display_all_variants() {
        let errors: Vec<(AdmissionError, &str)> = vec![
            (
                AdmissionError::ByteBudgetExceeded {
                    current: 100,
                    limit: 50,
                    retry_after: Duration::from_secs(30),
                },
                "byte budget exceeded",
            ),
            (
                AdmissionError::SymbolBudgetExceeded {
                    current: 200,
                    limit: 100,
                    retry_after: Duration::from_secs(10),
                },
                "symbol budget exceeded",
            ),
            (
                AdmissionError::AuthFailureBudgetExceeded {
                    current: 5,
                    limit: 3,
                    retry_after: Duration::from_secs(60),
                },
                "auth failure budget exceeded",
            ),
            (
                AdmissionError::DecodeCapacityExceeded {
                    current: 10,
                    limit: 5,
                },
                "decode capacity exceeded",
            ),
            (
                AdmissionError::DecodeCpuBudgetExceeded {
                    current_ms: 6000,
                    limit_ms: 5000,
                    retry_after: Duration::from_secs(20),
                },
                "decode CPU budget exceeded",
            ),
            (
                AdmissionError::AmplificationViolation {
                    request_symbols: 10,
                    response_symbols: 200,
                    max_factor: 10,
                },
                "amplification violation",
            ),
            (
                AdmissionError::AuthenticationRequired,
                "authentication required",
            ),
            (
                AdmissionError::ProofOfNeedRequired,
                "proof-of-need required",
            ),
            (
                AdmissionError::ObjectQuarantined {
                    object_id: "abc123".into(),
                },
                "quarantined",
            ),
            (
                AdmissionError::NotReachable {
                    object_id: "def456".into(),
                },
                "not reachable",
            ),
            (
                AdmissionError::QuarantineQuotaExceeded {
                    current_bytes: 300,
                    limit_bytes: 200,
                },
                "quarantine quota exceeded",
            ),
        ];
        for (err, expected_substr) in &errors {
            let s = err.to_string();
            assert!(
                s.contains(expected_substr),
                "Expected '{s}' to contain '{expected_substr}'"
            );
        }
    }

    #[test]
    fn admission_error_serde_roundtrip() {
        let err = AdmissionError::ByteBudgetExceeded {
            current: 100,
            limit: 50,
            retry_after: Duration::from_secs(30),
        };
        let json = serde_json::to_string(&err).unwrap();
        let deserialized: AdmissionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deserialized);
    }

    #[test]
    fn admission_error_all_error_codes() {
        let test_cases: Vec<(AdmissionError, u32, bool)> = vec![
            (
                AdmissionError::ByteBudgetExceeded {
                    current: 0,
                    limit: 0,
                    retry_after: Duration::ZERO,
                },
                6001,
                true,
            ),
            (
                AdmissionError::SymbolBudgetExceeded {
                    current: 0,
                    limit: 0,
                    retry_after: Duration::ZERO,
                },
                6002,
                true,
            ),
            (
                AdmissionError::AuthFailureBudgetExceeded {
                    current: 0,
                    limit: 0,
                    retry_after: Duration::ZERO,
                },
                6003,
                true,
            ),
            (
                AdmissionError::DecodeCapacityExceeded {
                    current: 0,
                    limit: 0,
                },
                6004,
                true,
            ),
            (
                AdmissionError::DecodeCpuBudgetExceeded {
                    current_ms: 0,
                    limit_ms: 0,
                    retry_after: Duration::ZERO,
                },
                6005,
                true,
            ),
            (
                AdmissionError::AmplificationViolation {
                    request_symbols: 0,
                    response_symbols: 0,
                    max_factor: 0,
                },
                6010,
                false,
            ),
            (AdmissionError::AuthenticationRequired, 6011, false),
            (AdmissionError::ProofOfNeedRequired, 6012, false),
            (
                AdmissionError::ObjectQuarantined {
                    object_id: String::new(),
                },
                6020,
                false,
            ),
            (
                AdmissionError::NotReachable {
                    object_id: String::new(),
                },
                6021,
                false,
            ),
            (
                AdmissionError::QuarantineQuotaExceeded {
                    current_bytes: 0,
                    limit_bytes: 0,
                },
                6022,
                false,
            ),
        ];
        for (err, code, retryable) in &test_cases {
            assert_eq!(err.error_code(), *code, "Wrong code for {err:?}");
            assert_eq!(
                err.is_retryable(),
                *retryable,
                "Wrong retryable for {err:?}"
            );
        }
    }

    #[test]
    fn admission_error_retry_after() {
        let with_retry = AdmissionError::DecodeCpuBudgetExceeded {
            current_ms: 6000,
            limit_ms: 5000,
            retry_after: Duration::from_secs(42),
        };
        assert_eq!(with_retry.retry_after(), Some(Duration::from_secs(42)));

        let without_retry = AdmissionError::AmplificationViolation {
            request_symbols: 1,
            response_symbols: 100,
            max_factor: 10,
        };
        assert_eq!(without_retry.retry_after(), None);

        let also_without = AdmissionError::ProofOfNeedRequired;
        assert_eq!(also_without.retry_after(), None);
    }

    #[test]
    fn decode_cpu_budget_exceeded() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_decode_cpu_ms_per_min: 100,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        assert!(controller.record_decode_cpu(&peer, 50, 0).is_ok());
        assert!(controller.record_decode_cpu(&peer, 40, 0).is_ok());

        let result = controller.record_decode_cpu(&peer, 20, 0);
        assert!(matches!(
            result,
            Err(AdmissionError::DecodeCpuBudgetExceeded { .. })
        ));
    }

    #[test]
    fn controller_set_and_check_authenticated() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        assert!(!controller.is_authenticated(&peer));

        controller.set_authenticated(&peer, true, 0);
        assert!(controller.is_authenticated(&peer));

        controller.set_authenticated(&peer, false, 0);
        assert!(!controller.is_authenticated(&peer));
    }

    #[test]
    fn controller_get_usage() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        assert!(controller.get_usage(&peer).is_none());

        controller.record_bytes(&peer, 500, 1000);
        let usage = controller.get_usage(&peer).unwrap();
        assert_eq!(usage.bytes_in_window, 500);
        assert_eq!(usage.window_start_ms, 1000);
    }

    #[test]
    fn controller_set_policy() {
        let mut controller = AdmissionController::with_default_policy();
        assert_eq!(controller.policy().max_amplification_factor, 10);

        let new_policy = AdmissionPolicy::trusted_mesh();
        controller.set_policy(new_policy);
        assert_eq!(controller.policy().max_amplification_factor, 100);
    }

    #[test]
    fn controller_debug() {
        let controller = AdmissionController::with_default_policy();
        let s = format!("{controller:?}");
        assert!(s.contains("AdmissionController"));
    }

    #[test]
    fn anti_amplification_authenticated_without_proof() {
        let controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        // Authenticated but no proof-of-need: still subject to amplification limit
        assert!(matches!(
            controller.check_amplification(&peer, 10, 110, true, false),
            Err(AdmissionError::AmplificationViolation { .. })
        ));

        // Within limit should pass
        assert!(
            controller
                .check_amplification(&peer, 10, 100, true, false)
                .is_ok()
        );
    }

    #[test]
    fn release_decode_saturates_at_zero() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        // Release without any acquired should not underflow
        controller.release_decode(&peer, 0);
        let usage = controller.get_usage(&peer).unwrap();
        assert_eq!(usage.inflight_decodes, 0);
    }

    #[test]
    fn gc_stale_peers_preserves_active_decodes() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        controller.record_bytes(&peer, 100, 0);
        controller.try_acquire_decode(&peer, 0).unwrap();

        // Even with very aggressive GC, active decode prevents removal
        controller.gc_stale_peers(1_000_000, 1);
        assert_eq!(controller.peer_count(), 1);
        assert!(controller.get_usage(&peer).is_some());
    }

    #[test]
    fn window_reset_clears_all_counters() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                max_symbols_per_min: 100,
                max_failed_auth_per_min: 10,
                max_decode_cpu_ms_per_min: 500,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // Fill up all counters at t=0
        controller.record_bytes(&peer, 900, 0);
        controller.record_symbols(&peer, 90, 0);
        controller.record_auth_failure(&peer, 0).unwrap();
        controller.record_decode_cpu(&peer, 400, 0).unwrap();

        // After window reset, all should be cleared
        controller.record_bytes(&peer, 1, 60_001);
        let usage = controller.get_usage(&peer).unwrap();
        // Window was reset, so bytes should be just 1
        assert_eq!(usage.bytes_in_window, 1);
    }

    // ── Constants validation ────────────────────────────────────

    #[test]
    fn constants_are_sensible() {
        assert_eq!(DEFAULT_MAX_BYTES_PER_MIN, 64 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_SYMBOLS_PER_MIN, 200_000);
        assert_eq!(DEFAULT_MAX_FAILED_AUTH_PER_MIN, 100);
        assert_eq!(DEFAULT_MAX_INFLIGHT_DECODES, 32);
        assert_eq!(DEFAULT_MAX_DECODE_CPU_MS_PER_MIN, 5_000);
        assert_eq!(DEFAULT_AMPLIFICATION_FACTOR, 10);
        assert_eq!(DEFAULT_MAX_QUARANTINE_BYTES_PER_ZONE, 256 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_QUARANTINE_OBJECTS_PER_ZONE, 100_000);
        assert_eq!(DEFAULT_QUARANTINE_TTL_SECS, 3600);
    }

    // ── AdmissionError trait impls ─────────────────────────────

    #[test]
    fn admission_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AdmissionError::AuthenticationRequired);
        assert!(err.to_string().contains("authentication required"));
    }

    #[test]
    fn admission_error_clone_and_debug() {
        let err = AdmissionError::ProofOfNeedRequired;
        let cloned = err.clone();
        assert_eq!(err, cloned);
        let s = format!("{err:?}");
        assert!(s.contains("ProofOfNeedRequired"));
    }

    #[test]
    fn admission_error_serde_all_variants() {
        let errors = vec![
            AdmissionError::SymbolBudgetExceeded {
                current: 500,
                limit: 200,
                retry_after: Duration::from_millis(1500),
            },
            AdmissionError::AuthFailureBudgetExceeded {
                current: 11,
                limit: 10,
                retry_after: Duration::from_secs(55),
            },
            AdmissionError::DecodeCapacityExceeded {
                current: 33,
                limit: 32,
            },
            AdmissionError::DecodeCpuBudgetExceeded {
                current_ms: 6000,
                limit_ms: 5000,
                retry_after: Duration::from_secs(40),
            },
            AdmissionError::AmplificationViolation {
                request_symbols: 5,
                response_symbols: 100,
                max_factor: 10,
            },
            AdmissionError::AuthenticationRequired,
            AdmissionError::ProofOfNeedRequired,
            AdmissionError::ObjectQuarantined {
                object_id: "obj-abc".into(),
            },
            AdmissionError::NotReachable {
                object_id: "obj-def".into(),
            },
            AdmissionError::QuarantineQuotaExceeded {
                current_bytes: 300,
                limit_bytes: 256,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let deserialized: AdmissionError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, deserialized, "Failed roundtrip for {err:?}");
        }
    }

    // ── Multi-peer tracking ────────────────────────────────────

    #[test]
    fn multiple_peers_tracked_independently() {
        let mut controller = AdmissionController::with_default_policy();
        let peer_a = NodeId::new("peer-a");
        let peer_b = NodeId::new("peer-b");

        controller.record_bytes(&peer_a, 1000, 0);
        controller.record_bytes(&peer_b, 2000, 0);

        assert_eq!(controller.get_usage(&peer_a).unwrap().bytes_in_window, 1000);
        assert_eq!(controller.get_usage(&peer_b).unwrap().bytes_in_window, 2000);
        assert_eq!(controller.peer_count(), 2);
    }

    // ── PeerBudget ordering ────────────────────────────────────

    #[test]
    fn peer_budget_restrictive_less_than_permissive() {
        let r = PeerBudget::restrictive();
        let p = PeerBudget::permissive();
        assert!(r.max_bytes_per_min < p.max_bytes_per_min);
        assert!(r.max_symbols_per_min < p.max_symbols_per_min);
        assert!(r.max_failed_auth_per_min < p.max_failed_auth_per_min);
        assert!(r.max_inflight_decodes < p.max_inflight_decodes);
        assert!(r.max_decode_cpu_ms_per_min < p.max_decode_cpu_ms_per_min);
    }

    // ── Window edge cases ──────────────────────────────────────

    #[test]
    fn peer_usage_time_until_window_reset() {
        let usage = PeerUsage::new(10_000);
        let remaining = usage.time_until_window_reset(10_000);
        assert_eq!(remaining, Duration::from_secs(60));

        let remaining_later = usage.time_until_window_reset(40_000);
        assert_eq!(remaining_later, Duration::from_secs(30));
    }

    #[test]
    fn window_does_not_reset_within_60_seconds() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        controller.record_bytes(&peer, 999, 0);
        // At 59_999ms, the current window still holds 999 bytes.
        assert!(controller.check_bytes(&peer, 100, 59_999).is_err());
        // Sliding-window: 60_000ms slides the current window into
        // the previous slot, but the previous slot still weighs in
        // fully at t=60_000 (weight=1.0), so the effective count is
        // ~999 and 100 more bytes still exceed the 1000 limit.
        assert!(controller.check_bytes(&peer, 100, 60_000).is_err());
        // Two full windows after recording, the previous slot has
        // drained and traffic succeeds again.
        assert!(controller.check_bytes(&peer, 100, 120_001).is_ok());
    }

    // ── Combined admission edge cases ──────────────────────────

    #[test]
    fn combined_admission_fails_bytes_after_auth_ok() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 100,
                ..PeerBudget::default()
            },
            require_authenticated_requests: true,
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // Auth passes but bytes fail
        let result = controller.check_admission(&peer, 200, 1, true, 0);
        assert!(matches!(
            result,
            Err(AdmissionError::ByteBudgetExceeded { .. })
        ));
    }

    #[test]
    fn combined_admission_fails_symbols_after_auth_and_bytes_ok() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 10_000,
                max_symbols_per_min: 50,
                ..PeerBudget::default()
            },
            require_authenticated_requests: true,
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        let result = controller.check_admission(&peer, 100, 100, true, 0);
        assert!(matches!(
            result,
            Err(AdmissionError::SymbolBudgetExceeded { .. })
        ));
    }

    // ── GC edge cases ──────────────────────────────────────────

    #[test]
    fn gc_removes_all_stale_peers() {
        let mut controller = AdmissionController::with_default_policy();
        controller.record_bytes(&NodeId::new("old-1"), 10, 0);
        controller.record_bytes(&NodeId::new("old-2"), 10, 0);
        assert_eq!(controller.peer_count(), 2);

        controller.gc_stale_peers(200_000, 60_000);
        assert_eq!(controller.peer_count(), 0);
    }

    #[test]
    fn gc_keeps_recent_peers() {
        let mut controller = AdmissionController::with_default_policy();
        controller.record_bytes(&NodeId::new("recent"), 10, 100_000);
        controller.gc_stale_peers(100_000, 60_000);
        assert_eq!(controller.peer_count(), 1);
    }

    // ── Amplification edge cases ───────────────────────────────

    #[test]
    fn amplification_zero_request_symbols() {
        let controller = AdmissionController::with_default_policy();
        let peer = test_peer();
        // 0 request symbols * 10 factor = 0, so any response > 0 fails
        assert!(matches!(
            controller.check_amplification(&peer, 0, 1, false, false),
            Err(AdmissionError::AmplificationViolation { .. })
        ));
        // 0 response is always ok
        assert!(
            controller
                .check_amplification(&peer, 0, 0, false, false)
                .is_ok()
        );
    }

    #[test]
    fn amplification_with_public_ingress_policy() {
        let controller = AdmissionController::new(AdmissionPolicy::public_ingress());
        let peer = test_peer();
        // Public ingress has factor=2
        assert!(
            controller
                .check_amplification(&peer, 10, 20, false, false)
                .is_ok()
        );
        assert!(matches!(
            controller.check_amplification(&peer, 10, 21, false, false),
            Err(AdmissionError::AmplificationViolation { .. })
        ));
    }

    // ── Decode CPU window reset ────────────────────────────────

    #[test]
    fn decode_cpu_resets_with_window() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_decode_cpu_ms_per_min: 100,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        controller.record_decode_cpu(&peer, 99, 0).unwrap();
        assert!(controller.record_decode_cpu(&peer, 10, 0).is_err());
        // Sliding-window: after two full windows the previous slot
        // has drained completely and a fresh allocation succeeds.
        assert!(controller.record_decode_cpu(&peer, 10, 120_001).is_ok());
    }

    // ── Auth failure window reset ──────────────────────────────

    #[test]
    fn auth_failure_resets_with_window() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_failed_auth_per_min: 2,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        controller.record_auth_failure(&peer, 0).unwrap();
        controller.record_auth_failure(&peer, 0).unwrap();
        assert!(controller.record_auth_failure(&peer, 0).is_err());
        // Sliding-window: after two full windows the previous slot
        // has drained and a fresh failure is within budget again.
        assert!(controller.record_auth_failure(&peer, 120_001).is_ok());
    }

    // ── Strict vs non-strict unauthenticated limits ────────────

    #[test]
    fn non_strict_unauthenticated_uses_full_budget() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 10 * 1024 * 1024,
                ..PeerBudget::default()
            },
            require_authenticated_requests: false,
            strict_unauthenticated_limits: false,
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // Without strict limits, unauthenticated gets full budget
        assert!(
            controller
                .check_admission(&peer, 2 * 1024 * 1024, 1, false, 0)
                .is_ok()
        );
    }

    // ── AdmissionError Display coverage ──────────────────────────

    #[test]
    fn admission_error_display_contains_expected_substrings() {
        let errors: Vec<AdmissionError> = vec![
            AdmissionError::ByteBudgetExceeded {
                current: 100,
                limit: 50,
                retry_after: Duration::from_secs(30),
            },
            AdmissionError::SymbolBudgetExceeded {
                current: 500,
                limit: 200,
                retry_after: Duration::from_secs(10),
            },
            AdmissionError::AuthFailureBudgetExceeded {
                current: 11,
                limit: 10,
                retry_after: Duration::from_secs(5),
            },
            AdmissionError::DecodeCapacityExceeded {
                current: 33,
                limit: 32,
            },
            AdmissionError::DecodeCpuBudgetExceeded {
                current_ms: 6000,
                limit_ms: 5000,
                retry_after: Duration::from_secs(20),
            },
            AdmissionError::AmplificationViolation {
                request_symbols: 1,
                response_symbols: 100,
                max_factor: 10,
            },
            AdmissionError::AuthenticationRequired,
            AdmissionError::ProofOfNeedRequired,
            AdmissionError::ObjectQuarantined {
                object_id: "abc123".to_string(),
            },
            AdmissionError::NotReachable {
                object_id: "def456".to_string(),
            },
            AdmissionError::QuarantineQuotaExceeded {
                current_bytes: 300,
                limit_bytes: 256,
            },
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "empty display for {err:?}");
        }

        assert!(errors[0].to_string().contains("byte budget"));
        assert!(errors[1].to_string().contains("symbol budget"));
        assert!(errors[2].to_string().contains("auth failure"));
        assert!(errors[3].to_string().contains("decode capacity"));
        assert!(errors[4].to_string().contains("decode CPU"));
        assert!(errors[5].to_string().contains("amplification"));
        assert!(errors[6].to_string().contains("authentication"));
        assert!(errors[7].to_string().contains("proof-of-need"));
        assert!(errors[8].to_string().contains("abc123"));
        assert!(errors[9].to_string().contains("def456"));
        assert!(errors[10].to_string().contains("quarantine quota"));
    }

    // ── AdmissionError error_code uniqueness ─────────────────────

    #[test]
    fn admission_error_codes_are_unique() {
        let errors: Vec<AdmissionError> = vec![
            AdmissionError::ByteBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::SymbolBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::AuthFailureBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::DecodeCapacityExceeded {
                current: 0,
                limit: 0,
            },
            AdmissionError::DecodeCpuBudgetExceeded {
                current_ms: 0,
                limit_ms: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::AmplificationViolation {
                request_symbols: 0,
                response_symbols: 0,
                max_factor: 0,
            },
            AdmissionError::AuthenticationRequired,
            AdmissionError::ProofOfNeedRequired,
            AdmissionError::ObjectQuarantined {
                object_id: String::new(),
            },
            AdmissionError::NotReachable {
                object_id: String::new(),
            },
            AdmissionError::QuarantineQuotaExceeded {
                current_bytes: 0,
                limit_bytes: 0,
            },
        ];

        let mut codes: Vec<u32> = errors.iter().map(AdmissionError::error_code).collect();
        let unique_count = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), unique_count, "error codes must be unique");
    }

    #[test]
    fn admission_error_codes_in_6xxx_range() {
        let errors = [
            AdmissionError::ByteBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::AuthenticationRequired,
            AdmissionError::QuarantineQuotaExceeded {
                current_bytes: 0,
                limit_bytes: 0,
            },
        ];
        for err in &errors {
            let code = err.error_code();
            assert!(
                (6000..7000).contains(&code),
                "error code {code} not in 6xxx range"
            );
        }
    }

    // ── AdmissionError is_retryable ──────────────────────────────

    #[test]
    fn non_retryable_errors() {
        assert!(
            !AdmissionError::AmplificationViolation {
                request_symbols: 1,
                response_symbols: 100,
                max_factor: 10,
            }
            .is_retryable()
        );
        assert!(!AdmissionError::AuthenticationRequired.is_retryable());
        assert!(!AdmissionError::ProofOfNeedRequired.is_retryable());
        assert!(
            !AdmissionError::ObjectQuarantined {
                object_id: "x".to_string(),
            }
            .is_retryable()
        );
        assert!(
            !AdmissionError::NotReachable {
                object_id: "x".to_string(),
            }
            .is_retryable()
        );
        assert!(
            !AdmissionError::QuarantineQuotaExceeded {
                current_bytes: 0,
                limit_bytes: 0,
            }
            .is_retryable()
        );
    }

    #[test]
    fn retryable_errors() {
        assert!(
            AdmissionError::ByteBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            }
            .is_retryable()
        );
        assert!(
            AdmissionError::SymbolBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            }
            .is_retryable()
        );
        assert!(
            AdmissionError::DecodeCapacityExceeded {
                current: 0,
                limit: 0,
            }
            .is_retryable()
        );
    }

    // ── AdmissionError serde roundtrip ───────────────────────────

    #[test]
    fn admission_error_byte_budget_serde_roundtrip() {
        let err = AdmissionError::ByteBudgetExceeded {
            current: 100,
            limit: 50,
            retry_after: Duration::from_secs(30),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let deser: AdmissionError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, deser);
    }

    #[test]
    fn admission_error_quarantined_serde_roundtrip() {
        let err = AdmissionError::ObjectQuarantined {
            object_id: "abc123".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let deser: AdmissionError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, deser);
    }

    // ── PeerBudget construction ──────────────────────────────────

    #[test]
    fn peer_budget_new_stores_all_fields() {
        let budget = PeerBudget::new(100, 200, 10, 5, 3000);
        assert_eq!(budget.max_bytes_per_min, 100);
        assert_eq!(budget.max_symbols_per_min, 200);
        assert_eq!(budget.max_failed_auth_per_min, 10);
        assert_eq!(budget.max_inflight_decodes, 5);
        assert_eq!(budget.max_decode_cpu_ms_per_min, 3000);
    }

    #[test]
    fn peer_budget_restrictive_values() {
        let r = PeerBudget::restrictive();
        assert_eq!(r.max_bytes_per_min, 1024 * 1024);
        assert_eq!(r.max_symbols_per_min, 10_000);
        assert_eq!(r.max_failed_auth_per_min, 10);
        assert_eq!(r.max_inflight_decodes, 4);
        assert_eq!(r.max_decode_cpu_ms_per_min, 500);
    }

    #[test]
    fn peer_budget_permissive_values() {
        let p = PeerBudget::permissive();
        assert_eq!(p.max_bytes_per_min, 512 * 1024 * 1024);
        assert_eq!(p.max_symbols_per_min, 1_000_000);
        assert_eq!(p.max_failed_auth_per_min, 1000);
        assert_eq!(p.max_inflight_decodes, 128);
        assert_eq!(p.max_decode_cpu_ms_per_min, 60_000);
    }

    #[test]
    fn peer_budget_new_serde_roundtrip() {
        let budget = PeerBudget::new(100, 200, 10, 5, 3000);
        let json = serde_json::to_string(&budget).expect("serialize");
        let deser: PeerBudget = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(budget, deser);
    }

    // ── ObjectAdmissionPolicy ────────────────────────────────────

    #[test]
    fn object_admission_policy_default_field_values() {
        let policy = ObjectAdmissionPolicy::default();
        assert_eq!(policy.max_quarantine_bytes_per_zone, 256 * 1024 * 1024);
        assert_eq!(policy.max_quarantine_objects_per_zone, 100_000);
        assert_eq!(policy.quarantine_ttl_secs, 3600);
        assert!(policy.require_schema_validation);
    }

    #[test]
    fn object_admission_policy_custom_serde_roundtrip() {
        let policy = ObjectAdmissionPolicy {
            max_quarantine_bytes_per_zone: 1024,
            max_quarantine_objects_per_zone: 50,
            quarantine_ttl_secs: 120,
            require_schema_validation: false,
        };
        let json = serde_json::to_string(&policy).expect("serialize");
        let deser: ObjectAdmissionPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, deser);
    }

    // ── ObjectAdmissionClass ─────────────────────────────────────

    #[test]
    fn object_admission_class_both_variants_serde_roundtrip() {
        let quarantined = ObjectAdmissionClass::Quarantined;
        let admitted = ObjectAdmissionClass::Admitted;

        let j1 = serde_json::to_string(&quarantined).expect("serialize");
        let j2 = serde_json::to_string(&admitted).expect("serialize");
        let d1: ObjectAdmissionClass = serde_json::from_str(&j1).expect("deserialize");
        let d2: ObjectAdmissionClass = serde_json::from_str(&j2).expect("deserialize");

        assert_eq!(quarantined, d1);
        assert_eq!(admitted, d2);
        assert_ne!(j1, j2);
    }

    #[test]
    fn object_admission_class_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ObjectAdmissionClass::Quarantined);
        set.insert(ObjectAdmissionClass::Quarantined);
        set.insert(ObjectAdmissionClass::Admitted);
        assert_eq!(set.len(), 2);
    }

    // ── AdmissionPolicy presets ──────────────────────────────────

    #[test]
    fn public_ingress_policy_values() {
        let p = AdmissionPolicy::public_ingress();
        assert!(!p.require_authenticated_requests);
        assert_eq!(p.max_amplification_factor, 2);
        assert!(p.strict_unauthenticated_limits);
        assert_eq!(p.per_peer, PeerBudget::restrictive());
    }

    #[test]
    fn trusted_mesh_policy_values() {
        let p = AdmissionPolicy::trusted_mesh();
        assert!(p.require_authenticated_requests);
        assert_eq!(p.max_amplification_factor, 100);
        assert!(!p.strict_unauthenticated_limits);
        assert_eq!(p.per_peer, PeerBudget::permissive());
    }

    #[test]
    fn admission_policy_default_serde_roundtrip() {
        let policy = AdmissionPolicy::default();
        let json = serde_json::to_string(&policy).expect("serialize");
        let deser: AdmissionPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, deser);
    }

    // ── Multiple peers independence ──────────────────────────────

    #[test]
    fn multiple_peers_byte_budgets_independent() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 100,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer_a = NodeId::new("peer-a");
        let peer_b = NodeId::new("peer-b");

        controller.record_bytes(&peer_a, 90, 0);
        // peer_a is near limit but peer_b is fresh
        assert!(controller.check_bytes(&peer_a, 20, 0).is_err());
        assert!(controller.check_bytes(&peer_b, 20, 0).is_ok());
    }

    // ── gc_stale_peers retains inflight ──────────────────────────

    #[test]
    fn gc_retains_peers_with_inflight_decodes() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("inflight-peer");
        controller.try_acquire_decode(&peer, 0).unwrap();

        // Even though window_start is old, inflight_decodes > 0 keeps it
        controller.gc_stale_peers(200_000, 60_000);
        assert_eq!(controller.peer_count(), 1);
    }

    // ── set_policy changes behavior ──────────────────────────────

    #[test]
    fn set_policy_changes_limits() {
        let mut controller = AdmissionController::new(AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 100,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        });
        let peer = test_peer();

        assert!(controller.check_bytes(&peer, 200, 0).is_err());

        controller.set_policy(AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        });
        assert!(controller.check_bytes(&peer, 200, 0).is_ok());
    }

    // ── get_usage / is_authenticated ─────────────────────────────

    #[test]
    fn get_usage_unknown_peer_returns_none() {
        let controller = AdmissionController::with_default_policy();
        assert!(controller.get_usage(&NodeId::new("unknown")).is_none());
    }

    #[test]
    fn get_usage_known_peer_returns_some() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();
        controller.record_bytes(&peer, 42, 0);
        let usage = controller.get_usage(&peer).expect("usage present");
        assert_eq!(usage.bytes_in_window, 42);
    }

    #[test]
    fn set_and_check_authenticated() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();

        assert!(!controller.is_authenticated(&peer));
        controller.set_authenticated(&peer, true, 0);
        assert!(controller.is_authenticated(&peer));
        controller.set_authenticated(&peer, false, 0);
        assert!(!controller.is_authenticated(&peer));
    }

    // ── Decode slot management ───────────────────────────────────

    #[test]
    fn decode_slot_acquire_and_release() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_inflight_decodes: 2,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        controller.try_acquire_decode(&peer, 0).unwrap();
        controller.try_acquire_decode(&peer, 0).unwrap();
        assert!(controller.try_acquire_decode(&peer, 0).is_err());

        controller.release_decode(&peer, 0);
        controller.try_acquire_decode(&peer, 0).unwrap();
    }

    #[test]
    fn release_decode_without_acquire_stays_at_zero() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();
        // Release without acquire — should not underflow
        controller.release_decode(&peer, 0);
        let usage = controller.get_usage(&peer).expect("usage");
        assert_eq!(usage.inflight_decodes, 0);
    }

    // ── Strict unauthenticated symbol limits ─────────────────────

    #[test]
    fn strict_unauthenticated_caps_symbols_at_restrictive_limit() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_symbols_per_min: 1_000_000,
                ..PeerBudget::default()
            },
            require_authenticated_requests: false,
            strict_unauthenticated_limits: true,
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        // Restrictive symbol limit is 10_000, even though policy says 1M
        assert!(
            controller
                .check_admission(&peer, 0, 10_001, false, 0)
                .is_err()
        );
        assert!(
            controller
                .check_admission(&peer, 0, 10_000, false, 0)
                .is_ok()
        );
    }

    // ── Window reset for symbols ─────────────────────────────────

    #[test]
    fn symbol_budget_resets_with_window() {
        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_symbols_per_min: 10,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = test_peer();

        controller.record_symbols(&peer, 10, 0);
        assert!(controller.check_symbols(&peer, 1, 0).is_err());
        // After window reset
        assert!(controller.check_symbols(&peer, 1, 60_001).is_ok());
    }

    // ── Record bytes/symbols saturation ──────────────────────────

    #[test]
    fn record_bytes_saturates() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();
        controller.record_bytes(&peer, u64::MAX, 0);
        controller.record_bytes(&peer, 1, 0);
        let usage = controller.get_usage(&peer).expect("usage");
        assert_eq!(usage.bytes_in_window, u64::MAX);
    }

    #[test]
    fn record_symbols_saturates() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = test_peer();
        controller.record_symbols(&peer, u32::MAX, 0);
        controller.record_symbols(&peer, 1, 0);
        let usage = controller.get_usage(&peer).expect("usage");
        assert_eq!(usage.symbols_in_window, u32::MAX);
    }

    // ── PeerUsage initial state ──────────────────────────────────

    #[test]
    fn peer_usage_initial_state() {
        let usage = PeerUsage::new(5000);
        assert_eq!(usage.bytes_in_window, 0);
        assert_eq!(usage.symbols_in_window, 0);
        assert_eq!(usage.failed_auth_in_window, 0);
        assert_eq!(usage.inflight_decodes, 0);
        assert_eq!(usage.decode_cpu_ms_in_window, 0);
        assert_eq!(usage.window_start_ms, 5000);
        assert!(!usage.is_authenticated);
    }

    // ── peer_count ───────────────────────────────────────────────

    #[test]
    fn peer_count_tracks_unique_peers() {
        let mut controller = AdmissionController::with_default_policy();
        assert_eq!(controller.peer_count(), 0);

        controller.record_bytes(&NodeId::new("a"), 1, 0);
        assert_eq!(controller.peer_count(), 1);

        controller.record_bytes(&NodeId::new("b"), 1, 0);
        assert_eq!(controller.peer_count(), 2);

        // Same peer doesn't increase count
        controller.record_bytes(&NodeId::new("a"), 1, 0);
        assert_eq!(controller.peer_count(), 2);
    }

    // ── Amplification exact boundary ─────────────────────────────

    #[test]
    fn amplification_exact_boundary() {
        let controller = AdmissionController::with_default_policy();
        let peer = test_peer();
        // Default factor is 10: 5 * 10 = 50
        assert!(
            controller
                .check_amplification(&peer, 5, 50, false, false)
                .is_ok()
        );
        assert!(
            controller
                .check_amplification(&peer, 5, 51, false, false)
                .is_err()
        );
    }

    #[test]
    fn amplification_authenticated_with_proof_bypasses() {
        let controller = AdmissionController::with_default_policy();
        let peer = test_peer();
        // Even a huge response is allowed with auth + proof
        assert!(
            controller
                .check_amplification(&peer, 1, 1_000_000, true, true)
                .is_ok()
        );
    }

    #[test]
    fn amplification_authenticated_without_proof_still_checked() {
        let controller = AdmissionController::with_default_policy();
        let peer = test_peer();
        assert!(
            controller
                .check_amplification(&peer, 1, 100, true, false)
                .is_err()
        );
    }

    // ── Constants sanity ─────────────────────────────────────────

    #[test]
    fn default_constants_are_reasonable() {
        const {
            assert!(DEFAULT_MAX_BYTES_PER_MIN > 0);
            assert!(DEFAULT_MAX_SYMBOLS_PER_MIN > 0);
            assert!(DEFAULT_MAX_FAILED_AUTH_PER_MIN > 0);
            assert!(DEFAULT_MAX_INFLIGHT_DECODES > 0);
            assert!(DEFAULT_MAX_DECODE_CPU_MS_PER_MIN > 0);
            assert!(DEFAULT_AMPLIFICATION_FACTOR > 0);
            assert!(DEFAULT_MAX_QUARANTINE_BYTES_PER_ZONE > 0);
            assert!(DEFAULT_MAX_QUARANTINE_OBJECTS_PER_ZONE > 0);
            assert!(DEFAULT_QUARANTINE_TTL_SECS > 0);
        }
    }

    // ── with_default_policy constructor ──────────────────────────

    #[test]
    fn with_default_policy_matches_default() {
        let a = AdmissionController::with_default_policy();
        let b = AdmissionController::new(AdmissionPolicy::default());
        assert_eq!(a.policy().per_peer, b.policy().per_peer);
        assert_eq!(
            a.policy().require_authenticated_requests,
            b.policy().require_authenticated_requests
        );
    }

    // ── check_authentication_required ────────────────────────────

    #[test]
    fn check_auth_required_policy_off() {
        let controller = AdmissionController::new(AdmissionPolicy {
            require_authenticated_requests: false,
            ..AdmissionPolicy::default()
        });
        assert!(controller.check_authentication_required(false).is_ok());
        assert!(controller.check_authentication_required(true).is_ok());
    }

    #[test]
    fn check_auth_required_policy_on() {
        let controller = AdmissionController::with_default_policy();
        assert!(controller.check_authentication_required(false).is_err());
        assert!(controller.check_authentication_required(true).is_ok());
    }

    // ── Batch: additional admission tests ──

    #[test]
    fn admission_error_display_auth_required() {
        let err = AdmissionError::AuthenticationRequired;
        assert!(err.to_string().contains("authentication required"));
    }

    #[test]
    fn admission_error_display_proof_of_need() {
        let err = AdmissionError::ProofOfNeedRequired;
        assert!(err.to_string().contains("proof-of-need required"));
    }

    #[test]
    fn admission_error_display_object_quarantined() {
        let err = AdmissionError::ObjectQuarantined {
            object_id: "obj-123".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("obj-123"));
        assert!(msg.contains("quarantined"));
    }

    #[test]
    fn admission_error_display_not_reachable() {
        let err = AdmissionError::NotReachable {
            object_id: "obj-456".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("obj-456"));
        assert!(msg.contains("not reachable"));
    }

    #[test]
    fn admission_error_display_quarantine_quota() {
        let err = AdmissionError::QuarantineQuotaExceeded {
            current_bytes: 1000,
            limit_bytes: 500,
        };
        let msg = err.to_string();
        assert!(msg.contains("1000"));
        assert!(msg.contains("500"));
    }

    #[test]
    fn admission_error_retry_after_none_for_auth() {
        assert!(
            AdmissionError::AuthenticationRequired
                .retry_after()
                .is_none()
        );
        assert!(AdmissionError::ProofOfNeedRequired.retry_after().is_none());
    }

    #[test]
    fn admission_error_retry_after_some_for_budget() {
        let err = AdmissionError::ByteBudgetExceeded {
            current: 100,
            limit: 50,
            retry_after: Duration::from_secs(30),
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn admission_error_is_retryable_budget_errors() {
        assert!(
            AdmissionError::ByteBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            }
            .is_retryable()
        );
        assert!(
            AdmissionError::SymbolBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            }
            .is_retryable()
        );
        assert!(
            AdmissionError::DecodeCapacityExceeded {
                current: 0,
                limit: 0,
            }
            .is_retryable()
        );
    }

    #[test]
    fn admission_error_not_retryable_non_budget() {
        assert!(!AdmissionError::AuthenticationRequired.is_retryable());
        assert!(!AdmissionError::ProofOfNeedRequired.is_retryable());
        assert!(
            !AdmissionError::AmplificationViolation {
                request_symbols: 1,
                response_symbols: 100,
                max_factor: 10,
            }
            .is_retryable()
        );
    }

    #[test]
    fn admission_error_error_codes_unique() {
        let errors: Vec<AdmissionError> = vec![
            AdmissionError::ByteBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::SymbolBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::AuthFailureBudgetExceeded {
                current: 0,
                limit: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::DecodeCapacityExceeded {
                current: 0,
                limit: 0,
            },
            AdmissionError::DecodeCpuBudgetExceeded {
                current_ms: 0,
                limit_ms: 0,
                retry_after: Duration::ZERO,
            },
            AdmissionError::AmplificationViolation {
                request_symbols: 0,
                response_symbols: 0,
                max_factor: 0,
            },
            AdmissionError::AuthenticationRequired,
            AdmissionError::ProofOfNeedRequired,
            AdmissionError::ObjectQuarantined {
                object_id: String::new(),
            },
            AdmissionError::NotReachable {
                object_id: String::new(),
            },
            AdmissionError::QuarantineQuotaExceeded {
                current_bytes: 0,
                limit_bytes: 0,
            },
        ];
        let codes: Vec<u32> = errors.iter().map(AdmissionError::error_code).collect();
        let mut unique_codes = codes.clone();
        unique_codes.sort_unstable();
        unique_codes.dedup();
        assert_eq!(codes.len(), unique_codes.len());
    }

    #[test]
    fn admission_error_byte_budget_serde_roundtrip_large_values() {
        let err = AdmissionError::ByteBudgetExceeded {
            current: 1024,
            limit: 512,
            retry_after: Duration::from_secs(5),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: AdmissionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn peer_budget_restrictive_vs_permissive() {
        let restrictive = PeerBudget::restrictive();
        let permissive = PeerBudget::permissive();
        assert!(restrictive.max_bytes_per_min < permissive.max_bytes_per_min);
        assert!(restrictive.max_symbols_per_min < permissive.max_symbols_per_min);
        assert!(restrictive.max_inflight_decodes < permissive.max_inflight_decodes);
    }

    #[test]
    fn admission_policy_public_ingress_allows_unauthenticated() {
        let policy = AdmissionPolicy::public_ingress();
        assert!(!policy.require_authenticated_requests);
        assert!(policy.strict_unauthenticated_limits);
        assert_eq!(policy.max_amplification_factor, 2);
    }

    #[test]
    fn admission_policy_trusted_mesh_requires_auth() {
        let policy = AdmissionPolicy::trusted_mesh();
        assert!(policy.require_authenticated_requests);
        assert_eq!(policy.max_amplification_factor, 100);
    }

    #[test]
    fn object_admission_class_all_variants_serde() {
        for class in [
            ObjectAdmissionClass::Quarantined,
            ObjectAdmissionClass::Admitted,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: ObjectAdmissionClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, back);
        }
    }

    #[test]
    fn object_admission_class_snake_case() {
        assert_eq!(
            serde_json::to_string(&ObjectAdmissionClass::Quarantined).unwrap(),
            "\"quarantined\""
        );
        assert_eq!(
            serde_json::to_string(&ObjectAdmissionClass::Admitted).unwrap(),
            "\"admitted\""
        );
    }

    #[test]
    fn peer_usage_new_fields() {
        let usage = PeerUsage::new(5000);
        assert_eq!(usage.bytes_in_window, 0);
        assert_eq!(usage.symbols_in_window, 0);
        assert_eq!(usage.failed_auth_in_window, 0);
        assert_eq!(usage.inflight_decodes, 0);
        assert_eq!(usage.decode_cpu_ms_in_window, 0);
        assert_eq!(usage.window_start_ms, 5000);
        assert!(!usage.is_authenticated);
    }

    #[test]
    fn controller_set_policy_updates() {
        let mut controller = AdmissionController::with_default_policy();
        let new_policy = AdmissionPolicy::trusted_mesh();
        controller.set_policy(new_policy);
        assert_eq!(controller.policy().max_amplification_factor, 100);
    }

    #[test]
    fn controller_gc_stale_peers_removes_old() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("stale-peer");
        controller.record_bytes(&peer, 100, 1000);
        // GC with threshold that makes the entry stale
        controller.gc_stale_peers(200_000, 10_000);
        assert!(controller.get_usage(&peer).is_none());
    }

    #[test]
    fn controller_gc_stale_peers_keeps_active() {
        let mut controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("active-peer");
        controller.record_bytes(&peer, 100, 100_000);
        // GC with threshold that keeps the entry
        controller.gc_stale_peers(100_500, 60_000);
        assert!(controller.get_usage(&peer).is_some());
    }
}
