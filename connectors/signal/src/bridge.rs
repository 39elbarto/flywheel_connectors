//! Signal bridge lifecycle management.
//!
//! Manages the connection lifecycle between the FCP connector and the
//! signal-cli REST daemon, including:
//!
//! - **Daemon reachability checks** — periodic `/v1/about` health probes
//! - **Receive loop scheduling** — background polling for incoming messages
//! - **Group synchronization** — sync group list and membership on start
//! - **Attachment transfer** — upload/download via signal-cli with base64 encoding
//! - **Reconnection/backoff** — exponential backoff when daemon is unreachable

use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::client::SignalClient;
use crate::error::{SignalError, SignalResult};
use crate::types::GroupInfo;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Bridge lifecycle configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Receive-loop polling interval in milliseconds.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,

    /// Maximum reconnection backoff delay in milliseconds.
    #[serde(default = "default_max_reconnect_delay_ms")]
    pub max_reconnect_delay_ms: u64,

    /// Health check interval in milliseconds.
    #[serde(default = "default_health_check_interval_ms")]
    pub health_check_interval_ms: u64,

    /// Maximum attachment size in bytes (default 100 MiB).
    #[serde(default = "default_max_attachment_bytes")]
    pub max_attachment_bytes: u64,
}

const fn default_poll_interval_ms() -> u64 {
    5_000
}

const fn default_max_reconnect_delay_ms() -> u64 {
    60_000
}

const fn default_health_check_interval_ms() -> u64 {
    30_000
}

const fn default_max_attachment_bytes() -> u64 {
    100 * 1024 * 1024 // 100 MiB
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: default_poll_interval_ms(),
            max_reconnect_delay_ms: default_max_reconnect_delay_ms(),
            health_check_interval_ms: default_health_check_interval_ms(),
            max_attachment_bytes: default_max_attachment_bytes(),
        }
    }
}

impl BridgeConfig {
    /// Validate configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns `SignalError::Config` when any interval is zero.
    pub fn validate(&self) -> SignalResult<()> {
        if self.poll_interval_ms == 0 {
            return Err(SignalError::Config(
                "poll_interval_ms must be greater than zero".into(),
            ));
        }
        if self.max_reconnect_delay_ms == 0 {
            return Err(SignalError::Config(
                "max_reconnect_delay_ms must be greater than zero".into(),
            ));
        }
        if self.health_check_interval_ms == 0 {
            return Err(SignalError::Config(
                "health_check_interval_ms must be greater than zero".into(),
            ));
        }
        if self.max_attachment_bytes == 0 {
            return Err(SignalError::Config(
                "max_attachment_bytes must be greater than zero".into(),
            ));
        }
        Ok(())
    }

    /// Compute the backoff delay for a given number of consecutive failures.
    ///
    /// Uses exponential backoff: base * 2^(failures-1), capped at `max_reconnect_delay_ms`.
    /// First failure returns the base delay (1 second).
    #[must_use]
    pub const fn backoff_delay_ms(&self, consecutive_failures: u32) -> u64 {
        if consecutive_failures == 0 {
            return 0;
        }
        let base_ms: u64 = 1_000;
        let raw_exp = consecutive_failures.saturating_sub(1);
        let exponent = if raw_exp < 30 { raw_exp } else { 30 };
        let shift = match 1u64.checked_shl(exponent) {
            Some(v) => v,
            None => u64::MAX,
        };
        let delay = base_ms.saturating_mul(shift);
        if delay < self.max_reconnect_delay_ms {
            delay
        } else {
            self.max_reconnect_delay_ms
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Bridge connection state.
#[derive(Debug, Clone, Default)]
pub struct BridgeState {
    /// Whether the daemon is currently reachable.
    pub connected: bool,

    /// Timestamp of the last successful health check.
    pub last_health_check: Option<Instant>,

    /// Number of consecutive health check failures.
    pub consecutive_failures: u32,

    /// Cursor for receive-loop pagination (last message timestamp).
    pub receive_cursor: Option<String>,

    /// Cached group list from the last sync.
    pub cached_groups: Vec<GroupInfo>,

    /// Timestamp of the last group sync.
    pub last_group_sync: Option<Instant>,
}

impl BridgeState {
    /// Reset state to disconnected.
    pub const fn mark_disconnected(&mut self) {
        self.connected = false;
    }

    /// Record a successful health check.
    pub fn record_health_success(&mut self) {
        self.connected = true;
        self.last_health_check = Some(Instant::now());
        self.consecutive_failures = 0;
    }

    /// Record a failed health check.
    pub const fn record_health_failure(&mut self) {
        self.connected = false;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Whether a health check is due based on the config interval.
    #[must_use]
    pub fn health_check_due(&self, interval_ms: u64) -> bool {
        self.last_health_check
            .is_none_or(|last| last.elapsed() >= Duration::from_millis(interval_ms))
    }

    /// Whether a group sync is due (once per 5 minutes).
    #[must_use]
    pub fn group_sync_due(&self) -> bool {
        self.last_group_sync
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(300))
    }

    /// Return a human-readable status string.
    #[must_use]
    pub fn status_summary(&self) -> String {
        if self.connected {
            let elapsed = self
                .last_health_check
                .map_or_else(|| String::from("unknown"), |t| {
                    format!("{}ms ago", t.elapsed().as_millis())
                });
            format!("connected (last check {elapsed})")
        } else if self.consecutive_failures > 0 {
            format!(
                "disconnected ({} consecutive failures)",
                self.consecutive_failures
            )
        } else {
            "not started".into()
        }
    }
}

// ---------------------------------------------------------------------------
// Attachment transfer
// ---------------------------------------------------------------------------

/// Result of encoding an attachment for upload.
#[derive(Debug, Clone)]
pub struct EncodedAttachment {
    /// Base64-encoded payload.
    pub base64_data: String,
    /// Original byte size before encoding.
    pub original_size: u64,
}

/// Encode raw bytes to base64 for signal-cli attachment upload.
///
/// # Errors
///
/// Returns `SignalError::AttachmentError` when the data is empty or exceeds
/// `max_bytes`.
pub fn encode_attachment(data: &[u8], max_bytes: u64) -> SignalResult<EncodedAttachment> {
    let size = data.len() as u64;
    if size > max_bytes {
        return Err(SignalError::AttachmentError(format!(
            "attachment size {size} bytes exceeds maximum {max_bytes} bytes"
        )));
    }
    if data.is_empty() {
        return Err(SignalError::AttachmentError(
            "attachment data must not be empty".into(),
        ));
    }
    let base64_data = base64::engine::general_purpose::STANDARD.encode(data);
    Ok(EncodedAttachment {
        base64_data,
        original_size: size,
    })
}

/// Decode a base64-encoded attachment from signal-cli.
///
/// # Errors
///
/// Returns `SignalError::AttachmentError` when the base64 data is invalid or the
/// decoded payload exceeds `max_bytes`.
pub fn decode_attachment(base64_data: &str, max_bytes: u64) -> SignalResult<Vec<u8>> {
    if base64_data.trim().is_empty() {
        return Err(SignalError::AttachmentError(
            "base64 attachment data must not be empty".into(),
        ));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(base64_data.trim())
        .map_err(|e| SignalError::AttachmentError(format!("invalid base64: {e}")))?;
    let size = decoded.len() as u64;
    if size > max_bytes {
        return Err(SignalError::AttachmentError(format!(
            "decoded attachment size {size} bytes exceeds maximum {max_bytes} bytes"
        )));
    }
    Ok(decoded)
}

// ---------------------------------------------------------------------------
// Bridge Manager
// ---------------------------------------------------------------------------

/// Manages the bridge lifecycle between the FCP connector and signal-cli daemon.
///
/// Responsibilities:
/// - Periodic health probes to `/v1/about`
/// - Receive loop scheduling with configurable interval
/// - Group synchronization on start and periodic refresh
/// - Attachment encoding/decoding
/// - Exponential backoff on daemon unreachability
#[derive(Debug)]
pub struct BridgeManager {
    config: BridgeConfig,
    pub(crate) state: BridgeState,
}

impl BridgeManager {
    /// Create a new bridge manager with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `SignalError::Config` when the configuration is invalid.
    pub fn new(config: BridgeConfig) -> SignalResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            state: BridgeState::default(),
        })
    }

    /// Create a bridge manager with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            config: BridgeConfig::default(),
            state: BridgeState::default(),
        }
    }

    /// Return a reference to the bridge configuration.
    #[must_use]
    pub const fn config(&self) -> &BridgeConfig {
        &self.config
    }

    /// Return a reference to the bridge state.
    #[must_use]
    pub const fn state(&self) -> &BridgeState {
        &self.state
    }

    /// Whether the daemon is currently reachable.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.state.connected
    }

    /// Number of consecutive failures.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.state.consecutive_failures
    }

    /// Compute the current backoff delay in milliseconds.
    #[must_use]
    pub const fn current_backoff_ms(&self) -> u64 {
        self.config
            .backoff_delay_ms(self.state.consecutive_failures)
    }

    /// Perform a health check against the signal-cli daemon.
    ///
    /// Updates internal state based on the result.
    ///
    /// # Errors
    ///
    /// Returns the underlying `SignalError` when the daemon is unreachable.
    pub async fn health_check(&mut self, client: &SignalClient) -> SignalResult<()> {
        debug!("Bridge health check starting");
        match client.health_check().await {
            Ok(()) => {
                if !self.state.connected {
                    info!("Signal daemon is now reachable");
                }
                self.state.record_health_success();
                Ok(())
            }
            Err(e) => {
                self.state.record_health_failure();
                let backoff = self.current_backoff_ms();
                warn!(
                    consecutive_failures = self.state.consecutive_failures,
                    backoff_ms = backoff,
                    "Signal daemon health check failed: {e}"
                );
                Err(e)
            }
        }
    }

    /// Whether a health check is currently due.
    #[must_use]
    pub fn health_check_due(&self) -> bool {
        self.state
            .health_check_due(self.config.health_check_interval_ms)
    }

    /// Whether a receive poll is appropriate right now.
    ///
    /// Returns `false` if the daemon is not connected (should wait for
    /// reconnection backoff instead).
    #[must_use]
    pub const fn should_poll(&self) -> bool {
        self.state.connected
    }

    /// Return the configured poll interval as a `Duration`.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.config.poll_interval_ms)
    }

    /// Update the receive cursor after processing messages.
    pub fn advance_cursor(&mut self, cursor: String) {
        self.state.receive_cursor = Some(cursor);
    }

    /// Return the current receive cursor.
    #[must_use]
    pub fn receive_cursor(&self) -> Option<&str> {
        self.state.receive_cursor.as_deref()
    }

    /// Synchronize group list from the daemon.
    ///
    /// Updates the cached group list in bridge state.
    ///
    /// # Errors
    ///
    /// Returns the underlying `SignalError` when the group list cannot be
    /// fetched from the daemon.
    pub async fn sync_groups(
        &mut self,
        client: &SignalClient,
        runtime: &fcp_sdk::migration::ConnectorRuntime,
    ) -> SignalResult<Vec<GroupInfo>> {
        debug!("Synchronizing Signal groups");
        let groups = client.list_groups(runtime).await?;
        info!(count = groups.len(), "Group sync complete");
        self.state.cached_groups.clone_from(&groups);
        self.state.last_group_sync = Some(Instant::now());
        Ok(groups)
    }

    /// Return the cached group list.
    #[must_use]
    pub fn cached_groups(&self) -> &[GroupInfo] {
        &self.state.cached_groups
    }

    /// Whether a group sync is due.
    #[must_use]
    pub fn group_sync_due(&self) -> bool {
        self.state.group_sync_due()
    }

    /// Encode an attachment for upload.
    ///
    /// # Errors
    ///
    /// Returns `SignalError::AttachmentError` when the data is empty or exceeds
    /// the configured maximum.
    pub fn encode_attachment(&self, data: &[u8]) -> SignalResult<EncodedAttachment> {
        encode_attachment(data, self.config.max_attachment_bytes)
    }

    /// Decode a base64 attachment from the daemon.
    ///
    /// # Errors
    ///
    /// Returns `SignalError::AttachmentError` when the data is invalid or
    /// exceeds the configured maximum.
    pub fn decode_attachment(&self, base64_data: &str) -> SignalResult<Vec<u8>> {
        decode_attachment(base64_data, self.config.max_attachment_bytes)
    }

    /// Reset bridge state (e.g., on shutdown).
    pub fn reset(&mut self) {
        self.state = BridgeState::default();
    }

    /// Build a diagnostic summary for `doctor` / `self_check`.
    #[must_use]
    pub fn diagnostic_summary(&self) -> BridgeDiagnostic {
        BridgeDiagnostic {
            connected: self.state.connected,
            consecutive_failures: self.state.consecutive_failures,
            current_backoff_ms: self.current_backoff_ms(),
            cached_group_count: self.state.cached_groups.len(),
            has_receive_cursor: self.state.receive_cursor.is_some(),
            status_summary: self.state.status_summary(),
            poll_interval_ms: self.config.poll_interval_ms,
            health_check_interval_ms: self.config.health_check_interval_ms,
        }
    }
}

/// Diagnostic snapshot for `doctor` / `self_check` integration.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeDiagnostic {
    /// Whether the daemon is reachable.
    pub connected: bool,
    /// Number of consecutive health check failures.
    pub consecutive_failures: u32,
    /// Current backoff delay in milliseconds.
    pub current_backoff_ms: u64,
    /// Number of cached groups.
    pub cached_group_count: usize,
    /// Whether a receive cursor is set.
    pub has_receive_cursor: bool,
    /// Human-readable status.
    pub status_summary: String,
    /// Configured poll interval.
    pub poll_interval_ms: u64,
    /// Configured health check interval.
    pub health_check_interval_ms: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- BridgeConfig tests --

    #[test]
    fn default_config_is_valid() {
        let config = BridgeConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.poll_interval_ms, 5_000);
        assert_eq!(config.max_reconnect_delay_ms, 60_000);
        assert_eq!(config.health_check_interval_ms, 30_000);
        assert_eq!(config.max_attachment_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn config_rejects_zero_poll_interval() {
        let config = BridgeConfig {
            poll_interval_ms: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, SignalError::Config(_)));
    }

    #[test]
    fn config_rejects_zero_max_reconnect_delay() {
        let config = BridgeConfig {
            max_reconnect_delay_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_rejects_zero_health_check_interval() {
        let config = BridgeConfig {
            health_check_interval_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_rejects_zero_max_attachment_bytes() {
        let config = BridgeConfig {
            max_attachment_bytes: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn backoff_delay_zero_failures() {
        let config = BridgeConfig::default();
        assert_eq!(config.backoff_delay_ms(0), 0);
    }

    #[test]
    fn backoff_delay_first_failure() {
        let config = BridgeConfig::default();
        assert_eq!(config.backoff_delay_ms(1), 1_000);
    }

    #[test]
    fn backoff_delay_exponential() {
        let config = BridgeConfig::default();
        assert_eq!(config.backoff_delay_ms(1), 1_000);
        assert_eq!(config.backoff_delay_ms(2), 2_000);
        assert_eq!(config.backoff_delay_ms(3), 4_000);
        assert_eq!(config.backoff_delay_ms(4), 8_000);
        assert_eq!(config.backoff_delay_ms(5), 16_000);
        assert_eq!(config.backoff_delay_ms(6), 32_000);
    }

    #[test]
    fn backoff_delay_caps_at_max() {
        let config = BridgeConfig {
            max_reconnect_delay_ms: 10_000,
            ..Default::default()
        };
        assert_eq!(config.backoff_delay_ms(1), 1_000);
        assert_eq!(config.backoff_delay_ms(4), 8_000);
        assert_eq!(config.backoff_delay_ms(5), 10_000);
        assert_eq!(config.backoff_delay_ms(20), 10_000);
    }

    #[test]
    fn backoff_delay_very_large_failures_no_overflow() {
        let config = BridgeConfig::default();
        // Should not panic or overflow
        let delay = config.backoff_delay_ms(u32::MAX);
        assert!(delay <= config.max_reconnect_delay_ms);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = BridgeConfig::default();
        let json = serde_json::to_value(&config).unwrap();
        let deserialized: BridgeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.poll_interval_ms, config.poll_interval_ms);
        assert_eq!(
            deserialized.max_reconnect_delay_ms,
            config.max_reconnect_delay_ms
        );
    }

    // -- BridgeState tests --

    #[test]
    fn default_state_is_disconnected() {
        let state = BridgeState::default();
        assert!(!state.connected);
        assert!(state.last_health_check.is_none());
        assert_eq!(state.consecutive_failures, 0);
        assert!(state.receive_cursor.is_none());
        assert!(state.cached_groups.is_empty());
        assert!(state.last_group_sync.is_none());
    }

    #[test]
    fn record_health_success_sets_connected() {
        let mut state = BridgeState::default();
        state.record_health_success();
        assert!(state.connected);
        assert!(state.last_health_check.is_some());
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn record_health_failure_increments_counter() {
        let mut state = BridgeState::default();
        state.record_health_failure();
        assert!(!state.connected);
        assert_eq!(state.consecutive_failures, 1);
        state.record_health_failure();
        assert_eq!(state.consecutive_failures, 2);
    }

    #[test]
    fn record_success_resets_failures() {
        let mut state = BridgeState::default();
        state.record_health_failure();
        state.record_health_failure();
        state.record_health_failure();
        assert_eq!(state.consecutive_failures, 3);
        state.record_health_success();
        assert_eq!(state.consecutive_failures, 0);
        assert!(state.connected);
    }

    #[test]
    fn mark_disconnected_clears_connected() {
        let mut state = BridgeState::default();
        state.record_health_success();
        assert!(state.connected);
        state.mark_disconnected();
        assert!(!state.connected);
    }

    #[test]
    fn health_check_due_when_never_checked() {
        let state = BridgeState::default();
        assert!(state.health_check_due(30_000));
    }

    #[test]
    fn health_check_not_due_immediately_after_check() {
        let mut state = BridgeState::default();
        state.record_health_success();
        assert!(!state.health_check_due(30_000));
    }

    #[test]
    fn group_sync_due_when_never_synced() {
        let state = BridgeState::default();
        assert!(state.group_sync_due());
    }

    #[test]
    fn status_summary_not_started() {
        let state = BridgeState::default();
        assert_eq!(state.status_summary(), "not started");
    }

    #[test]
    fn status_summary_connected() {
        let mut state = BridgeState::default();
        state.record_health_success();
        let summary = state.status_summary();
        assert!(summary.starts_with("connected"));
    }

    #[test]
    fn status_summary_disconnected_with_failures() {
        let mut state = BridgeState::default();
        state.record_health_failure();
        state.record_health_failure();
        let summary = state.status_summary();
        assert!(summary.contains("2 consecutive failures"));
    }

    #[test]
    fn consecutive_failures_saturates() {
        let mut state = BridgeState::default();
        state.consecutive_failures = u32::MAX;
        state.record_health_failure();
        assert_eq!(state.consecutive_failures, u32::MAX);
    }

    // -- BridgeManager tests --

    #[test]
    fn manager_with_defaults() {
        let manager = BridgeManager::with_defaults();
        assert!(!manager.is_connected());
        assert_eq!(manager.consecutive_failures(), 0);
        assert_eq!(manager.current_backoff_ms(), 0);
    }

    #[test]
    fn manager_new_validates_config() {
        let bad_config = BridgeConfig {
            poll_interval_ms: 0,
            ..Default::default()
        };
        let result = BridgeManager::new(bad_config);
        assert!(result.is_err());
    }

    #[test]
    fn manager_new_accepts_valid_config() {
        let config = BridgeConfig {
            poll_interval_ms: 1_000,
            max_reconnect_delay_ms: 30_000,
            health_check_interval_ms: 10_000,
            max_attachment_bytes: 50 * 1024 * 1024,
        };
        let manager = BridgeManager::new(config).unwrap();
        assert_eq!(manager.config().poll_interval_ms, 1_000);
        assert_eq!(manager.config().max_reconnect_delay_ms, 30_000);
    }

    #[test]
    fn manager_poll_interval() {
        let manager = BridgeManager::with_defaults();
        assert_eq!(manager.poll_interval(), Duration::from_millis(5_000));
    }

    #[test]
    fn manager_should_poll_when_disconnected() {
        let manager = BridgeManager::with_defaults();
        assert!(!manager.should_poll());
    }

    #[test]
    fn manager_cursor_advance() {
        let mut manager = BridgeManager::with_defaults();
        assert!(manager.receive_cursor().is_none());
        manager.advance_cursor("1700000001000".into());
        assert_eq!(manager.receive_cursor(), Some("1700000001000"));
    }

    #[test]
    fn manager_reset_clears_state() {
        let mut manager = BridgeManager::with_defaults();
        manager.advance_cursor("some_cursor".into());
        manager.state.record_health_success();
        assert!(manager.is_connected());
        manager.reset();
        assert!(!manager.is_connected());
        assert!(manager.receive_cursor().is_none());
    }

    #[test]
    fn manager_cached_groups_empty_initially() {
        let manager = BridgeManager::with_defaults();
        assert!(manager.cached_groups().is_empty());
    }

    #[test]
    fn manager_group_sync_due_initially() {
        let manager = BridgeManager::with_defaults();
        assert!(manager.group_sync_due());
    }

    #[test]
    fn manager_diagnostic_summary() {
        let manager = BridgeManager::with_defaults();
        let diag = manager.diagnostic_summary();
        assert!(!diag.connected);
        assert_eq!(diag.consecutive_failures, 0);
        assert_eq!(diag.current_backoff_ms, 0);
        assert_eq!(diag.cached_group_count, 0);
        assert!(!diag.has_receive_cursor);
        assert_eq!(diag.status_summary, "not started");
        assert_eq!(diag.poll_interval_ms, 5_000);
        assert_eq!(diag.health_check_interval_ms, 30_000);
    }

    #[test]
    fn manager_diagnostic_after_failures() {
        let mut manager = BridgeManager::with_defaults();
        manager.state.record_health_failure();
        manager.state.record_health_failure();
        manager.state.record_health_failure();
        let diag = manager.diagnostic_summary();
        assert!(!diag.connected);
        assert_eq!(diag.consecutive_failures, 3);
        assert_eq!(diag.current_backoff_ms, 4_000); // 1000 * 2^2
        assert!(diag.status_summary.contains("3 consecutive failures"));
    }

    // -- Attachment encoding/decoding tests --

    #[test]
    fn encode_attachment_success() {
        let data = b"hello signal";
        let result = encode_attachment(data, 1024).unwrap();
        assert_eq!(result.original_size, 12);
        // Verify it decodes back
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&result.base64_data)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_attachment_exceeds_max() {
        let data = vec![0u8; 1025];
        let result = encode_attachment(&data, 1024);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignalError::AttachmentError(_)
        ));
    }

    #[test]
    fn encode_attachment_empty_data() {
        let result = encode_attachment(&[], 1024);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignalError::AttachmentError(_)
        ));
    }

    #[test]
    fn decode_attachment_success() {
        let original = b"binary data here";
        let encoded = base64::engine::general_purpose::STANDARD.encode(original);
        let decoded = decode_attachment(&encoded, 1024).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_attachment_exceeds_max() {
        let data = vec![0u8; 1025];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
        let result = decode_attachment(&encoded, 1024);
        assert!(result.is_err());
    }

    #[test]
    fn decode_attachment_empty_string() {
        let result = decode_attachment("", 1024);
        assert!(result.is_err());
    }

    #[test]
    fn decode_attachment_whitespace_string() {
        let result = decode_attachment("   ", 1024);
        assert!(result.is_err());
    }

    #[test]
    fn decode_attachment_invalid_base64() {
        let result = decode_attachment("not-valid-base64!!!", 1024);
        assert!(result.is_err());
    }

    #[test]
    fn manager_encode_attachment() {
        let manager = BridgeManager::with_defaults();
        let result = manager.encode_attachment(b"test data");
        assert!(result.is_ok());
    }

    #[test]
    fn manager_decode_attachment() {
        let manager = BridgeManager::with_defaults();
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"test data");
        let result = manager.decode_attachment(&encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test data");
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = b"roundtrip test with special chars: \x00\xff\x80";
        let encoded = encode_attachment(original, 1024).unwrap();
        let decoded = decode_attachment(&encoded.base64_data, 1024).unwrap();
        assert_eq!(decoded, original);
    }

    // -- Health check integration tests (with wiremock) --

    #[fcp_async_core::runtime::test]
    async fn manager_health_check_success() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/about"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "versions": ["v1", "v2"],
                    "build": 1
                })),
            )
            .mount(&mock_server)
            .await;

        let config = crate::types::SignalConfig::from_value(serde_json::json!({
            "daemon_url": mock_server.uri(),
            "phone_number": "+15551234567"
        }))
        .unwrap();

        let client = SignalClient::new(&config).unwrap();
        let mut manager = BridgeManager::with_defaults();

        assert!(!manager.is_connected());
        manager.health_check(&client).await.unwrap();
        assert!(manager.is_connected());
        assert_eq!(manager.consecutive_failures(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn manager_health_check_failure() {
        // Port 1 will refuse connections
        let config = crate::types::SignalConfig::from_value(serde_json::json!({
            "daemon_url": "http://127.0.0.1:1",
            "phone_number": "+15551234567"
        }))
        .unwrap();

        let client = SignalClient::new(&config).unwrap();
        let mut manager = BridgeManager::with_defaults();

        let result = manager.health_check(&client).await;
        assert!(result.is_err());
        assert!(!manager.is_connected());
        assert_eq!(manager.consecutive_failures(), 1);
        assert_eq!(manager.current_backoff_ms(), 1_000);

        let _ = manager.health_check(&client).await;
        assert_eq!(manager.consecutive_failures(), 2);
        assert_eq!(manager.current_backoff_ms(), 2_000);
    }

    #[fcp_async_core::runtime::test]
    async fn manager_health_check_recovery() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/about"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "versions": ["v1", "v2"]
                })),
            )
            .mount(&mock_server)
            .await;

        let config = crate::types::SignalConfig::from_value(serde_json::json!({
            "daemon_url": mock_server.uri(),
            "phone_number": "+15551234567"
        }))
        .unwrap();

        let client = SignalClient::new(&config).unwrap();
        let mut manager = BridgeManager::with_defaults();

        // Simulate some failures first
        manager.state.record_health_failure();
        manager.state.record_health_failure();
        assert_eq!(manager.consecutive_failures(), 2);

        // Now succeed
        manager.health_check(&client).await.unwrap();
        assert!(manager.is_connected());
        assert_eq!(manager.consecutive_failures(), 0);
        assert_eq!(manager.current_backoff_ms(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn manager_sync_groups_success() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/groups/+15551234567"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "id": "Z3JvdXBfMQ==",
                        "name": "Engineers",
                        "members": ["+15551111111"],
                        "admins": ["+15551111111"]
                    },
                    {
                        "id": "Z3JvdXBfMg==",
                        "name": "Design",
                        "members": ["+15552222222"],
                        "admins": []
                    }
                ])),
            )
            .mount(&mock_server)
            .await;

        let config = crate::types::SignalConfig::from_value(serde_json::json!({
            "daemon_url": mock_server.uri(),
            "phone_number": "+15551234567"
        }))
        .unwrap();

        let client = SignalClient::new(&config).unwrap();
        let runtime = fcp_sdk::migration::ConnectorRuntime::new(
            fcp_sdk::migration::ConnectorRuntimeConfig::default(),
        );
        let mut manager = BridgeManager::with_defaults();

        let groups = manager.sync_groups(&client, &runtime).await.unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(manager.cached_groups().len(), 2);
        assert_eq!(manager.cached_groups()[0].name, Some("Engineers".into()));
        assert!(!manager.group_sync_due()); // just synced
    }

    #[test]
    fn diagnostic_serializes_to_json() {
        let manager = BridgeManager::with_defaults();
        let diag = manager.diagnostic_summary();
        let json = serde_json::to_value(&diag).unwrap();
        assert_eq!(json["connected"], false);
        assert_eq!(json["consecutive_failures"], 0);
        assert_eq!(json["poll_interval_ms"], 5_000);
    }
}
