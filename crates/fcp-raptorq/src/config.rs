//! `RaptorQ` configuration (NORMATIVE).

// Allow truncation casts - symbol/repair counts are bounded by protocol
#![allow(clippy::cast_possible_truncation)]

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// MTU-safe defaults from `FCP_Specification_V2.md`.
pub const DEFAULT_MAX_DATAGRAM_BYTES: u16 = 1200;

/// Default symbols per FCPS frame (single-symbol frames are safest for MTU).
pub const DEFAULT_SYMBOLS_PER_FRAME: u16 = 1;

const FCPS_HEADER_LEN: u16 = 114;
const SYMBOL_RECORD_OVERHEAD: u16 = 22;

/// `RaptorQ` path profile for preset selection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RaptorQPathProfile {
    /// LAN (direct) transport.
    Lan,
    /// DERP / relay transport.
    Derp,
}

/// Preset inputs for auto-tuning symbol size and repair ratio.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RaptorQPreset {
    /// Path profile.
    pub profile: RaptorQPathProfile,
    /// Max datagram bytes allowed for FCPS frames.
    pub max_datagram_bytes: u16,
    /// Symbols per FCPS frame.
    pub symbols_per_frame: u16,
    /// Preferred symbol size (clamped to MTU-safe max).
    pub preferred_symbol_size: u16,
    /// Repair ratio in basis points.
    pub repair_ratio_bps: u16,
}

impl RaptorQPreset {
    /// MTU-safe preset for LAN paths (defaults to spec-safe limits).
    #[must_use]
    pub const fn lan() -> Self {
        Self {
            profile: RaptorQPathProfile::Lan,
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
            symbols_per_frame: DEFAULT_SYMBOLS_PER_FRAME,
            preferred_symbol_size: 1024,
            repair_ratio_bps: 500,
        }
    }

    /// MTU-safe preset for DERP paths (defaults to spec-safe limits).
    #[must_use]
    pub const fn derp() -> Self {
        Self {
            profile: RaptorQPathProfile::Derp,
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
            symbols_per_frame: DEFAULT_SYMBOLS_PER_FRAME,
            preferred_symbol_size: 1024,
            repair_ratio_bps: 500,
        }
    }

    /// Get preset by path profile.
    #[must_use]
    pub const fn for_profile(profile: RaptorQPathProfile) -> Self {
        match profile {
            RaptorQPathProfile::Lan => Self::lan(),
            RaptorQPathProfile::Derp => Self::derp(),
        }
    }
}

/// `RaptorQ` configuration (NORMATIVE).
///
/// Controls symbol size, repair ratio, object size limits, decode timeouts,
/// and chunking thresholds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RaptorQConfig {
    /// Symbol size in bytes.
    ///
    /// Default: 1024
    pub symbol_size: u16,

    /// Repair ratio in basis points (NORMATIVE).
    ///
    /// 500 = 5% = K × 1.05 total symbols.
    ///
    /// Default: 500
    pub repair_ratio_bps: u16,

    /// Maximum object size that can be encoded.
    ///
    /// Default: 64MB
    pub max_object_size: u32,

    /// Maximum time to wait for object reconstruction.
    ///
    /// Default: 30s
    #[serde(with = "duration_secs")]
    pub decode_timeout: Duration,

    /// Objects above this size MUST use `ChunkedObjectManifest`.
    ///
    /// Default: 256KB
    pub max_chunk_threshold: u32,

    /// Chunk size for `ChunkedObjectManifest`.
    ///
    /// Default: 64KB
    pub chunk_size: u32,
}

impl Default for RaptorQConfig {
    fn default() -> Self {
        Self {
            symbol_size: 1024,
            repair_ratio_bps: 500,
            max_object_size: 64 * 1024 * 1024, // 64MB
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024, // 256KB
            chunk_size: 64 * 1024,           // 64KB
        }
    }
}

impl RaptorQConfig {
    /// Calculate number of repair symbols from basis points.
    ///
    /// `repair_ratio_bps = 500` means 5% overhead.
    /// For K source symbols, generate K + K×500/10000 = K×1.05 total symbols.
    ///
    /// Uses saturating conversion to avoid truncation on extreme inputs.
    #[must_use]
    pub fn repair_symbols(&self, source_symbols: u32) -> u32 {
        let repair = u64::from(source_symbols) * u64::from(self.repair_ratio_bps) / 10000;
        u32::try_from(repair).unwrap_or(u32::MAX)
    }

    /// Calculate K (source symbols) needed for a payload.
    #[must_use]
    pub fn source_symbols(&self, payload_len: usize) -> u32 {
        let size = usize::from(self.symbol_size).max(1);
        payload_len.div_ceil(size) as u32
    }

    /// Total symbols (source + repair) for a payload.
    #[must_use]
    pub fn total_symbols(&self, payload_len: usize) -> u32 {
        let k = self.source_symbols(payload_len);
        k.saturating_add(self.repair_symbols(k))
    }

    /// Check if a payload requires chunking.
    #[must_use]
    pub const fn requires_chunking(&self, payload_len: usize) -> bool {
        payload_len > self.max_chunk_threshold as usize
    }

    /// Calculate the number of chunks for a payload.
    #[must_use]
    pub const fn chunk_count(&self, payload_len: usize) -> usize {
        if payload_len == 0 {
            return 0;
        }
        payload_len.div_ceil(self.chunk_size as usize)
    }

    /// Compute an MTU-safe symbol size for the given datagram limit.
    ///
    /// Returns `None` if inputs are invalid (e.g., `symbols_per_frame` = 0 or MTU too small).
    #[must_use]
    pub fn mtu_safe_symbol_size(max_datagram_bytes: u16, symbols_per_frame: u16) -> Option<u16> {
        if symbols_per_frame == 0 {
            return None;
        }

        let max_payload = u32::from(max_datagram_bytes).checked_sub(u32::from(FCPS_HEADER_LEN))?;
        let per_symbol = max_payload / u32::from(symbols_per_frame);
        if per_symbol <= u32::from(SYMBOL_RECORD_OVERHEAD) {
            return None;
        }
        let symbol_size = per_symbol - u32::from(SYMBOL_RECORD_OVERHEAD);
        u16::try_from(symbol_size).ok()
    }

    /// Create a config from a preset, clamping symbol size to MTU-safe limits.
    #[must_use]
    pub fn from_preset(preset: RaptorQPreset) -> Option<Self> {
        let max_symbol =
            Self::mtu_safe_symbol_size(preset.max_datagram_bytes, preset.symbols_per_frame)?;
        let symbol_size = preset.preferred_symbol_size.min(max_symbol);
        Some(Self {
            symbol_size,
            repair_ratio_bps: preset.repair_ratio_bps,
            ..Default::default()
        })
    }

    /// Clamp the configured symbol size to MTU-safe limits.
    ///
    /// Returns the adjusted symbol size or `None` if inputs are invalid.
    pub fn bound_symbol_size(
        &mut self,
        max_datagram_bytes: u16,
        symbols_per_frame: u16,
    ) -> Option<u16> {
        let max_symbol = Self::mtu_safe_symbol_size(max_datagram_bytes, symbols_per_frame)?;
        if self.symbol_size > max_symbol {
            self.symbol_size = max_symbol;
        }
        Some(self.symbol_size)
    }
}

/// Serde helper for `Duration` as seconds.
mod duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fcp_testkit::LogCapture;
    use serde_json::json;

    #[allow(clippy::needless_pass_by_value)]
    fn log_selection(
        capture: &LogCapture,
        test_name: &str,
        phase: &str,
        context: serde_json::Value,
    ) {
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": test_name,
            "module": "fcp-raptorq",
            "phase": phase,
            "correlation_id": "00000000-0000-4000-8000-000000000000",
            "result": "pass",
            "duration_ms": 0,
            "assertions": { "passed": 1, "failed": 0 },
            "context": context,
        });
        capture.push_value(&entry).expect("serialize log entry");
    }

    #[test]
    fn default_config_values() {
        let config = RaptorQConfig::default();
        assert_eq!(config.symbol_size, 1024);
        assert_eq!(config.repair_ratio_bps, 500);
        assert_eq!(config.max_object_size, 64 * 1024 * 1024);
        assert_eq!(config.decode_timeout, Duration::from_secs(30));
        assert_eq!(config.max_chunk_threshold, 256 * 1024);
        assert_eq!(config.chunk_size, 64 * 1024);
    }

    #[test]
    fn repair_symbols_calculation() {
        let config = RaptorQConfig::default();
        // 500 bps = 5% overhead
        // 100 source symbols -> 5 repair symbols
        assert_eq!(config.repair_symbols(100), 5);
        // 1000 source symbols -> 50 repair symbols
        assert_eq!(config.repair_symbols(1000), 50);
        // 0 source symbols -> 0 repair symbols
        assert_eq!(config.repair_symbols(0), 0);
    }

    #[test]
    fn repair_symbols_saturates_on_extreme_values() {
        // Test that extreme values saturate to u32::MAX instead of truncating
        let config = RaptorQConfig {
            repair_ratio_bps: u16::MAX, // 655% overhead
            ..RaptorQConfig::default()
        };
        // u32::MAX * 65535 / 10000 = ~28 billion, exceeds u32::MAX
        // Should saturate to u32::MAX instead of wrapping
        assert_eq!(config.repair_symbols(u32::MAX), u32::MAX);
    }

    #[test]
    fn source_symbols_calculation() {
        let config = RaptorQConfig::default();
        // 1024 bytes = 1 symbol
        assert_eq!(config.source_symbols(1024), 1);
        // 1025 bytes = 2 symbols (ceiling division)
        assert_eq!(config.source_symbols(1025), 2);
        // 0 bytes = 0 symbols
        assert_eq!(config.source_symbols(0), 0);
        // 10240 bytes = 10 symbols
        assert_eq!(config.source_symbols(10240), 10);
    }

    #[test]
    fn total_symbols_calculation() {
        let config = RaptorQConfig::default();
        // 10240 bytes = 10 source + 0 repair (5% of 10 rounds down)
        assert_eq!(config.total_symbols(10240), 10);
        // 102400 bytes = 100 source + 5 repair
        assert_eq!(config.total_symbols(102_400), 105);
    }

    #[test]
    fn requires_chunking() {
        let config = RaptorQConfig::default();
        // Under threshold: no chunking
        assert!(!config.requires_chunking(256 * 1024));
        // Over threshold: requires chunking
        assert!(config.requires_chunking(256 * 1024 + 1));
        // Zero: no chunking
        assert!(!config.requires_chunking(0));
    }

    #[test]
    fn chunk_count_calculation() {
        let config = RaptorQConfig::default();
        // 0 bytes = 0 chunks
        assert_eq!(config.chunk_count(0), 0);
        // 64KB = 1 chunk
        assert_eq!(config.chunk_count(64 * 1024), 1);
        // 64KB + 1 = 2 chunks
        assert_eq!(config.chunk_count(64 * 1024 + 1), 2);
        // 256KB = 4 chunks
        assert_eq!(config.chunk_count(256 * 1024), 4);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = RaptorQConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RaptorQConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.symbol_size, config.symbol_size);
        assert_eq!(deserialized.repair_ratio_bps, config.repair_ratio_bps);
        assert_eq!(deserialized.decode_timeout, config.decode_timeout);
    }

    #[test]
    fn custom_config() {
        let config = RaptorQConfig {
            symbol_size: 2048,
            repair_ratio_bps: 1000, // 10%
            max_object_size: 128 * 1024 * 1024,
            decode_timeout: Duration::from_secs(60),
            max_chunk_threshold: 512 * 1024,
            chunk_size: 128 * 1024,
        };

        // 10% repair ratio
        assert_eq!(config.repair_symbols(100), 10);
        // 2048 byte symbols
        assert_eq!(config.source_symbols(2048), 1);
        assert_eq!(config.source_symbols(2049), 2);
    }

    #[test]
    fn mtu_safe_symbol_size_default_limit() {
        let safe = RaptorQConfig::mtu_safe_symbol_size(1200, 1).expect("safe symbol size");
        assert_eq!(safe, 1064);
    }

    #[test]
    fn mtu_safe_symbol_size_multiple_symbols() {
        let safe = RaptorQConfig::mtu_safe_symbol_size(1200, 2).expect("safe symbol size");
        assert_eq!(safe, 521);
    }

    #[test]
    fn mtu_safe_symbol_size_invalid_inputs() {
        assert!(RaptorQConfig::mtu_safe_symbol_size(1200, 0).is_none());
        assert!(RaptorQConfig::mtu_safe_symbol_size(100, 1).is_none());
    }

    #[test]
    fn from_preset_clamps_preferred_symbol_size() {
        let preset = RaptorQPreset {
            profile: RaptorQPathProfile::Lan,
            max_datagram_bytes: 1200,
            symbols_per_frame: 1,
            preferred_symbol_size: 2048,
            repair_ratio_bps: 500,
        };
        let config = RaptorQConfig::from_preset(preset).expect("preset config");
        assert_eq!(config.symbol_size, 1064);
        assert_eq!(config.repair_ratio_bps, 500);
    }

    #[test]
    fn bound_symbol_size_clamps_override() {
        let mut config = RaptorQConfig {
            symbol_size: 2048,
            ..Default::default()
        };
        let adjusted = config
            .bound_symbol_size(1200, 1)
            .expect("bounded symbol size");
        assert_eq!(adjusted, 1064);
        assert_eq!(config.symbol_size, 1064);
    }

    #[test]
    fn preset_selection_logs_and_validates_jsonl() {
        let capture = LogCapture::new();
        let test_name = "preset_selection_logs_and_validates_jsonl";

        let lan = RaptorQPreset::for_profile(RaptorQPathProfile::Lan);
        let derp = RaptorQPreset::for_profile(RaptorQPathProfile::Derp);

        assert_eq!(lan.profile, RaptorQPathProfile::Lan);
        assert_eq!(derp.profile, RaptorQPathProfile::Derp);

        log_selection(
            &capture,
            test_name,
            "execute",
            json!({
                "profile": format!("{:?}", lan.profile),
                "max_datagram_bytes": lan.max_datagram_bytes,
                "symbols_per_frame": lan.symbols_per_frame,
                "preferred_symbol_size": lan.preferred_symbol_size,
                "repair_ratio_bps": lan.repair_ratio_bps,
            }),
        );

        log_selection(
            &capture,
            test_name,
            "verify",
            json!({
                "profile": format!("{:?}", derp.profile),
                "max_datagram_bytes": derp.max_datagram_bytes,
                "symbols_per_frame": derp.symbols_per_frame,
                "preferred_symbol_size": derp.preferred_symbol_size,
                "repair_ratio_bps": derp.repair_ratio_bps,
            }),
        );

        capture.assert_valid();
    }

    #[test]
    fn from_preset_clamps_to_mtu_bounds_and_logs() {
        let capture = LogCapture::new();
        let test_name = "from_preset_clamps_to_mtu_bounds_and_logs";
        let preset = RaptorQPreset {
            profile: RaptorQPathProfile::Lan,
            max_datagram_bytes: 1200,
            symbols_per_frame: 2,
            preferred_symbol_size: 2048,
            repair_ratio_bps: 700,
        };

        let config = RaptorQConfig::from_preset(preset).expect("preset config");
        assert_eq!(config.symbol_size, 521);
        assert_eq!(config.repair_ratio_bps, 700);

        log_selection(
            &capture,
            test_name,
            "verify",
            json!({
                "profile": format!("{:?}", preset.profile),
                "max_datagram_bytes": preset.max_datagram_bytes,
                "symbols_per_frame": preset.symbols_per_frame,
                "preferred_symbol_size": preset.preferred_symbol_size,
                "selected_symbol_size": config.symbol_size,
                "repair_ratio_bps": config.repair_ratio_bps,
            }),
        );

        capture.assert_valid();
    }

    #[test]
    fn bound_symbol_size_respects_override_and_logs() {
        let capture = LogCapture::new();
        let test_name = "bound_symbol_size_respects_override_and_logs";

        let mut config = RaptorQConfig {
            symbol_size: 512,
            repair_ratio_bps: 500,
            ..Default::default()
        };

        let adjusted = config
            .bound_symbol_size(1200, 1)
            .expect("bounded symbol size");
        assert_eq!(adjusted, 512);
        assert_eq!(config.symbol_size, 512);

        log_selection(
            &capture,
            test_name,
            "verify",
            json!({
                "max_datagram_bytes": 1200,
                "symbols_per_frame": 1,
                "requested_symbol_size": 512,
                "bounded_symbol_size": adjusted,
            }),
        );

        capture.assert_valid();
    }

    // ── Repair symbols edge cases ──────────────────────────────────────────

    #[test]
    fn repair_symbols_zero_bps() {
        let config = RaptorQConfig {
            repair_ratio_bps: 0,
            ..RaptorQConfig::default()
        };
        assert_eq!(config.repair_symbols(100), 0);
        assert_eq!(config.repair_symbols(1000), 0);
    }

    #[test]
    fn repair_symbols_full_ratio() {
        // 10000 bps = 100% overhead
        let config = RaptorQConfig {
            repair_ratio_bps: 10000,
            ..RaptorQConfig::default()
        };
        assert_eq!(config.repair_symbols(100), 100);
        assert_eq!(config.repair_symbols(1), 1);
    }

    #[test]
    fn repair_symbols_one_source() {
        let config = RaptorQConfig::default(); // 500 bps
        // 1 * 500 / 10000 = 0 (integer division)
        assert_eq!(config.repair_symbols(1), 0);
    }

    // ── Source symbols edge cases ──────────────────────────────────────────

    #[test]
    fn source_symbols_one_byte() {
        let config = RaptorQConfig::default();
        assert_eq!(config.source_symbols(1), 1);
    }

    #[test]
    fn source_symbols_exactly_two_symbols() {
        let config = RaptorQConfig::default(); // symbol_size = 1024
        assert_eq!(config.source_symbols(2048), 2);
    }

    #[test]
    fn source_symbols_one_over_boundary() {
        let config = RaptorQConfig::default(); // symbol_size = 1024
        // 2049 / 1024 = 2.0009... → ceil = 3
        assert_eq!(config.source_symbols(2049), 3);
    }

    // ── Total symbols edge cases ───────────────────────────────────────────

    #[test]
    fn total_symbols_empty_payload() {
        let config = RaptorQConfig::default();
        assert_eq!(config.total_symbols(0), 0);
    }

    #[test]
    fn total_symbols_single_byte() {
        let config = RaptorQConfig::default();
        // 1 source symbol, repair = 1*500/10000 = 0
        assert_eq!(config.total_symbols(1), 1);
    }

    // ── Chunking tests ─────────────────────────────────────────────────────

    #[test]
    fn requires_chunking_zero() {
        let config = RaptorQConfig::default();
        assert!(!config.requires_chunking(0));
    }

    #[test]
    fn chunk_count_one_byte() {
        let config = RaptorQConfig::default();
        assert_eq!(config.chunk_count(1), 1);
    }

    #[test]
    fn chunk_count_large_payload() {
        let config = RaptorQConfig::default(); // chunk_size = 64KB
        // 1MB / 64KB = 16 chunks
        assert_eq!(config.chunk_count(1024 * 1024), 16);
    }

    #[test]
    fn chunk_count_not_evenly_divisible() {
        let config = RaptorQConfig::default(); // chunk_size = 64KB
        // 64KB + 1 byte = 2 chunks (ceiling)
        assert_eq!(config.chunk_count(64 * 1024 + 1), 2);
    }

    // ── MTU safe symbol size ───────────────────────────────────────────────

    #[test]
    fn mtu_safe_symbol_size_just_over_header() {
        // max_datagram = FCPS_HEADER_LEN + SYMBOL_RECORD_OVERHEAD + 1 = 114 + 22 + 1 = 137
        let safe = RaptorQConfig::mtu_safe_symbol_size(137, 1);
        assert_eq!(safe, Some(1));
    }

    #[test]
    fn mtu_safe_symbol_size_exactly_header_plus_overhead() {
        // max_datagram = 114 + 22 = 136 → per_symbol = 22, which equals overhead → None
        let safe = RaptorQConfig::mtu_safe_symbol_size(136, 1);
        assert!(safe.is_none());
    }

    #[test]
    fn mtu_safe_symbol_size_large_datagram() {
        // 9000 byte jumbo frame
        let safe = RaptorQConfig::mtu_safe_symbol_size(9000, 1).unwrap();
        // (9000 - 114) / 1 - 22 = 8864
        assert_eq!(safe, 8864);
    }

    // ── Preset tests ───────────────────────────────────────────────────────

    #[test]
    fn preset_lan_defaults() {
        let preset = RaptorQPreset::lan();
        assert_eq!(preset.profile, RaptorQPathProfile::Lan);
        assert_eq!(preset.max_datagram_bytes, 1200);
        assert_eq!(preset.symbols_per_frame, 1);
        assert_eq!(preset.preferred_symbol_size, 1024);
        assert_eq!(preset.repair_ratio_bps, 500);
    }

    #[test]
    fn preset_derp_defaults() {
        let preset = RaptorQPreset::derp();
        assert_eq!(preset.profile, RaptorQPathProfile::Derp);
        assert_eq!(preset.max_datagram_bytes, 1200);
        assert_eq!(preset.symbols_per_frame, 1);
        assert_eq!(preset.preferred_symbol_size, 1024);
        assert_eq!(preset.repair_ratio_bps, 500);
    }

    #[test]
    fn from_preset_with_small_preferred_size() {
        let preset = RaptorQPreset {
            profile: RaptorQPathProfile::Lan,
            max_datagram_bytes: 1200,
            symbols_per_frame: 1,
            preferred_symbol_size: 100, // Way under MTU limit
            repair_ratio_bps: 500,
        };
        let config = RaptorQConfig::from_preset(preset).unwrap();
        // Should use the preferred size since it's under the MTU-safe limit
        assert_eq!(config.symbol_size, 100);
    }

    #[test]
    fn from_preset_returns_none_for_tiny_mtu() {
        let preset = RaptorQPreset {
            profile: RaptorQPathProfile::Lan,
            max_datagram_bytes: 50, // Way too small
            symbols_per_frame: 1,
            preferred_symbol_size: 1024,
            repair_ratio_bps: 500,
        };
        assert!(RaptorQConfig::from_preset(preset).is_none());
    }

    // ── bound_symbol_size tests ────────────────────────────────────────────

    #[test]
    fn bound_symbol_size_invalid_inputs_returns_none() {
        let mut config = RaptorQConfig::default();
        assert!(config.bound_symbol_size(1200, 0).is_none());
        assert!(config.bound_symbol_size(50, 1).is_none());
    }

    #[test]
    fn bound_symbol_size_already_within_bounds() {
        let mut config = RaptorQConfig {
            symbol_size: 100,
            ..Default::default()
        };
        let adjusted = config.bound_symbol_size(1200, 1).unwrap();
        assert_eq!(adjusted, 100); // Should stay at 100
        assert_eq!(config.symbol_size, 100);
    }

    // ── Config serde tests ─────────────────────────────────────────────────

    #[test]
    fn config_serde_custom_values() {
        let config = RaptorQConfig {
            symbol_size: 2048,
            repair_ratio_bps: 1000,
            max_object_size: 128 * 1024 * 1024,
            decode_timeout: Duration::from_secs(60),
            max_chunk_threshold: 512 * 1024,
            chunk_size: 128 * 1024,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RaptorQConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.symbol_size, 2048);
        assert_eq!(deserialized.repair_ratio_bps, 1000);
        assert_eq!(deserialized.max_object_size, 128 * 1024 * 1024);
        assert_eq!(deserialized.decode_timeout, Duration::from_secs(60));
        assert_eq!(deserialized.max_chunk_threshold, 512 * 1024);
        assert_eq!(deserialized.chunk_size, 128 * 1024);
    }

    #[test]
    fn config_debug_format() {
        let config = RaptorQConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("RaptorQConfig"));
        assert!(debug.contains("1024"));
    }

    #[test]
    fn config_clone() {
        let config = RaptorQConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.symbol_size, config.symbol_size);
        assert_eq!(cloned.repair_ratio_bps, config.repair_ratio_bps);
        assert_eq!(cloned.max_object_size, config.max_object_size);
        assert_eq!(cloned.decode_timeout, config.decode_timeout);
        assert_eq!(cloned.max_chunk_threshold, config.max_chunk_threshold);
        assert_eq!(cloned.chunk_size, config.chunk_size);
    }

    // ── RaptorQPathProfile tests ───────────────────────────────────────────

    #[test]
    fn path_profile_equality() {
        assert_eq!(RaptorQPathProfile::Lan, RaptorQPathProfile::Lan);
        assert_eq!(RaptorQPathProfile::Derp, RaptorQPathProfile::Derp);
        assert_ne!(RaptorQPathProfile::Lan, RaptorQPathProfile::Derp);
    }

    #[test]
    fn path_profile_debug() {
        assert!(format!("{:?}", RaptorQPathProfile::Lan).contains("Lan"));
        assert!(format!("{:?}", RaptorQPathProfile::Derp).contains("Derp"));
    }

    #[test]
    fn path_profile_clone_copy() {
        let profile = RaptorQPathProfile::Lan;
        let copied = profile; // Copy
        let also = profile; // Can use again because Copy
        assert_eq!(copied, also);
    }

    #[test]
    fn path_profile_serde_roundtrip() {
        let lan = RaptorQPathProfile::Lan;
        let json = serde_json::to_string(&lan).unwrap();
        let deserialized: RaptorQPathProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, lan);

        let derp = RaptorQPathProfile::Derp;
        let json = serde_json::to_string(&derp).unwrap();
        let deserialized: RaptorQPathProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, derp);
    }

    // ── Constants tests ────────────────────────────────────────────────────

    #[test]
    fn default_constants() {
        assert_eq!(super::DEFAULT_MAX_DATAGRAM_BYTES, 1200);
        assert_eq!(super::DEFAULT_SYMBOLS_PER_FRAME, 1);
    }

    // ── Additional config tests ───────────────────────────────────────────

    #[test]
    fn config_serde_decode_timeout_as_seconds() {
        let json = r#"{"symbol_size":1024,"repair_ratio_bps":500,"max_object_size":67108864,"decode_timeout":45,"max_chunk_threshold":262144,"chunk_size":65536}"#;
        let config: RaptorQConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.decode_timeout, Duration::from_secs(45));
    }

    #[test]
    fn config_serde_json_structure() {
        let config = RaptorQConfig::default();
        let value: serde_json::Value = serde_json::to_value(&config).unwrap();
        assert_eq!(value["symbol_size"], 1024);
        assert_eq!(value["repair_ratio_bps"], 500);
        assert_eq!(value["max_object_size"], 64 * 1024 * 1024);
        assert_eq!(value["decode_timeout"], 30);
        assert_eq!(value["max_chunk_threshold"], 256 * 1024);
        assert_eq!(value["chunk_size"], 64 * 1024);
    }

    #[test]
    fn repair_symbols_small_ratio() {
        let config = RaptorQConfig {
            repair_ratio_bps: 1,
            ..RaptorQConfig::default()
        };
        // 1 bps = 0.01% overhead. 10000 source -> 1 repair
        assert_eq!(config.repair_symbols(10000), 1);
        // 9999 source -> 0 repair
        assert_eq!(config.repair_symbols(9999), 0);
    }

    #[test]
    fn source_symbols_with_symbol_size_one() {
        let config = RaptorQConfig {
            symbol_size: 1,
            ..RaptorQConfig::default()
        };
        assert_eq!(config.source_symbols(100), 100);
        assert_eq!(config.source_symbols(1), 1);
        assert_eq!(config.source_symbols(0), 0);
    }

    #[test]
    fn total_symbols_saturation() {
        let config = RaptorQConfig {
            symbol_size: 1,
            repair_ratio_bps: 10000,
            ..RaptorQConfig::default()
        };
        // Large payload: check saturation
        let total = config.total_symbols(1000);
        // 1000 source + 1000 repair = 2000
        assert_eq!(total, 2000);
    }

    #[test]
    fn chunk_count_with_small_chunk_size() {
        let config = RaptorQConfig {
            chunk_size: 1,
            ..RaptorQConfig::default()
        };
        assert_eq!(config.chunk_count(100), 100);
        assert_eq!(config.chunk_count(1), 1);
    }

    #[test]
    fn requires_chunking_at_threshold() {
        let config = RaptorQConfig {
            max_chunk_threshold: 100,
            ..RaptorQConfig::default()
        };
        assert!(!config.requires_chunking(100));
        assert!(config.requires_chunking(101));
        assert!(!config.requires_chunking(99));
    }

    #[test]
    fn mtu_safe_symbol_size_max_datagram() {
        // Very large datagram size
        let safe = RaptorQConfig::mtu_safe_symbol_size(u16::MAX, 1).unwrap();
        // (65535 - 114) / 1 - 22 = 65399
        assert_eq!(safe, 65399);
    }

    #[test]
    fn mtu_safe_symbol_size_many_symbols_per_frame() {
        // With many symbols per frame, the per-symbol budget shrinks
        let safe = RaptorQConfig::mtu_safe_symbol_size(1200, 10);
        // (1200 - 114) / 10 = 108, minus 22 = 86
        assert_eq!(safe, Some(86));
    }

    #[test]
    fn mtu_safe_symbol_size_tight_fit() {
        // Just barely fits one byte
        // Need: header(114) + overhead(22) + 1 = 137
        assert_eq!(RaptorQConfig::mtu_safe_symbol_size(137, 1), Some(1));
        // One less: does not fit
        assert!(RaptorQConfig::mtu_safe_symbol_size(136, 1).is_none());
    }

    #[test]
    fn preset_for_profile_roundtrip() {
        let lan = RaptorQPreset::for_profile(RaptorQPathProfile::Lan);
        let derp = RaptorQPreset::for_profile(RaptorQPathProfile::Derp);
        assert_eq!(lan.profile, RaptorQPathProfile::Lan);
        assert_eq!(derp.profile, RaptorQPathProfile::Derp);
        // Both have same defaults currently
        assert_eq!(lan.max_datagram_bytes, derp.max_datagram_bytes);
    }

    #[test]
    fn preset_clone_and_copy() {
        let preset = RaptorQPreset::lan();
        let cloned = preset;
        let also = preset;
        assert_eq!(cloned.profile, also.profile);
        assert_eq!(cloned.preferred_symbol_size, also.preferred_symbol_size);
    }

    #[test]
    fn preset_serde_roundtrip() {
        let preset = RaptorQPreset::lan();
        let json = serde_json::to_string(&preset).unwrap();
        let deserialized: RaptorQPreset = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.profile, preset.profile);
        assert_eq!(deserialized.max_datagram_bytes, preset.max_datagram_bytes);
        assert_eq!(deserialized.symbols_per_frame, preset.symbols_per_frame);
        assert_eq!(
            deserialized.preferred_symbol_size,
            preset.preferred_symbol_size
        );
        assert_eq!(deserialized.repair_ratio_bps, preset.repair_ratio_bps);
    }

    #[test]
    fn preset_debug_format() {
        let preset = RaptorQPreset::lan();
        let debug = format!("{preset:?}");
        assert!(debug.contains("RaptorQPreset"));
        assert!(debug.contains("Lan"));
    }

    #[test]
    fn from_preset_returns_none_for_zero_symbols_per_frame() {
        let preset = RaptorQPreset {
            profile: RaptorQPathProfile::Lan,
            max_datagram_bytes: 1200,
            symbols_per_frame: 0,
            preferred_symbol_size: 1024,
            repair_ratio_bps: 500,
        };
        assert!(RaptorQConfig::from_preset(preset).is_none());
    }

    #[test]
    fn bound_symbol_size_no_change_when_under_limit() {
        let mut config = RaptorQConfig {
            symbol_size: 64,
            ..Default::default()
        };
        let adjusted = config.bound_symbol_size(1200, 1).unwrap();
        assert_eq!(adjusted, 64);
        assert_eq!(config.symbol_size, 64);
    }

    #[test]
    fn config_clone_independence() {
        let config = RaptorQConfig::default();
        let mut cloned = config.clone();
        cloned.symbol_size = 2048;
        // Original should be unchanged
        assert_eq!(config.symbol_size, 1024);
        assert_eq!(cloned.symbol_size, 2048);
    }

    // ── Additional config edge cases ──────────────────────────────────────

    #[test]
    fn repair_symbols_exact_10000_bps_doubles_count() {
        let config = RaptorQConfig {
            repair_ratio_bps: 10000,
            ..RaptorQConfig::default()
        };
        assert_eq!(config.repair_symbols(50), 50);
        assert_eq!(config.repair_symbols(1), 1);
    }

    #[test]
    fn repair_symbols_50_percent_overhead() {
        let config = RaptorQConfig {
            repair_ratio_bps: 5000,
            ..RaptorQConfig::default()
        };
        assert_eq!(config.repair_symbols(200), 100);
    }

    #[test]
    fn source_symbols_large_payload() {
        let config = RaptorQConfig::default(); // symbol_size = 1024
        // 1MB -> 1024 source symbols
        assert_eq!(config.source_symbols(1024 * 1024), 1024);
    }

    #[test]
    fn total_symbols_with_zero_repair() {
        let config = RaptorQConfig {
            repair_ratio_bps: 0,
            ..RaptorQConfig::default()
        };
        assert_eq!(config.total_symbols(10240), 10);
    }

    #[test]
    fn chunk_count_exact_multiple() {
        let config = RaptorQConfig {
            chunk_size: 100,
            ..RaptorQConfig::default()
        };
        assert_eq!(config.chunk_count(500), 5);
        assert_eq!(config.chunk_count(501), 6);
    }

    #[test]
    fn mtu_safe_symbol_size_three_symbols_per_frame() {
        let safe = RaptorQConfig::mtu_safe_symbol_size(1200, 3);
        // (1200 - 114) / 3 = 362, minus 22 = 340
        assert_eq!(safe, Some(340));
    }

    #[test]
    fn from_preset_preferred_equals_mtu_safe() {
        // When preferred exactly equals MTU-safe, it should use it
        let mtu_safe = RaptorQConfig::mtu_safe_symbol_size(1200, 1).unwrap();
        let preset = RaptorQPreset {
            profile: RaptorQPathProfile::Lan,
            max_datagram_bytes: 1200,
            symbols_per_frame: 1,
            preferred_symbol_size: mtu_safe,
            repair_ratio_bps: 500,
        };
        let config = RaptorQConfig::from_preset(preset).unwrap();
        assert_eq!(config.symbol_size, mtu_safe);
    }

    #[test]
    fn bound_symbol_size_mutates_config() {
        let mut config = RaptorQConfig {
            symbol_size: 5000,
            ..Default::default()
        };
        let before = config.symbol_size;
        config.bound_symbol_size(1200, 1).unwrap();
        assert!(config.symbol_size < before);
        assert_eq!(config.symbol_size, 1064);
    }

    #[test]
    fn requires_chunking_custom_threshold() {
        let config = RaptorQConfig {
            max_chunk_threshold: 50,
            ..RaptorQConfig::default()
        };
        assert!(!config.requires_chunking(50));
        assert!(config.requires_chunking(51));
        assert!(!config.requires_chunking(0));
    }

    #[test]
    fn config_serde_preserves_all_custom_fields() {
        let config = RaptorQConfig {
            symbol_size: 512,
            repair_ratio_bps: 750,
            max_object_size: 32 * 1024 * 1024,
            decode_timeout: Duration::from_secs(15),
            max_chunk_threshold: 128 * 1024,
            chunk_size: 32 * 1024,
        };
        let json = serde_json::to_string(&config).unwrap();
        let d: RaptorQConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(d.symbol_size, 512);
        assert_eq!(d.repair_ratio_bps, 750);
        assert_eq!(d.max_object_size, 32 * 1024 * 1024);
        assert_eq!(d.decode_timeout, Duration::from_secs(15));
        assert_eq!(d.max_chunk_threshold, 128 * 1024);
        assert_eq!(d.chunk_size, 32 * 1024);
    }

    #[test]
    fn preset_derp_serde_roundtrip() {
        let preset = RaptorQPreset::derp();
        let json = serde_json::to_string(&preset).unwrap();
        let d: RaptorQPreset = serde_json::from_str(&json).unwrap();
        assert_eq!(d.profile, RaptorQPathProfile::Derp);
        assert_eq!(d.max_datagram_bytes, preset.max_datagram_bytes);
    }

    #[test]
    fn path_profile_serde_from_string() {
        let json = "\"Lan\"";
        let p: RaptorQPathProfile = serde_json::from_str(json).unwrap();
        assert_eq!(p, RaptorQPathProfile::Lan);

        let json = "\"Derp\"";
        let p: RaptorQPathProfile = serde_json::from_str(json).unwrap();
        assert_eq!(p, RaptorQPathProfile::Derp);
    }

    #[test]
    fn path_profile_invalid_serde_fails() {
        let json = "\"Unknown\"";
        let result = serde_json::from_str::<RaptorQPathProfile>(json);
        assert!(result.is_err());
    }

    // ── Additional config tests (batch 2) ─────────────────────────────────

    #[test]
    fn repair_symbols_with_250_bps() {
        let config = RaptorQConfig {
            repair_ratio_bps: 250,
            ..RaptorQConfig::default()
        };
        // 250 bps = 2.5% overhead
        // 1000 source -> 1000 * 250 / 10000 = 25 repair
        assert_eq!(config.repair_symbols(1000), 25);
        // 40 source -> 40 * 250 / 10000 = 1 repair
        assert_eq!(config.repair_symbols(40), 1);
    }

    #[test]
    fn source_symbols_max_symbol_size() {
        let config = RaptorQConfig {
            symbol_size: u16::MAX,
            ..RaptorQConfig::default()
        };
        // 65535 bytes -> 1 source symbol
        assert_eq!(config.source_symbols(65535), 1);
        // 65536 bytes -> 2 source symbols
        assert_eq!(config.source_symbols(65536), 2);
    }

    #[test]
    fn total_symbols_large_repair_ratio() {
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 5000, // 50%
            ..RaptorQConfig::default()
        };
        // 640 bytes = 10 source symbols, 50% repair = 5
        assert_eq!(config.total_symbols(640), 15);
    }

    #[test]
    fn chunk_count_very_large_payload() {
        let config = RaptorQConfig {
            chunk_size: 1024,
            ..RaptorQConfig::default()
        };
        // 1MB / 1KB = 1024 chunks
        assert_eq!(config.chunk_count(1024 * 1024), 1024);
    }

    #[test]
    fn mtu_safe_symbol_size_minimum_viable() {
        // Minimum viable: header(114) + overhead(22) + 2 = 138
        let safe = RaptorQConfig::mtu_safe_symbol_size(138, 1);
        assert_eq!(safe, Some(2));
    }

    #[test]
    fn from_preset_uses_default_non_symbol_fields() {
        let preset = RaptorQPreset::lan();
        let config = RaptorQConfig::from_preset(preset).unwrap();
        // Non-symbol fields should be defaults
        assert_eq!(config.max_object_size, 64 * 1024 * 1024);
        assert_eq!(config.decode_timeout, Duration::from_secs(30));
        assert_eq!(config.max_chunk_threshold, 256 * 1024);
        assert_eq!(config.chunk_size, 64 * 1024);
    }

    #[test]
    fn bound_symbol_size_does_not_increase() {
        let mut config = RaptorQConfig {
            symbol_size: 500,
            ..Default::default()
        };
        // MTU-safe limit is 1064 for (1200, 1)
        let adjusted = config.bound_symbol_size(1200, 1).unwrap();
        // Should stay at 500 since it's below the limit
        assert_eq!(adjusted, 500);
        assert_eq!(config.symbol_size, 500);
    }

    #[test]
    fn config_serde_decode_timeout_zero() {
        let json = r#"{"symbol_size":1024,"repair_ratio_bps":500,"max_object_size":67108864,"decode_timeout":0,"max_chunk_threshold":262144,"chunk_size":65536}"#;
        let config: RaptorQConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.decode_timeout, Duration::from_secs(0));
    }

    #[test]
    fn preset_lan_and_derp_have_same_defaults() {
        let lan = RaptorQPreset::lan();
        let derp = RaptorQPreset::derp();
        assert_eq!(lan.max_datagram_bytes, derp.max_datagram_bytes);
        assert_eq!(lan.symbols_per_frame, derp.symbols_per_frame);
        assert_eq!(lan.preferred_symbol_size, derp.preferred_symbol_size);
        assert_eq!(lan.repair_ratio_bps, derp.repair_ratio_bps);
        // Only profile differs
        assert_ne!(lan.profile, derp.profile);
    }

    #[test]
    fn config_requires_chunking_with_zero_threshold() {
        let config = RaptorQConfig {
            max_chunk_threshold: 0,
            ..RaptorQConfig::default()
        };
        // Anything above 0 requires chunking
        assert!(config.requires_chunking(1));
        assert!(!config.requires_chunking(0));
    }

    #[test]
    fn config_chunk_count_with_large_chunk_size() {
        let config = RaptorQConfig {
            chunk_size: u32::MAX,
            ..RaptorQConfig::default()
        };
        // 100 bytes with enormous chunk size -> 1 chunk
        assert_eq!(config.chunk_count(100), 1);
    }

    #[test]
    fn mtu_safe_symbol_size_with_header_exactly() {
        // max_datagram = header only (114) -> no room for anything
        assert!(RaptorQConfig::mtu_safe_symbol_size(114, 1).is_none());
    }

    #[test]
    fn preset_debug_contains_profile() {
        let derp = RaptorQPreset::derp();
        let debug = format!("{derp:?}");
        assert!(debug.contains("Derp"));
        assert!(debug.contains("1200"));
    }

    #[test]
    fn config_serde_roundtrip_with_zero_repair() {
        let config = RaptorQConfig {
            repair_ratio_bps: 0,
            ..RaptorQConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let d: RaptorQConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(d.repair_ratio_bps, 0);
        assert_eq!(d.repair_symbols(1000), 0);
    }

    #[test]
    fn mtu_safe_symbol_size_four_symbols_per_frame() {
        let safe = RaptorQConfig::mtu_safe_symbol_size(1200, 4);
        // (1200 - 114) / 4 = 271, minus 22 = 249
        assert_eq!(safe, Some(249));
    }
}
