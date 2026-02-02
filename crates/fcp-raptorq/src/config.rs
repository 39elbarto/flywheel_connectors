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
        payload_len.div_ceil(usize::from(self.symbol_size)) as u32
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
}
