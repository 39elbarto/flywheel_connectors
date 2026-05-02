//! Device profile types for execution planning and capability reporting.
//!
//! This module implements the `DeviceProfile` schema (NORMATIVE) used by the
//! execution planner to make device-aware routing and execution decisions.
//!
//! # Overview
//!
//! - [`DeviceProfile`] - Complete device capability snapshot
//! - [`GpuProfile`] - GPU hardware capabilities
//! - [`TpuProfile`] - TPU hardware capabilities
//! - [`InstalledConnector`] - Connector installation info
//! - [`FitnessScore`] - Execution fitness calculation
//!
//! # Example
//!
//! ```rust
//! use fcp_mesh::device::{DeviceProfile, CpuArch, PowerSource, LatencyClass, AvailabilityProfile};
//! use fcp_tailscale::NodeId;
//!
//! let profile = DeviceProfile::builder(NodeId::new("node-12345"))
//!     .cpu_cores(8)
//!     .cpu_arch(CpuArch::X86_64)
//!     .memory_mb(16384)
//!     .power_source(PowerSource::Mains)
//!     .latency_class(LatencyClass::Lan)
//!     .availability(AvailabilityProfile::AlwaysOn)
//!     .build();
//!
//! assert_eq!(profile.cpu_cores, 8);
//! ```

#[cfg(test)]
use fcp_prelude::CapabilityId;
use fcp_prelude::{CapabilityGrant, ConnectorId, ObjectId};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};

/// Current schema version for `DeviceProfile`.
pub const DEVICE_PROFILE_VERSION: u32 = 1;

/// Default periodic refresh interval in seconds (5 minutes).
pub const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 300;

// ============================================================================
// Enums
// ============================================================================

/// CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CpuArch {
    /// x86-64 (AMD64)
    #[cfg_attr(
        any(
            target_arch = "x86_64",
            not(any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "wasm32",
                target_arch = "riscv64"
            ))
        ),
        default
    )]
    X86_64,
    /// ARM 64-bit (`AArch64`)
    #[cfg_attr(target_arch = "aarch64", default)]
    Aarch64,
    /// WebAssembly 32-bit
    #[cfg_attr(target_arch = "wasm32", default)]
    Wasm32,
    /// RISC-V 64-bit
    #[cfg_attr(target_arch = "riscv64", default)]
    Riscv64,
}

/// Power source type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerSource {
    /// Connected to mains power
    Mains,
    /// Running on battery
    Battery,
    /// Solar powered
    Solar,
    /// Unknown power source
    #[default]
    Unknown,
}

/// Network latency class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    /// Local (same machine)
    Local,
    /// LAN (same network)
    Lan,
    /// Internet (direct connection)
    #[default]
    Internet,
    /// DERP relay (Tailscale fallback)
    Derp,
}

/// Device availability profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityProfile {
    /// Always online
    AlwaysOn,
    /// Available on schedule
    Scheduled,
    /// Best effort (may go offline)
    #[default]
    BestEffort,
}

/// GPU vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuVendor {
    /// NVIDIA
    Nvidia,
    /// AMD
    Amd,
    /// Apple Silicon
    Apple,
    /// Intel
    Intel,
    /// Other vendor
    Other,
}

/// TPU vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TpuVendor {
    /// Google TPU
    Google,
    /// Other vendor
    Other,
}

// ============================================================================
// GPU/TPU Profiles
// ============================================================================

/// GPU hardware profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuProfile {
    /// GPU vendor
    pub vendor: GpuVendor,
    /// Model name (e.g., "RTX 4090", "M3 Max")
    pub model: String,
    /// Video RAM in megabytes
    pub vram_mb: u32,
    /// Compute capability (e.g., CUDA version "8.9")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_capability: Option<String>,
}

impl GpuProfile {
    /// Create a new GPU profile.
    #[must_use]
    pub fn new(vendor: GpuVendor, model: impl Into<String>, vram_mb: u32) -> Self {
        Self {
            vendor,
            model: model.into(),
            vram_mb,
            compute_capability: None,
        }
    }

    /// Set compute capability.
    #[must_use]
    pub fn with_compute_capability(mut self, capability: impl Into<String>) -> Self {
        self.compute_capability = Some(capability.into());
        self
    }
}

/// TPU hardware profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpuProfile {
    /// TPU vendor
    pub vendor: TpuVendor,
    /// Model name (e.g., "v4", "v5e")
    pub model: String,
    /// Number of cores
    pub cores: u32,
    /// HBM memory in megabytes
    pub hbm_mb: u32,
}

impl TpuProfile {
    /// Create a new TPU profile.
    #[must_use]
    pub fn new(vendor: TpuVendor, model: impl Into<String>, cores: u32, hbm_mb: u32) -> Self {
        Self {
            vendor,
            model: model.into(),
            cores,
            hbm_mb,
        }
    }
}

// ============================================================================
// Installed Connector
// ============================================================================

/// Installed connector information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledConnector {
    /// Connector identifier
    pub connector_id: ConnectorId,
    /// Semantic version string
    pub version: String,
    /// Binary content hash (`ObjectId`)
    pub binary_hash: ObjectId,
    /// Capabilities granted to this connector
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityGrant>,
}

impl InstalledConnector {
    /// Create a new installed connector entry.
    #[must_use]
    pub fn new(
        connector_id: ConnectorId,
        version: impl Into<String>,
        binary_hash: ObjectId,
    ) -> Self {
        Self {
            connector_id,
            version: version.into(),
            binary_hash,
            capabilities: Vec::new(),
        }
    }

    /// Add capabilities to this connector.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<CapabilityGrant>) -> Self {
        self.capabilities = capabilities;
        self
    }
}

// ============================================================================
// Device Profile
// ============================================================================

/// Complete device capability profile (NORMATIVE).
///
/// Published by nodes to the mesh for execution planning decisions.
/// Nodes MUST publish `DeviceProfile` on:
/// - Startup
/// - Significant capability change
/// - Connector install/remove
/// - Periodic refresh (every 5 minutes default)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// Tailscale node identifier
    pub node_id: NodeId,
    /// Schema version
    pub profile_version: u32,
    /// Profile creation timestamp (Unix millis)
    pub timestamp: u64,

    // Compute
    /// Number of CPU cores
    pub cpu_cores: u16,
    /// CPU architecture
    pub cpu_arch: CpuArch,
    /// System memory in megabytes
    pub memory_mb: u32,
    /// GPU capabilities (if present)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuProfile>,
    /// TPU capabilities (if present)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpu: Option<TpuProfile>,

    // Storage
    /// Local storage capacity in megabytes
    pub local_storage_mb: u64,
    /// Symbol store quota in megabytes
    pub symbol_store_quota_mb: u32,

    // Power
    /// Current power source
    pub power_source: PowerSource,
    /// Battery percentage (if on battery)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery_percent: Option<u8>,

    // Network
    /// Estimated bandwidth in kilobits per second
    pub bandwidth_estimate_kbps: u32,
    /// Network latency class
    pub latency_class: LatencyClass,
    /// Whether connection is metered
    #[serde(default)]
    pub metered: bool,

    // Availability
    /// Device availability profile
    pub availability: AvailabilityProfile,
    /// Next expected downtime (Unix millis)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_expected_downtime: Option<u64>,

    // Connectors
    /// Installed connectors
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connectors: Vec<InstalledConnector>,
}

impl DeviceProfile {
    /// Create a new profile builder.
    #[must_use]
    pub fn builder(node_id: NodeId) -> DeviceProfileBuilder {
        DeviceProfileBuilder::new(node_id)
    }

    /// Check if the profile has GPU capabilities.
    #[must_use]
    pub const fn has_gpu(&self) -> bool {
        self.gpu.is_some()
    }

    /// Check if the profile has TPU capabilities.
    #[must_use]
    pub const fn has_tpu(&self) -> bool {
        self.tpu.is_some()
    }

    /// Check if a specific connector is installed.
    #[must_use]
    pub fn has_connector(&self, connector_id: &ConnectorId) -> bool {
        self.connectors
            .iter()
            .any(|c| &c.connector_id == connector_id)
    }

    /// Get an installed connector by ID.
    #[must_use]
    pub fn get_connector(&self, connector_id: &ConnectorId) -> Option<&InstalledConnector> {
        self.connectors
            .iter()
            .find(|c| &c.connector_id == connector_id)
    }

    /// Check if device is on low battery (< 20%).
    #[must_use]
    pub fn is_low_battery(&self) -> bool {
        matches!(self.power_source, PowerSource::Battery)
            && self.battery_percent.is_some_and(|p| p < 20)
    }

    /// Compute execution fitness score for this device.
    #[must_use]
    pub fn compute_fitness(&self, ctx: &FitnessContext) -> FitnessScore {
        FitnessScore::compute(self, ctx)
    }
}

// ============================================================================
// Device Profile Builder
// ============================================================================

/// Builder for `DeviceProfile`.
#[derive(Debug)]
pub struct DeviceProfileBuilder {
    node_id: NodeId,
    profile_version: u32,
    timestamp: u64,
    cpu_cores: u16,
    cpu_arch: CpuArch,
    memory_mb: u32,
    gpu: Option<GpuProfile>,
    tpu: Option<TpuProfile>,
    local_storage_mb: u64,
    symbol_store_quota_mb: u32,
    power_source: PowerSource,
    battery_percent: Option<u8>,
    bandwidth_estimate_kbps: u32,
    latency_class: LatencyClass,
    metered: bool,
    availability: AvailabilityProfile,
    next_expected_downtime: Option<u64>,
    connectors: Vec<InstalledConnector>,
}

impl DeviceProfileBuilder {
    /// Create a new builder with the given node ID.
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // timestamp_millis() is always positive
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            profile_version: DEVICE_PROFILE_VERSION,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            cpu_cores: 1,
            cpu_arch: CpuArch::default(),
            memory_mb: 1024,
            gpu: None,
            tpu: None,
            local_storage_mb: 0,
            symbol_store_quota_mb: 0,
            power_source: PowerSource::default(),
            battery_percent: None,
            bandwidth_estimate_kbps: 1000,
            latency_class: LatencyClass::default(),
            metered: false,
            availability: AvailabilityProfile::default(),
            next_expected_downtime: None,
            connectors: Vec::new(),
        }
    }

    /// Set CPU core count.
    #[must_use]
    pub const fn cpu_cores(mut self, cores: u16) -> Self {
        self.cpu_cores = cores;
        self
    }

    /// Set CPU architecture.
    #[must_use]
    pub const fn cpu_arch(mut self, arch: CpuArch) -> Self {
        self.cpu_arch = arch;
        self
    }

    /// Set memory in megabytes.
    #[must_use]
    pub const fn memory_mb(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set GPU profile.
    #[must_use]
    pub fn gpu(mut self, gpu: GpuProfile) -> Self {
        self.gpu = Some(gpu);
        self
    }

    /// Set TPU profile.
    #[must_use]
    pub fn tpu(mut self, tpu: TpuProfile) -> Self {
        self.tpu = Some(tpu);
        self
    }

    /// Set local storage in megabytes.
    #[must_use]
    pub const fn local_storage_mb(mut self, mb: u64) -> Self {
        self.local_storage_mb = mb;
        self
    }

    /// Set symbol store quota in megabytes.
    #[must_use]
    pub const fn symbol_store_quota_mb(mut self, mb: u32) -> Self {
        self.symbol_store_quota_mb = mb;
        self
    }

    /// Set power source.
    #[must_use]
    pub const fn power_source(mut self, source: PowerSource) -> Self {
        self.power_source = source;
        self
    }

    /// Set battery percentage.
    #[must_use]
    pub const fn battery_percent(mut self, percent: u8) -> Self {
        self.battery_percent = Some(percent);
        self
    }

    /// Set bandwidth estimate in kbps.
    #[must_use]
    pub const fn bandwidth_estimate_kbps(mut self, kbps: u32) -> Self {
        self.bandwidth_estimate_kbps = kbps;
        self
    }

    /// Set latency class.
    #[must_use]
    pub const fn latency_class(mut self, class: LatencyClass) -> Self {
        self.latency_class = class;
        self
    }

    /// Set metered connection flag.
    #[must_use]
    pub const fn metered(mut self, metered: bool) -> Self {
        self.metered = metered;
        self
    }

    /// Set availability profile.
    #[must_use]
    pub const fn availability(mut self, availability: AvailabilityProfile) -> Self {
        self.availability = availability;
        self
    }

    /// Set next expected downtime.
    #[must_use]
    pub const fn next_expected_downtime(mut self, timestamp: u64) -> Self {
        self.next_expected_downtime = Some(timestamp);
        self
    }

    /// Set timestamp.
    #[must_use]
    pub const fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Add an installed connector.
    #[must_use]
    pub fn add_connector(mut self, connector: InstalledConnector) -> Self {
        self.connectors.push(connector);
        self
    }

    /// Build the `DeviceProfile`.
    #[must_use]
    pub fn build(self) -> DeviceProfile {
        DeviceProfile {
            node_id: self.node_id,
            profile_version: self.profile_version,
            timestamp: self.timestamp,
            cpu_cores: self.cpu_cores,
            cpu_arch: self.cpu_arch,
            memory_mb: self.memory_mb,
            gpu: self.gpu,
            tpu: self.tpu,
            local_storage_mb: self.local_storage_mb,
            symbol_store_quota_mb: self.symbol_store_quota_mb,
            power_source: self.power_source,
            battery_percent: self.battery_percent,
            bandwidth_estimate_kbps: self.bandwidth_estimate_kbps,
            latency_class: self.latency_class,
            metered: self.metered,
            availability: self.availability,
            next_expected_downtime: self.next_expected_downtime,
            connectors: self.connectors,
        }
    }
}

// ============================================================================
// Fitness Scoring
// ============================================================================

/// Context for fitness score computation.
#[derive(Debug, Clone, Default)]
pub struct FitnessContext {
    /// Whether required symbols are already present locally
    pub symbols_present: bool,
    /// Whether GPU is required for the operation
    pub requires_gpu: bool,
    /// Whether TPU is required for the operation
    pub requires_tpu: bool,
    /// Minimum memory required (MB)
    pub min_memory_mb: Option<u32>,
    /// Required connector ID
    pub required_connector: Option<ConnectorId>,
}

impl FitnessContext {
    /// Create an empty fitness context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set symbols present flag.
    #[must_use]
    pub const fn with_symbols_present(mut self, present: bool) -> Self {
        self.symbols_present = present;
        self
    }

    /// Set GPU requirement.
    #[must_use]
    pub const fn with_requires_gpu(mut self, required: bool) -> Self {
        self.requires_gpu = required;
        self
    }

    /// Set TPU requirement.
    #[must_use]
    pub const fn with_requires_tpu(mut self, required: bool) -> Self {
        self.requires_tpu = required;
        self
    }

    /// Set minimum memory requirement.
    #[must_use]
    pub const fn with_min_memory_mb(mut self, mb: u32) -> Self {
        self.min_memory_mb = Some(mb);
        self
    }

    /// Set required connector.
    #[must_use]
    pub fn with_required_connector(mut self, connector_id: ConnectorId) -> Self {
        self.required_connector = Some(connector_id);
        self
    }
}

/// Execution fitness score.
///
/// Higher scores indicate better fitness for execution.
/// A score of 0 means the device cannot execute the operation.
#[derive(Debug, Clone, Copy)]
pub struct FitnessScore {
    /// The computed score (0.0 = cannot execute, higher = better)
    pub score: f64,
    /// Whether the device meets minimum requirements
    pub eligible: bool,
}

impl FitnessScore {
    /// Base score for eligible devices.
    const BASE_SCORE: f64 = 100.0;
    /// Penalty for using DERP relay.
    const DERP_PENALTY: f64 = 30.0;
    /// Bonus for local symbols.
    const LOCALITY_BONUS: f64 = 25.0;
    /// Penalty for low battery (< 20%).
    const LOW_BATTERY_PENALTY: f64 = 40.0;
    /// Bonus for having required GPU.
    const GPU_BONUS: f64 = 20.0;
    /// Bonus for having required TPU.
    const TPU_BONUS: f64 = 20.0;
    /// Penalty per latency class step.
    const LATENCY_PENALTY_PER_CLASS: f64 = 10.0;
    /// Penalty for metered connection.
    const METERED_PENALTY: f64 = 15.0;
    /// Penalty for best-effort availability.
    const BEST_EFFORT_PENALTY: f64 = 10.0;

    /// Create an ineligible score.
    #[must_use]
    pub const fn ineligible() -> Self {
        Self {
            score: 0.0,
            eligible: false,
        }
    }

    /// Compute fitness score for a device profile.
    #[must_use]
    pub fn compute(profile: &DeviceProfile, ctx: &FitnessContext) -> Self {
        // Check minimum requirements
        if ctx.requires_gpu && !profile.has_gpu() {
            return Self::ineligible();
        }
        if ctx.requires_tpu && !profile.has_tpu() {
            return Self::ineligible();
        }
        if let Some(min_mem) = ctx.min_memory_mb {
            if profile.memory_mb < min_mem {
                return Self::ineligible();
            }
        }
        if let Some(ref connector_id) = ctx.required_connector {
            if !profile.has_connector(connector_id) {
                return Self::ineligible();
            }
        }

        // Start with base score
        let mut score = Self::BASE_SCORE;

        // DERP penalty
        if profile.latency_class == LatencyClass::Derp {
            score -= Self::DERP_PENALTY;
        }

        // Locality bonus
        if ctx.symbols_present {
            score += Self::LOCALITY_BONUS;
        }

        // Battery penalty
        if profile.is_low_battery() {
            score -= Self::LOW_BATTERY_PENALTY;
        }

        // Capability bonuses
        if ctx.requires_gpu && profile.has_gpu() {
            score += Self::GPU_BONUS;
        }
        if ctx.requires_tpu && profile.has_tpu() {
            score += Self::TPU_BONUS;
        }

        // Latency penalty (0 for Local, increasing for each class)
        let latency_penalty = match profile.latency_class {
            LatencyClass::Local => 0.0,
            LatencyClass::Lan => Self::LATENCY_PENALTY_PER_CLASS,
            LatencyClass::Internet => Self::LATENCY_PENALTY_PER_CLASS * 2.0,
            LatencyClass::Derp => Self::LATENCY_PENALTY_PER_CLASS * 3.0,
        };
        score -= latency_penalty;

        // Metered connection penalty
        if profile.metered {
            score -= Self::METERED_PENALTY;
        }

        // Availability penalty
        if profile.availability == AvailabilityProfile::BestEffort {
            score -= Self::BEST_EFFORT_PENALTY;
        }

        Self {
            score: score.max(0.0),
            eligible: true,
        }
    }
}

impl PartialEq for FitnessScore {
    fn eq(&self, other: &Self) -> bool {
        self.eligible == other.eligible && self.score == other.score
    }
}

impl Eq for FitnessScore {}

impl PartialOrd for FitnessScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FitnessScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Eligible devices always rank higher than ineligible
        match (self.eligible, other.eligible) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => self
                .score
                .partial_cmp(&other.score)
                .unwrap_or(std::cmp::Ordering::Equal),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        NodeId::new("test-node-12345")
    }

    #[test]
    fn test_device_profile_builder() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .cpu_arch(CpuArch::X86_64)
            .memory_mb(16384)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Lan)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(1000)
            .build();

        assert_eq!(profile.node_id.as_str(), "test-node-12345");
        assert_eq!(profile.cpu_cores, 8);
        assert_eq!(profile.cpu_arch, CpuArch::X86_64);
        assert_eq!(profile.memory_mb, 16384);
        assert_eq!(profile.power_source, PowerSource::Mains);
        assert_eq!(profile.latency_class, LatencyClass::Lan);
        assert_eq!(profile.availability, AvailabilityProfile::AlwaysOn);
        assert_eq!(profile.profile_version, DEVICE_PROFILE_VERSION);
    }

    #[test]
    fn test_device_profile_with_gpu() {
        let gpu =
            GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576).with_compute_capability("8.9");

        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(16)
            .memory_mb(65536)
            .gpu(gpu)
            .build();

        assert!(profile.has_gpu());
        assert!(!profile.has_tpu());

        let gpu = profile.gpu.as_ref().unwrap();
        assert_eq!(gpu.vendor, GpuVendor::Nvidia);
        assert_eq!(gpu.model, "RTX 4090");
        assert_eq!(gpu.vram_mb, 24576);
        assert_eq!(gpu.compute_capability.as_deref(), Some("8.9"));
    }

    #[test]
    fn test_device_profile_with_tpu() {
        let tpu = TpuProfile::new(TpuVendor::Google, "v4", 4, 32768);

        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(96)
            .memory_mb(262_144)
            .tpu(tpu)
            .build();

        assert!(!profile.has_gpu());
        assert!(profile.has_tpu());

        let tpu = profile.tpu.as_ref().unwrap();
        assert_eq!(tpu.vendor, TpuVendor::Google);
        assert_eq!(tpu.model, "v4");
        assert_eq!(tpu.cores, 4);
        assert_eq!(tpu.hbm_mb, 32768);
    }

    #[test]
    fn test_low_battery_detection() {
        let profile_mains = DeviceProfile::builder(test_node_id())
            .power_source(PowerSource::Mains)
            .build();
        assert!(!profile_mains.is_low_battery());

        let profile_battery_ok = DeviceProfile::builder(test_node_id())
            .power_source(PowerSource::Battery)
            .battery_percent(50)
            .build();
        assert!(!profile_battery_ok.is_low_battery());

        let profile_battery_low = DeviceProfile::builder(test_node_id())
            .power_source(PowerSource::Battery)
            .battery_percent(15)
            .build();
        assert!(profile_battery_low.is_low_battery());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let gpu = GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576);
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .cpu_arch(CpuArch::X86_64)
            .memory_mb(16384)
            .gpu(gpu)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Lan)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(1_705_000_000_000)
            .build();

        // JSON roundtrip
        let json = serde_json::to_string(&profile).unwrap();
        let decoded: DeviceProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, decoded);
    }

    #[test]
    fn test_fitness_score_basic() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .build();

        let ctx = FitnessContext::new();
        let score = profile.compute_fitness(&ctx);

        assert!(score.eligible);
        assert!((score.score - FitnessScore::BASE_SCORE).abs() < 1e-9);
    }

    #[test]
    fn test_fitness_score_with_locality_bonus() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .latency_class(LatencyClass::Local)
            .build();

        let ctx = FitnessContext::new().with_symbols_present(true);
        let score = profile.compute_fitness(&ctx);

        assert!(score.eligible);
        assert!(score.score > FitnessScore::BASE_SCORE);
    }

    #[test]
    fn test_fitness_score_derp_penalty() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .latency_class(LatencyClass::Derp)
            .build();

        let ctx = FitnessContext::new();
        let score = profile.compute_fitness(&ctx);

        assert!(score.eligible);
        // DERP has both DERP_PENALTY and 3x LATENCY_PENALTY_PER_CLASS
        assert!(score.score < FitnessScore::BASE_SCORE);
    }

    #[test]
    fn test_fitness_score_low_battery_penalty() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .power_source(PowerSource::Battery)
            .battery_percent(10)
            .latency_class(LatencyClass::Local)
            .build();

        let ctx = FitnessContext::new();
        let score = profile.compute_fitness(&ctx);

        assert!(score.eligible);
        assert!(score.score < FitnessScore::BASE_SCORE);
    }

    #[test]
    fn test_fitness_score_gpu_requirement() {
        let profile_no_gpu = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .build();

        let profile_with_gpu = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .gpu(GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576))
            .build();

        let ctx = FitnessContext::new().with_requires_gpu(true);

        let score_no_gpu = profile_no_gpu.compute_fitness(&ctx);
        let score_with_gpu = profile_with_gpu.compute_fitness(&ctx);

        assert!(!score_no_gpu.eligible);
        assert!(score_with_gpu.eligible);
        assert!(score_with_gpu.score > 0.0);
    }

    #[test]
    fn test_fitness_score_memory_requirement() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(8192)
            .build();

        let ctx_ok = FitnessContext::new().with_min_memory_mb(4096);
        let ctx_fail = FitnessContext::new().with_min_memory_mb(16384);

        let score_ok = profile.compute_fitness(&ctx_ok);
        let score_fail = profile.compute_fitness(&ctx_fail);

        assert!(score_ok.eligible);
        assert!(!score_fail.eligible);
    }

    #[test]
    fn test_fitness_score_ordering() {
        let profile_good = DeviceProfile::builder(test_node_id())
            .cpu_cores(16)
            .memory_mb(32768)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .build();

        let profile_bad = DeviceProfile::builder(test_node_id())
            .cpu_cores(4)
            .memory_mb(8192)
            .power_source(PowerSource::Battery)
            .battery_percent(10)
            .latency_class(LatencyClass::Derp)
            .availability(AvailabilityProfile::BestEffort)
            .metered(true)
            .build();

        let ctx = FitnessContext::new();
        let score_good = profile_good.compute_fitness(&ctx);
        let score_bad = profile_bad.compute_fitness(&ctx);

        // Both eligible but good should score higher
        assert!(score_good.eligible);
        assert!(score_bad.eligible);
        assert!(score_good > score_bad);
    }

    #[test]
    fn test_fitness_score_deterministic() {
        let profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(8)
            .memory_mb(16384)
            .latency_class(LatencyClass::Lan)
            .timestamp(1000)
            .build();

        let ctx = FitnessContext::new().with_symbols_present(true);

        // Compute multiple times
        let score1 = profile.compute_fitness(&ctx);
        let score2 = profile.compute_fitness(&ctx);
        let score3 = profile.compute_fitness(&ctx);

        // Should be deterministic
        assert_eq!(score1, score2);
        assert_eq!(score2, score3);
    }

    #[test]
    fn test_cpu_arch_default() {
        let arch = CpuArch::default();
        // Should match current architecture
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, CpuArch::X86_64);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, CpuArch::Aarch64);
    }

    #[test]
    fn test_gpu_profile_builder() {
        let gpu =
            GpuProfile::new(GpuVendor::Apple, "M3 Max", 40960).with_compute_capability("Metal 3");

        assert_eq!(gpu.vendor, GpuVendor::Apple);
        assert_eq!(gpu.model, "M3 Max");
        assert_eq!(gpu.vram_mb, 40960);
        assert_eq!(gpu.compute_capability.as_deref(), Some("Metal 3"));
    }

    #[test]
    fn test_installed_connector() {
        let connector_id = ConnectorId::new("fcp", "test", "1.0.0").unwrap();
        let binary_hash = ObjectId::from_bytes([0u8; 32]);
        let connector = InstalledConnector::new(connector_id.clone(), "1.0.0", binary_hash);

        let profile = DeviceProfile::builder(test_node_id())
            .add_connector(connector)
            .build();

        assert!(profile.has_connector(&connector_id));
        assert!(profile.get_connector(&connector_id).is_some());

        let other_id = ConnectorId::new("fcp", "other", "1.0.0").unwrap();
        assert!(!profile.has_connector(&other_id));
    }

    // =========================================================================
    // Golden Vector Tests
    // =========================================================================

    #[test]
    fn golden_vector_device_profile_minimal_cbor() {
        // Minimal profile with deterministic inputs
        let profile = DeviceProfile::builder(NodeId::new("node-golden"))
            .cpu_cores(4)
            .cpu_arch(CpuArch::X86_64)
            .memory_mb(8192)
            .local_storage_mb(100_000)
            .symbol_store_quota_mb(1000)
            .power_source(PowerSource::Mains)
            .bandwidth_estimate_kbps(100_000)
            .latency_class(LatencyClass::Lan)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(1_705_000_000_000)
            .build();

        // CBOR roundtrip
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&profile, &mut cbor_bytes).unwrap();

        let decoded: DeviceProfile = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(
            profile, decoded,
            "CBOR roundtrip mismatch for minimal profile"
        );

        // Verify specific fields survived
        assert_eq!(decoded.node_id.as_str(), "node-golden");
        assert_eq!(decoded.cpu_cores, 4);
        assert_eq!(decoded.memory_mb, 8192);
        assert_eq!(decoded.timestamp, 1_705_000_000_000);
    }

    #[test]
    fn golden_vector_device_profile_full_cbor() {
        // Full profile with all optional fields
        let gpu =
            GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576).with_compute_capability("8.9");
        let tpu = TpuProfile::new(TpuVendor::Google, "v4", 4, 32768);
        let connector_id = ConnectorId::new("fcp", "anthropic", "1.0.0").unwrap();
        let connector =
            InstalledConnector::new(connector_id, "1.0.0", ObjectId::from_bytes([0xAAu8; 32]));

        let profile = DeviceProfile::builder(NodeId::new("node-full-golden"))
            .cpu_cores(64)
            .cpu_arch(CpuArch::Aarch64)
            .memory_mb(524_288)
            .gpu(gpu)
            .tpu(tpu)
            .local_storage_mb(10_000_000)
            .symbol_store_quota_mb(50_000)
            .power_source(PowerSource::Battery)
            .battery_percent(75)
            .bandwidth_estimate_kbps(1_000_000)
            .latency_class(LatencyClass::Local)
            .metered(false)
            .availability(AvailabilityProfile::Scheduled)
            .next_expected_downtime(1_705_100_000_000)
            .add_connector(connector)
            .timestamp(1_705_000_000_000)
            .build();

        // CBOR roundtrip
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&profile, &mut cbor_bytes).unwrap();

        let decoded: DeviceProfile = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(profile, decoded, "CBOR roundtrip mismatch for full profile");

        // Verify optional fields
        assert!(decoded.gpu.is_some());
        assert!(decoded.tpu.is_some());
        assert_eq!(decoded.battery_percent, Some(75));
        assert_eq!(decoded.next_expected_downtime, Some(1_705_100_000_000));
        assert_eq!(decoded.connectors.len(), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn golden_vector_fitness_calculation() {
        // Deterministic fitness calculation vectors
        struct FitnessVector {
            name: &'static str,
            profile_fn: fn() -> DeviceProfile,
            ctx_fn: fn() -> FitnessContext,
            expected_eligible: bool,
            expected_score: f64,
        }

        let vectors = [
            FitnessVector {
                name: "baseline_local",
                profile_fn: || {
                    DeviceProfile::builder(NodeId::new("v1"))
                        .cpu_cores(8)
                        .memory_mb(16384)
                        .latency_class(LatencyClass::Local)
                        .power_source(PowerSource::Mains)
                        .availability(AvailabilityProfile::AlwaysOn)
                        .timestamp(1000)
                        .build()
                },
                ctx_fn: FitnessContext::new,
                expected_eligible: true,
                expected_score: 100.0, // BASE_SCORE
            },
            FitnessVector {
                name: "derp_penalty",
                profile_fn: || {
                    DeviceProfile::builder(NodeId::new("v2"))
                        .cpu_cores(8)
                        .memory_mb(16384)
                        .latency_class(LatencyClass::Derp)
                        .power_source(PowerSource::Mains)
                        .availability(AvailabilityProfile::AlwaysOn)
                        .timestamp(1000)
                        .build()
                },
                ctx_fn: FitnessContext::new,
                expected_eligible: true,
                // BASE - DERP_PENALTY - 3*LATENCY_PENALTY = 100 - 30 - 30 = 40
                expected_score: 40.0,
            },
            FitnessVector {
                name: "low_battery",
                profile_fn: || {
                    DeviceProfile::builder(NodeId::new("v3"))
                        .cpu_cores(8)
                        .memory_mb(16384)
                        .latency_class(LatencyClass::Local)
                        .power_source(PowerSource::Battery)
                        .battery_percent(10)
                        .availability(AvailabilityProfile::AlwaysOn)
                        .timestamp(1000)
                        .build()
                },
                ctx_fn: FitnessContext::new,
                expected_eligible: true,
                // BASE - LOW_BATTERY_PENALTY = 100 - 40 = 60
                expected_score: 60.0,
            },
            FitnessVector {
                name: "locality_bonus",
                profile_fn: || {
                    DeviceProfile::builder(NodeId::new("v4"))
                        .cpu_cores(8)
                        .memory_mb(16384)
                        .latency_class(LatencyClass::Local)
                        .power_source(PowerSource::Mains)
                        .availability(AvailabilityProfile::AlwaysOn)
                        .timestamp(1000)
                        .build()
                },
                ctx_fn: || FitnessContext::new().with_symbols_present(true),
                expected_eligible: true,
                // BASE + LOCALITY_BONUS = 100 + 25 = 125
                expected_score: 125.0,
            },
            FitnessVector {
                name: "missing_gpu",
                profile_fn: || {
                    DeviceProfile::builder(NodeId::new("v5"))
                        .cpu_cores(8)
                        .memory_mb(16384)
                        .timestamp(1000)
                        .build()
                },
                ctx_fn: || FitnessContext::new().with_requires_gpu(true),
                expected_eligible: false,
                expected_score: 0.0,
            },
            FitnessVector {
                name: "insufficient_memory",
                profile_fn: || {
                    DeviceProfile::builder(NodeId::new("v6"))
                        .cpu_cores(8)
                        .memory_mb(4096)
                        .timestamp(1000)
                        .build()
                },
                ctx_fn: || FitnessContext::new().with_min_memory_mb(8192),
                expected_eligible: false,
                expected_score: 0.0,
            },
        ];

        for v in vectors {
            let profile = (v.profile_fn)();
            let ctx = (v.ctx_fn)();
            let score = profile.compute_fitness(&ctx);

            assert_eq!(
                score.eligible, v.expected_eligible,
                "Eligibility mismatch for vector '{}'",
                v.name
            );
            assert!(
                (score.score - v.expected_score).abs() < 0.001,
                "Score mismatch for vector '{}': expected {}, got {}",
                v.name,
                v.expected_score,
                score.score
            );
        }
    }

    // =========================================================================
    // Capability Reporting Tests
    // =========================================================================

    #[test]
    fn test_capability_reporting_cpu() {
        for cores in [1u16, 4, 8, 16, 64, 128] {
            let profile = DeviceProfile::builder(test_node_id())
                .cpu_cores(cores)
                .build();
            assert_eq!(profile.cpu_cores, cores, "CPU cores mismatch for {cores}");
        }
    }

    #[test]
    fn test_capability_reporting_memory() {
        for mem_mb in [512u32, 1024, 4096, 16384, 65536, 262_144] {
            let profile = DeviceProfile::builder(test_node_id())
                .memory_mb(mem_mb)
                .build();
            assert_eq!(profile.memory_mb, mem_mb, "Memory mismatch for {mem_mb}");
        }
    }

    #[test]
    fn test_capability_reporting_storage() {
        let profile = DeviceProfile::builder(test_node_id())
            .local_storage_mb(1_000_000)
            .symbol_store_quota_mb(10_000)
            .build();

        assert_eq!(profile.local_storage_mb, 1_000_000);
        assert_eq!(profile.symbol_store_quota_mb, 10_000);
    }

    #[test]
    fn test_capability_reporting_network() {
        for (kbps, class) in [
            (1_000u32, LatencyClass::Derp),
            (10_000, LatencyClass::Internet),
            (100_000, LatencyClass::Lan),
            (1_000_000, LatencyClass::Local),
        ] {
            let profile = DeviceProfile::builder(test_node_id())
                .bandwidth_estimate_kbps(kbps)
                .latency_class(class)
                .build();

            assert_eq!(profile.bandwidth_estimate_kbps, kbps);
            assert_eq!(profile.latency_class, class);
        }
    }

    #[test]
    fn test_capability_reporting_power_states() {
        let tests = [
            (PowerSource::Mains, None, false),
            (PowerSource::Battery, Some(100u8), false),
            (PowerSource::Battery, Some(50), false),
            (PowerSource::Battery, Some(19), true),
            (PowerSource::Solar, None, false),
            (PowerSource::Unknown, None, false),
        ];

        for (source, battery, expected_low) in tests {
            let mut builder = DeviceProfile::builder(test_node_id()).power_source(source);
            if let Some(pct) = battery {
                builder = builder.battery_percent(pct);
            }
            let profile = builder.build();

            assert_eq!(profile.power_source, source);
            assert_eq!(profile.battery_percent, battery);
            assert_eq!(
                profile.is_low_battery(),
                expected_low,
                "Low battery mismatch for {source:?}/{battery:?}"
            );
        }
    }

    // =========================================================================
    // Resource Constraint Tests
    // =========================================================================

    #[test]
    fn test_constraint_cpu_bound() {
        // CPU-bound connectors should work regardless of memory
        let low_mem_profile = DeviceProfile::builder(test_node_id())
            .cpu_cores(16)
            .memory_mb(2048)
            .build();

        let ctx = FitnessContext::new(); // No memory requirement
        let score = low_mem_profile.compute_fitness(&ctx);
        assert!(score.eligible);
    }

    #[test]
    fn test_constraint_memory_bound() {
        // Memory-bound connectors require minimum memory
        let ctx = FitnessContext::new().with_min_memory_mb(32768);

        let small = DeviceProfile::builder(test_node_id())
            .memory_mb(16384)
            .build();
        let large = DeviceProfile::builder(test_node_id())
            .memory_mb(65536)
            .build();

        assert!(!small.compute_fitness(&ctx).eligible);
        assert!(large.compute_fitness(&ctx).eligible);
    }

    #[test]
    fn test_constraint_gpu_requirement() {
        let ctx = FitnessContext::new().with_requires_gpu(true);

        let no_gpu = DeviceProfile::builder(test_node_id()).build();
        let with_gpu = DeviceProfile::builder(test_node_id())
            .gpu(GpuProfile::new(GpuVendor::Nvidia, "RTX 3080", 10240))
            .build();

        assert!(!no_gpu.compute_fitness(&ctx).eligible);
        assert!(with_gpu.compute_fitness(&ctx).eligible);
    }

    #[test]
    fn test_constraint_tpu_requirement() {
        let ctx = FitnessContext::new().with_requires_tpu(true);

        let no_tpu = DeviceProfile::builder(test_node_id()).build();
        let with_tpu = DeviceProfile::builder(test_node_id())
            .tpu(TpuProfile::new(TpuVendor::Google, "v4", 4, 32768))
            .build();

        assert!(!no_tpu.compute_fitness(&ctx).eligible);
        assert!(with_tpu.compute_fitness(&ctx).eligible);
    }

    #[test]
    fn test_constraint_connector_requirement() {
        let required_id = ConnectorId::new("fcp", "anthropic", "1.0.0").unwrap();
        let ctx = FitnessContext::new().with_required_connector(required_id.clone());

        let no_connector = DeviceProfile::builder(test_node_id()).build();
        let wrong_connector = DeviceProfile::builder(test_node_id())
            .add_connector(InstalledConnector::new(
                ConnectorId::new("fcp", "openai", "1.0.0").unwrap(),
                "1.0.0",
                ObjectId::from_bytes([0u8; 32]),
            ))
            .build();
        let correct_connector = DeviceProfile::builder(test_node_id())
            .add_connector(InstalledConnector::new(
                required_id,
                "1.0.0",
                ObjectId::from_bytes([0u8; 32]),
            ))
            .build();

        assert!(!no_connector.compute_fitness(&ctx).eligible);
        assert!(!wrong_connector.compute_fitness(&ctx).eligible);
        assert!(correct_connector.compute_fitness(&ctx).eligible);
    }

    #[test]
    fn test_constraint_combined() {
        // Require both GPU and minimum memory
        let ctx = FitnessContext::new()
            .with_requires_gpu(true)
            .with_min_memory_mb(32768);

        let tests = [
            ("no_gpu_no_mem", false, 16384, false),
            ("no_gpu_has_mem", false, 65536, false),
            ("has_gpu_no_mem", true, 16384, false),
            ("has_gpu_has_mem", true, 65536, true),
        ];

        for (name, has_gpu, mem_mb, expected_eligible) in tests {
            let mut builder = DeviceProfile::builder(test_node_id()).memory_mb(mem_mb);
            if has_gpu {
                builder = builder.gpu(GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576));
            }
            let profile = builder.build();
            let score = profile.compute_fitness(&ctx);

            assert_eq!(
                score.eligible, expected_eligible,
                "Combined constraint mismatch for '{name}'"
            );
        }
    }

    // =========================================================================
    // Fitness Ranking & Tie-breaking Tests
    // =========================================================================

    #[test]
    fn test_fitness_ranking_orders_devices_correctly() {
        let ctx = FitnessContext::new();

        // Create profiles with varying quality
        let profiles = [
            (
                "worst",
                DeviceProfile::builder(NodeId::new("worst"))
                    .latency_class(LatencyClass::Derp)
                    .power_source(PowerSource::Battery)
                    .battery_percent(10)
                    .availability(AvailabilityProfile::BestEffort)
                    .metered(true)
                    .timestamp(1000)
                    .build(),
            ),
            (
                "medium",
                DeviceProfile::builder(NodeId::new("medium"))
                    .latency_class(LatencyClass::Lan)
                    .power_source(PowerSource::Mains)
                    .availability(AvailabilityProfile::AlwaysOn)
                    .timestamp(1000)
                    .build(),
            ),
            (
                "best",
                DeviceProfile::builder(NodeId::new("best"))
                    .latency_class(LatencyClass::Local)
                    .power_source(PowerSource::Mains)
                    .availability(AvailabilityProfile::AlwaysOn)
                    .timestamp(1000)
                    .build(),
            ),
        ];

        let mut scores: Vec<_> = profiles
            .iter()
            .map(|(name, p)| (*name, p.compute_fitness(&ctx)))
            .collect();

        // Sort by score descending
        scores.sort_by_key(|score| std::cmp::Reverse(score.1));

        assert_eq!(scores[0].0, "best", "Best device should rank first");
        assert_eq!(scores[1].0, "medium", "Medium device should rank second");
        assert_eq!(scores[2].0, "worst", "Worst device should rank last");
    }

    #[test]
    fn test_fitness_tiebreaking_by_node_id() {
        let ctx = FitnessContext::new();

        // Create identical profiles with different node IDs
        let make_profile = |id: &str| {
            DeviceProfile::builder(NodeId::new(id))
                .cpu_cores(8)
                .memory_mb(16384)
                .latency_class(LatencyClass::Local)
                .power_source(PowerSource::Mains)
                .availability(AvailabilityProfile::AlwaysOn)
                .timestamp(1000)
                .build()
        };

        let profiles = [
            ("charlie", make_profile("charlie")),
            ("alice", make_profile("alice")),
            ("bob", make_profile("bob")),
        ];

        let scores: Vec<_> = profiles
            .iter()
            .map(|(name, p)| {
                (
                    *name,
                    p.compute_fitness(&ctx),
                    p.node_id.as_str().to_string(),
                )
            })
            .collect();

        // All scores should be equal
        assert!(
            scores.windows(2).all(|w| w[0].1 == w[1].1),
            "All fitness scores should be equal for tie-breaking test"
        );

        // When scores are equal, sort by node_id for determinism
        let mut sorted = scores.clone();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));

        // Node IDs should be in alphabetical order due to tie-breaking
        assert_eq!(sorted[0].0, "alice");
        assert_eq!(sorted[1].0, "bob");
        assert_eq!(sorted[2].0, "charlie");
    }

    #[test]
    fn test_fitness_eligible_always_ranks_above_ineligible() {
        let ctx = FitnessContext::new().with_requires_gpu(true);

        let ineligible = DeviceProfile::builder(NodeId::new("no-gpu"))
            .cpu_cores(128)
            .memory_mb(1_048_576)
            .latency_class(LatencyClass::Local)
            .timestamp(1000)
            .build();

        let eligible = DeviceProfile::builder(NodeId::new("has-gpu"))
            .cpu_cores(1)
            .memory_mb(512)
            .latency_class(LatencyClass::Derp)
            .power_source(PowerSource::Battery)
            .battery_percent(5)
            .gpu(GpuProfile::new(GpuVendor::Intel, "Arc A380", 6144))
            .timestamp(1000)
            .build();

        let score_ineligible = ineligible.compute_fitness(&ctx);
        let score_eligible = eligible.compute_fitness(&ctx);

        // Despite better specs, ineligible device ranks lower
        assert!(!score_ineligible.eligible);
        assert!(score_eligible.eligible);
        assert!(score_eligible > score_ineligible);
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_cbor_roundtrip_preserves_all_fields() {
        let connector = InstalledConnector::new(
            ConnectorId::new("fcp", "test", "2.0.0").unwrap(),
            "2.0.0",
            ObjectId::from_bytes([0x55u8; 32]),
        );

        let original = DeviceProfile::builder(NodeId::new("roundtrip-test"))
            .cpu_cores(32)
            .cpu_arch(CpuArch::Aarch64)
            .memory_mb(131_072)
            .gpu(
                GpuProfile::new(GpuVendor::Apple, "M3 Ultra", 192 * 1024)
                    .with_compute_capability("Metal 3"),
            )
            .tpu(TpuProfile::new(TpuVendor::Google, "v5e", 8, 65536))
            .local_storage_mb(2_000_000)
            .symbol_store_quota_mb(100_000)
            .power_source(PowerSource::Solar)
            .bandwidth_estimate_kbps(10_000_000)
            .latency_class(LatencyClass::Lan)
            .metered(true)
            .availability(AvailabilityProfile::Scheduled)
            .next_expected_downtime(1_800_000_000_000)
            .add_connector(connector)
            .timestamp(1_705_000_000_000)
            .build();

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&original, &mut cbor_bytes).unwrap();

        let decoded: DeviceProfile = ciborium::from_reader(&cbor_bytes[..]).unwrap();

        // Verify every field
        assert_eq!(original.node_id, decoded.node_id);
        assert_eq!(original.profile_version, decoded.profile_version);
        assert_eq!(original.timestamp, decoded.timestamp);
        assert_eq!(original.cpu_cores, decoded.cpu_cores);
        assert_eq!(original.cpu_arch, decoded.cpu_arch);
        assert_eq!(original.memory_mb, decoded.memory_mb);
        assert_eq!(original.gpu, decoded.gpu);
        assert_eq!(original.tpu, decoded.tpu);
        assert_eq!(original.local_storage_mb, decoded.local_storage_mb);
        assert_eq!(
            original.symbol_store_quota_mb,
            decoded.symbol_store_quota_mb
        );
        assert_eq!(original.power_source, decoded.power_source);
        assert_eq!(original.battery_percent, decoded.battery_percent);
        assert_eq!(
            original.bandwidth_estimate_kbps,
            decoded.bandwidth_estimate_kbps
        );
        assert_eq!(original.latency_class, decoded.latency_class);
        assert_eq!(original.metered, decoded.metered);
        assert_eq!(original.availability, decoded.availability);
        assert_eq!(
            original.next_expected_downtime,
            decoded.next_expected_downtime
        );
        assert_eq!(original.connectors, decoded.connectors);
    }

    #[test]
    fn test_json_roundtrip_preserves_all_fields() {
        let original = DeviceProfile::builder(NodeId::new("json-test"))
            .cpu_cores(16)
            .cpu_arch(CpuArch::X86_64)
            .memory_mb(32768)
            .gpu(GpuProfile::new(GpuVendor::Amd, "RX 7900 XTX", 24576))
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Internet)
            .availability(AvailabilityProfile::BestEffort)
            .timestamp(1_705_000_000_000)
            .build();

        let json = serde_json::to_string_pretty(&original).unwrap();
        let decoded: DeviceProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_enum_serialization_formats() {
        // Verify enums serialize to expected string formats
        let profile = DeviceProfile::builder(NodeId::new("enum-test"))
            .cpu_arch(CpuArch::Aarch64)
            .power_source(PowerSource::Battery)
            .latency_class(LatencyClass::Derp)
            .availability(AvailabilityProfile::Scheduled)
            .timestamp(1000)
            .build();

        let json = serde_json::to_string(&profile).unwrap();

        // Check snake_case serialization
        assert!(
            json.contains("\"aarch64\""),
            "CpuArch should serialize as snake_case"
        );
        assert!(
            json.contains("\"battery\""),
            "PowerSource should serialize as snake_case"
        );
        assert!(
            json.contains("\"derp\""),
            "LatencyClass should serialize as snake_case"
        );
        assert!(
            json.contains("\"scheduled\""),
            "AvailabilityProfile should serialize as snake_case"
        );
    }

    // ── Builder chain tests ──────────────────────────────────

    #[test]
    fn builder_cpu_cores() {
        let p = DeviceProfile::builder(NodeId::new("b1"))
            .cpu_cores(32)
            .timestamp(0)
            .build();
        assert_eq!(p.cpu_cores, 32);
    }

    #[test]
    fn builder_cpu_arch() {
        let p = DeviceProfile::builder(NodeId::new("b2"))
            .cpu_arch(CpuArch::Aarch64)
            .timestamp(0)
            .build();
        assert_eq!(p.cpu_arch, CpuArch::Aarch64);
    }

    #[test]
    fn builder_memory_mb() {
        let p = DeviceProfile::builder(NodeId::new("b3"))
            .memory_mb(65536)
            .timestamp(0)
            .build();
        assert_eq!(p.memory_mb, 65536);
    }

    #[test]
    fn builder_local_storage_mb() {
        let p = DeviceProfile::builder(NodeId::new("b4"))
            .local_storage_mb(500_000)
            .timestamp(0)
            .build();
        assert_eq!(p.local_storage_mb, 500_000);
    }

    #[test]
    fn builder_symbol_store_quota_mb() {
        let p = DeviceProfile::builder(NodeId::new("b5"))
            .symbol_store_quota_mb(4096)
            .timestamp(0)
            .build();
        assert_eq!(p.symbol_store_quota_mb, 4096);
    }

    #[test]
    fn builder_power_source() {
        let p = DeviceProfile::builder(NodeId::new("b6"))
            .power_source(PowerSource::Solar)
            .timestamp(0)
            .build();
        assert_eq!(p.power_source, PowerSource::Solar);
    }

    #[test]
    fn builder_battery_percent() {
        let p = DeviceProfile::builder(NodeId::new("b7"))
            .battery_percent(75)
            .timestamp(0)
            .build();
        assert_eq!(p.battery_percent, Some(75));
    }

    #[test]
    fn builder_bandwidth_estimate_kbps() {
        let p = DeviceProfile::builder(NodeId::new("b8"))
            .bandwidth_estimate_kbps(100_000)
            .timestamp(0)
            .build();
        assert_eq!(p.bandwidth_estimate_kbps, 100_000);
    }

    #[test]
    fn builder_latency_class() {
        let p = DeviceProfile::builder(NodeId::new("b9"))
            .latency_class(LatencyClass::Local)
            .timestamp(0)
            .build();
        assert_eq!(p.latency_class, LatencyClass::Local);
    }

    #[test]
    fn builder_metered() {
        let p = DeviceProfile::builder(NodeId::new("b10"))
            .metered(true)
            .timestamp(0)
            .build();
        assert!(p.metered);
    }

    #[test]
    fn builder_availability() {
        let p = DeviceProfile::builder(NodeId::new("b11"))
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(0)
            .build();
        assert_eq!(p.availability, AvailabilityProfile::AlwaysOn);
    }

    #[test]
    fn builder_next_expected_downtime() {
        let p = DeviceProfile::builder(NodeId::new("b12"))
            .next_expected_downtime(999_999)
            .timestamp(0)
            .build();
        assert_eq!(p.next_expected_downtime, Some(999_999));
    }

    #[test]
    fn builder_timestamp() {
        let p = DeviceProfile::builder(NodeId::new("b13"))
            .timestamp(42)
            .build();
        assert_eq!(p.timestamp, 42);
    }

    #[test]
    fn builder_add_connector() {
        let c = InstalledConnector::new(
            ConnectorId::from_static("test:connector:1.0.0"),
            "1.0.0",
            ObjectId::from_bytes([0xAA; 32]),
        );
        let p = DeviceProfile::builder(NodeId::new("b14"))
            .add_connector(c)
            .timestamp(0)
            .build();
        assert_eq!(p.connectors.len(), 1);
        assert_eq!(
            p.connectors[0].connector_id,
            ConnectorId::from_static("test:connector:1.0.0")
        );
    }

    #[test]
    fn builder_defaults() {
        let p = DeviceProfile::builder(NodeId::new("defaults"))
            .timestamp(0)
            .build();
        assert_eq!(p.cpu_cores, 1);
        assert_eq!(p.memory_mb, 1024);
        assert!(p.gpu.is_none());
        assert!(p.tpu.is_none());
        assert_eq!(p.local_storage_mb, 0);
        assert_eq!(p.symbol_store_quota_mb, 0);
        assert_eq!(p.power_source, PowerSource::Unknown);
        assert!(p.battery_percent.is_none());
        assert_eq!(p.bandwidth_estimate_kbps, 1000);
        assert!(!p.metered);
        assert!(p.next_expected_downtime.is_none());
        assert!(p.connectors.is_empty());
        assert_eq!(p.profile_version, DEVICE_PROFILE_VERSION);
    }

    #[test]
    fn builder_full_chain() {
        let gpu =
            GpuProfile::new(GpuVendor::Nvidia, "RTX 5090", 32768).with_compute_capability("10.0");
        let tpu = TpuProfile::new(TpuVendor::Google, "v5e", 8, 16384);
        let connector = InstalledConnector::new(
            ConnectorId::from_static("fcp:discord:2.0.0"),
            "2.0.0",
            ObjectId::from_bytes([0xBB; 32]),
        );

        let p = DeviceProfile::builder(NodeId::new("full"))
            .cpu_cores(64)
            .cpu_arch(CpuArch::X86_64)
            .memory_mb(131_072)
            .gpu(gpu)
            .tpu(tpu)
            .local_storage_mb(2_000_000)
            .symbol_store_quota_mb(8192)
            .power_source(PowerSource::Mains)
            .battery_percent(100)
            .bandwidth_estimate_kbps(1_000_000)
            .latency_class(LatencyClass::Lan)
            .metered(false)
            .availability(AvailabilityProfile::AlwaysOn)
            .next_expected_downtime(9_999_999)
            .timestamp(12345)
            .add_connector(connector)
            .build();

        assert_eq!(p.cpu_cores, 64);
        assert!(p.has_gpu());
        assert!(p.has_tpu());
        assert_eq!(p.connectors.len(), 1);
        assert_eq!(
            p.gpu.as_ref().unwrap().compute_capability.as_deref(),
            Some("10.0")
        );
    }

    // ── DeviceProfile query method tests ─────────────────────

    #[test]
    fn has_gpu_true_when_set() {
        let p = DeviceProfile::builder(NodeId::new("gpu"))
            .gpu(GpuProfile::new(GpuVendor::Apple, "M3 Max", 48000))
            .timestamp(0)
            .build();
        assert!(p.has_gpu());
    }

    #[test]
    fn has_gpu_false_when_not_set() {
        let p = DeviceProfile::builder(NodeId::new("nogpu"))
            .timestamp(0)
            .build();
        assert!(!p.has_gpu());
    }

    #[test]
    fn has_tpu_true_when_set() {
        let p = DeviceProfile::builder(NodeId::new("tpu"))
            .tpu(TpuProfile::new(TpuVendor::Google, "v4", 4, 8192))
            .timestamp(0)
            .build();
        assert!(p.has_tpu());
    }

    #[test]
    fn has_tpu_false_when_not_set() {
        let p = DeviceProfile::builder(NodeId::new("notpu"))
            .timestamp(0)
            .build();
        assert!(!p.has_tpu());
    }

    #[test]
    fn has_connector_finds_installed() {
        let cid = ConnectorId::from_static("fcp:slack:1.0.0");
        let c = InstalledConnector::new(cid.clone(), "1.0.0", ObjectId::from_bytes([0; 32]));
        let p = DeviceProfile::builder(NodeId::new("hc"))
            .add_connector(c)
            .timestamp(0)
            .build();
        assert!(p.has_connector(&cid));
    }

    #[test]
    fn has_connector_returns_false_when_missing() {
        let p = DeviceProfile::builder(NodeId::new("hc2"))
            .timestamp(0)
            .build();
        assert!(!p.has_connector(&ConnectorId::from_static("fcp:missing:1.0.0")));
    }

    #[test]
    fn get_connector_returns_some() {
        let cid = ConnectorId::from_static("fcp:github:1.0.0");
        let c = InstalledConnector::new(cid.clone(), "3.2.1", ObjectId::from_bytes([0x11; 32]));
        let p = DeviceProfile::builder(NodeId::new("gc"))
            .add_connector(c)
            .timestamp(0)
            .build();
        let found = p.get_connector(&cid).unwrap();
        assert_eq!(found.version, "3.2.1");
    }

    #[test]
    fn get_connector_returns_none_when_missing() {
        let p = DeviceProfile::builder(NodeId::new("gc2"))
            .timestamp(0)
            .build();
        assert!(
            p.get_connector(&ConnectorId::from_static("fcp:nope:1.0.0"))
                .is_none()
        );
    }

    #[test]
    fn is_low_battery_true() {
        let p = DeviceProfile::builder(NodeId::new("lb"))
            .power_source(PowerSource::Battery)
            .battery_percent(15)
            .timestamp(0)
            .build();
        assert!(p.is_low_battery());
    }

    #[test]
    fn is_low_battery_false_when_mains() {
        let p = DeviceProfile::builder(NodeId::new("lb2"))
            .power_source(PowerSource::Mains)
            .battery_percent(10)
            .timestamp(0)
            .build();
        assert!(!p.is_low_battery());
    }

    #[test]
    fn is_low_battery_false_when_above_threshold() {
        let p = DeviceProfile::builder(NodeId::new("lb3"))
            .power_source(PowerSource::Battery)
            .battery_percent(50)
            .timestamp(0)
            .build();
        assert!(!p.is_low_battery());
    }

    #[test]
    fn is_low_battery_false_when_no_battery_percent() {
        let p = DeviceProfile::builder(NodeId::new("lb4"))
            .power_source(PowerSource::Battery)
            .timestamp(0)
            .build();
        assert!(!p.is_low_battery());
    }

    // ── FitnessScore computation tests ───────────────────────

    #[test]
    fn fitness_ineligible_no_gpu() {
        let p = DeviceProfile::builder(NodeId::new("f1"))
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new().with_requires_gpu(true);
        let score = p.compute_fitness(&ctx);
        assert!(!score.eligible);
        assert!(score.score.abs() < f64::EPSILON);
    }

    #[test]
    fn fitness_ineligible_no_tpu() {
        let p = DeviceProfile::builder(NodeId::new("f2"))
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new().with_requires_tpu(true);
        let score = p.compute_fitness(&ctx);
        assert!(!score.eligible);
    }

    #[test]
    fn fitness_ineligible_low_memory() {
        let p = DeviceProfile::builder(NodeId::new("f3"))
            .memory_mb(512)
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new().with_min_memory_mb(1024);
        let score = p.compute_fitness(&ctx);
        assert!(!score.eligible);
    }

    #[test]
    fn fitness_ineligible_missing_connector() {
        let p = DeviceProfile::builder(NodeId::new("f4"))
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new()
            .with_required_connector(ConnectorId::from_static("fcp:missing:1.0.0"));
        let score = p.compute_fitness(&ctx);
        assert!(!score.eligible);
    }

    #[test]
    fn fitness_eligible_basic() {
        let p = DeviceProfile::builder(NodeId::new("f5"))
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new();
        let score = p.compute_fitness(&ctx);
        assert!(score.eligible);
        assert!(score.score > 0.0);
    }

    #[test]
    fn fitness_locality_bonus() {
        let p = DeviceProfile::builder(NodeId::new("f6"))
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(0)
            .build();
        let without_symbols = p.compute_fitness(&FitnessContext::new());
        let with_symbols = p.compute_fitness(&FitnessContext::new().with_symbols_present(true));
        assert!(
            with_symbols.score > without_symbols.score,
            "symbols present should give bonus"
        );
    }

    #[test]
    fn fitness_derp_penalty() {
        let base = DeviceProfile::builder(NodeId::new("f7"))
            .latency_class(LatencyClass::Lan)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(0)
            .build();
        let derp = DeviceProfile::builder(NodeId::new("f7d"))
            .latency_class(LatencyClass::Derp)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new();
        assert!(base.compute_fitness(&ctx).score > derp.compute_fitness(&ctx).score);
    }

    #[test]
    fn fitness_low_battery_penalty() {
        let full = DeviceProfile::builder(NodeId::new("f8"))
            .power_source(PowerSource::Mains)
            .availability(AvailabilityProfile::AlwaysOn)
            .latency_class(LatencyClass::Local)
            .timestamp(0)
            .build();
        let low = DeviceProfile::builder(NodeId::new("f8l"))
            .power_source(PowerSource::Battery)
            .battery_percent(5)
            .availability(AvailabilityProfile::AlwaysOn)
            .latency_class(LatencyClass::Local)
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new();
        assert!(full.compute_fitness(&ctx).score > low.compute_fitness(&ctx).score);
    }

    #[test]
    fn fitness_metered_penalty() {
        let unmetered = DeviceProfile::builder(NodeId::new("f9"))
            .metered(false)
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(0)
            .build();
        let metered = DeviceProfile::builder(NodeId::new("f9m"))
            .metered(true)
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new();
        assert!(unmetered.compute_fitness(&ctx).score > metered.compute_fitness(&ctx).score);
    }

    #[test]
    fn fitness_always_on_better_than_best_effort() {
        let always = DeviceProfile::builder(NodeId::new("f10"))
            .availability(AvailabilityProfile::AlwaysOn)
            .latency_class(LatencyClass::Local)
            .timestamp(0)
            .build();
        let best_effort = DeviceProfile::builder(NodeId::new("f10b"))
            .availability(AvailabilityProfile::BestEffort)
            .latency_class(LatencyClass::Local)
            .timestamp(0)
            .build();
        let ctx = FitnessContext::new();
        assert!(always.compute_fitness(&ctx).score > best_effort.compute_fitness(&ctx).score);
    }

    #[test]
    fn fitness_ineligible_score_is_zero() {
        let ineligible = FitnessScore::ineligible();
        assert!(!ineligible.eligible);
        assert!(ineligible.score.abs() < f64::EPSILON);
    }

    #[test]
    fn fitness_score_ordering() {
        let low = FitnessScore {
            score: 50.0,
            eligible: true,
        };
        let high = FitnessScore {
            score: 100.0,
            eligible: true,
        };
        assert!(high > low);
    }

    // ── GpuProfile tests ────────────────────────────────────

    #[test]
    fn gpu_profile_new() {
        let gpu = GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576);
        assert_eq!(gpu.vendor, GpuVendor::Nvidia);
        assert_eq!(gpu.model, "RTX 4090");
        assert_eq!(gpu.vram_mb, 24576);
        assert!(gpu.compute_capability.is_none());
    }

    #[test]
    fn gpu_profile_with_compute_capability() {
        let gpu = GpuProfile::new(GpuVendor::Nvidia, "H100", 80000).with_compute_capability("9.0");
        assert_eq!(gpu.compute_capability.as_deref(), Some("9.0"));
    }

    // ── TpuProfile tests ────────────────────────────────────

    #[test]
    fn tpu_profile_new() {
        let tpu = TpuProfile::new(TpuVendor::Google, "v5p", 16, 98304);
        assert_eq!(tpu.vendor, TpuVendor::Google);
        assert_eq!(tpu.model, "v5p");
        assert_eq!(tpu.cores, 16);
        assert_eq!(tpu.hbm_mb, 98304);
    }

    // ── InstalledConnector tests ─────────────────────────────

    #[test]
    fn installed_connector_new() {
        let c = InstalledConnector::new(
            ConnectorId::from_static("fcp:test:1.0.0"),
            "1.2.3",
            ObjectId::from_bytes([0x55; 32]),
        );
        assert_eq!(c.connector_id, ConnectorId::from_static("fcp:test:1.0.0"));
        assert_eq!(c.version, "1.2.3");
        assert!(c.capabilities.is_empty());
    }

    #[test]
    fn installed_connector_with_capabilities() {
        let caps = vec![
            CapabilityGrant {
                capability: CapabilityId::from_static("cap:read"),
                operation: None,
            },
            CapabilityGrant {
                capability: CapabilityId::from_static("cap:write"),
                operation: None,
            },
        ];
        let c = InstalledConnector::new(
            ConnectorId::from_static("fcp:test:1.0.0"),
            "1.0.0",
            ObjectId::from_bytes([0; 32]),
        )
        .with_capabilities(caps);
        assert_eq!(c.capabilities.len(), 2);
    }

    // ── FitnessContext builder tests ─────────────────────────

    #[test]
    fn fitness_context_default() {
        let ctx = FitnessContext::new();
        assert!(!ctx.symbols_present);
        assert!(!ctx.requires_gpu);
        assert!(!ctx.requires_tpu);
        assert!(ctx.min_memory_mb.is_none());
        assert!(ctx.required_connector.is_none());
    }

    #[test]
    fn fitness_context_with_symbols_present() {
        let ctx = FitnessContext::new().with_symbols_present(true);
        assert!(ctx.symbols_present);
    }

    #[test]
    fn fitness_context_with_requires_gpu() {
        let ctx = FitnessContext::new().with_requires_gpu(true);
        assert!(ctx.requires_gpu);
    }

    #[test]
    fn fitness_context_with_requires_tpu() {
        let ctx = FitnessContext::new().with_requires_tpu(true);
        assert!(ctx.requires_tpu);
    }

    #[test]
    fn fitness_context_with_min_memory() {
        let ctx = FitnessContext::new().with_min_memory_mb(8192);
        assert_eq!(ctx.min_memory_mb, Some(8192));
    }

    #[test]
    fn fitness_context_with_required_connector() {
        let ctx = FitnessContext::new()
            .with_required_connector(ConnectorId::from_static("fcp:slack:1.0.0"));
        assert_eq!(
            ctx.required_connector,
            Some(ConnectorId::from_static("fcp:slack:1.0.0"))
        );
    }

    // ── Enum default tests ───────────────────────────────────

    #[test]
    fn power_source_default_is_unknown() {
        assert_eq!(PowerSource::default(), PowerSource::Unknown);
    }

    #[test]
    fn availability_default_is_best_effort() {
        assert_eq!(
            AvailabilityProfile::default(),
            AvailabilityProfile::BestEffort
        );
    }

    #[test]
    fn latency_class_default_is_internet() {
        assert_eq!(LatencyClass::default(), LatencyClass::Internet);
    }

    // ── Constant tests ───────────────────────────────────────

    #[test]
    fn device_profile_version_is_1() {
        assert_eq!(DEVICE_PROFILE_VERSION, 1);
    }

    #[test]
    fn default_refresh_interval() {
        assert_eq!(DEFAULT_REFRESH_INTERVAL_SECS, 300);
    }

    // ── Clone semantics tests ─────────────────────────────────

    #[test]
    fn device_profile_clone_eq() {
        let profile = DeviceProfile::builder(NodeId::new("clone-test"))
            .cpu_cores(8)
            .memory_mb(16384)
            .timestamp(1000)
            .build();
        let cloned = profile.clone();
        assert_eq!(profile, cloned);
    }

    #[test]
    fn gpu_profile_clone_eq() {
        let gpu =
            GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576).with_compute_capability("8.9");
        let cloned = gpu.clone();
        assert_eq!(gpu, cloned);
    }

    #[test]
    fn tpu_profile_clone_eq() {
        let tpu = TpuProfile::new(TpuVendor::Google, "v5p", 16, 98304);
        let cloned = tpu.clone();
        assert_eq!(tpu, cloned);
    }

    #[test]
    fn installed_connector_clone_eq() {
        let c = InstalledConnector::new(
            ConnectorId::from_static("fcp:test:1.0.0"),
            "1.0.0",
            ObjectId::from_bytes([0x55; 32]),
        );
        let cloned = c.clone();
        assert_eq!(c, cloned);
    }

    // ── Copy semantics for enums ──────────────────────────────

    #[test]
    fn cpu_arch_copy() {
        let arch = CpuArch::Aarch64;
        let copied = arch;
        assert_eq!(arch, copied);
    }

    #[test]
    fn power_source_copy() {
        let src = PowerSource::Solar;
        let copied = src;
        assert_eq!(src, copied);
    }

    #[test]
    fn latency_class_copy() {
        let lc = LatencyClass::Lan;
        let copied = lc;
        assert_eq!(lc, copied);
    }

    #[test]
    fn availability_profile_copy() {
        let avail = AvailabilityProfile::Scheduled;
        let copied = avail;
        assert_eq!(avail, copied);
    }

    #[test]
    fn gpu_vendor_copy() {
        let v = GpuVendor::Apple;
        let copied = v;
        assert_eq!(v, copied);
    }

    #[test]
    fn tpu_vendor_copy() {
        let v = TpuVendor::Google;
        let copied = v;
        assert_eq!(v, copied);
    }

    // ── Hash tests for enums ──────────────────────────────────

    #[test]
    fn cpu_arch_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CpuArch::X86_64);
        set.insert(CpuArch::Aarch64);
        set.insert(CpuArch::Wasm32);
        set.insert(CpuArch::Riscv64);
        assert_eq!(set.len(), 4);
        // Inserting duplicate does nothing
        set.insert(CpuArch::X86_64);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn power_source_hash_all_variants() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PowerSource::Mains);
        set.insert(PowerSource::Battery);
        set.insert(PowerSource::Solar);
        set.insert(PowerSource::Unknown);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn latency_class_hash_all_variants() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LatencyClass::Local);
        set.insert(LatencyClass::Lan);
        set.insert(LatencyClass::Internet);
        set.insert(LatencyClass::Derp);
        assert_eq!(set.len(), 4);
    }

    // ── Debug formatting ──────────────────────────────────────

    #[test]
    fn device_profile_debug_contains_fields() {
        let profile = DeviceProfile::builder(NodeId::new("debug-test"))
            .cpu_cores(4)
            .timestamp(0)
            .build();
        let dbg = format!("{profile:?}");
        assert!(dbg.contains("DeviceProfile"));
        assert!(dbg.contains("debug-test"));
    }

    #[test]
    fn gpu_profile_debug() {
        let gpu = GpuProfile::new(GpuVendor::Amd, "RX 7900", 24576);
        let dbg = format!("{gpu:?}");
        assert!(dbg.contains("GpuProfile"));
        assert!(dbg.contains("RX 7900"));
    }

    #[test]
    fn tpu_profile_debug() {
        let tpu = TpuProfile::new(TpuVendor::Other, "custom-v1", 8, 65536);
        let dbg = format!("{tpu:?}");
        assert!(dbg.contains("TpuProfile"));
        assert!(dbg.contains("custom-v1"));
    }

    #[test]
    fn fitness_score_debug() {
        let score = FitnessScore {
            score: 85.5,
            eligible: true,
        };
        let dbg = format!("{score:?}");
        assert!(dbg.contains("FitnessScore"));
        assert!(dbg.contains("85.5"));
    }

    #[test]
    fn fitness_context_debug() {
        let ctx = FitnessContext::new().with_requires_gpu(true);
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("FitnessContext"));
    }

    #[test]
    fn device_profile_builder_debug() {
        let builder = DeviceProfileBuilder::new(NodeId::new("builder-dbg"));
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("DeviceProfileBuilder"));
    }

    // ── Battery boundary values ───────────────────────────────

    #[test]
    fn battery_boundary_at_20_not_low() {
        let p = DeviceProfile::builder(NodeId::new("bnd1"))
            .power_source(PowerSource::Battery)
            .battery_percent(20)
            .timestamp(0)
            .build();
        assert!(!p.is_low_battery());
    }

    #[test]
    fn battery_boundary_at_19_is_low() {
        let p = DeviceProfile::builder(NodeId::new("bnd2"))
            .power_source(PowerSource::Battery)
            .battery_percent(19)
            .timestamp(0)
            .build();
        assert!(p.is_low_battery());
    }

    #[test]
    fn battery_boundary_at_0_is_low() {
        let p = DeviceProfile::builder(NodeId::new("bnd3"))
            .power_source(PowerSource::Battery)
            .battery_percent(0)
            .timestamp(0)
            .build();
        assert!(p.is_low_battery());
    }

    #[test]
    fn battery_boundary_at_100_not_low() {
        let p = DeviceProfile::builder(NodeId::new("bnd4"))
            .power_source(PowerSource::Battery)
            .battery_percent(100)
            .timestamp(0)
            .build();
        assert!(!p.is_low_battery());
    }

    // ── Multiple connectors ───────────────────────────────────

    #[test]
    fn profile_with_multiple_connectors() {
        let c1 = InstalledConnector::new(
            ConnectorId::from_static("fcp:slack:1.0.0"),
            "1.0.0",
            ObjectId::from_bytes([0x01; 32]),
        );
        let c2 = InstalledConnector::new(
            ConnectorId::from_static("fcp:github:2.0.0"),
            "2.0.0",
            ObjectId::from_bytes([0x02; 32]),
        );
        let c3 = InstalledConnector::new(
            ConnectorId::from_static("fcp:linear:3.0.0"),
            "3.0.0",
            ObjectId::from_bytes([0x03; 32]),
        );

        let p = DeviceProfile::builder(NodeId::new("multi-conn"))
            .add_connector(c1)
            .add_connector(c2)
            .add_connector(c3)
            .timestamp(0)
            .build();

        assert_eq!(p.connectors.len(), 3);
        assert!(p.has_connector(&ConnectorId::from_static("fcp:slack:1.0.0")));
        assert!(p.has_connector(&ConnectorId::from_static("fcp:github:2.0.0")));
        assert!(p.has_connector(&ConnectorId::from_static("fcp:linear:3.0.0")));
        assert!(!p.has_connector(&ConnectorId::from_static("fcp:discord:1.0.0")));
    }

    // ── FitnessScore ordering edge cases ──────────────────────

    #[test]
    fn fitness_score_partial_eq() {
        let a = FitnessScore {
            score: 75.0,
            eligible: true,
        };
        let b = FitnessScore {
            score: 75.0,
            eligible: true,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn fitness_score_partial_ord() {
        let low = FitnessScore {
            score: 50.0,
            eligible: true,
        };
        let high = FitnessScore {
            score: 80.0,
            eligible: true,
        };
        assert!(low < high);
        assert!(high > low);
    }

    #[test]
    fn fitness_score_eligible_vs_ineligible_ordering() {
        let eligible = FitnessScore {
            score: 1.0,
            eligible: true,
        };
        let ineligible = FitnessScore {
            score: 999.0,
            eligible: false,
        };
        assert!(eligible > ineligible);
    }

    #[test]
    fn fitness_score_both_ineligible_ordering() {
        let a = FitnessScore {
            score: 0.0,
            eligible: false,
        };
        let b = FitnessScore {
            score: 0.0,
            eligible: false,
        };
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn fitness_score_copy_semantics() {
        let score = FitnessScore {
            score: 42.0,
            eligible: true,
        };
        let copied = score;
        assert!((score.score - copied.score).abs() < f64::EPSILON);
        assert_eq!(score.eligible, copied.eligible);
    }

    // ── Fitness with GPU + TPU bonuses ────────────────────────

    #[test]
    fn fitness_gpu_bonus_when_required_and_present() {
        let p = DeviceProfile::builder(NodeId::new("gpu-bonus"))
            .gpu(GpuProfile::new(GpuVendor::Nvidia, "A100", 80000))
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(0)
            .build();

        let ctx_no_gpu = FitnessContext::new();
        let ctx_gpu = FitnessContext::new().with_requires_gpu(true);

        let score_no_req = p.compute_fitness(&ctx_no_gpu);
        let score_gpu_req = p.compute_fitness(&ctx_gpu);

        assert!(score_gpu_req.eligible);
        assert!(
            score_gpu_req.score > score_no_req.score,
            "GPU bonus should increase score"
        );
    }

    #[test]
    fn fitness_tpu_bonus_when_required_and_present() {
        let p = DeviceProfile::builder(NodeId::new("tpu-bonus"))
            .tpu(TpuProfile::new(TpuVendor::Google, "v5e", 8, 65536))
            .latency_class(LatencyClass::Local)
            .availability(AvailabilityProfile::AlwaysOn)
            .timestamp(0)
            .build();

        let ctx_no_tpu = FitnessContext::new();
        let ctx_tpu = FitnessContext::new().with_requires_tpu(true);

        let score_no_req = p.compute_fitness(&ctx_no_tpu);
        let score_tpu_req = p.compute_fitness(&ctx_tpu);

        assert!(score_tpu_req.eligible);
        assert!(
            score_tpu_req.score > score_no_req.score,
            "TPU bonus should increase score"
        );
    }

    // ── Fitness latency penalty scaling ───────────────────────

    #[test]
    fn fitness_latency_classes_ordered() {
        let ctx = FitnessContext::new();
        let make = |lc| {
            DeviceProfile::builder(NodeId::new("lat"))
                .latency_class(lc)
                .availability(AvailabilityProfile::AlwaysOn)
                .power_source(PowerSource::Mains)
                .timestamp(0)
                .build()
                .compute_fitness(&ctx)
                .score
        };
        let local = make(LatencyClass::Local);
        let lan = make(LatencyClass::Lan);
        let internet = make(LatencyClass::Internet);
        let derp = make(LatencyClass::Derp);

        assert!(local > lan);
        assert!(lan > internet);
        assert!(internet > derp);
    }

    // ── Fitness score max(0) clamping ─────────────────────────

    #[test]
    fn fitness_score_never_goes_negative() {
        // Create worst possible eligible profile
        let p = DeviceProfile::builder(NodeId::new("negative"))
            .latency_class(LatencyClass::Derp)
            .power_source(PowerSource::Battery)
            .battery_percent(1)
            .availability(AvailabilityProfile::BestEffort)
            .metered(true)
            .timestamp(0)
            .build();

        let ctx = FitnessContext::new();
        let score = p.compute_fitness(&ctx);
        assert!(score.eligible);
        assert!(score.score >= 0.0, "Score should never go negative");
    }

    // ── GpuVendor all variants ────────────────────────────────

    #[test]
    fn gpu_vendor_all_variants_distinct() {
        let variants = [
            GpuVendor::Nvidia,
            GpuVendor::Amd,
            GpuVendor::Apple,
            GpuVendor::Intel,
            GpuVendor::Other,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn tpu_vendor_all_variants_distinct() {
        assert_ne!(TpuVendor::Google, TpuVendor::Other);
    }

    // ── Serde: GPU vendor roundtrip ───────────────────────────

    #[test]
    fn gpu_vendor_json_roundtrip() {
        for vendor in [
            GpuVendor::Nvidia,
            GpuVendor::Amd,
            GpuVendor::Apple,
            GpuVendor::Intel,
            GpuVendor::Other,
        ] {
            let json = serde_json::to_string(&vendor).unwrap();
            let decoded: GpuVendor = serde_json::from_str(&json).unwrap();
            assert_eq!(vendor, decoded);
        }
    }

    #[test]
    fn tpu_vendor_json_roundtrip() {
        for vendor in [TpuVendor::Google, TpuVendor::Other] {
            let json = serde_json::to_string(&vendor).unwrap();
            let decoded: TpuVendor = serde_json::from_str(&json).unwrap();
            assert_eq!(vendor, decoded);
        }
    }

    #[test]
    fn power_source_json_roundtrip() {
        for src in [
            PowerSource::Mains,
            PowerSource::Battery,
            PowerSource::Solar,
            PowerSource::Unknown,
        ] {
            let json = serde_json::to_string(&src).unwrap();
            let decoded: PowerSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, decoded);
        }
    }

    #[test]
    fn latency_class_json_roundtrip() {
        for lc in [
            LatencyClass::Local,
            LatencyClass::Lan,
            LatencyClass::Internet,
            LatencyClass::Derp,
        ] {
            let json = serde_json::to_string(&lc).unwrap();
            let decoded: LatencyClass = serde_json::from_str(&json).unwrap();
            assert_eq!(lc, decoded);
        }
    }

    #[test]
    fn availability_json_roundtrip() {
        for avail in [
            AvailabilityProfile::AlwaysOn,
            AvailabilityProfile::Scheduled,
            AvailabilityProfile::BestEffort,
        ] {
            let json = serde_json::to_string(&avail).unwrap();
            let decoded: AvailabilityProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(avail, decoded);
        }
    }

    #[test]
    fn cpu_arch_json_roundtrip() {
        for arch in [
            CpuArch::X86_64,
            CpuArch::Aarch64,
            CpuArch::Wasm32,
            CpuArch::Riscv64,
        ] {
            let json = serde_json::to_string(&arch).unwrap();
            let decoded: CpuArch = serde_json::from_str(&json).unwrap();
            assert_eq!(arch, decoded);
        }
    }

    // ── InstalledConnector serde ───────────────────────────────

    #[test]
    fn installed_connector_json_roundtrip() {
        let caps = vec![CapabilityGrant {
            capability: CapabilityId::from_static("cap:admin"),
            operation: None,
        }];
        let c = InstalledConnector::new(
            ConnectorId::from_static("fcp:test:1.0.0"),
            "2.5.0",
            ObjectId::from_bytes([0xAB; 32]),
        )
        .with_capabilities(caps);

        let json = serde_json::to_string(&c).unwrap();
        let decoded: InstalledConnector = serde_json::from_str(&json).unwrap();
        assert_eq!(c, decoded);
        assert_eq!(decoded.capabilities.len(), 1);
    }

    #[test]
    fn installed_connector_cbor_roundtrip() {
        let c = InstalledConnector::new(
            ConnectorId::from_static("fcp:test:1.0.0"),
            "3.0.0",
            ObjectId::from_bytes([0xCD; 32]),
        );
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&c, &mut cbor_bytes).unwrap();
        let decoded: InstalledConnector = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(c, decoded);
    }

    // ── GpuProfile serde ──────────────────────────────────────

    #[test]
    fn gpu_profile_json_roundtrip() {
        let gpu =
            GpuProfile::new(GpuVendor::Intel, "Arc A770", 16384).with_compute_capability("Xe");
        let json = serde_json::to_string(&gpu).unwrap();
        let decoded: GpuProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(gpu, decoded);
    }

    #[test]
    fn gpu_profile_without_compute_capability_json() {
        let gpu = GpuProfile::new(GpuVendor::Apple, "M4", 32768);
        let json = serde_json::to_string(&gpu).unwrap();
        assert!(!json.contains("compute_capability"));
        let decoded: GpuProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.compute_capability, None);
    }

    // ── TpuProfile serde ──────────────────────────────────────

    #[test]
    fn tpu_profile_json_roundtrip() {
        let tpu = TpuProfile::new(TpuVendor::Other, "custom-chip", 32, 131_072);
        let json = serde_json::to_string(&tpu).unwrap();
        let decoded: TpuProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(tpu, decoded);
    }

    // ── FitnessContext clone ──────────────────────────────────

    #[test]
    fn fitness_context_clone() {
        let ctx = FitnessContext::new()
            .with_requires_gpu(true)
            .with_min_memory_mb(4096)
            .with_symbols_present(true);
        let cloned = ctx.clone();
        // Verify original
        assert!(ctx.requires_gpu);
        assert_eq!(ctx.min_memory_mb, Some(4096));
        // Verify clone
        assert!(cloned.requires_gpu);
        assert!(cloned.symbols_present);
    }

    // ── Profile equality with different optional fields ───────

    #[test]
    fn profiles_differ_by_gpu() {
        let a = DeviceProfile::builder(NodeId::new("eq1"))
            .timestamp(0)
            .build();
        let b = DeviceProfile::builder(NodeId::new("eq1"))
            .gpu(GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576))
            .timestamp(0)
            .build();
        assert_ne!(a, b);
    }

    #[test]
    fn profiles_differ_by_metered() {
        let a = DeviceProfile::builder(NodeId::new("eq2"))
            .metered(false)
            .timestamp(0)
            .build();
        let b = DeviceProfile::builder(NodeId::new("eq2"))
            .metered(true)
            .timestamp(0)
            .build();
        assert_ne!(a, b);
    }

    #[test]
    fn profiles_differ_by_node_id() {
        let a = DeviceProfile::builder(NodeId::new("node-a"))
            .timestamp(0)
            .build();
        let b = DeviceProfile::builder(NodeId::new("node-b"))
            .timestamp(0)
            .build();
        assert_ne!(a, b);
    }
}
