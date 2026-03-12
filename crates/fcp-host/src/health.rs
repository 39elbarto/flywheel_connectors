//! Composite health check API for the FCP host.
//!
//! Aggregates health signals from connectors, mesh connectivity,
//! resource utilisation, and enforcement subsystems into a unified
//! health status suitable for liveness/readiness probes and operator
//! dashboards.
//!
//! # Health Model
//!
//! The host exposes a three-state health model:
//! - **Healthy** — all subsystems nominal
//! - **Degraded** — some subsystems impaired but service continues
//! - **Unhealthy** — critical failure, service should be restarted
//!
//! Each subsystem contributes a [`ComponentHealth`] entry, and the
//! composite [`HealthStatus`] is the worst-case rollup.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Health state
// ─────────────────────────────────────────────────────────────────────────────

/// Tri-state health model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum HealthState {
    /// All subsystems nominal.
    Healthy,
    /// Some subsystems impaired; service is partially available.
    Degraded {
        /// Human-readable reasons for degradation.
        reasons: Vec<String>,
    },
    /// Critical failure; service should be restarted.
    Unhealthy {
        /// Human-readable reasons for failure.
        reasons: Vec<String>,
    },
}

impl HealthState {
    /// Whether the host is healthy.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Whether the host is degraded (but not unhealthy).
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }

    /// Whether the host is unhealthy.
    #[must_use]
    pub const fn is_unhealthy(&self) -> bool {
        matches!(self, Self::Unhealthy { .. })
    }

    /// Severity level as an integer (0 = healthy, 1 = degraded, 2 = unhealthy).
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Degraded { .. } => 1,
            Self::Unhealthy { .. } => 2,
        }
    }

    /// Merge two health states, keeping the worst.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unhealthy { reasons: a }, Self::Unhealthy { reasons: b }) => {
                let mut merged = a.clone();
                merged.extend(b.iter().cloned());
                Self::Unhealthy { reasons: merged }
            }
            (Self::Unhealthy { reasons }, _) | (_, Self::Unhealthy { reasons }) => {
                Self::Unhealthy {
                    reasons: reasons.clone(),
                }
            }
            (Self::Degraded { reasons: a }, Self::Degraded { reasons: b }) => {
                let mut merged = a.clone();
                merged.extend(b.iter().cloned());
                Self::Degraded { reasons: merged }
            }
            (Self::Degraded { reasons }, _) | (_, Self::Degraded { reasons }) => {
                Self::Degraded {
                    reasons: reasons.clone(),
                }
            }
            _ => Self::Healthy,
        }
    }
}

impl std::fmt::Display for HealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded { reasons } => write!(f, "degraded: {}", reasons.join("; ")),
            Self::Unhealthy { reasons } => write!(f, "unhealthy: {}", reasons.join("; ")),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Component health
// ─────────────────────────────────────────────────────────────────────────────

/// Health of a single named subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Subsystem name (e.g. "connector:discord", "mesh", "enforcement").
    pub name: String,
    /// Current health state.
    pub state: HealthState,
    /// When the last health check ran.
    pub last_check_elapsed_ms: Option<f64>,
    /// Number of consecutive check failures (0 when healthy).
    pub consecutive_failures: u32,
    /// Optional metadata for diagnostics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ComponentHealth {
    /// Create a healthy component.
    #[must_use]
    pub fn healthy(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: HealthState::Healthy,
            last_check_elapsed_ms: None,
            consecutive_failures: 0,
            message: None,
        }
    }

    /// Create a degraded component.
    #[must_use]
    pub fn degraded(name: impl Into<String>, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            name: name.into(),
            state: HealthState::Degraded {
                reasons: vec![reason],
            },
            last_check_elapsed_ms: None,
            consecutive_failures: 0,
            message: None,
        }
    }

    /// Create an unhealthy component.
    #[must_use]
    pub fn unhealthy(name: impl Into<String>, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            name: name.into(),
            state: HealthState::Unhealthy {
                reasons: vec![reason],
            },
            last_check_elapsed_ms: None,
            consecutive_failures: 0,
            message: None,
        }
    }

    /// Attach a check elapsed time.
    #[must_use]
    pub const fn with_elapsed_ms(mut self, ms: f64) -> Self {
        self.last_check_elapsed_ms = Some(ms);
        self
    }

    /// Attach a consecutive failure count.
    #[must_use]
    pub const fn with_failures(mut self, count: u32) -> Self {
        self.consecutive_failures = count;
        self
    }

    /// Attach an optional message.
    #[must_use]
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector health
// ─────────────────────────────────────────────────────────────────────────────

/// Health details for a single connector process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorHealth {
    /// Connector identifier.
    pub connector_id: String,
    /// Current process state label.
    pub process_state: String,
    /// Whether the last health check passed.
    pub last_check_passed: Option<bool>,
    /// Number of restarts since host boot.
    pub restart_count: u32,
    /// Process uptime in seconds (if running).
    pub uptime_seconds: Option<u64>,
    /// Whether this connector is in a crash loop.
    pub crash_loop: bool,
}

impl ConnectorHealth {
    /// Create connector health for a running connector.
    #[must_use]
    pub fn running(connector_id: impl Into<String>, uptime_seconds: u64) -> Self {
        Self {
            connector_id: connector_id.into(),
            process_state: "running".into(),
            last_check_passed: Some(true),
            restart_count: 0,
            uptime_seconds: Some(uptime_seconds),
            crash_loop: false,
        }
    }

    /// Create connector health for a stopped connector.
    #[must_use]
    pub fn stopped(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            process_state: "stopped".into(),
            last_check_passed: None,
            restart_count: 0,
            uptime_seconds: None,
            crash_loop: false,
        }
    }

    /// Create connector health for a failed/crash-looping connector.
    #[must_use]
    pub fn failed(connector_id: impl Into<String>, restarts: u32) -> Self {
        Self {
            connector_id: connector_id.into(),
            process_state: "failed".into(),
            last_check_passed: Some(false),
            restart_count: restarts,
            uptime_seconds: None,
            crash_loop: restarts >= 3,
        }
    }

    /// Set restart count.
    #[must_use]
    pub const fn with_restarts(mut self, count: u32) -> Self {
        self.restart_count = count;
        self
    }

    /// Contribute to composite health.
    #[must_use]
    pub fn to_health_state(&self) -> HealthState {
        if self.crash_loop {
            HealthState::Unhealthy {
                reasons: vec![format!("{}: crash loop ({} restarts)", self.connector_id, self.restart_count)],
            }
        } else if self.last_check_passed == Some(false) {
            HealthState::Degraded {
                reasons: vec![format!("{}: health check failing", self.connector_id)],
            }
        } else {
            HealthState::Healthy
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesh health
// ─────────────────────────────────────────────────────────────────────────────

/// Health of mesh connectivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshHealth {
    /// Whether the node is connected to the mesh.
    pub connected: bool,
    /// Whether the checkpoint is fresh.
    pub checkpoint_fresh: bool,
    /// Whether the revocation list is fresh.
    pub revocation_fresh: bool,
    /// Number of connected peers.
    pub peer_count: u32,
    /// Seconds since last successful mesh sync.
    pub last_sync_age_seconds: Option<u64>,
}

impl MeshHealth {
    /// Fully connected mesh.
    #[must_use]
    pub const fn connected(peer_count: u32) -> Self {
        Self {
            connected: true,
            checkpoint_fresh: true,
            revocation_fresh: true,
            peer_count,
            last_sync_age_seconds: Some(0),
        }
    }

    /// Disconnected mesh.
    #[must_use]
    pub const fn disconnected() -> Self {
        Self {
            connected: false,
            checkpoint_fresh: false,
            revocation_fresh: false,
            peer_count: 0,
            last_sync_age_seconds: None,
        }
    }

    /// Contribute to composite health.
    #[must_use]
    pub fn to_health_state(&self) -> HealthState {
        if !self.connected {
            return HealthState::Unhealthy {
                reasons: vec!["mesh disconnected".into()],
            };
        }
        let mut reasons = Vec::new();
        if !self.checkpoint_fresh {
            reasons.push("checkpoint stale".into());
        }
        if !self.revocation_fresh {
            reasons.push("revocation list stale".into());
        }
        if reasons.is_empty() {
            HealthState::Healthy
        } else {
            HealthState::Degraded { reasons }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource health
// ─────────────────────────────────────────────────────────────────────────────

/// Health of system resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceHealth {
    /// Memory used in megabytes.
    pub memory_used_mb: u64,
    /// Memory limit in megabytes (if configured).
    pub memory_limit_mb: Option<u64>,
    /// CPU usage percentage (0-100).
    pub cpu_percent: f32,
    /// Number of open file descriptors.
    pub open_fds: u64,
    /// Maximum file descriptors allowed.
    pub max_fds: u64,
}

impl ResourceHealth {
    /// Create resource health with the given values.
    #[must_use]
    pub const fn new(memory_used_mb: u64, cpu_percent: f32, open_fds: u64, max_fds: u64) -> Self {
        Self {
            memory_used_mb,
            memory_limit_mb: None,
            cpu_percent,
            open_fds,
            max_fds,
        }
    }

    /// Set the memory limit.
    #[must_use]
    pub const fn with_memory_limit_mb(mut self, limit: u64) -> Self {
        self.memory_limit_mb = Some(limit);
        self
    }

    /// Memory utilisation as a fraction (0.0–1.0), or `None` if no limit set.
    #[must_use]
    pub fn memory_utilisation(&self) -> Option<f64> {
        self.memory_limit_mb.map(|limit| {
            if limit == 0 {
                0.0
            } else {
                #[allow(clippy::cast_precision_loss)]
                {
                    self.memory_used_mb as f64 / limit as f64
                }
            }
        })
    }

    /// FD utilisation as a fraction (0.0–1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fd_utilisation(&self) -> f64 {
        if self.max_fds == 0 {
            0.0
        } else {
            self.open_fds as f64 / self.max_fds as f64
        }
    }

    /// Contribute to composite health.
    #[must_use]
    pub fn to_health_state(&self) -> HealthState {
        let mut reasons = Vec::new();

        // Memory check.
        if let Some(util) = self.memory_utilisation() {
            if util > 0.95 {
                return HealthState::Unhealthy {
                    reasons: vec![format!("memory at {:.0}%", util * 100.0)],
                };
            }
            if util > 0.80 {
                reasons.push(format!("memory at {:.0}%", util * 100.0));
            }
        }

        // CPU check.
        if self.cpu_percent > 95.0 {
            return HealthState::Unhealthy {
                reasons: vec![format!("CPU at {:.0}%", self.cpu_percent)],
            };
        }
        if self.cpu_percent > 80.0 {
            reasons.push(format!("CPU at {:.0}%", self.cpu_percent));
        }

        // FD check.
        let fd_util = self.fd_utilisation();
        if fd_util > 0.95 {
            return HealthState::Unhealthy {
                reasons: vec![format!("FDs at {:.0}%", fd_util * 100.0)],
            };
        }
        if fd_util > 0.80 {
            reasons.push(format!("FDs at {:.0}%", fd_util * 100.0));
        }

        if reasons.is_empty() {
            HealthState::Healthy
        } else {
            HealthState::Degraded { reasons }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Composite health status
// ─────────────────────────────────────────────────────────────────────────────

/// Full composite health status of the FCP host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health state (worst-case rollup).
    pub status: HealthState,
    /// Host version string.
    pub version: String,
    /// Host uptime in seconds.
    pub uptime_seconds: u64,
    /// Per-connector health details.
    pub connectors: Vec<ConnectorHealth>,
    /// Mesh connectivity health.
    pub mesh: MeshHealth,
    /// System resource health.
    pub resources: ResourceHealth,
    /// Per-subsystem component health.
    pub components: Vec<ComponentHealth>,
}

impl HealthStatus {
    /// Whether the host is healthy.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.status.is_healthy()
    }

    /// Whether the host is suitable for serving requests (healthy or degraded).
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        !self.status.is_unhealthy()
    }

    /// Count of running connectors.
    #[must_use]
    pub fn running_connector_count(&self) -> usize {
        self.connectors
            .iter()
            .filter(|c| c.process_state == "running")
            .count()
    }

    /// Count of crash-looping connectors.
    #[must_use]
    pub fn crash_loop_count(&self) -> usize {
        self.connectors.iter().filter(|c| c.crash_loop).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health aggregator
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the health aggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// How often to run health checks (milliseconds).
    pub check_interval_ms: u64,
    /// Health check timeout (milliseconds).
    pub check_timeout_ms: u64,
    /// Number of consecutive failures before marking unhealthy.
    pub unhealthy_threshold: u32,
    /// Number of consecutive failures before marking degraded.
    pub degraded_threshold: u32,
    /// Memory utilisation threshold for degraded (0.0–1.0).
    pub memory_degraded_threshold: f64,
    /// Memory utilisation threshold for unhealthy (0.0–1.0).
    pub memory_unhealthy_threshold: f64,
    /// CPU percentage threshold for degraded.
    pub cpu_degraded_threshold: f32,
    /// CPU percentage threshold for unhealthy.
    pub cpu_unhealthy_threshold: f32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_ms: 30_000,
            check_timeout_ms: 5_000,
            unhealthy_threshold: 3,
            degraded_threshold: 1,
            memory_degraded_threshold: 0.80,
            memory_unhealthy_threshold: 0.95,
            cpu_degraded_threshold: 80.0,
            cpu_unhealthy_threshold: 95.0,
        }
    }
}

impl HealthConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the check interval.
    #[must_use]
    pub const fn with_check_interval_ms(mut self, ms: u64) -> Self {
        self.check_interval_ms = ms;
        self
    }

    /// Set the check timeout.
    #[must_use]
    pub const fn with_check_timeout_ms(mut self, ms: u64) -> Self {
        self.check_timeout_ms = ms;
        self
    }

    /// Set the unhealthy threshold.
    #[must_use]
    pub const fn with_unhealthy_threshold(mut self, threshold: u32) -> Self {
        self.unhealthy_threshold = threshold;
        self
    }

    /// Check interval as a `Duration`.
    #[must_use]
    pub const fn check_interval(&self) -> Duration {
        Duration::from_millis(self.check_interval_ms)
    }

    /// Check timeout as a `Duration`.
    #[must_use]
    pub const fn check_timeout(&self) -> Duration {
        Duration::from_millis(self.check_timeout_ms)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health aggregator
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregates health signals from multiple sources into a composite status.
#[derive(Debug)]
pub struct HealthAggregator {
    config: HealthConfig,
    version: String,
    started_at: Instant,
    components: Vec<ComponentHealth>,
    connectors: Vec<ConnectorHealth>,
    mesh: Option<MeshHealth>,
    resources: Option<ResourceHealth>,
}

impl HealthAggregator {
    /// Create a new aggregator.
    #[must_use]
    pub fn new(version: impl Into<String>, config: HealthConfig) -> Self {
        Self {
            config,
            version: version.into(),
            started_at: Instant::now(),
            components: Vec::new(),
            connectors: Vec::new(),
            mesh: None,
            resources: None,
        }
    }

    /// Create an aggregator with defaults.
    #[must_use]
    pub fn with_defaults(version: impl Into<String>) -> Self {
        Self::new(version, HealthConfig::default())
    }

    /// Report health for a named component.
    pub fn report_component(&mut self, health: ComponentHealth) {
        // Update existing or insert new.
        if let Some(existing) = self
            .components
            .iter_mut()
            .find(|c| c.name == health.name)
        {
            *existing = health;
        } else {
            self.components.push(health);
        }
    }

    /// Report health for a connector.
    pub fn report_connector(&mut self, health: ConnectorHealth) {
        if let Some(existing) = self
            .connectors
            .iter_mut()
            .find(|c| c.connector_id == health.connector_id)
        {
            *existing = health;
        } else {
            self.connectors.push(health);
        }
    }

    /// Report mesh health.
    #[allow(clippy::missing_const_for_fn)]
    pub fn report_mesh(&mut self, mesh: MeshHealth) {
        self.mesh = Some(mesh);
    }

    /// Report resource health.
    #[allow(clippy::missing_const_for_fn)]
    pub fn report_resources(&mut self, resources: ResourceHealth) {
        self.resources = Some(resources);
    }

    /// Number of tracked components.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Number of tracked connectors.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn connector_count(&self) -> usize {
        self.connectors.len()
    }

    /// Compute the composite health status.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn evaluate(&self) -> HealthStatus {
        let mut overall = HealthState::Healthy;

        // Roll up connector health.
        for connector in &self.connectors {
            overall = overall.merge(&connector.to_health_state());
        }

        // Roll up mesh health.
        if let Some(mesh) = &self.mesh {
            overall = overall.merge(&mesh.to_health_state());
        }

        // Roll up resource health.
        if let Some(resources) = &self.resources {
            overall = overall.merge(&resources.to_health_state());
        }

        // Roll up component health.
        for component in &self.components {
            // Consecutive failures escalation.
            let component_state = if component.consecutive_failures >= self.config.unhealthy_threshold {
                HealthState::Unhealthy {
                    reasons: vec![format!(
                        "{}: {} consecutive failures",
                        component.name, component.consecutive_failures
                    )],
                }
            } else if component.consecutive_failures >= self.config.degraded_threshold {
                HealthState::Degraded {
                    reasons: vec![format!(
                        "{}: {} consecutive failures",
                        component.name, component.consecutive_failures
                    )],
                }
            } else {
                component.state.clone()
            };
            overall = overall.merge(&component_state);
        }

        let uptime_seconds = self.started_at.elapsed().as_secs();

        HealthStatus {
            status: overall,
            version: self.version.clone(),
            uptime_seconds,
            connectors: self.connectors.clone(),
            mesh: self.mesh.clone().unwrap_or_else(MeshHealth::disconnected),
            resources: self
                .resources
                .clone()
                .unwrap_or_else(|| ResourceHealth::new(0, 0.0, 0, 1024)),
            components: self.components.clone(),
        }
    }

    /// Get the config.
    #[must_use]
    pub const fn config(&self) -> &HealthConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ────────── HealthState ──────────

    #[test]
    fn health_state_healthy() {
        let s = HealthState::Healthy;
        assert!(s.is_healthy());
        assert!(!s.is_degraded());
        assert!(!s.is_unhealthy());
        assert_eq!(s.severity(), 0);
    }

    #[test]
    fn health_state_degraded() {
        let s = HealthState::Degraded {
            reasons: vec!["test".into()],
        };
        assert!(!s.is_healthy());
        assert!(s.is_degraded());
        assert!(!s.is_unhealthy());
        assert_eq!(s.severity(), 1);
    }

    #[test]
    fn health_state_unhealthy() {
        let s = HealthState::Unhealthy {
            reasons: vec!["down".into()],
        };
        assert!(!s.is_healthy());
        assert!(!s.is_degraded());
        assert!(s.is_unhealthy());
        assert_eq!(s.severity(), 2);
    }

    #[test]
    fn health_state_display_healthy() {
        assert_eq!(HealthState::Healthy.to_string(), "healthy");
    }

    #[test]
    fn health_state_display_degraded() {
        let s = HealthState::Degraded {
            reasons: vec!["a".into(), "b".into()],
        };
        assert_eq!(s.to_string(), "degraded: a; b");
    }

    #[test]
    fn health_state_display_unhealthy() {
        let s = HealthState::Unhealthy {
            reasons: vec!["x".into()],
        };
        assert_eq!(s.to_string(), "unhealthy: x");
    }

    // ────────── HealthState::merge ──────────

    #[test]
    fn merge_healthy_healthy() {
        let result = HealthState::Healthy.merge(&HealthState::Healthy);
        assert!(result.is_healthy());
    }

    #[test]
    fn merge_healthy_degraded() {
        let d = HealthState::Degraded {
            reasons: vec!["r".into()],
        };
        let result = HealthState::Healthy.merge(&d);
        assert!(result.is_degraded());
    }

    #[test]
    fn merge_degraded_healthy() {
        let d = HealthState::Degraded {
            reasons: vec!["r".into()],
        };
        let result = d.merge(&HealthState::Healthy);
        assert!(result.is_degraded());
    }

    #[test]
    fn merge_healthy_unhealthy() {
        let u = HealthState::Unhealthy {
            reasons: vec!["u".into()],
        };
        let result = HealthState::Healthy.merge(&u);
        assert!(result.is_unhealthy());
    }

    #[test]
    fn merge_degraded_unhealthy() {
        let d = HealthState::Degraded {
            reasons: vec!["d".into()],
        };
        let u = HealthState::Unhealthy {
            reasons: vec!["u".into()],
        };
        let result = d.merge(&u);
        assert!(result.is_unhealthy());
    }

    #[test]
    fn merge_degraded_degraded_combines_reasons() {
        let a = HealthState::Degraded {
            reasons: vec!["a".into()],
        };
        let b = HealthState::Degraded {
            reasons: vec!["b".into()],
        };
        if let HealthState::Degraded { reasons } = a.merge(&b) {
            assert_eq!(reasons.len(), 2);
            assert!(reasons.contains(&"a".to_string()));
            assert!(reasons.contains(&"b".to_string()));
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn merge_unhealthy_unhealthy_combines_reasons() {
        let a = HealthState::Unhealthy {
            reasons: vec!["a".into()],
        };
        let b = HealthState::Unhealthy {
            reasons: vec!["b".into()],
        };
        if let HealthState::Unhealthy { reasons } = a.merge(&b) {
            assert_eq!(reasons.len(), 2);
        } else {
            panic!("expected unhealthy");
        }
    }

    // ────────── ComponentHealth ──────────

    #[test]
    fn component_healthy() {
        let c = ComponentHealth::healthy("test");
        assert!(c.state.is_healthy());
        assert_eq!(c.name, "test");
        assert_eq!(c.consecutive_failures, 0);
    }

    #[test]
    fn component_degraded() {
        let c = ComponentHealth::degraded("test", "slow");
        assert!(c.state.is_degraded());
    }

    #[test]
    fn component_unhealthy() {
        let c = ComponentHealth::unhealthy("test", "down");
        assert!(c.state.is_unhealthy());
    }

    #[test]
    fn component_with_elapsed() {
        let c = ComponentHealth::healthy("test").with_elapsed_ms(42.5);
        assert_eq!(c.last_check_elapsed_ms, Some(42.5));
    }

    #[test]
    fn component_with_failures() {
        let c = ComponentHealth::healthy("test").with_failures(5);
        assert_eq!(c.consecutive_failures, 5);
    }

    #[test]
    fn component_with_message() {
        let c = ComponentHealth::healthy("test").with_message("ok");
        assert_eq!(c.message.as_deref(), Some("ok"));
    }

    // ────────── ConnectorHealth ──────────

    #[test]
    fn connector_running() {
        let c = ConnectorHealth::running("fcp.discord", 3600);
        assert_eq!(c.process_state, "running");
        assert_eq!(c.uptime_seconds, Some(3600));
        assert!(!c.crash_loop);
    }

    #[test]
    fn connector_stopped() {
        let c = ConnectorHealth::stopped("fcp.discord");
        assert_eq!(c.process_state, "stopped");
        assert!(c.uptime_seconds.is_none());
    }

    #[test]
    fn connector_failed_crash_loop() {
        let c = ConnectorHealth::failed("fcp.discord", 5);
        assert!(c.crash_loop);
        assert_eq!(c.restart_count, 5);
    }

    #[test]
    fn connector_failed_no_crash_loop() {
        let c = ConnectorHealth::failed("fcp.discord", 2);
        assert!(!c.crash_loop);
    }

    #[test]
    fn connector_with_restarts() {
        let c = ConnectorHealth::running("fcp.discord", 100).with_restarts(3);
        assert_eq!(c.restart_count, 3);
    }

    #[test]
    fn connector_health_state_running() {
        let c = ConnectorHealth::running("fcp.discord", 100);
        assert!(c.to_health_state().is_healthy());
    }

    #[test]
    fn connector_health_state_crash_loop() {
        let c = ConnectorHealth::failed("fcp.discord", 5);
        assert!(c.to_health_state().is_unhealthy());
    }

    #[test]
    fn connector_health_state_check_failing() {
        let mut c = ConnectorHealth::running("fcp.discord", 100);
        c.last_check_passed = Some(false);
        assert!(c.to_health_state().is_degraded());
    }

    // ────────── MeshHealth ──────────

    #[test]
    fn mesh_connected() {
        let m = MeshHealth::connected(5);
        assert!(m.connected);
        assert_eq!(m.peer_count, 5);
        assert!(m.to_health_state().is_healthy());
    }

    #[test]
    fn mesh_disconnected() {
        let m = MeshHealth::disconnected();
        assert!(!m.connected);
        assert!(m.to_health_state().is_unhealthy());
    }

    #[test]
    fn mesh_stale_checkpoint() {
        let mut m = MeshHealth::connected(3);
        m.checkpoint_fresh = false;
        assert!(m.to_health_state().is_degraded());
    }

    #[test]
    fn mesh_stale_revocation() {
        let mut m = MeshHealth::connected(3);
        m.revocation_fresh = false;
        assert!(m.to_health_state().is_degraded());
    }

    #[test]
    fn mesh_both_stale() {
        let mut m = MeshHealth::connected(3);
        m.checkpoint_fresh = false;
        m.revocation_fresh = false;
        let state = m.to_health_state();
        assert!(state.is_degraded());
        if let HealthState::Degraded { reasons } = state {
            assert_eq!(reasons.len(), 2);
        }
    }

    // ────────── ResourceHealth ──────────

    #[test]
    fn resource_healthy() {
        let r = ResourceHealth::new(256, 30.0, 100, 1024);
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_memory_degraded() {
        let r = ResourceHealth::new(850, 30.0, 100, 1024).with_memory_limit_mb(1000);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_memory_unhealthy() {
        let r = ResourceHealth::new(960, 30.0, 100, 1024).with_memory_limit_mb(1000);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_cpu_degraded() {
        let r = ResourceHealth::new(256, 85.0, 100, 1024);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_cpu_unhealthy() {
        let r = ResourceHealth::new(256, 98.0, 100, 1024);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_fd_degraded() {
        let r = ResourceHealth::new(256, 30.0, 850, 1024);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_fd_unhealthy() {
        let r = ResourceHealth::new(256, 30.0, 1000, 1024);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_memory_utilisation() {
        let r = ResourceHealth::new(500, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!((util - 0.5).abs() < 0.01);
    }

    #[test]
    fn resource_memory_utilisation_no_limit() {
        let r = ResourceHealth::new(500, 0.0, 0, 1024);
        assert!(r.memory_utilisation().is_none());
    }

    #[test]
    fn resource_memory_utilisation_zero_limit() {
        let r = ResourceHealth::new(500, 0.0, 0, 1024).with_memory_limit_mb(0);
        assert_eq!(r.memory_utilisation(), Some(0.0));
    }

    #[test]
    fn resource_fd_utilisation() {
        let r = ResourceHealth::new(0, 0.0, 512, 1024);
        assert!((r.fd_utilisation() - 0.5).abs() < 0.01);
    }

    #[test]
    fn resource_fd_utilisation_zero_max() {
        let r = ResourceHealth::new(0, 0.0, 100, 0);
        assert!(r.fd_utilisation().abs() < f64::EPSILON);
    }

    #[test]
    fn resource_no_limit_always_healthy() {
        let r = ResourceHealth::new(999_999, 50.0, 100, 1024);
        // No memory limit set → memory check skipped, CPU at 50% is fine.
        assert!(r.to_health_state().is_healthy());
    }

    // ────────── HealthConfig ──────────

    #[test]
    fn config_defaults() {
        let c = HealthConfig::default();
        assert_eq!(c.check_interval_ms, 30_000);
        assert_eq!(c.check_timeout_ms, 5_000);
        assert_eq!(c.unhealthy_threshold, 3);
        assert_eq!(c.degraded_threshold, 1);
    }

    #[test]
    fn config_builder() {
        let c = HealthConfig::new()
            .with_check_interval_ms(10_000)
            .with_check_timeout_ms(2_000)
            .with_unhealthy_threshold(5);
        assert_eq!(c.check_interval_ms, 10_000);
        assert_eq!(c.check_timeout_ms, 2_000);
        assert_eq!(c.unhealthy_threshold, 5);
    }

    #[test]
    fn config_durations() {
        let c = HealthConfig::default();
        assert_eq!(c.check_interval(), Duration::from_secs(30));
        assert_eq!(c.check_timeout(), Duration::from_secs(5));
    }

    // ────────── HealthAggregator ──────────

    #[test]
    fn aggregator_empty_is_healthy() {
        let agg = HealthAggregator::with_defaults("1.0.0");
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert!(status.is_ready());
        assert_eq!(status.version, "1.0.0");
    }

    #[test]
    fn aggregator_with_running_connector() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorHealth::running("fcp.discord", 100));
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert_eq!(status.running_connector_count(), 1);
        assert_eq!(status.crash_loop_count(), 0);
    }

    #[test]
    fn aggregator_crash_loop_makes_unhealthy() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorHealth::failed("fcp.discord", 5));
        let status = agg.evaluate();
        assert!(status.status.is_unhealthy());
        assert!(!status.is_ready());
        assert_eq!(status.crash_loop_count(), 1);
    }

    #[test]
    fn aggregator_mesh_disconnect_unhealthy() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_mesh(MeshHealth::disconnected());
        let status = agg.evaluate();
        assert!(status.status.is_unhealthy());
    }

    #[test]
    fn aggregator_resource_pressure_degraded() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_resources(ResourceHealth::new(850, 85.0, 100, 1024).with_memory_limit_mb(1000));
        let status = agg.evaluate();
        assert!(status.status.is_degraded());
        assert!(status.is_ready()); // degraded is still ready
    }

    #[test]
    fn aggregator_component_failures_escalation() {
        let mut agg = HealthAggregator::new("1.0.0", HealthConfig::default());
        agg.report_component(
            ComponentHealth::healthy("enforcement").with_failures(3),
        );
        let status = agg.evaluate();
        // 3 failures >= unhealthy_threshold (3) → unhealthy
        assert!(status.status.is_unhealthy());
    }

    #[test]
    fn aggregator_component_degraded_threshold() {
        let mut agg = HealthAggregator::new("1.0.0", HealthConfig::default());
        agg.report_component(
            ComponentHealth::healthy("enforcement").with_failures(1),
        );
        let status = agg.evaluate();
        // 1 failure >= degraded_threshold (1) → degraded
        assert!(status.status.is_degraded());
    }

    #[test]
    fn aggregator_component_zero_failures_healthy() {
        let mut agg = HealthAggregator::new("1.0.0", HealthConfig::default());
        agg.report_component(ComponentHealth::healthy("enforcement"));
        let status = agg.evaluate();
        assert!(status.is_healthy());
    }

    #[test]
    fn aggregator_update_existing_component() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_component(ComponentHealth::unhealthy("test", "down"));
        agg.report_component(ComponentHealth::healthy("test"));
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert_eq!(agg.component_count(), 1);
    }

    #[test]
    fn aggregator_update_existing_connector() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorHealth::failed("fcp.discord", 5));
        agg.report_connector(ConnectorHealth::running("fcp.discord", 100));
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert_eq!(agg.connector_count(), 1);
    }

    #[test]
    fn aggregator_multiple_connectors() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorHealth::running("fcp.discord", 100));
        agg.report_connector(ConnectorHealth::running("fcp.slack", 200));
        agg.report_connector(ConnectorHealth::stopped("fcp.telegram"));
        let status = agg.evaluate();
        assert_eq!(status.running_connector_count(), 2);
        assert_eq!(agg.connector_count(), 3);
    }

    #[test]
    fn aggregator_worst_case_rollup() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorHealth::running("fcp.discord", 100));
        agg.report_mesh(MeshHealth::connected(3));
        agg.report_resources(ResourceHealth::new(256, 30.0, 100, 1024));
        agg.report_component(ComponentHealth::degraded("enforcement", "slow"));
        let status = agg.evaluate();
        // One degraded component → overall degraded.
        assert!(status.status.is_degraded());
    }

    #[test]
    fn aggregator_uptime_is_non_negative() {
        let agg = HealthAggregator::with_defaults("1.0.0");
        let status = agg.evaluate();
        // Just created, uptime should be 0 or very small.
        assert!(status.uptime_seconds < 2);
    }

    #[test]
    fn aggregator_config_access() {
        let config = HealthConfig::new().with_check_interval_ms(10_000);
        let agg = HealthAggregator::new("1.0.0", config);
        assert_eq!(agg.config().check_interval_ms, 10_000);
    }

    // ────────── HealthStatus ──────────

    #[test]
    fn health_status_serialization() {
        let status = HealthStatus {
            status: HealthState::Healthy,
            version: "1.0.0".into(),
            uptime_seconds: 3600,
            connectors: vec![ConnectorHealth::running("fcp.discord", 100)],
            mesh: MeshHealth::connected(3),
            resources: ResourceHealth::new(256, 30.0, 100, 1024),
            components: vec![],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("fcp.discord"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn health_status_deserialization() {
        let status = HealthStatus {
            status: HealthState::Degraded {
                reasons: vec!["test".into()],
            },
            version: "2.0.0".into(),
            uptime_seconds: 0,
            connectors: vec![],
            mesh: MeshHealth::disconnected(),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![],
        };
        let json = serde_json::to_string(&status).unwrap();
        let restored: HealthStatus = serde_json::from_str(&json).unwrap();
        assert!(restored.status.is_degraded());
        assert_eq!(restored.version, "2.0.0");
    }

    #[test]
    fn health_status_ready_when_degraded() {
        let status = HealthStatus {
            status: HealthState::Degraded {
                reasons: vec!["test".into()],
            },
            version: "1.0.0".into(),
            uptime_seconds: 0,
            connectors: vec![],
            mesh: MeshHealth::connected(1),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![],
        };
        assert!(!status.is_healthy());
        assert!(status.is_ready());
    }

    #[test]
    fn health_status_not_ready_when_unhealthy() {
        let status = HealthStatus {
            status: HealthState::Unhealthy {
                reasons: vec!["down".into()],
            },
            version: "1.0.0".into(),
            uptime_seconds: 0,
            connectors: vec![],
            mesh: MeshHealth::disconnected(),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![],
        };
        assert!(!status.is_healthy());
        assert!(!status.is_ready());
    }

    // ────────── Serde roundtrips ──────────

    #[test]
    fn connector_health_serde_roundtrip() {
        let c = ConnectorHealth::running("fcp.discord", 100).with_restarts(3);
        let json = serde_json::to_string(&c).unwrap();
        let restored: ConnectorHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.connector_id, "fcp.discord");
        assert_eq!(restored.restart_count, 3);
    }

    #[test]
    fn mesh_health_serde_roundtrip() {
        let m = MeshHealth::connected(5);
        let json = serde_json::to_string(&m).unwrap();
        let restored: MeshHealth = serde_json::from_str(&json).unwrap();
        assert!(restored.connected);
        assert_eq!(restored.peer_count, 5);
    }

    #[test]
    fn resource_health_serde_roundtrip() {
        let r = ResourceHealth::new(512, 45.0, 200, 1024).with_memory_limit_mb(2048);
        let json = serde_json::to_string(&r).unwrap();
        let restored: ResourceHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.memory_used_mb, 512);
        assert_eq!(restored.memory_limit_mb, Some(2048));
    }

    #[test]
    fn component_health_serde_roundtrip() {
        let c = ComponentHealth::degraded("test", "slow")
            .with_elapsed_ms(42.5)
            .with_failures(2)
            .with_message("details");
        let json = serde_json::to_string(&c).unwrap();
        let restored: ComponentHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "test");
        assert_eq!(restored.consecutive_failures, 2);
        assert_eq!(restored.message.as_deref(), Some("details"));
    }

    #[test]
    fn health_config_serde_roundtrip() {
        let c = HealthConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let restored: HealthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.check_interval_ms, 30_000);
        assert_eq!(restored.unhealthy_threshold, 3);
    }

    // ────────── Edge cases ──────────

    #[test]
    fn aggregator_no_mesh_uses_disconnected_default() {
        let agg = HealthAggregator::with_defaults("1.0.0");
        let status = agg.evaluate();
        // No mesh reported → uses disconnected default.
        assert!(!status.mesh.connected);
    }

    #[test]
    fn aggregator_no_resources_uses_zero_default() {
        let agg = HealthAggregator::with_defaults("1.0.0");
        let status = agg.evaluate();
        assert_eq!(status.resources.memory_used_mb, 0);
    }

    #[test]
    fn multiple_degraded_components_still_degraded() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_component(ComponentHealth::degraded("a", "slow"));
        agg.report_component(ComponentHealth::degraded("b", "laggy"));
        let status = agg.evaluate();
        assert!(status.status.is_degraded());
        if let HealthState::Degraded { reasons } = &status.status {
            assert!(reasons.len() >= 2);
        }
    }

    #[test]
    fn mixed_connector_states() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorHealth::running("a", 100));
        agg.report_connector(ConnectorHealth::stopped("b"));
        let mut failing = ConnectorHealth::running("c", 50);
        failing.last_check_passed = Some(false);
        agg.report_connector(failing);
        let status = agg.evaluate();
        // One failing health check → degraded.
        assert!(status.status.is_degraded());
        assert_eq!(status.running_connector_count(), 2); // a and c are "running"
    }

    #[test]
    fn resource_multiple_pressures() {
        let r = ResourceHealth::new(850, 85.0, 900, 1024).with_memory_limit_mb(1000);
        let state = r.to_health_state();
        assert!(state.is_degraded());
        if let HealthState::Degraded { reasons } = state {
            // Memory, CPU, and FDs all degraded.
            assert!(reasons.len() >= 2);
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(HealthState::Healthy.severity() < HealthState::Degraded { reasons: vec![] }.severity());
        assert!(
            HealthState::Degraded { reasons: vec![] }.severity()
                < HealthState::Unhealthy { reasons: vec![] }.severity()
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // EXPANDED COVERAGE — 55 new tests
    // ══════════════════════════════════════════════════════════════════════

    // ────────── HealthState merge exhaustive ──────────

    #[test]
    fn merge_unhealthy_healthy() {
        let u = HealthState::Unhealthy {
            reasons: vec!["crash".into()],
        };
        let result = u.merge(&HealthState::Healthy);
        assert!(result.is_unhealthy());
        if let HealthState::Unhealthy { reasons } = &result {
            assert_eq!(reasons, &["crash"]);
        }
    }

    #[test]
    fn merge_unhealthy_degraded() {
        let u = HealthState::Unhealthy {
            reasons: vec!["crash".into()],
        };
        let d = HealthState::Degraded {
            reasons: vec!["slow".into()],
        };
        let result = u.merge(&d);
        assert!(result.is_unhealthy());
        // Only keeps unhealthy reasons (not degraded).
        if let HealthState::Unhealthy { reasons } = &result {
            assert_eq!(reasons, &["crash"]);
        }
    }

    #[test]
    fn merge_degraded_with_empty_reasons() {
        let a = HealthState::Degraded {
            reasons: vec![],
        };
        let b = HealthState::Degraded {
            reasons: vec!["x".into()],
        };
        if let HealthState::Degraded { reasons } = a.merge(&b) {
            assert_eq!(reasons, &["x"]);
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn merge_unhealthy_with_empty_reasons() {
        let a = HealthState::Unhealthy {
            reasons: vec![],
        };
        let b = HealthState::Unhealthy {
            reasons: vec!["fatal".into()],
        };
        if let HealthState::Unhealthy { reasons } = a.merge(&b) {
            assert_eq!(reasons, &["fatal"]);
        } else {
            panic!("expected unhealthy");
        }
    }

    #[test]
    fn merge_many_reasons_accumulate() {
        let a = HealthState::Degraded {
            reasons: vec!["r1".into(), "r2".into()],
        };
        let b = HealthState::Degraded {
            reasons: vec!["r3".into(), "r4".into()],
        };
        if let HealthState::Degraded { reasons } = a.merge(&b) {
            assert_eq!(reasons.len(), 4);
            assert_eq!(reasons[0], "r1");
            assert_eq!(reasons[3], "r4");
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn merge_is_not_commutative_for_mixed_unhealthy_degraded() {
        // When one is unhealthy and the other degraded, only the unhealthy
        // side's reasons are kept. The result depends on which side is unhealthy.
        let u = HealthState::Unhealthy {
            reasons: vec!["u_reason".into()],
        };
        let d = HealthState::Degraded {
            reasons: vec!["d_reason".into()],
        };
        let result_ud = u.merge(&d);
        let result_du = d.merge(&u);
        // Both unhealthy, but potentially different reasons.
        assert!(result_ud.is_unhealthy());
        assert!(result_du.is_unhealthy());
    }

    #[test]
    fn merge_chain_three_states() {
        let h = HealthState::Healthy;
        let d = HealthState::Degraded {
            reasons: vec!["slow".into()],
        };
        let u = HealthState::Unhealthy {
            reasons: vec!["dead".into()],
        };
        let result = h.merge(&d).merge(&u);
        assert!(result.is_unhealthy());
    }

    // ────────── HealthState clone and equality ──────────

    #[test]
    fn health_state_clone_healthy() {
        let s = HealthState::Healthy;
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn health_state_clone_degraded() {
        let s = HealthState::Degraded {
            reasons: vec!["r1".into(), "r2".into()],
        };
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn health_state_clone_unhealthy() {
        let s = HealthState::Unhealthy {
            reasons: vec!["x".into()],
        };
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn health_state_not_equal_different_variants() {
        let h = HealthState::Healthy;
        let d = HealthState::Degraded {
            reasons: vec!["r".into()],
        };
        assert_ne!(h, d);
    }

    #[test]
    fn health_state_not_equal_different_reasons() {
        let a = HealthState::Degraded {
            reasons: vec!["a".into()],
        };
        let b = HealthState::Degraded {
            reasons: vec!["b".into()],
        };
        assert_ne!(a, b);
    }

    // ────────── HealthState Display edge cases ──────────

    #[test]
    fn health_state_display_degraded_empty_reasons() {
        let s = HealthState::Degraded { reasons: vec![] };
        assert_eq!(s.to_string(), "degraded: ");
    }

    #[test]
    fn health_state_display_unhealthy_multiple_reasons() {
        let s = HealthState::Unhealthy {
            reasons: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(s.to_string(), "unhealthy: a; b; c");
    }

    // ────────── HealthState serde ──────────

    #[test]
    fn health_state_serde_healthy() {
        let s = HealthState::Healthy;
        let json = serde_json::to_string(&s).unwrap();
        let restored: HealthState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }

    #[test]
    fn health_state_serde_degraded() {
        let s = HealthState::Degraded {
            reasons: vec!["reason1".into(), "reason2".into()],
        };
        let json = serde_json::to_string(&s).unwrap();
        let restored: HealthState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }

    #[test]
    fn health_state_serde_unhealthy() {
        let s = HealthState::Unhealthy {
            reasons: vec!["fatal".into()],
        };
        let json = serde_json::to_string(&s).unwrap();
        let restored: HealthState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }

    #[test]
    fn health_state_serde_tagged_format() {
        let json = serde_json::to_string(&HealthState::Healthy).unwrap();
        assert!(json.contains(r#""state":"healthy"#));
    }

    // ────────── ComponentHealth edge cases ──────────

    #[test]
    fn component_healthy_no_message() {
        let c = ComponentHealth::healthy("comp");
        assert!(c.message.is_none());
        assert!(c.last_check_elapsed_ms.is_none());
    }

    #[test]
    fn component_builder_chain() {
        let c = ComponentHealth::unhealthy("db", "timeout")
            .with_elapsed_ms(120.5)
            .with_failures(7)
            .with_message("connection refused");
        assert_eq!(c.name, "db");
        assert!(c.state.is_unhealthy());
        assert_eq!(c.last_check_elapsed_ms, Some(120.5));
        assert_eq!(c.consecutive_failures, 7);
        assert_eq!(c.message.as_deref(), Some("connection refused"));
    }

    #[test]
    fn component_serde_skips_none_message() {
        let c = ComponentHealth::healthy("test");
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn component_serde_includes_some_message() {
        let c = ComponentHealth::healthy("test").with_message("info");
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("message"));
        assert!(json.contains("info"));
    }

    #[test]
    fn component_debug_format() {
        let c = ComponentHealth::healthy("debug_test");
        let dbg = format!("{c:?}");
        assert!(dbg.contains("debug_test"));
        assert!(dbg.contains("ComponentHealth"));
    }

    // ────────── ConnectorHealth edge cases ──────────

    #[test]
    fn connector_failed_exactly_3_restarts_is_crash_loop() {
        let c = ConnectorHealth::failed("test", 3);
        assert!(c.crash_loop);
        assert_eq!(c.restart_count, 3);
    }

    #[test]
    fn connector_stopped_health_state_is_healthy() {
        let c = ConnectorHealth::stopped("test");
        // Stopped connector: last_check_passed is None → healthy.
        assert!(c.to_health_state().is_healthy());
    }

    #[test]
    fn connector_health_state_message_content() {
        let c = ConnectorHealth::failed("fcp.redis", 5);
        if let HealthState::Unhealthy { reasons } = c.to_health_state() {
            assert!(reasons[0].contains("fcp.redis"));
            assert!(reasons[0].contains("crash loop"));
            assert!(reasons[0].contains('5'));
        } else {
            panic!("expected unhealthy");
        }
    }

    #[test]
    fn connector_failed_check_not_crash_loop_is_degraded() {
        let c = ConnectorHealth::failed("test", 1);
        assert!(!c.crash_loop);
        assert_eq!(c.last_check_passed, Some(false));
        let state = c.to_health_state();
        assert!(state.is_degraded());
    }

    #[test]
    fn connector_running_zero_uptime() {
        let c = ConnectorHealth::running("test", 0);
        assert_eq!(c.uptime_seconds, Some(0));
        assert!(c.to_health_state().is_healthy());
    }

    #[test]
    fn connector_with_restarts_preserves_other_fields() {
        let c = ConnectorHealth::stopped("x").with_restarts(10);
        assert_eq!(c.process_state, "stopped");
        assert_eq!(c.restart_count, 10);
        assert!(c.uptime_seconds.is_none());
    }

    #[test]
    fn connector_clone_independence() {
        let original = ConnectorHealth::running("orig", 999);
        let cloned = original.clone();
        assert_eq!(cloned.connector_id, "orig");
        assert_eq!(cloned.uptime_seconds, Some(999));
        assert_eq!(original.connector_id, "orig");
    }

    // ────────── MeshHealth edge cases ──────────

    #[test]
    fn mesh_connected_zero_peers() {
        let m = MeshHealth::connected(0);
        assert!(m.connected);
        assert_eq!(m.peer_count, 0);
        // Still healthy since connected=true and both fresh.
        assert!(m.to_health_state().is_healthy());
    }

    #[test]
    fn mesh_connected_sync_age() {
        let m = MeshHealth::connected(5);
        assert_eq!(m.last_sync_age_seconds, Some(0));
    }

    #[test]
    fn mesh_disconnected_no_sync_age() {
        let m = MeshHealth::disconnected();
        assert!(m.last_sync_age_seconds.is_none());
    }

    #[test]
    fn mesh_disconnected_health_reason() {
        let m = MeshHealth::disconnected();
        if let HealthState::Unhealthy { reasons } = m.to_health_state() {
            assert_eq!(reasons, &["mesh disconnected"]);
        } else {
            panic!("expected unhealthy");
        }
    }

    #[test]
    fn mesh_stale_checkpoint_reason() {
        let mut m = MeshHealth::connected(3);
        m.checkpoint_fresh = false;
        if let HealthState::Degraded { reasons } = m.to_health_state() {
            assert_eq!(reasons, &["checkpoint stale"]);
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn mesh_stale_revocation_reason() {
        let mut m = MeshHealth::connected(3);
        m.revocation_fresh = false;
        if let HealthState::Degraded { reasons } = m.to_health_state() {
            assert_eq!(reasons, &["revocation list stale"]);
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn mesh_both_stale_reason_order() {
        let mut m = MeshHealth::connected(3);
        m.checkpoint_fresh = false;
        m.revocation_fresh = false;
        if let HealthState::Degraded { reasons } = m.to_health_state() {
            assert_eq!(reasons[0], "checkpoint stale");
            assert_eq!(reasons[1], "revocation list stale");
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn mesh_clone_preserves_fields() {
        let m = MeshHealth::connected(42);
        let cloned = m.clone();
        assert_eq!(cloned.peer_count, 42);
        assert!(cloned.checkpoint_fresh);
        assert!(cloned.revocation_fresh);
        assert_eq!(m.peer_count, 42);
    }

    // ────────── ResourceHealth threshold edge cases ──────────

    #[test]
    fn resource_memory_exactly_at_80_percent() {
        let r = ResourceHealth::new(800, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!((util - 0.8).abs() < f64::EPSILON);
        // 0.80 is NOT > 0.80 → healthy.
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_memory_just_above_80_percent() {
        let r = ResourceHealth::new(810, 0.0, 0, 1024).with_memory_limit_mb(1000);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_memory_exactly_at_95_percent() {
        let r = ResourceHealth::new(950, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!((util - 0.95).abs() < f64::EPSILON);
        // 0.95 is NOT > 0.95 → stays degraded (>0.80 but not >0.95).
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_memory_just_above_95_percent() {
        let r = ResourceHealth::new(960, 0.0, 0, 1024).with_memory_limit_mb(1000);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_memory_at_100_percent() {
        let r = ResourceHealth::new(1000, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!((util - 1.0).abs() < f64::EPSILON);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_memory_over_100_percent() {
        let r = ResourceHealth::new(1500, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!(util > 1.0);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_memory_at_0_percent() {
        let r = ResourceHealth::new(0, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!(util.abs() < f64::EPSILON);
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_cpu_exactly_80() {
        let r = ResourceHealth::new(0, 80.0, 0, 1024);
        // 80.0 is NOT > 80.0 → healthy.
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_cpu_just_above_80() {
        let r = ResourceHealth::new(0, 80.1, 0, 1024);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_cpu_exactly_95() {
        let r = ResourceHealth::new(0, 95.0, 0, 1024);
        // 95.0 is NOT > 95.0 → degraded (>80 but not >95).
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_cpu_just_above_95() {
        let r = ResourceHealth::new(0, 95.1, 0, 1024);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_cpu_at_zero() {
        let r = ResourceHealth::new(0, 0.0, 0, 1024);
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_fd_exactly_at_80_percent() {
        // 80% of 1000 = 800.
        let r = ResourceHealth::new(0, 0.0, 800, 1000);
        let util = r.fd_utilisation();
        assert!((util - 0.8).abs() < f64::EPSILON);
        // 0.80 is NOT > 0.80 → healthy.
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_fd_just_above_80_percent() {
        let r = ResourceHealth::new(0, 0.0, 810, 1000);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_fd_exactly_at_95_percent() {
        let r = ResourceHealth::new(0, 0.0, 950, 1000);
        let util = r.fd_utilisation();
        assert!((util - 0.95).abs() < f64::EPSILON);
        // 0.95 is NOT > 0.95 → degraded.
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_fd_just_above_95_percent() {
        let r = ResourceHealth::new(0, 0.0, 960, 1000);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_fd_at_100_percent() {
        let r = ResourceHealth::new(0, 0.0, 1024, 1024);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_fd_at_zero() {
        let r = ResourceHealth::new(0, 0.0, 0, 1024);
        let util = r.fd_utilisation();
        assert!(util.abs() < f64::EPSILON);
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_all_critical_returns_first_unhealthy() {
        // Memory > 95%, CPU > 95%, FDs > 95% — memory check fires first.
        let r = ResourceHealth::new(990, 99.0, 990, 1000).with_memory_limit_mb(1000);
        let state = r.to_health_state();
        assert!(state.is_unhealthy());
        if let HealthState::Unhealthy { reasons } = &state {
            // Memory check returns first.
            assert!(reasons[0].contains("memory"));
        }
    }

    #[test]
    fn resource_cpu_unhealthy_no_memory_limit() {
        // No memory limit → skip memory, CPU > 95 → unhealthy.
        let r = ResourceHealth::new(0, 99.0, 0, 1024);
        let state = r.to_health_state();
        assert!(state.is_unhealthy());
        if let HealthState::Unhealthy { reasons } = &state {
            assert!(reasons[0].contains("CPU"));
        }
    }

    #[test]
    fn resource_fd_unhealthy_memory_and_cpu_ok() {
        let r = ResourceHealth::new(0, 0.0, 999, 1000);
        let state = r.to_health_state();
        assert!(state.is_unhealthy());
        if let HealthState::Unhealthy { reasons } = &state {
            assert!(reasons[0].contains("FD"));
        }
    }

    // ────────── HealthConfig validation and builder ──────────

    #[test]
    fn config_new_equals_default() {
        let a = HealthConfig::new();
        let b = HealthConfig::default();
        assert_eq!(a.check_interval_ms, b.check_interval_ms);
        assert_eq!(a.check_timeout_ms, b.check_timeout_ms);
        assert_eq!(a.unhealthy_threshold, b.unhealthy_threshold);
        assert_eq!(a.degraded_threshold, b.degraded_threshold);
    }

    #[test]
    fn config_default_thresholds() {
        let c = HealthConfig::default();
        assert!((c.memory_degraded_threshold - 0.80).abs() < f64::EPSILON);
        assert!((c.memory_unhealthy_threshold - 0.95).abs() < f64::EPSILON);
        assert!((f64::from(c.cpu_degraded_threshold) - 80.0).abs() < f64::EPSILON);
        assert!((f64::from(c.cpu_unhealthy_threshold) - 95.0).abs() < f64::EPSILON);
    }

    #[test]
    fn config_check_interval_duration() {
        let c = HealthConfig::new().with_check_interval_ms(60_000);
        assert_eq!(c.check_interval(), Duration::from_mins(1));
    }

    #[test]
    fn config_check_timeout_duration() {
        let c = HealthConfig::new().with_check_timeout_ms(10_000);
        assert_eq!(c.check_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn config_zero_interval() {
        let c = HealthConfig::new().with_check_interval_ms(0);
        assert_eq!(c.check_interval(), Duration::from_secs(0));
    }

    #[test]
    fn config_clone_independence() {
        let original = HealthConfig::new().with_check_interval_ms(5000);
        let cloned = original.clone();
        assert_eq!(cloned.check_interval_ms, 5000);
        assert_eq!(original.check_interval_ms, 5000);
    }

    #[test]
    fn config_debug_format() {
        let c = HealthConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("HealthConfig"));
        assert!(dbg.contains("30000"));
    }

    // ────────── HealthAggregator expanded ──────────

    #[test]
    fn aggregator_many_components_worst_wins() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        for i in 0..10 {
            agg.report_component(ComponentHealth::healthy(format!("comp_{i}")));
        }
        agg.report_component(ComponentHealth::unhealthy("bad", "fatal"));
        let status = agg.evaluate();
        assert!(status.status.is_unhealthy());
        assert_eq!(agg.component_count(), 11);
    }

    #[test]
    fn aggregator_component_failures_below_degraded_threshold() {
        let config = HealthConfig::new().with_unhealthy_threshold(5);
        let mut agg = HealthAggregator::new("1.0.0", config);
        agg.report_component(ComponentHealth::healthy("x").with_failures(0));
        let status = agg.evaluate();
        assert!(status.is_healthy());
    }

    #[test]
    fn aggregator_component_failures_between_thresholds() {
        let config = HealthConfig {
            degraded_threshold: 2,
            unhealthy_threshold: 5,
            ..HealthConfig::default()
        };
        let mut agg = HealthAggregator::new("1.0.0", config);
        agg.report_component(ComponentHealth::healthy("x").with_failures(3));
        let status = agg.evaluate();
        // 3 >= degraded(2) but < unhealthy(5) → degraded.
        assert!(status.status.is_degraded());
    }

    #[test]
    fn aggregator_component_failures_at_unhealthy_threshold() {
        let config = HealthConfig {
            unhealthy_threshold: 5,
            ..HealthConfig::default()
        };
        let mut agg = HealthAggregator::new("1.0.0", config);
        agg.report_component(ComponentHealth::healthy("x").with_failures(5));
        let status = agg.evaluate();
        assert!(status.status.is_unhealthy());
    }

    #[test]
    fn aggregator_mixed_healthy_and_crash_loop() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorHealth::running("a", 100));
        agg.report_connector(ConnectorHealth::running("b", 200));
        agg.report_connector(ConnectorHealth::failed("c", 10));
        let status = agg.evaluate();
        assert!(status.status.is_unhealthy());
        assert_eq!(status.running_connector_count(), 2);
        assert_eq!(status.crash_loop_count(), 1);
    }

    #[test]
    fn aggregator_mesh_override_updates() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_mesh(MeshHealth::disconnected());
        let s1 = agg.evaluate();
        assert!(s1.status.is_unhealthy());

        agg.report_mesh(MeshHealth::connected(5));
        let s2 = agg.evaluate();
        assert!(s2.is_healthy());
    }

    #[test]
    fn aggregator_resource_override_updates() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_resources(ResourceHealth::new(0, 99.0, 0, 1024));
        let s1 = agg.evaluate();
        assert!(s1.status.is_unhealthy());

        agg.report_resources(ResourceHealth::new(0, 10.0, 0, 1024));
        let s2 = agg.evaluate();
        assert!(s2.is_healthy());
    }

    #[test]
    fn aggregator_evaluate_default_mesh_is_disconnected() {
        let agg = HealthAggregator::with_defaults("1.0.0");
        let status = agg.evaluate();
        assert!(!status.mesh.connected);
        assert_eq!(status.mesh.peer_count, 0);
    }

    #[test]
    fn aggregator_evaluate_default_resources() {
        let agg = HealthAggregator::with_defaults("1.0.0");
        let status = agg.evaluate();
        assert_eq!(status.resources.memory_used_mb, 0);
        assert_eq!(status.resources.max_fds, 1024);
    }

    #[test]
    fn aggregator_version_preserved() {
        let agg = HealthAggregator::with_defaults("2.5.3-beta");
        let status = agg.evaluate();
        assert_eq!(status.version, "2.5.3-beta");
    }

    // ────────── HealthStatus composite evaluations ──────────

    #[test]
    fn health_status_running_count_empty() {
        let status = HealthStatus {
            status: HealthState::Healthy,
            version: "1.0.0".into(),
            uptime_seconds: 0,
            connectors: vec![],
            mesh: MeshHealth::connected(1),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![],
        };
        assert_eq!(status.running_connector_count(), 0);
        assert_eq!(status.crash_loop_count(), 0);
    }

    #[test]
    fn health_status_crash_loop_count_many() {
        let status = HealthStatus {
            status: HealthState::Healthy,
            version: "1.0.0".into(),
            uptime_seconds: 0,
            connectors: vec![
                ConnectorHealth::failed("a", 5),
                ConnectorHealth::failed("b", 4),
                ConnectorHealth::running("c", 100),
            ],
            mesh: MeshHealth::connected(1),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![],
        };
        assert_eq!(status.crash_loop_count(), 2);
        assert_eq!(status.running_connector_count(), 1);
    }

    #[test]
    fn health_status_serialization_unhealthy() {
        let status = HealthStatus {
            status: HealthState::Unhealthy {
                reasons: vec!["bad".into()],
            },
            version: "1.0.0".into(),
            uptime_seconds: 42,
            connectors: vec![],
            mesh: MeshHealth::disconnected(),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![ComponentHealth::unhealthy("db", "timeout")],
        };
        let json = serde_json::to_string(&status).unwrap();
        let restored: HealthStatus = serde_json::from_str(&json).unwrap();
        assert!(restored.status.is_unhealthy());
        assert_eq!(restored.uptime_seconds, 42);
        assert_eq!(restored.components.len(), 1);
        assert_eq!(restored.components[0].name, "db");
    }

    #[test]
    fn health_status_ready_and_healthy() {
        let status = HealthStatus {
            status: HealthState::Healthy,
            version: "1.0.0".into(),
            uptime_seconds: 0,
            connectors: vec![],
            mesh: MeshHealth::connected(1),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![],
        };
        assert!(status.is_healthy());
        assert!(status.is_ready());
    }

    #[test]
    fn health_status_debug_format() {
        let status = HealthStatus {
            status: HealthState::Healthy,
            version: "1.0.0".into(),
            uptime_seconds: 0,
            connectors: vec![],
            mesh: MeshHealth::connected(1),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![],
        };
        let dbg = format!("{status:?}");
        assert!(dbg.contains("HealthStatus"));
        assert!(dbg.contains("1.0.0"));
    }
}
