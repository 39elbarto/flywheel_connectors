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
//! composite [`CompositeHealthStatus`] is the worst-case rollup.

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
            (Self::Degraded { reasons }, _) | (_, Self::Degraded { reasons }) => Self::Degraded {
                reasons: reasons.clone(),
            },
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

/// Host-local health details for a single connector process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorProcessHealth {
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

impl ConnectorProcessHealth {
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
                reasons: vec![format!(
                    "{}: crash loop ({} restarts)",
                    self.connector_id, self.restart_count
                )],
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
pub struct CompositeHealthStatus {
    /// Overall health state (worst-case rollup).
    pub status: HealthState,
    /// Host version string.
    pub version: String,
    /// Host uptime in seconds.
    pub uptime_seconds: u64,
    /// Per-connector health details.
    pub connectors: Vec<ConnectorProcessHealth>,
    /// Mesh connectivity health.
    pub mesh: MeshHealth,
    /// System resource health.
    pub resources: ResourceHealth,
    /// Per-subsystem component health.
    pub components: Vec<ComponentHealth>,
}

impl CompositeHealthStatus {
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
    connectors: Vec<ConnectorProcessHealth>,
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
        if let Some(existing) = self.components.iter_mut().find(|c| c.name == health.name) {
            *existing = health;
        } else {
            self.components.push(health);
        }
    }

    /// Report health for a connector.
    pub fn report_connector(&mut self, health: ConnectorProcessHealth) {
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
    pub fn evaluate(&self) -> CompositeHealthStatus {
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
            let component_state =
                if component.consecutive_failures >= self.config.unhealthy_threshold {
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

        CompositeHealthStatus {
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

    // ────────── ConnectorProcessHealth ──────────

    #[test]
    fn connector_running() {
        let c = ConnectorProcessHealth::running("fcp.discord", 3600);
        assert_eq!(c.process_state, "running");
        assert_eq!(c.uptime_seconds, Some(3600));
        assert!(!c.crash_loop);
    }

    #[test]
    fn connector_stopped() {
        let c = ConnectorProcessHealth::stopped("fcp.discord");
        assert_eq!(c.process_state, "stopped");
        assert!(c.uptime_seconds.is_none());
    }

    #[test]
    fn connector_failed_crash_loop() {
        let c = ConnectorProcessHealth::failed("fcp.discord", 5);
        assert!(c.crash_loop);
        assert_eq!(c.restart_count, 5);
    }

    #[test]
    fn connector_failed_no_crash_loop() {
        let c = ConnectorProcessHealth::failed("fcp.discord", 2);
        assert!(!c.crash_loop);
    }

    #[test]
    fn connector_with_restarts() {
        let c = ConnectorProcessHealth::running("fcp.discord", 100).with_restarts(3);
        assert_eq!(c.restart_count, 3);
    }

    #[test]
    fn connector_health_state_running() {
        let c = ConnectorProcessHealth::running("fcp.discord", 100);
        assert!(c.to_health_state().is_healthy());
    }

    #[test]
    fn connector_health_state_crash_loop() {
        let c = ConnectorProcessHealth::failed("fcp.discord", 5);
        assert!(c.to_health_state().is_unhealthy());
    }

    #[test]
    fn connector_health_state_check_failing() {
        let mut c = ConnectorProcessHealth::running("fcp.discord", 100);
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
        agg.report_connector(ConnectorProcessHealth::running("fcp.discord", 100));
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert_eq!(status.running_connector_count(), 1);
        assert_eq!(status.crash_loop_count(), 0);
    }

    #[test]
    fn aggregator_crash_loop_makes_unhealthy() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorProcessHealth::failed("fcp.discord", 5));
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
        agg.report_component(ComponentHealth::healthy("enforcement").with_failures(3));
        let status = agg.evaluate();
        // 3 failures >= unhealthy_threshold (3) → unhealthy
        assert!(status.status.is_unhealthy());
    }

    #[test]
    fn aggregator_component_degraded_threshold() {
        let mut agg = HealthAggregator::new("1.0.0", HealthConfig::default());
        agg.report_component(ComponentHealth::healthy("enforcement").with_failures(1));
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
        agg.report_connector(ConnectorProcessHealth::failed("fcp.discord", 5));
        agg.report_connector(ConnectorProcessHealth::running("fcp.discord", 100));
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert_eq!(agg.connector_count(), 1);
    }

    #[test]
    fn aggregator_multiple_connectors() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorProcessHealth::running("fcp.discord", 100));
        agg.report_connector(ConnectorProcessHealth::running("fcp.slack", 200));
        agg.report_connector(ConnectorProcessHealth::stopped("fcp.telegram"));
        let status = agg.evaluate();
        assert_eq!(status.running_connector_count(), 2);
        assert_eq!(agg.connector_count(), 3);
    }

    #[test]
    fn aggregator_worst_case_rollup() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorProcessHealth::running("fcp.discord", 100));
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

    // ────────── CompositeHealthStatus ──────────

    #[test]
    fn health_status_serialization() {
        let status = CompositeHealthStatus {
            status: HealthState::Healthy,
            version: "1.0.0".into(),
            uptime_seconds: 3600,
            connectors: vec![ConnectorProcessHealth::running("fcp.discord", 100)],
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
        let status = CompositeHealthStatus {
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
        let restored: CompositeHealthStatus = serde_json::from_str(&json).unwrap();
        assert!(restored.status.is_degraded());
        assert_eq!(restored.version, "2.0.0");
    }

    #[test]
    fn health_status_ready_when_degraded() {
        let status = CompositeHealthStatus {
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
        let status = CompositeHealthStatus {
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
        let c = ConnectorProcessHealth::running("fcp.discord", 100).with_restarts(3);
        let json = serde_json::to_string(&c).unwrap();
        let restored: ConnectorProcessHealth = serde_json::from_str(&json).unwrap();
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
        agg.report_connector(ConnectorProcessHealth::running("a", 100));
        agg.report_connector(ConnectorProcessHealth::stopped("b"));
        let mut failing = ConnectorProcessHealth::running("c", 50);
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
        assert!(
            HealthState::Healthy.severity() < HealthState::Degraded { reasons: vec![] }.severity()
        );
        assert!(
            HealthState::Degraded { reasons: vec![] }.severity()
                < HealthState::Unhealthy { reasons: vec![] }.severity()
        );
    }

    // ────────── HealthState merge (additional edge cases) ──────────

    #[test]
    fn merge_unhealthy_degraded_keeps_unhealthy() {
        let u = HealthState::Unhealthy {
            reasons: vec!["crash".into()],
        };
        let d = HealthState::Degraded {
            reasons: vec!["slow".into()],
        };
        let result = u.merge(&d);
        assert!(result.is_unhealthy());
        if let HealthState::Unhealthy { reasons } = &result {
            assert_eq!(reasons.len(), 1);
            assert_eq!(reasons[0], "crash");
        } else {
            panic!("expected unhealthy");
        }
    }

    #[test]
    fn merge_with_empty_reasons_degraded() {
        let a = HealthState::Degraded { reasons: vec![] };
        let b = HealthState::Degraded {
            reasons: vec!["r".into()],
        };
        if let HealthState::Degraded { reasons } = a.merge(&b) {
            assert_eq!(reasons.len(), 1);
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn merge_with_empty_reasons_unhealthy() {
        let a = HealthState::Unhealthy { reasons: vec![] };
        let b = HealthState::Unhealthy { reasons: vec![] };
        if let HealthState::Unhealthy { reasons } = a.merge(&b) {
            assert!(reasons.is_empty());
        } else {
            panic!("expected unhealthy");
        }
    }

    #[test]
    fn merge_is_commutative_healthy_degraded() {
        let h = HealthState::Healthy;
        let d = HealthState::Degraded {
            reasons: vec!["x".into()],
        };
        assert_eq!(h.merge(&d).severity(), d.merge(&h).severity());
    }

    #[test]
    fn merge_is_commutative_healthy_unhealthy() {
        let h = HealthState::Healthy;
        let u = HealthState::Unhealthy {
            reasons: vec!["x".into()],
        };
        assert_eq!(h.merge(&u).severity(), u.merge(&h).severity());
    }

    #[test]
    fn merge_is_commutative_degraded_unhealthy() {
        let d = HealthState::Degraded {
            reasons: vec!["d".into()],
        };
        let u = HealthState::Unhealthy {
            reasons: vec!["u".into()],
        };
        assert_eq!(d.merge(&u).severity(), u.merge(&d).severity());
    }

    #[test]
    fn merge_multiple_reasons_preserved_in_order() {
        let a = HealthState::Degraded {
            reasons: vec!["first".into(), "second".into()],
        };
        let b = HealthState::Degraded {
            reasons: vec!["third".into()],
        };
        if let HealthState::Degraded { reasons } = a.merge(&b) {
            assert_eq!(reasons.len(), 3);
            assert_eq!(reasons[0], "first");
            assert_eq!(reasons[1], "second");
            assert_eq!(reasons[2], "third");
        } else {
            panic!("expected degraded");
        }
    }

    // ────────── HealthState Display edge cases ──────────

    #[test]
    fn display_degraded_empty_reasons() {
        let s = HealthState::Degraded { reasons: vec![] };
        assert_eq!(s.to_string(), "degraded: ");
    }

    #[test]
    fn display_unhealthy_empty_reasons() {
        let s = HealthState::Unhealthy { reasons: vec![] };
        assert_eq!(s.to_string(), "unhealthy: ");
    }

    #[test]
    fn display_degraded_single_reason() {
        let s = HealthState::Degraded {
            reasons: vec!["only one".into()],
        };
        assert_eq!(s.to_string(), "degraded: only one");
    }

    #[test]
    fn display_unhealthy_multiple_reasons() {
        let s = HealthState::Unhealthy {
            reasons: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(s.to_string(), "unhealthy: a; b; c");
    }

    // ────────── HealthState serde ──────────

    #[test]
    fn health_state_serde_healthy_roundtrip() {
        let s = HealthState::Healthy;
        let json = serde_json::to_string(&s).unwrap();
        let restored: HealthState = serde_json::from_str(&json).unwrap();
        assert!(restored.is_healthy());
    }

    #[test]
    fn health_state_serde_degraded_roundtrip() {
        let s = HealthState::Degraded {
            reasons: vec!["r1".into(), "r2".into()],
        };
        let json = serde_json::to_string(&s).unwrap();
        let restored: HealthState = serde_json::from_str(&json).unwrap();
        assert!(restored.is_degraded());
        if let HealthState::Degraded { reasons } = restored {
            assert_eq!(reasons.len(), 2);
        }
    }

    #[test]
    fn health_state_serde_unhealthy_roundtrip() {
        let s = HealthState::Unhealthy {
            reasons: vec!["critical".into()],
        };
        let json = serde_json::to_string(&s).unwrap();
        let restored: HealthState = serde_json::from_str(&json).unwrap();
        assert!(restored.is_unhealthy());
    }

    // ────────── ComponentHealth edge cases ──────────

    #[test]
    fn component_healthy_defaults_no_message() {
        let c = ComponentHealth::healthy("comp");
        assert!(c.message.is_none());
        assert!(c.last_check_elapsed_ms.is_none());
    }

    #[test]
    fn component_degraded_reason_stored() {
        let c = ComponentHealth::degraded("comp", "latency high");
        if let HealthState::Degraded { reasons } = &c.state {
            assert_eq!(reasons.len(), 1);
            assert_eq!(reasons[0], "latency high");
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn component_unhealthy_reason_stored() {
        let c = ComponentHealth::unhealthy("comp", "OOM");
        if let HealthState::Unhealthy { reasons } = &c.state {
            assert_eq!(reasons.len(), 1);
            assert_eq!(reasons[0], "OOM");
        } else {
            panic!("expected unhealthy");
        }
    }

    #[test]
    fn component_builder_chain() {
        let c = ComponentHealth::healthy("comp")
            .with_elapsed_ms(10.0)
            .with_failures(2)
            .with_message("checking");
        assert_eq!(c.last_check_elapsed_ms, Some(10.0));
        assert_eq!(c.consecutive_failures, 2);
        assert_eq!(c.message.as_deref(), Some("checking"));
        assert!(c.state.is_healthy());
    }

    #[test]
    fn component_serde_skip_none_message() {
        let c = ComponentHealth::healthy("comp");
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn component_serde_includes_message_when_set() {
        let c = ComponentHealth::healthy("comp").with_message("info");
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("message"));
        assert!(json.contains("info"));
    }

    // ────────── ConnectorProcessHealth edge cases ──────────

    #[test]
    fn connector_failed_exact_threshold() {
        // 3 restarts is the exact crash_loop threshold
        let c = ConnectorProcessHealth::failed("x", 3);
        assert!(c.crash_loop);
        assert_eq!(c.restart_count, 3);
    }

    #[test]
    fn connector_failed_below_threshold() {
        let c = ConnectorProcessHealth::failed("x", 2);
        assert!(!c.crash_loop);
    }

    #[test]
    fn connector_failed_zero_restarts() {
        let c = ConnectorProcessHealth::failed("x", 0);
        assert!(!c.crash_loop);
        assert_eq!(c.process_state, "failed");
        assert_eq!(c.last_check_passed, Some(false));
    }

    #[test]
    fn connector_stopped_health_state_is_healthy() {
        // Stopped connector has last_check_passed=None, not in crash loop → healthy
        let c = ConnectorProcessHealth::stopped("x");
        assert!(c.to_health_state().is_healthy());
    }

    #[test]
    fn connector_running_check_passed_none_is_healthy() {
        let mut c = ConnectorProcessHealth::running("x", 100);
        c.last_check_passed = None;
        assert!(c.to_health_state().is_healthy());
    }

    #[test]
    fn connector_health_state_crash_loop_message_format() {
        let c = ConnectorProcessHealth::failed("fcp.test", 5);
        if let HealthState::Unhealthy { reasons } = c.to_health_state() {
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("fcp.test"));
            assert!(reasons[0].contains("crash loop"));
            assert!(reasons[0].contains('5'));
        } else {
            panic!("expected unhealthy");
        }
    }

    #[test]
    fn connector_health_state_failing_message_format() {
        let mut c = ConnectorProcessHealth::running("fcp.test", 50);
        c.last_check_passed = Some(false);
        if let HealthState::Degraded { reasons } = c.to_health_state() {
            assert!(reasons[0].contains("fcp.test"));
            assert!(reasons[0].contains("health check failing"));
        } else {
            panic!("expected degraded");
        }
    }

    // ────────── MeshHealth edge cases ──────────

    #[test]
    fn mesh_connected_zero_peers() {
        let m = MeshHealth::connected(0);
        assert!(m.connected);
        assert_eq!(m.peer_count, 0);
        // Still healthy — connected with fresh data
        assert!(m.to_health_state().is_healthy());
    }

    #[test]
    fn mesh_connected_initial_sync_age() {
        let m = MeshHealth::connected(3);
        assert_eq!(m.last_sync_age_seconds, Some(0));
    }

    #[test]
    fn mesh_disconnected_no_sync_age() {
        let m = MeshHealth::disconnected();
        assert!(m.last_sync_age_seconds.is_none());
        assert!(!m.checkpoint_fresh);
        assert!(!m.revocation_fresh);
    }

    #[test]
    fn mesh_disconnected_health_reason_text() {
        let m = MeshHealth::disconnected();
        if let HealthState::Unhealthy { reasons } = m.to_health_state() {
            assert_eq!(reasons[0], "mesh disconnected");
        } else {
            panic!("expected unhealthy");
        }
    }

    #[test]
    fn mesh_stale_checkpoint_reason_text() {
        let mut m = MeshHealth::connected(3);
        m.checkpoint_fresh = false;
        if let HealthState::Degraded { reasons } = m.to_health_state() {
            assert!(reasons.contains(&"checkpoint stale".to_string()));
        } else {
            panic!("expected degraded");
        }
    }

    #[test]
    fn mesh_stale_revocation_reason_text() {
        let mut m = MeshHealth::connected(3);
        m.revocation_fresh = false;
        if let HealthState::Degraded { reasons } = m.to_health_state() {
            assert!(reasons.contains(&"revocation list stale".to_string()));
        } else {
            panic!("expected degraded");
        }
    }

    // ────────── ResourceHealth boundary conditions ──────────

    #[test]
    fn resource_memory_at_exact_80_percent_is_degraded() {
        // 80.1% should be degraded (threshold is > 0.80)
        let r = ResourceHealth::new(801, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!(util > 0.80);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_memory_at_exact_80_percent_is_healthy() {
        // Exactly 80% is not > 0.80, so healthy
        let r = ResourceHealth::new(800, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!((util - 0.80).abs() < f64::EPSILON);
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_memory_at_exact_95_percent_is_degraded() {
        // Exactly 95% is not > 0.95, so degraded (not unhealthy)
        let r = ResourceHealth::new(950, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!((util - 0.95).abs() < f64::EPSILON);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_memory_above_95_percent_is_unhealthy() {
        let r = ResourceHealth::new(951, 0.0, 0, 1024).with_memory_limit_mb(1000);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_cpu_at_exact_80_is_healthy() {
        // cpu_percent > 80.0 triggers degraded, so 80.0 exactly is healthy
        let r = ResourceHealth::new(0, 80.0, 0, 1024);
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_cpu_just_above_80_is_degraded() {
        let r = ResourceHealth::new(0, 80.1, 0, 1024);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_cpu_at_exact_95_is_degraded() {
        // cpu_percent > 95.0 triggers unhealthy, so 95.0 exactly is degraded
        let r = ResourceHealth::new(0, 95.0, 0, 1024);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_cpu_just_above_95_is_unhealthy() {
        let r = ResourceHealth::new(0, 95.1, 0, 1024);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_fd_at_exact_80_percent_is_healthy() {
        // 80/100 = 0.80, not > 0.80, so healthy
        let r = ResourceHealth::new(0, 0.0, 80, 100);
        let util = r.fd_utilisation();
        assert!((util - 0.80).abs() < f64::EPSILON);
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_fd_above_80_percent_is_degraded() {
        let r = ResourceHealth::new(0, 0.0, 81, 100);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_fd_at_exact_95_percent_is_degraded() {
        // 95/100 = 0.95, not > 0.95, so degraded (from > 0.80)
        let r = ResourceHealth::new(0, 0.0, 95, 100);
        assert!(r.to_health_state().is_degraded());
    }

    #[test]
    fn resource_fd_above_95_percent_is_unhealthy() {
        let r = ResourceHealth::new(0, 0.0, 96, 100);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_memory_utilisation_exact_one() {
        let r = ResourceHealth::new(1000, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!((util - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn resource_memory_over_limit() {
        // used > limit is possible
        let r = ResourceHealth::new(1500, 0.0, 0, 1024).with_memory_limit_mb(1000);
        let util = r.memory_utilisation().unwrap();
        assert!(util > 1.0);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_fd_utilisation_exact_one() {
        let r = ResourceHealth::new(0, 0.0, 1024, 1024);
        let util = r.fd_utilisation();
        assert!((util - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn resource_cpu_at_zero() {
        let r = ResourceHealth::new(0, 0.0, 0, 1024);
        assert!(r.to_health_state().is_healthy());
    }

    #[test]
    fn resource_cpu_at_100() {
        let r = ResourceHealth::new(0, 100.0, 0, 1024);
        assert!(r.to_health_state().is_unhealthy());
    }

    #[test]
    fn resource_all_at_degraded_level() {
        // Memory, CPU, and FDs all at degraded level (but not unhealthy)
        let r = ResourceHealth::new(850, 85.0, 850, 1024).with_memory_limit_mb(1000);
        let state = r.to_health_state();
        assert!(state.is_degraded());
        if let HealthState::Degraded { reasons } = state {
            assert_eq!(reasons.len(), 3);
        }
    }

    // ────────── HealthConfig edge cases ──────────

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
    fn config_check_interval_zero() {
        let c = HealthConfig::new().with_check_interval_ms(0);
        assert_eq!(c.check_interval(), Duration::ZERO);
    }

    #[test]
    fn config_check_timeout_zero() {
        let c = HealthConfig::new().with_check_timeout_ms(0);
        assert_eq!(c.check_timeout(), Duration::ZERO);
    }

    #[test]
    fn config_large_values() {
        let c = HealthConfig::new()
            .with_check_interval_ms(u64::MAX)
            .with_check_timeout_ms(u64::MAX);
        assert_eq!(c.check_interval_ms, u64::MAX);
        assert_eq!(c.check_timeout_ms, u64::MAX);
    }

    #[test]
    fn config_threshold_defaults() {
        let c = HealthConfig::default();
        assert!((c.memory_degraded_threshold - 0.80).abs() < f64::EPSILON);
        assert!((c.memory_unhealthy_threshold - 0.95).abs() < f64::EPSILON);
        assert!((f64::from(c.cpu_degraded_threshold) - 80.0).abs() < f64::EPSILON);
        assert!((f64::from(c.cpu_unhealthy_threshold) - 95.0).abs() < f64::EPSILON);
    }

    // ────────── HealthAggregator edge cases ──────────

    #[test]
    fn aggregator_component_below_degraded_threshold_uses_own_state() {
        let mut agg = HealthAggregator::new("1.0.0", HealthConfig::default());
        // 0 failures < degraded_threshold(1) → uses component's own state (healthy)
        agg.report_component(ComponentHealth::healthy("test").with_failures(0));
        let status = agg.evaluate();
        assert!(status.is_healthy());
    }

    #[test]
    fn aggregator_component_at_exact_degraded_threshold() {
        let config = HealthConfig::default(); // degraded_threshold = 1
        let mut agg = HealthAggregator::new("1.0.0", config);
        agg.report_component(ComponentHealth::healthy("test").with_failures(1));
        let status = agg.evaluate();
        assert!(status.status.is_degraded());
    }

    #[test]
    fn aggregator_component_between_thresholds() {
        let config = HealthConfig::default(); // degraded=1, unhealthy=3
        let mut agg = HealthAggregator::new("1.0.0", config);
        agg.report_component(ComponentHealth::healthy("test").with_failures(2));
        let status = agg.evaluate();
        // 2 >= degraded(1) but < unhealthy(3) → degraded
        assert!(status.status.is_degraded());
    }

    #[test]
    fn aggregator_component_at_exact_unhealthy_threshold() {
        let config = HealthConfig::default(); // unhealthy=3
        let mut agg = HealthAggregator::new("1.0.0", config);
        agg.report_component(ComponentHealth::healthy("test").with_failures(3));
        let status = agg.evaluate();
        assert!(status.status.is_unhealthy());
    }

    #[test]
    fn aggregator_component_well_above_unhealthy_threshold() {
        let config = HealthConfig::default();
        let mut agg = HealthAggregator::new("1.0.0", config);
        agg.report_component(ComponentHealth::healthy("test").with_failures(100));
        let status = agg.evaluate();
        assert!(status.status.is_unhealthy());
    }

    #[test]
    fn aggregator_custom_thresholds() {
        let config = HealthConfig::default().with_unhealthy_threshold(10);
        let mut agg = HealthAggregator::new("1.0.0", config);
        // 5 failures < custom unhealthy(10) → degraded (>= degraded(1))
        agg.report_component(ComponentHealth::healthy("test").with_failures(5));
        let status = agg.evaluate();
        assert!(status.status.is_degraded());
    }

    #[test]
    fn aggregator_evaluate_defaults_mesh_disconnected() {
        let agg = HealthAggregator::with_defaults("1.0.0");
        let status = agg.evaluate();
        assert!(!status.mesh.connected);
        assert_eq!(status.mesh.peer_count, 0);
    }

    #[test]
    fn aggregator_evaluate_defaults_resources() {
        let agg = HealthAggregator::with_defaults("1.0.0");
        let status = agg.evaluate();
        assert_eq!(status.resources.memory_used_mb, 0);
        assert!(status.resources.cpu_percent.abs() < f32::EPSILON);
        assert_eq!(status.resources.open_fds, 0);
        assert_eq!(status.resources.max_fds, 1024);
    }

    #[test]
    fn aggregator_many_components() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        for i in 0..10 {
            agg.report_component(ComponentHealth::healthy(format!("comp-{i}")));
        }
        assert_eq!(agg.component_count(), 10);
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert_eq!(status.components.len(), 10);
    }

    #[test]
    fn aggregator_many_connectors() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        for i in 0..5 {
            agg.report_connector(ConnectorProcessHealth::running(format!("fcp.c{i}"), 100));
        }
        assert_eq!(agg.connector_count(), 5);
        let status = agg.evaluate();
        assert_eq!(status.running_connector_count(), 5);
        assert_eq!(status.crash_loop_count(), 0);
    }

    #[test]
    fn aggregator_update_component_replaces_state() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_component(ComponentHealth::unhealthy("test", "bad"));
        assert_eq!(agg.component_count(), 1);
        agg.report_component(ComponentHealth::degraded("test", "recovering"));
        assert_eq!(agg.component_count(), 1);
        let status = agg.evaluate();
        assert!(status.status.is_degraded());
    }

    #[test]
    fn aggregator_update_connector_replaces_fully() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorProcessHealth::failed("x", 10));
        agg.report_connector(ConnectorProcessHealth::running("x", 500));
        assert_eq!(agg.connector_count(), 1);
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert_eq!(status.running_connector_count(), 1);
        assert_eq!(status.crash_loop_count(), 0);
    }

    #[test]
    fn aggregator_all_subsystems_healthy() {
        let mut agg = HealthAggregator::with_defaults("2.0.0");
        agg.report_connector(ConnectorProcessHealth::running("fcp.a", 100));
        agg.report_mesh(MeshHealth::connected(5));
        agg.report_resources(ResourceHealth::new(256, 30.0, 100, 1024));
        agg.report_component(ComponentHealth::healthy("enforcement"));
        let status = agg.evaluate();
        assert!(status.is_healthy());
        assert!(status.is_ready());
        assert_eq!(status.version, "2.0.0");
    }

    #[test]
    fn aggregator_all_subsystems_unhealthy() {
        let mut agg = HealthAggregator::with_defaults("1.0.0");
        agg.report_connector(ConnectorProcessHealth::failed("x", 10));
        agg.report_mesh(MeshHealth::disconnected());
        agg.report_resources(ResourceHealth::new(990, 99.0, 990, 1024).with_memory_limit_mb(1000));
        agg.report_component(ComponentHealth::unhealthy("e", "down"));
        let status = agg.evaluate();
        assert!(status.status.is_unhealthy());
        assert!(!status.is_ready());
    }

    #[test]
    fn aggregator_version_preserved() {
        let agg = HealthAggregator::with_defaults("3.14.159");
        let status = agg.evaluate();
        assert_eq!(status.version, "3.14.159");
    }

    // ────────── CompositeHealthStatus edge cases ──────────

    #[test]
    fn health_status_running_connector_count_empty() {
        let status = CompositeHealthStatus {
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
    fn health_status_crash_loop_count_mixed() {
        let status = CompositeHealthStatus {
            status: HealthState::Unhealthy {
                reasons: vec!["test".into()],
            },
            version: "1.0.0".into(),
            uptime_seconds: 0,
            connectors: vec![
                ConnectorProcessHealth::running("a", 100),
                ConnectorProcessHealth::failed("b", 5),
                ConnectorProcessHealth::failed("c", 3),
                ConnectorProcessHealth::stopped("d"),
                ConnectorProcessHealth::failed("e", 1), // not crash loop
            ],
            mesh: MeshHealth::connected(1),
            resources: ResourceHealth::new(0, 0.0, 0, 1024),
            components: vec![],
        };
        assert_eq!(status.running_connector_count(), 1); // only "a"
        assert_eq!(status.crash_loop_count(), 2); // "b" (5>=3) and "c" (3>=3)
    }

    #[test]
    fn health_status_healthy_is_ready() {
        let status = CompositeHealthStatus {
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
    fn health_status_serde_with_components() {
        let status = CompositeHealthStatus {
            status: HealthState::Degraded {
                reasons: vec!["slow".into()],
            },
            version: "1.0.0".into(),
            uptime_seconds: 42,
            connectors: vec![ConnectorProcessHealth::running("a", 10)],
            mesh: MeshHealth::connected(2),
            resources: ResourceHealth::new(100, 50.0, 50, 1024),
            components: vec![
                ComponentHealth::healthy("comp_a"),
                ComponentHealth::degraded("comp_b", "slow"),
            ],
        };
        let json = serde_json::to_string(&status).unwrap();
        let restored: CompositeHealthStatus = serde_json::from_str(&json).unwrap();
        assert!(restored.status.is_degraded());
        assert_eq!(restored.connectors.len(), 1);
        assert_eq!(restored.components.len(), 2);
        assert_eq!(restored.uptime_seconds, 42);
    }

    // ────────── Clone behavior ──────────

    #[test]
    fn health_state_clone_independence() {
        let original = HealthState::Degraded {
            reasons: vec!["a".into()],
        };
        let cloned = original.clone();
        // Use the original after clone to verify independence
        assert_eq!(original.severity(), cloned.severity());
        assert!(original.is_degraded());
        assert!(cloned.is_degraded());
    }

    #[test]
    fn component_health_clone_independence() {
        let original = ComponentHealth::degraded("comp", "reason")
            .with_failures(3)
            .with_message("msg");
        let cloned = original.clone();
        assert_eq!(original.name, cloned.name);
        assert_eq!(original.consecutive_failures, cloned.consecutive_failures);
    }

    #[test]
    fn connector_health_clone_independence() {
        let original = ConnectorProcessHealth::running("x", 100).with_restarts(5);
        let cloned = original.clone();
        assert_eq!(original.connector_id, cloned.connector_id);
        assert_eq!(original.restart_count, cloned.restart_count);
    }
}
