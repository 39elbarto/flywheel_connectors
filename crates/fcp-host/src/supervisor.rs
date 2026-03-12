//! Connector process supervisor with restart policies and health monitoring.
//!
//! Implements the supervisor model from the oip0 bead:
//! - Configurable restart policies (`Always`, `OnFailure`, `OnCrash`, `Never`)
//! - Exponential backoff with jitter for restart timing
//! - Restart window tracking (max N restarts within a time window)
//! - Process state machine (Starting → Running → Stopping → Stopped/Failed)
//! - Health check scheduling with configurable intervals and timeouts
//! - Graceful shutdown with SIGTERM → timeout → SIGKILL sequencing

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Restart Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy governing when a connector process should be restarted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RestartPolicy {
    /// Always restart, regardless of exit status.
    Always,
    /// Restart only on failure (non-zero exit or signal).
    #[default]
    OnFailure,
    /// Restart only on crash (signal-terminated, not clean non-zero exit).
    OnCrash,
    /// Never restart automatically.
    Never,
}

impl RestartPolicy {
    /// Determine whether a restart should be attempted for the given exit.
    #[must_use]
    pub fn should_restart(&self, exit: &ProcessExit) -> bool {
        match self {
            Self::Always => true,
            Self::OnFailure => !exit.is_clean(),
            Self::OnCrash => exit.is_signal_terminated(),
            Self::Never => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process Exit
// ─────────────────────────────────────────────────────────────────────────────

/// How a connector process exited.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessExit {
    /// Exit code, if the process exited normally.
    pub code: Option<i32>,
    /// Signal number, if the process was terminated by a signal.
    pub signal: Option<i32>,
}

impl ProcessExit {
    /// Clean exit (code 0).
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            code: Some(0),
            signal: None,
        }
    }

    /// Exit with a specific code.
    #[must_use]
    pub const fn with_code(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
        }
    }

    /// Terminated by a signal.
    #[must_use]
    pub const fn with_signal(signal: i32) -> Self {
        Self {
            code: None,
            signal: Some(signal),
        }
    }

    /// Whether this was a clean exit (code 0).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.code == Some(0) && self.signal.is_none()
    }

    /// Whether the process was terminated by a signal.
    #[must_use]
    pub const fn is_signal_terminated(&self) -> bool {
        self.signal.is_some()
    }
}

impl std::fmt::Display for ProcessExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.code, self.signal) {
            (Some(code), None) => write!(f, "exit code {code}"),
            (None, Some(sig)) => write!(f, "signal {sig}"),
            (Some(code), Some(sig)) => write!(f, "exit code {code}, signal {sig}"),
            (None, None) => write!(f, "unknown exit"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process State
// ─────────────────────────────────────────────────────────────────────────────

/// Current state of a supervised connector process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is starting up.
    Starting {
        /// When the start was initiated.
        since: Instant,
    },
    /// Process is running normally.
    Running {
        /// Process ID.
        pid: u32,
        /// When the process started.
        started_at: Instant,
    },
    /// Process is being stopped gracefully.
    Stopping {
        /// Why the process is being stopped.
        reason: StopReason,
        /// When the stop was initiated.
        since: Instant,
    },
    /// Process has stopped.
    Stopped {
        /// How the process exited.
        exit: ProcessExit,
        /// When the process stopped.
        stopped_at: Instant,
    },
    /// Process has failed and won't be restarted.
    Failed {
        /// Error description.
        error: String,
        /// When the failure was recorded.
        failed_at: Instant,
    },
}

impl ProcessState {
    /// Whether the process is currently running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Whether the process is in a terminal state (Stopped or Failed).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped { .. } | Self::Failed { .. })
    }

    /// Human-readable label for the current state.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Starting { .. } => "starting",
            Self::Running { .. } => "running",
            Self::Stopping { .. } => "stopping",
            Self::Stopped { .. } => "stopped",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Reason for stopping a connector process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Operator requested shutdown.
    Requested,
    /// Host is shutting down.
    HostShutdown,
    /// Health check failed too many times.
    HealthCheckFailed,
    /// Resource limits exceeded.
    ResourceLimitExceeded,
    /// Being replaced by a new version.
    Upgrade,
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Requested => write!(f, "requested"),
            Self::HostShutdown => write!(f, "host shutdown"),
            Self::HealthCheckFailed => write!(f, "health check failed"),
            Self::ResourceLimitExceeded => write!(f, "resource limit exceeded"),
            Self::Upgrade => write!(f, "upgrade"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Supervisor Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the connector process supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorConfig {
    /// Policy for automatic restarts.
    pub restart_policy: RestartPolicy,
    /// Maximum number of restarts allowed within the restart window.
    pub max_restarts: u32,
    /// Time window for counting restarts.
    pub restart_window: Duration,
    /// How often to check connector health.
    pub health_check_interval: Duration,
    /// Timeout for individual health checks.
    pub health_check_timeout: Duration,
    /// How long to wait for graceful shutdown before SIGKILL.
    pub graceful_shutdown_timeout: Duration,
    /// Initial backoff delay for restart attempts.
    pub initial_backoff: Duration,
    /// Maximum backoff delay.
    pub max_backoff: Duration,
    /// Backoff multiplier (typically 2.0).
    pub backoff_multiplier: f64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            restart_policy: RestartPolicy::default(),
            max_restarts: 5,
            restart_window: Duration::from_mins(5),
            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(10),
            graceful_shutdown_timeout: Duration::from_secs(30),
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_mins(1),
            backoff_multiplier: 2.0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Restart Event
// ─────────────────────────────────────────────────────────────────────────────

/// Record of a restart event.
#[derive(Debug, Clone)]
pub struct RestartEvent {
    /// When the restart occurred.
    pub timestamp: Instant,
    /// How the previous process exited.
    pub previous_exit: ProcessExit,
    /// Which restart attempt this is (1-based).
    pub attempt: u32,
    /// Backoff delay applied before this restart.
    pub backoff_delay: Duration,
}

// ─────────────────────────────────────────────────────────────────────────────
// Exponential Backoff
// ─────────────────────────────────────────────────────────────────────────────

/// Exponential backoff calculator with configurable parameters.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    initial: Duration,
    max: Duration,
    multiplier: f64,
    attempt: u32,
}

impl ExponentialBackoff {
    /// Create a new backoff calculator.
    #[must_use]
    pub fn new(initial: Duration, max: Duration, multiplier: f64) -> Self {
        Self {
            initial,
            max,
            multiplier: if multiplier < 1.0 { 2.0 } else { multiplier },
            attempt: 0,
        }
    }

    /// Create from a supervisor config.
    #[must_use]
    pub fn from_config(config: &SupervisorConfig) -> Self {
        Self::new(
            config.initial_backoff,
            config.max_backoff,
            config.backoff_multiplier,
        )
    }

    /// Get the next backoff duration, advancing the attempt counter.
    #[must_use]
    pub fn next_backoff(&mut self) -> Duration {
        let delay = self.current_delay();
        self.attempt = self.attempt.saturating_add(1);
        delay
    }

    /// Get the current delay without advancing.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn current_delay(&self) -> Duration {
        if self.attempt == 0 {
            return self.initial;
        }
        let factor = self
            .multiplier
            .powi(i32::try_from(self.attempt).unwrap_or(i32::MAX));
        let initial_ms = self.initial.as_millis() as f64;
        let max_ms = self.max.as_millis() as f64;
        let delay_ms = (initial_ms * factor).min(max_ms).max(0.0);
        let capped = Duration::from_millis(delay_ms as u64);
        capped.min(self.max)
    }

    /// Reset the backoff counter.
    pub const fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Current attempt count.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempt
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Restart Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks restart events within a sliding window to enforce limits.
#[derive(Debug, Clone)]
pub struct RestartTracker {
    config: SupervisorConfig,
    history: VecDeque<RestartEvent>,
    backoff: ExponentialBackoff,
}

impl RestartTracker {
    /// Create a new tracker with the given configuration.
    #[must_use]
    pub fn new(config: SupervisorConfig) -> Self {
        let backoff = ExponentialBackoff::from_config(&config);
        Self {
            config,
            history: VecDeque::new(),
            backoff,
        }
    }

    /// Evaluate whether a restart should be attempted for the given exit.
    ///
    /// Returns `Ok(delay)` if a restart should be attempted after the given delay,
    /// or `Err(reason)` if the process should not be restarted.
    ///
    /// # Errors
    ///
    /// Returns `RestartDenied::PolicyDenied` if the restart policy does not allow
    /// restart for this exit type, or `RestartDenied::MaxRestartsExceeded` if the
    /// maximum number of restarts within the window has been reached.
    pub fn evaluate_restart(
        &mut self,
        exit: &ProcessExit,
        now: Instant,
    ) -> Result<Duration, RestartDenied> {
        // Check policy first.
        if !self.config.restart_policy.should_restart(exit) {
            return Err(RestartDenied::PolicyDenied);
        }

        // Prune events outside the window.
        let window_start = now.checked_sub(self.config.restart_window).unwrap_or(now);
        while self
            .history
            .front()
            .is_some_and(|event| event.timestamp < window_start)
        {
            self.history.pop_front();
        }

        // Check restart count within window.
        let restarts_in_window = u32::try_from(self.history.len()).unwrap_or(u32::MAX);
        if restarts_in_window >= self.config.max_restarts {
            return Err(RestartDenied::MaxRestartsExceeded {
                count: restarts_in_window,
                window: self.config.restart_window,
            });
        }

        // Calculate backoff delay.
        let delay = self.backoff.next_backoff();
        let attempt = restarts_in_window + 1;

        // Record the restart event.
        self.history.push_back(RestartEvent {
            timestamp: now,
            previous_exit: exit.clone(),
            attempt,
            backoff_delay: delay,
        });

        Ok(delay)
    }

    /// Record a successful start, resetting the backoff.
    pub const fn record_successful_start(&mut self) {
        self.backoff.reset();
    }

    /// Total number of restarts recorded (including pruned).
    #[must_use]
    pub fn total_restarts(&self) -> usize {
        self.history.len()
    }

    /// Restarts within the current window.
    #[must_use]
    pub fn restarts_in_window(&self, now: Instant) -> u32 {
        let window_start = now.checked_sub(self.config.restart_window).unwrap_or(now);
        u32::try_from(
            self.history
                .iter()
                .filter(|event| event.timestamp >= window_start)
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    /// Get the restart history.
    #[must_use]
    pub const fn history(&self) -> &VecDeque<RestartEvent> {
        &self.history
    }

    /// Get the supervisor configuration.
    #[must_use]
    pub const fn config(&self) -> &SupervisorConfig {
        &self.config
    }
}

/// Reason why a restart was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartDenied {
    /// Restart policy does not allow restart for this exit type.
    PolicyDenied,
    /// Maximum restarts within the window have been exceeded.
    MaxRestartsExceeded {
        /// Number of restarts in the window.
        count: u32,
        /// The window duration.
        window: Duration,
    },
}

impl std::fmt::Display for RestartDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyDenied => write!(f, "restart policy denied"),
            Self::MaxRestartsExceeded { count, window } => {
                write!(
                    f,
                    "max restarts exceeded: {count} restarts in {}s window",
                    window.as_secs()
                )
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shutdown Coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks the graceful shutdown sequence for a process.
#[derive(Debug, Clone)]
pub struct ShutdownCoordinator {
    /// Timeout for graceful shutdown before escalating to SIGKILL.
    graceful_timeout: Duration,
    /// Current phase of shutdown.
    phase: ShutdownPhase,
}

/// Phase of the shutdown sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownPhase {
    /// Not shutting down.
    NotStarted,
    /// SIGTERM sent, waiting for graceful exit.
    GracefulWait { sent_at: Instant },
    /// Graceful timeout expired, SIGKILL should be sent.
    ForceKill { escalated_at: Instant },
    /// Process has exited.
    Complete { exit: ProcessExit },
}

impl ShutdownCoordinator {
    /// Create a new coordinator with the given graceful timeout.
    #[must_use]
    pub const fn new(graceful_timeout: Duration) -> Self {
        Self {
            graceful_timeout,
            phase: ShutdownPhase::NotStarted,
        }
    }

    /// Start the graceful shutdown sequence.
    pub fn start_graceful(&mut self, now: Instant) {
        if self.phase == ShutdownPhase::NotStarted {
            self.phase = ShutdownPhase::GracefulWait { sent_at: now };
        }
    }

    /// Check whether it's time to escalate to SIGKILL.
    #[must_use]
    pub fn should_force_kill(&self, now: Instant) -> bool {
        match self.phase {
            ShutdownPhase::GracefulWait { sent_at } => {
                now.saturating_duration_since(sent_at) >= self.graceful_timeout
            }
            _ => false,
        }
    }

    /// Record that force kill has been sent.
    pub const fn record_force_kill(&mut self, now: Instant) {
        if matches!(self.phase, ShutdownPhase::GracefulWait { .. }) {
            self.phase = ShutdownPhase::ForceKill { escalated_at: now };
        }
    }

    /// Record that the process has exited.
    pub const fn record_exit(&mut self, exit: ProcessExit) {
        self.phase = ShutdownPhase::Complete { exit };
    }

    /// Current shutdown phase.
    #[must_use]
    pub const fn phase(&self) -> &ShutdownPhase {
        &self.phase
    }

    /// Whether shutdown is in progress.
    #[must_use]
    pub const fn is_shutting_down(&self) -> bool {
        matches!(
            self.phase,
            ShutdownPhase::GracefulWait { .. } | ShutdownPhase::ForceKill { .. }
        )
    }

    /// Whether shutdown is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, ShutdownPhase::Complete { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Check Scheduler
// ─────────────────────────────────────────────────────────────────────────────

/// Schedules periodic health checks for a connector.
#[derive(Debug, Clone)]
pub struct HealthCheckScheduler {
    interval: Duration,
    timeout: Duration,
    last_check: Option<Instant>,
    consecutive_failures: u32,
    max_consecutive_failures: u32,
}

impl HealthCheckScheduler {
    /// Create a new scheduler from supervisor config.
    #[must_use]
    pub const fn new(interval: Duration, timeout: Duration) -> Self {
        Self {
            interval,
            timeout,
            last_check: None,
            consecutive_failures: 0,
            max_consecutive_failures: 3,
        }
    }

    /// Create with a custom failure threshold.
    #[must_use]
    pub const fn with_max_failures(mut self, max: u32) -> Self {
        self.max_consecutive_failures = max;
        self
    }

    /// Whether a health check is due now.
    #[must_use]
    pub fn is_due(&self, now: Instant) -> bool {
        self.last_check
            .is_none_or(|last| now.saturating_duration_since(last) >= self.interval)
    }

    /// Record a successful health check.
    pub const fn record_success(&mut self, now: Instant) {
        self.last_check = Some(now);
        self.consecutive_failures = 0;
    }

    /// Record a failed health check.
    pub const fn record_failure(&mut self, now: Instant) {
        self.last_check = Some(now);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Whether the connector should be considered unhealthy.
    #[must_use]
    pub const fn is_unhealthy(&self) -> bool {
        self.consecutive_failures >= self.max_consecutive_failures
    }

    /// Current consecutive failure count.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Health check timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Time until next health check is due.
    #[must_use]
    pub fn time_until_next(&self, now: Instant) -> Duration {
        self.last_check.map_or(Duration::ZERO, |last| {
            self.interval
                .saturating_sub(now.saturating_duration_since(last))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource Limits
// ─────────────────────────────────────────────────────────────────────────────

/// Resource limits for a supervised connector process.
///
/// These map to OS-level resource constraints (e.g. `setrlimit` on Unix).
/// All limits are optional — `None` means unlimited.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum resident memory in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum CPU time in seconds (cumulative).
    pub cpu_seconds: Option<u64>,
    /// Maximum number of open file descriptors.
    pub max_fds: Option<u64>,
    /// Maximum number of child processes.
    pub max_processes: Option<u64>,
    /// Maximum file size in bytes that the process can create.
    pub max_file_size_bytes: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: Some(512 * 1024 * 1024), // 512 MiB
            cpu_seconds: None,
            max_fds: Some(1024),
            max_processes: Some(64),
            max_file_size_bytes: None,
        }
    }
}

impl ResourceLimits {
    /// Create unlimited resource limits (no constraints).
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            memory_bytes: None,
            cpu_seconds: None,
            max_fds: None,
            max_processes: None,
            max_file_size_bytes: None,
        }
    }

    /// Whether any limits are set.
    #[must_use]
    pub const fn has_any_limits(&self) -> bool {
        self.memory_bytes.is_some()
            || self.cpu_seconds.is_some()
            || self.max_fds.is_some()
            || self.max_processes.is_some()
            || self.max_file_size_bytes.is_some()
    }

    /// Count how many limits are set.
    #[must_use]
    pub const fn active_limit_count(&self) -> u32 {
        let mut count = 0;
        if self.memory_bytes.is_some() {
            count += 1;
        }
        if self.cpu_seconds.is_some() {
            count += 1;
        }
        if self.max_fds.is_some() {
            count += 1;
        }
        if self.max_processes.is_some() {
            count += 1;
        }
        if self.max_file_size_bytes.is_some() {
            count += 1;
        }
        count
    }

    /// Merge with another set of limits, taking the stricter (lower) value for each.
    #[must_use]
    pub fn merge_strict(&self, other: &Self) -> Self {
        Self {
            memory_bytes: merge_option_min(self.memory_bytes, other.memory_bytes),
            cpu_seconds: merge_option_min(self.cpu_seconds, other.cpu_seconds),
            max_fds: merge_option_min(self.max_fds, other.max_fds),
            max_processes: merge_option_min(self.max_processes, other.max_processes),
            max_file_size_bytes: merge_option_min(
                self.max_file_size_bytes,
                other.max_file_size_bytes,
            ),
        }
    }
}

/// Merge two optional limits, taking the stricter (lower) value.
fn merge_option_min(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Snapshot of current resource usage for a process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceUsage {
    /// Current resident memory in bytes.
    pub memory_bytes: u64,
    /// Cumulative CPU time in milliseconds.
    pub cpu_millis: u64,
    /// Current open file descriptors.
    pub open_fds: u64,
    /// Current child process count.
    pub process_count: u64,
}

impl ResourceUsage {
    /// Check which resource limits are violated, if any.
    #[must_use]
    pub fn violations(&self, limits: &ResourceLimits) -> Vec<ResourceViolation> {
        let mut violations = Vec::new();

        if let Some(limit) = limits.memory_bytes
            && self.memory_bytes > limit
        {
            violations.push(ResourceViolation {
                resource: ResourceKind::Memory,
                current: self.memory_bytes,
                limit,
            });
        }

        if let Some(limit) = limits.cpu_seconds {
            let cpu_seconds = self.cpu_millis / 1000;
            if cpu_seconds > limit {
                violations.push(ResourceViolation {
                    resource: ResourceKind::CpuTime,
                    current: cpu_seconds,
                    limit,
                });
            }
        }

        if let Some(limit) = limits.max_fds
            && self.open_fds > limit
        {
            violations.push(ResourceViolation {
                resource: ResourceKind::FileDescriptors,
                current: self.open_fds,
                limit,
            });
        }

        if let Some(limit) = limits.max_processes
            && self.process_count > limit
        {
            violations.push(ResourceViolation {
                resource: ResourceKind::Processes,
                current: self.process_count,
                limit,
            });
        }

        violations
    }

    /// Whether all resource usage is within the given limits.
    #[must_use]
    pub fn within_limits(&self, limits: &ResourceLimits) -> bool {
        self.violations(limits).is_empty()
    }

    /// Percentage of each limit consumed (0.0–1.0+). Returns None for unlimited.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn utilization(&self, limits: &ResourceLimits) -> ResourceUtilization {
        ResourceUtilization {
            memory: limits
                .memory_bytes
                .map(|l| self.memory_bytes as f64 / l as f64),
            cpu: limits
                .cpu_seconds
                .map(|l| (self.cpu_millis as f64 / 1000.0) / l as f64),
            fds: limits.max_fds.map(|l| self.open_fds as f64 / l as f64),
            processes: limits
                .max_processes
                .map(|l| self.process_count as f64 / l as f64),
        }
    }
}

/// A specific resource limit violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceViolation {
    /// Which resource is violated.
    pub resource: ResourceKind,
    /// Current usage.
    pub current: u64,
    /// The limit that was exceeded.
    pub limit: u64,
}

impl std::fmt::Display for ResourceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} limit exceeded: {} > {} (limit)",
            self.resource, self.current, self.limit
        )
    }
}

/// Kind of resource being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// Resident memory.
    Memory,
    /// Cumulative CPU time.
    CpuTime,
    /// Open file descriptors.
    FileDescriptors,
    /// Child processes.
    Processes,
    /// File size.
    FileSize,
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            Self::CpuTime => write!(f, "cpu_time"),
            Self::FileDescriptors => write!(f, "file_descriptors"),
            Self::Processes => write!(f, "processes"),
            Self::FileSize => write!(f, "file_size"),
        }
    }
}

/// Utilization percentages for each resource type.
#[derive(Debug, Clone)]
pub struct ResourceUtilization {
    /// Memory utilization (0.0–1.0+), None if unlimited.
    pub memory: Option<f64>,
    /// CPU utilization (0.0–1.0+), None if unlimited.
    pub cpu: Option<f64>,
    /// FD utilization (0.0–1.0+), None if unlimited.
    pub fds: Option<f64>,
    /// Process utilization (0.0–1.0+), None if unlimited.
    pub processes: Option<f64>,
}

impl ResourceUtilization {
    /// The highest utilization across all tracked resources.
    #[must_use]
    pub fn max_utilization(&self) -> Option<f64> {
        [self.memory, self.cpu, self.fds, self.processes]
            .into_iter()
            .flatten()
            .reduce(f64::max)
    }

    /// Whether any resource is at or above the given threshold (e.g. 0.9 for 90%).
    #[must_use]
    pub fn any_above_threshold(&self, threshold: f64) -> bool {
        self.max_utilization().is_some_and(|max| max >= threshold)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection Tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks active connections for graceful shutdown draining.
///
/// During normal operation, connections are counted. When shutdown is initiated,
/// new connections are rejected and the system waits for in-flight connections
/// to complete before fully stopping.
#[derive(Debug)]
pub struct ConnectionTracker {
    active: std::sync::atomic::AtomicU32,
    draining: std::sync::atomic::AtomicBool,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTracker {
    /// Create a new connection tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: std::sync::atomic::AtomicU32::new(0),
            draining: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Try to acquire a connection slot. Returns `None` if draining.
    #[must_use]
    pub fn try_acquire(&self) -> Option<ConnectionGuard<'_>> {
        if self.draining.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        // Double-check after incrementing (avoid race with start_drain).
        if self.draining.load(std::sync::atomic::Ordering::Acquire) {
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            return None;
        }
        Some(ConnectionGuard { tracker: self })
    }

    /// Current number of active connections.
    #[must_use]
    pub fn active_count(&self) -> u32 {
        self.active.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether the tracker is in drain mode (rejecting new connections).
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Start draining — no new connections will be accepted.
    pub fn start_drain(&self) {
        self.draining
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether all connections have drained (draining + zero active).
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.is_draining() && self.active_count() == 0
    }
}

/// RAII guard that decrements the active connection count on drop.
#[derive(Debug)]
pub struct ConnectionGuard<'a> {
    tracker: &'a ConnectionTracker,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.tracker
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProcessExit ──

    #[test]
    fn clean_exit_is_clean() {
        let exit = ProcessExit::clean();
        assert!(exit.is_clean());
        assert!(!exit.is_signal_terminated());
    }

    #[test]
    fn exit_code_nonzero_is_not_clean() {
        let exit = ProcessExit::with_code(1);
        assert!(!exit.is_clean());
        assert!(!exit.is_signal_terminated());
    }

    #[test]
    fn signal_exit_is_signal_terminated() {
        let exit = ProcessExit::with_signal(9);
        assert!(!exit.is_clean());
        assert!(exit.is_signal_terminated());
    }

    #[test]
    fn exit_display_code() {
        assert_eq!(ProcessExit::with_code(42).to_string(), "exit code 42");
    }

    #[test]
    fn exit_display_signal() {
        assert_eq!(ProcessExit::with_signal(15).to_string(), "signal 15");
    }

    #[test]
    fn exit_display_both() {
        let exit = ProcessExit {
            code: Some(1),
            signal: Some(11),
        };
        assert_eq!(exit.to_string(), "exit code 1, signal 11");
    }

    #[test]
    fn exit_display_unknown() {
        let exit = ProcessExit {
            code: None,
            signal: None,
        };
        assert_eq!(exit.to_string(), "unknown exit");
    }

    // ── RestartPolicy ──

    #[test]
    fn always_restarts_on_clean_exit() {
        assert!(RestartPolicy::Always.should_restart(&ProcessExit::clean()));
    }

    #[test]
    fn always_restarts_on_crash() {
        assert!(RestartPolicy::Always.should_restart(&ProcessExit::with_signal(9)));
    }

    #[test]
    fn on_failure_does_not_restart_clean_exit() {
        assert!(!RestartPolicy::OnFailure.should_restart(&ProcessExit::clean()));
    }

    #[test]
    fn on_failure_restarts_nonzero_exit() {
        assert!(RestartPolicy::OnFailure.should_restart(&ProcessExit::with_code(1)));
    }

    #[test]
    fn on_failure_restarts_signal() {
        assert!(RestartPolicy::OnFailure.should_restart(&ProcessExit::with_signal(15)));
    }

    #[test]
    fn on_crash_does_not_restart_clean_exit() {
        assert!(!RestartPolicy::OnCrash.should_restart(&ProcessExit::clean()));
    }

    #[test]
    fn on_crash_does_not_restart_nonzero_exit() {
        assert!(!RestartPolicy::OnCrash.should_restart(&ProcessExit::with_code(1)));
    }

    #[test]
    fn on_crash_restarts_signal() {
        assert!(RestartPolicy::OnCrash.should_restart(&ProcessExit::with_signal(11)));
    }

    #[test]
    fn never_does_not_restart_anything() {
        assert!(!RestartPolicy::Never.should_restart(&ProcessExit::clean()));
        assert!(!RestartPolicy::Never.should_restart(&ProcessExit::with_code(1)));
        assert!(!RestartPolicy::Never.should_restart(&ProcessExit::with_signal(9)));
    }

    #[test]
    fn default_policy_is_on_failure() {
        assert_eq!(RestartPolicy::default(), RestartPolicy::OnFailure);
    }

    // ── ProcessState ──

    #[test]
    fn starting_is_not_running_or_terminal() {
        let state = ProcessState::Starting {
            since: Instant::now(),
        };
        assert!(!state.is_running());
        assert!(!state.is_terminal());
        assert_eq!(state.label(), "starting");
    }

    #[test]
    fn running_is_running_not_terminal() {
        let state = ProcessState::Running {
            pid: 1234,
            started_at: Instant::now(),
        };
        assert!(state.is_running());
        assert!(!state.is_terminal());
        assert_eq!(state.label(), "running");
    }

    #[test]
    fn stopping_is_not_running_or_terminal() {
        let state = ProcessState::Stopping {
            reason: StopReason::Requested,
            since: Instant::now(),
        };
        assert!(!state.is_running());
        assert!(!state.is_terminal());
        assert_eq!(state.label(), "stopping");
    }

    #[test]
    fn stopped_is_terminal() {
        let state = ProcessState::Stopped {
            exit: ProcessExit::clean(),
            stopped_at: Instant::now(),
        };
        assert!(!state.is_running());
        assert!(state.is_terminal());
        assert_eq!(state.label(), "stopped");
    }

    #[test]
    fn failed_is_terminal() {
        let state = ProcessState::Failed {
            error: "boom".into(),
            failed_at: Instant::now(),
        };
        assert!(!state.is_running());
        assert!(state.is_terminal());
        assert_eq!(state.label(), "failed");
    }

    // ── StopReason ──

    #[test]
    fn stop_reason_display() {
        assert_eq!(StopReason::Requested.to_string(), "requested");
        assert_eq!(StopReason::HostShutdown.to_string(), "host shutdown");
        assert_eq!(
            StopReason::HealthCheckFailed.to_string(),
            "health check failed"
        );
        assert_eq!(
            StopReason::ResourceLimitExceeded.to_string(),
            "resource limit exceeded"
        );
        assert_eq!(StopReason::Upgrade.to_string(), "upgrade");
    }

    // ── ExponentialBackoff ──

    #[test]
    fn backoff_starts_at_initial() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 2.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
    }

    #[test]
    fn backoff_doubles_each_attempt() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 2.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(200));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(400));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(800));
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(500), Duration::from_secs(2), 2.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(500));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(2));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(2));
    }

    #[test]
    fn backoff_reset_restarts_from_initial() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 2.0);
        let _ = backoff.next_backoff();
        let _ = backoff.next_backoff();
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
    }

    #[test]
    fn backoff_from_config() {
        let config = SupervisorConfig::default();
        let backoff = ExponentialBackoff::from_config(&config);
        assert_eq!(backoff.current_delay(), config.initial_backoff);
    }

    #[test]
    fn backoff_negative_multiplier_defaults_to_two() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), -1.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(200));
    }

    #[test]
    fn backoff_triple_multiplier() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_mins(1), 3.0);
        assert_eq!(backoff.next_backoff(), Duration::from_millis(100));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(300));
        assert_eq!(backoff.next_backoff(), Duration::from_millis(900));
    }

    // ── SupervisorConfig ──

    #[test]
    fn supervisor_config_default_values() {
        let config = SupervisorConfig::default();
        assert_eq!(config.max_restarts, 5);
        assert_eq!(config.restart_window, Duration::from_mins(5));
        assert_eq!(config.health_check_interval, Duration::from_secs(30));
        assert_eq!(config.health_check_timeout, Duration::from_secs(10));
        assert_eq!(config.graceful_shutdown_timeout, Duration::from_secs(30));
        assert_eq!(config.initial_backoff, Duration::from_millis(500));
        assert_eq!(config.max_backoff, Duration::from_mins(1));
    }

    // ── RestartTracker ──

    #[test]
    fn tracker_allows_restart_on_failure() {
        let config = SupervisorConfig::default();
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let result = tracker.evaluate_restart(&exit, Instant::now());
        assert!(result.is_ok());
    }

    #[test]
    fn tracker_denies_restart_on_clean_exit_with_default_policy() {
        let config = SupervisorConfig::default();
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::clean();
        let result = tracker.evaluate_restart(&exit, Instant::now());
        assert_eq!(result, Err(RestartDenied::PolicyDenied));
    }

    #[test]
    fn tracker_enforces_max_restarts() {
        let config = SupervisorConfig {
            max_restarts: 2,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        // First two restarts should succeed.
        assert!(tracker.evaluate_restart(&exit, now).is_ok());
        assert!(tracker.evaluate_restart(&exit, now).is_ok());

        // Third restart should be denied.
        let result = tracker.evaluate_restart(&exit, now);
        assert!(matches!(
            result,
            Err(RestartDenied::MaxRestartsExceeded { count: 2, .. })
        ));
    }

    #[test]
    fn tracker_window_expiry_allows_new_restarts() {
        let config = SupervisorConfig {
            max_restarts: 2,
            restart_window: Duration::from_secs(1),
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let start = Instant::now();

        // Fill up the window.
        assert!(tracker.evaluate_restart(&exit, start).is_ok());
        assert!(tracker.evaluate_restart(&exit, start).is_ok());
        assert!(tracker.evaluate_restart(&exit, start).is_err());

        // After the window expires, restarts should be allowed again.
        let later = start + Duration::from_secs(2);
        assert!(tracker.evaluate_restart(&exit, later).is_ok());
    }

    #[test]
    fn tracker_backoff_increases() {
        let config = SupervisorConfig {
            max_restarts: 10,
            initial_backoff: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        let delay1 = tracker.evaluate_restart(&exit, now).unwrap();
        let delay2 = tracker.evaluate_restart(&exit, now).unwrap();
        let delay3 = tracker.evaluate_restart(&exit, now).unwrap();

        assert_eq!(delay1, Duration::from_millis(100));
        assert_eq!(delay2, Duration::from_millis(200));
        assert_eq!(delay3, Duration::from_millis(400));
    }

    #[test]
    fn tracker_successful_start_resets_backoff() {
        let config = SupervisorConfig {
            max_restarts: 10,
            initial_backoff: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        // Build up backoff.
        tracker.evaluate_restart(&exit, now).unwrap();
        tracker.evaluate_restart(&exit, now).unwrap();

        // Successful start resets backoff.
        tracker.record_successful_start();
        let delay = tracker.evaluate_restart(&exit, now).unwrap();
        assert_eq!(delay, Duration::from_millis(100));
    }

    #[test]
    fn tracker_restarts_in_window_counts_correctly() {
        let config = SupervisorConfig {
            max_restarts: 10,
            restart_window: Duration::from_secs(10),
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        tracker.evaluate_restart(&exit, now).unwrap();
        tracker.evaluate_restart(&exit, now).unwrap();
        assert_eq!(tracker.restarts_in_window(now), 2);
        assert_eq!(tracker.total_restarts(), 2);
    }

    #[test]
    fn tracker_history_records_events() {
        let config = SupervisorConfig::default();
        let mut tracker = RestartTracker::new(config);
        let exit = ProcessExit::with_code(1);
        let now = Instant::now();

        tracker.evaluate_restart(&exit, now).unwrap();
        assert_eq!(tracker.history().len(), 1);
        assert_eq!(tracker.history()[0].attempt, 1);
    }

    #[test]
    fn restart_denied_display() {
        let denied = RestartDenied::PolicyDenied;
        assert_eq!(denied.to_string(), "restart policy denied");

        let denied = RestartDenied::MaxRestartsExceeded {
            count: 5,
            window: Duration::from_mins(5),
        };
        assert!(denied.to_string().contains("5 restarts"));
        assert!(denied.to_string().contains("300s"));
    }

    #[test]
    fn tracker_always_policy_restarts_clean_exit() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::Always,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        assert!(
            tracker
                .evaluate_restart(&ProcessExit::clean(), Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn tracker_never_policy_denies_crash() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::Never,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let result = tracker.evaluate_restart(&ProcessExit::with_signal(9), Instant::now());
        assert_eq!(result, Err(RestartDenied::PolicyDenied));
    }

    // ── ShutdownCoordinator ──

    #[test]
    fn shutdown_not_started_initially() {
        let coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        assert!(!coordinator.is_shutting_down());
        assert!(!coordinator.is_complete());
        assert_eq!(*coordinator.phase(), ShutdownPhase::NotStarted);
    }

    #[test]
    fn shutdown_graceful_transitions_to_waiting() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let now = Instant::now();
        coordinator.start_graceful(now);
        assert!(coordinator.is_shutting_down());
        assert!(!coordinator.is_complete());
        assert!(matches!(
            coordinator.phase(),
            ShutdownPhase::GracefulWait { .. }
        ));
    }

    #[test]
    fn shutdown_should_not_force_kill_before_timeout() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let now = Instant::now();
        coordinator.start_graceful(now);
        assert!(!coordinator.should_force_kill(now));
    }

    #[test]
    fn shutdown_should_force_kill_after_timeout() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        let now = Instant::now();
        coordinator.start_graceful(now);
        let later = now + Duration::from_secs(2);
        assert!(coordinator.should_force_kill(later));
    }

    #[test]
    fn shutdown_stale_now_does_not_panic_or_force_kill() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let now = Instant::now();
        coordinator.start_graceful(now);
        let earlier = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(!coordinator.should_force_kill(earlier));
    }

    #[test]
    fn shutdown_record_force_kill() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        let now = Instant::now();
        coordinator.start_graceful(now);
        let later = now + Duration::from_secs(2);
        coordinator.record_force_kill(later);
        assert!(matches!(
            coordinator.phase(),
            ShutdownPhase::ForceKill { .. }
        ));
        assert!(coordinator.is_shutting_down());
    }

    #[test]
    fn shutdown_record_exit_completes() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        coordinator.start_graceful(Instant::now());
        coordinator.record_exit(ProcessExit::clean());
        assert!(coordinator.is_complete());
        assert!(!coordinator.is_shutting_down());
    }

    #[test]
    fn shutdown_double_start_is_idempotent() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(30));
        let now = Instant::now();
        coordinator.start_graceful(now);
        let later = now + Duration::from_secs(5);
        coordinator.start_graceful(later);
        // Should still have the original start time.
        if let ShutdownPhase::GracefulWait { sent_at } = coordinator.phase() {
            assert_eq!(*sent_at, now);
        } else {
            panic!("expected GracefulWait");
        }
    }

    #[test]
    fn shutdown_not_started_does_not_force_kill() {
        let coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        assert!(!coordinator.should_force_kill(Instant::now()));
    }

    // ── HealthCheckScheduler ──

    #[test]
    fn health_check_due_initially() {
        let scheduler = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        assert!(scheduler.is_due(Instant::now()));
    }

    #[test]
    fn health_check_not_due_after_recent_check() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_success(now);
        assert!(!scheduler.is_due(now));
    }

    #[test]
    fn health_check_stale_now_is_not_due() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_success(now);
        let earlier = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(!scheduler.is_due(earlier));
    }

    #[test]
    fn health_check_due_after_interval() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(1), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_success(now);
        let later = now + Duration::from_secs(2);
        assert!(scheduler.is_due(later));
    }

    #[test]
    fn health_check_consecutive_failures_tracked() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        assert_eq!(scheduler.consecutive_failures(), 0);
        scheduler.record_failure(now);
        assert_eq!(scheduler.consecutive_failures(), 1);
        scheduler.record_failure(now);
        assert_eq!(scheduler.consecutive_failures(), 2);
    }

    #[test]
    fn health_check_success_resets_failures() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_failure(now);
        scheduler.record_failure(now);
        scheduler.record_success(now);
        assert_eq!(scheduler.consecutive_failures(), 0);
    }

    #[test]
    fn health_check_unhealthy_after_threshold() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10))
                .with_max_failures(2);
        let now = Instant::now();
        assert!(!scheduler.is_unhealthy());
        scheduler.record_failure(now);
        assert!(!scheduler.is_unhealthy());
        scheduler.record_failure(now);
        assert!(scheduler.is_unhealthy());
    }

    #[test]
    fn health_check_time_until_next() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        assert_eq!(scheduler.time_until_next(now), Duration::ZERO);
        scheduler.record_success(now);
        let remaining = scheduler.time_until_next(now + Duration::from_secs(10));
        assert_eq!(remaining, Duration::from_secs(20));
    }

    #[test]
    fn health_check_time_until_next_saturates_for_stale_now() {
        let mut scheduler =
            HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
        let now = Instant::now();
        scheduler.record_success(now);
        let earlier = now.checked_sub(Duration::from_secs(5)).unwrap();
        assert_eq!(scheduler.time_until_next(earlier), Duration::from_secs(30));
    }

    #[test]
    fn health_check_timeout_accessor() {
        let scheduler = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(5));
        assert_eq!(scheduler.timeout(), Duration::from_secs(5));
    }

    // ── JSON serialization roundtrips ──

    #[test]
    fn restart_policy_json_roundtrip() {
        for policy in [
            RestartPolicy::Always,
            RestartPolicy::OnFailure,
            RestartPolicy::OnCrash,
            RestartPolicy::Never,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let parsed: RestartPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
    }

    #[test]
    fn process_exit_json_roundtrip() {
        for exit in [
            ProcessExit::clean(),
            ProcessExit::with_code(42),
            ProcessExit::with_signal(15),
            ProcessExit {
                code: Some(1),
                signal: Some(11),
            },
        ] {
            let json = serde_json::to_string(&exit).unwrap();
            let parsed: ProcessExit = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, exit);
        }
    }

    #[test]
    fn supervisor_config_json_roundtrip() {
        let config = SupervisorConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SupervisorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_restarts, config.max_restarts);
        assert_eq!(parsed.restart_window, config.restart_window);
    }

    #[test]
    fn stop_reason_equality() {
        assert_eq!(StopReason::Requested, StopReason::Requested);
        assert_ne!(StopReason::Requested, StopReason::HostShutdown);
    }

    #[test]
    fn backoff_zero_initial_stays_zero() {
        let mut backoff = ExponentialBackoff::new(Duration::ZERO, Duration::from_mins(1), 2.0);
        assert_eq!(backoff.next_backoff(), Duration::ZERO);
        assert_eq!(backoff.next_backoff(), Duration::ZERO);
    }

    #[test]
    fn tracker_on_crash_denies_nonzero_exit() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::OnCrash,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        let result = tracker.evaluate_restart(&ProcessExit::with_code(1), Instant::now());
        assert_eq!(result, Err(RestartDenied::PolicyDenied));
    }

    #[test]
    fn tracker_on_crash_allows_signal() {
        let config = SupervisorConfig {
            restart_policy: RestartPolicy::OnCrash,
            ..Default::default()
        };
        let mut tracker = RestartTracker::new(config);
        assert!(
            tracker
                .evaluate_restart(&ProcessExit::with_signal(11), Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn backoff_saturates_attempt_counter() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(1), Duration::from_secs(1), 2.0);
        for _ in 0..1000 {
            let _ = backoff.next_backoff();
        }
        // Should cap at max, never panic.
        assert!(backoff.current_delay() <= Duration::from_secs(1));
    }

    #[test]
    fn health_scheduler_custom_max_failures() {
        let scheduler = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10))
            .with_max_failures(5);
        assert!(!scheduler.is_unhealthy());
    }

    #[test]
    fn shutdown_force_kill_not_from_not_started() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        // record_force_kill should be a no-op when not in GracefulWait.
        coordinator.record_force_kill(Instant::now());
        assert_eq!(*coordinator.phase(), ShutdownPhase::NotStarted);
    }

    #[test]
    fn shutdown_complete_after_force_kill() {
        let mut coordinator = ShutdownCoordinator::new(Duration::from_secs(1));
        let now = Instant::now();
        coordinator.start_graceful(now);
        coordinator.record_force_kill(now + Duration::from_secs(2));
        coordinator.record_exit(ProcessExit::with_signal(9));
        assert!(coordinator.is_complete());
    }

    #[test]
    fn tracker_config_accessor() {
        let config = SupervisorConfig {
            max_restarts: 42,
            ..Default::default()
        };
        let tracker = RestartTracker::new(config);
        assert_eq!(tracker.config().max_restarts, 42);
    }

    // ── ResourceLimits ──

    #[test]
    fn resource_limits_default_has_memory_and_fds() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(limits.max_fds, Some(1024));
        assert_eq!(limits.max_processes, Some(64));
        assert!(limits.cpu_seconds.is_none());
        assert!(limits.max_file_size_bytes.is_none());
    }

    #[test]
    fn resource_limits_unlimited_has_no_limits() {
        let limits = ResourceLimits::unlimited();
        assert!(!limits.has_any_limits());
        assert_eq!(limits.active_limit_count(), 0);
    }

    #[test]
    fn resource_limits_default_has_three_active() {
        let limits = ResourceLimits::default();
        assert!(limits.has_any_limits());
        assert_eq!(limits.active_limit_count(), 3);
    }

    #[test]
    fn resource_limits_all_set_counts_five() {
        let limits = ResourceLimits {
            memory_bytes: Some(1),
            cpu_seconds: Some(1),
            max_fds: Some(1),
            max_processes: Some(1),
            max_file_size_bytes: Some(1),
        };
        assert_eq!(limits.active_limit_count(), 5);
    }

    #[test]
    fn resource_limits_merge_strict_takes_lower() {
        let a = ResourceLimits {
            memory_bytes: Some(1000),
            max_fds: Some(100),
            ..ResourceLimits::unlimited()
        };
        let b = ResourceLimits {
            memory_bytes: Some(500),
            max_fds: Some(200),
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        let merged = a.merge_strict(&b);
        assert_eq!(merged.memory_bytes, Some(500));
        assert_eq!(merged.max_fds, Some(100));
        assert_eq!(merged.cpu_seconds, Some(60));
    }

    #[test]
    fn resource_limits_merge_strict_with_unlimited() {
        let limited = ResourceLimits::default();
        let unlimited = ResourceLimits::unlimited();
        let merged = limited.merge_strict(&unlimited);
        assert_eq!(merged.memory_bytes, limited.memory_bytes);
        assert_eq!(merged.max_fds, limited.max_fds);
    }

    #[test]
    fn resource_limits_merge_strict_both_unlimited() {
        let a = ResourceLimits::unlimited();
        let b = ResourceLimits::unlimited();
        assert!(!a.merge_strict(&b).has_any_limits());
    }

    #[test]
    fn resource_limits_json_roundtrip() {
        let limits = ResourceLimits::default();
        let json = serde_json::to_string(&limits).unwrap();
        let parsed: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, limits);
    }

    #[test]
    fn resource_limits_unlimited_json_roundtrip() {
        let limits = ResourceLimits::unlimited();
        let json = serde_json::to_string(&limits).unwrap();
        let parsed: ResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, limits);
    }

    // ── ResourceUsage ──

    #[test]
    fn resource_usage_within_limits() {
        let usage = ResourceUsage {
            memory_bytes: 100 * 1024 * 1024,
            cpu_millis: 5000,
            open_fds: 50,
            process_count: 10,
        };
        let limits = ResourceLimits::default();
        assert!(usage.within_limits(&limits));
        assert!(usage.violations(&limits).is_empty());
    }

    #[test]
    fn resource_usage_memory_violation() {
        let usage = ResourceUsage {
            memory_bytes: 1024 * 1024 * 1024, // 1 GiB
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024), // 512 MiB
            ..ResourceLimits::unlimited()
        };
        assert!(!usage.within_limits(&limits));
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::Memory);
        assert_eq!(violations[0].current, 1024 * 1024 * 1024);
        assert_eq!(violations[0].limit, 512 * 1024 * 1024);
    }

    #[test]
    fn resource_usage_fds_violation() {
        let usage = ResourceUsage {
            open_fds: 2048,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_fds: Some(1024),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::FileDescriptors);
    }

    #[test]
    fn resource_usage_cpu_violation() {
        let usage = ResourceUsage {
            cpu_millis: 120_000, // 120 seconds
            ..Default::default()
        };
        let limits = ResourceLimits {
            cpu_seconds: Some(60),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::CpuTime);
        assert_eq!(violations[0].current, 120);
        assert_eq!(violations[0].limit, 60);
    }

    #[test]
    fn resource_usage_process_violation() {
        let usage = ResourceUsage {
            process_count: 100,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_processes: Some(64),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource, ResourceKind::Processes);
    }

    #[test]
    fn resource_usage_multiple_violations() {
        let usage = ResourceUsage {
            memory_bytes: 1024 * 1024 * 1024,
            open_fds: 2048,
            process_count: 100,
            cpu_millis: 0,
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            max_fds: Some(1024),
            max_processes: Some(50),
            ..ResourceLimits::unlimited()
        };
        let violations = usage.violations(&limits);
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn resource_usage_no_violations_unlimited() {
        let usage = ResourceUsage {
            memory_bytes: u64::MAX,
            cpu_millis: u64::MAX,
            open_fds: u64::MAX,
            process_count: u64::MAX,
        };
        let limits = ResourceLimits::unlimited();
        assert!(usage.within_limits(&limits));
    }

    #[test]
    fn resource_usage_at_exact_limit_is_ok() {
        let usage = ResourceUsage {
            memory_bytes: 512 * 1024 * 1024,
            open_fds: 1024,
            process_count: 64,
            cpu_millis: 60_000,
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            max_fds: Some(1024),
            max_processes: Some(64),
            cpu_seconds: Some(60),
            max_file_size_bytes: None,
        };
        assert!(usage.within_limits(&limits));
    }

    #[test]
    fn resource_usage_one_over_limit_violates() {
        let usage = ResourceUsage {
            memory_bytes: 512 * 1024 * 1024 + 1,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        assert!(!usage.within_limits(&limits));
    }

    // ── ResourceViolation ──

    #[test]
    fn resource_violation_display() {
        let v = ResourceViolation {
            resource: ResourceKind::Memory,
            current: 1024,
            limit: 512,
        };
        let msg = v.to_string();
        assert!(msg.contains("memory"));
        assert!(msg.contains("1024"));
        assert!(msg.contains("512"));
    }

    // ── ResourceKind ──

    #[test]
    fn resource_kind_display_all_variants() {
        assert_eq!(ResourceKind::Memory.to_string(), "memory");
        assert_eq!(ResourceKind::CpuTime.to_string(), "cpu_time");
        assert_eq!(
            ResourceKind::FileDescriptors.to_string(),
            "file_descriptors"
        );
        assert_eq!(ResourceKind::Processes.to_string(), "processes");
        assert_eq!(ResourceKind::FileSize.to_string(), "file_size");
    }

    #[test]
    fn resource_kind_json_roundtrip() {
        for kind in [
            ResourceKind::Memory,
            ResourceKind::CpuTime,
            ResourceKind::FileDescriptors,
            ResourceKind::Processes,
            ResourceKind::FileSize,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: ResourceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    // ── ResourceUtilization ──

    #[test]
    fn utilization_50_percent_memory() {
        let usage = ResourceUsage {
            memory_bytes: 256 * 1024 * 1024,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        assert!((util.memory.unwrap() - 0.5).abs() < f64::EPSILON);
        assert!(util.cpu.is_none());
        assert!(util.fds.is_none());
        assert!(util.processes.is_none());
    }

    #[test]
    fn utilization_over_100_percent() {
        let usage = ResourceUsage {
            memory_bytes: 1024 * 1024 * 1024,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        assert!(util.memory.unwrap() > 1.0);
    }

    #[test]
    fn utilization_max_returns_highest() {
        let usage = ResourceUsage {
            memory_bytes: 400 * 1024 * 1024,
            open_fds: 900,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            max_fds: Some(1000),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        let max = util.max_utilization().unwrap();
        // FDs: 900/1000 = 0.9, Memory: 400/512 ≈ 0.78
        assert!((max - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn utilization_all_unlimited_returns_none() {
        let usage = ResourceUsage::default();
        let limits = ResourceLimits::unlimited();
        let util = usage.utilization(&limits);
        assert!(util.max_utilization().is_none());
    }

    #[test]
    fn utilization_above_threshold() {
        let usage = ResourceUsage {
            memory_bytes: 480 * 1024 * 1024,
            ..Default::default()
        };
        let limits = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::unlimited()
        };
        let util = usage.utilization(&limits);
        assert!(util.any_above_threshold(0.9));
        assert!(!util.any_above_threshold(0.95));
    }

    #[test]
    fn utilization_not_above_threshold_when_unlimited() {
        let usage = ResourceUsage::default();
        let limits = ResourceLimits::unlimited();
        let util = usage.utilization(&limits);
        assert!(!util.any_above_threshold(0.0));
    }

    // ── merge_option_min ──

    #[test]
    fn merge_option_min_both_some() {
        assert_eq!(merge_option_min(Some(10), Some(5)), Some(5));
        assert_eq!(merge_option_min(Some(5), Some(10)), Some(5));
    }

    #[test]
    fn merge_option_min_one_none() {
        assert_eq!(merge_option_min(Some(10), None), Some(10));
        assert_eq!(merge_option_min(None, Some(10)), Some(10));
    }

    #[test]
    fn merge_option_min_both_none() {
        assert_eq!(merge_option_min(None, None), None);
    }

    // ── ConnectionTracker ──

    #[test]
    fn connection_tracker_starts_at_zero() {
        let tracker = ConnectionTracker::new();
        assert_eq!(tracker.active_count(), 0);
        assert!(!tracker.is_draining());
        assert!(!tracker.is_drained()); // Not drained because not draining.
    }

    #[test]
    fn connection_tracker_default_same_as_new() {
        let tracker = ConnectionTracker::default();
        assert_eq!(tracker.active_count(), 0);
        assert!(!tracker.is_draining());
    }

    #[test]
    fn connection_tracker_acquire_increments() {
        let tracker = ConnectionTracker::new();
        let _g1 = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 1);
        let _g2 = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 2);
    }

    #[test]
    fn connection_tracker_drop_decrements() {
        let tracker = ConnectionTracker::new();
        let g1 = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 1);
        drop(g1);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn connection_tracker_drain_rejects_new() {
        let tracker = ConnectionTracker::new();
        tracker.start_drain();
        assert!(tracker.is_draining());
        assert!(tracker.try_acquire().is_none());
    }

    #[test]
    fn connection_tracker_existing_during_drain() {
        let tracker = ConnectionTracker::new();
        let _g = tracker.try_acquire().unwrap();
        assert_eq!(tracker.active_count(), 1);
        tracker.start_drain();
        assert!(tracker.is_draining());
        assert!(!tracker.is_drained()); // Still has active connection.
        assert!(tracker.try_acquire().is_none()); // New connections rejected.
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn connection_tracker_drained_after_all_drop() {
        let tracker = ConnectionTracker::new();
        let g1 = tracker.try_acquire().unwrap();
        let g2 = tracker.try_acquire().unwrap();
        tracker.start_drain();
        assert!(!tracker.is_drained());
        drop(g1);
        assert!(!tracker.is_drained());
        drop(g2);
        assert!(tracker.is_drained());
    }

    #[test]
    fn connection_tracker_multiple_drains_idempotent() {
        let tracker = ConnectionTracker::new();
        tracker.start_drain();
        tracker.start_drain();
        assert!(tracker.is_draining());
        assert!(tracker.is_drained());
    }

    #[test]
    fn connection_tracker_many_connections() {
        let tracker = ConnectionTracker::new();
        let guards: Vec<_> = (0..100).map(|_| tracker.try_acquire().unwrap()).collect();
        assert_eq!(tracker.active_count(), 100);
        drop(guards);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn connection_guard_debug_format() {
        let tracker = ConnectionTracker::new();
        let guard = tracker.try_acquire().unwrap();
        let debug = format!("{guard:?}");
        assert!(debug.contains("ConnectionGuard"));
    }
}
