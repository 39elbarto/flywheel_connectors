//! Resilience primitives for `fcp-host`.
//!
//! This module provides host-side resilience controls that can be applied to
//! connector RPCs:
//! - circuit breakers to stop cascading failures
//! - bulkheads to isolate connector saturation
//! - health-based routing with probe-only recovery
//! - adaptive load shedding that respects request priority

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use fcp_async_core::sync::{OwnedSemaphorePermit, Semaphore};
use fcp_async_core::time;
use fcp_core::{ConnectorHealth, ConnectorId};

const MAX_PER_MILLE: u32 = 1_000;

/// Request priority used by load shedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestPriority {
    /// Essential traffic that should never be shed.
    Critical,
    /// Important operational traffic.
    High,
    /// Default traffic.
    Normal,
    /// Best-effort traffic that can be shed aggressively.
    Low,
}

impl RequestPriority {
    const fn shed_factor_per_mille(self) -> u32 {
        match self {
            Self::Critical => 0,
            Self::High => 300,
            Self::Normal => 700,
            Self::Low => MAX_PER_MILLE,
        }
    }
}

/// Error returned by the resilience layer.
#[derive(Debug, PartialEq, Eq)]
pub enum ResilienceError<E> {
    /// The request was shed due to host load.
    LoadShed { load_per_mille: u16 },
    /// The connector is currently considered unhealthy.
    Unhealthy { reason: String },
    /// The connector circuit breaker is open.
    CircuitOpen { retry_after: Duration },
    /// Half-open probe traffic is already in flight.
    HalfOpenLimited,
    /// Bulkhead queue is full.
    BulkheadFull,
    /// Bulkhead queue wait timed out.
    QueueTimeout { timeout: Duration },
    /// Operation timed out while executing.
    TimedOut { timeout: Duration },
    /// The wrapped operation itself failed.
    Inner(E),
}

impl<E: std::fmt::Debug> std::fmt::Display for ResilienceError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoadShed { load_per_mille } => {
                write!(f, "request load shed at {load_per_mille}‰ load")
            }
            Self::Unhealthy { reason } => write!(f, "connector unhealthy: {reason}"),
            Self::CircuitOpen { retry_after } => write!(
                f,
                "circuit breaker open for another {}ms",
                retry_after.as_millis()
            ),
            Self::HalfOpenLimited => write!(f, "half-open probe already in flight"),
            Self::BulkheadFull => write!(f, "bulkhead queue is full"),
            Self::QueueTimeout { timeout } => {
                write!(
                    f,
                    "bulkhead queue timed out after {}ms",
                    timeout.as_millis()
                )
            }
            Self::TimedOut { timeout } => {
                write!(f, "operation timed out after {}ms", timeout.as_millis())
            }
            Self::Inner(error) => write!(f, "inner error: {error:?}"),
        }
    }
}

impl<E> std::error::Error for ResilienceError<E> where E: std::error::Error + 'static {}

/// Top-level resilience configuration.
#[derive(Debug, Clone, Default)]
pub struct ResilienceConfig {
    /// Circuit breaker configuration.
    pub circuit_breaker: CircuitBreakerConfig,
    /// Bulkhead configuration.
    pub bulkhead: BulkheadConfig,
    /// Health routing configuration.
    pub health: HealthRouterConfig,
    /// Load shedding configuration.
    pub load_shed: LoadShedConfig,
    /// Optional end-to-end operation timeout.
    pub operation_timeout: Option<Duration>,
}

/// Failure matching policy for circuit breaker tripping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePredicate {
    /// Any explicit error or timeout.
    AnyError,
    /// Only timeouts contribute to the breaker.
    TimeoutsOnly,
    /// Slow successes count as failures.
    SlowResponses { threshold: Duration },
    /// Explicit failures, timeouts, or slow successes count as failures.
    ErrorOrSlowResponses { threshold: Duration },
}

impl FailurePredicate {
    fn matches(self, outcome: OutcomeKind, latency: Duration) -> bool {
        match self {
            Self::AnyError => matches!(outcome, OutcomeKind::Failure | OutcomeKind::TimedOut),
            Self::TimeoutsOnly => outcome == OutcomeKind::TimedOut,
            Self::SlowResponses { threshold } => {
                outcome == OutcomeKind::Success && latency > threshold
            }
            Self::ErrorOrSlowResponses { threshold } => {
                matches!(outcome, OutcomeKind::Failure | OutcomeKind::TimedOut)
                    || (outcome == OutcomeKind::Success && latency > threshold)
            }
        }
    }
}

/// Circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failures required to open the breaker.
    pub failure_threshold: u32,
    /// Successes required to close a half-open breaker.
    pub success_threshold: u32,
    /// How long the breaker remains open before a probe is allowed.
    pub open_duration: Duration,
    /// Failure counting window.
    pub window_duration: Duration,
    /// Which outcomes count as failures.
    pub failure_predicate: FailurePredicate,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 2,
            open_duration: Duration::from_secs(5),
            window_duration: Duration::from_secs(30),
            failure_predicate: FailurePredicate::AnyError,
        }
    }
}

/// Observable circuit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Requests are rejected until open duration elapses.
    Open,
    /// Limited probe traffic is allowed while recovering.
    HalfOpen,
}

/// Bulkhead configuration.
#[derive(Debug, Clone)]
pub struct BulkheadConfig {
    /// Maximum in-flight requests for a connector.
    pub max_concurrent: usize,
    /// Maximum queued waiters for a connector.
    pub max_queued: usize,
    /// Maximum wait time for a queue slot.
    pub queue_timeout: Duration,
}

impl Default for BulkheadConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 16,
            max_queued: 32,
            queue_timeout: Duration::from_millis(250),
        }
    }
}

/// Health router configuration.
#[derive(Debug, Clone)]
pub struct HealthRouterConfig {
    /// Consecutive failures required to mark a connector unavailable.
    pub unhealthy_threshold: u32,
    /// Consecutive successes required to recover from unavailable.
    pub recovery_success_threshold: u32,
    /// Latency threshold for degraded status.
    pub latency_degraded_threshold: Duration,
    /// Error-rate threshold for degraded status.
    pub error_rate_degraded_threshold_per_mille: u16,
    /// Minimum spacing between probe requests.
    pub probe_interval: Duration,
    /// Sliding window used for error-rate estimation.
    pub error_window: Duration,
    /// EWMA alpha in per-mille form.
    pub latency_alpha_per_mille: u16,
}

impl Default for HealthRouterConfig {
    fn default() -> Self {
        Self {
            unhealthy_threshold: 3,
            recovery_success_threshold: 2,
            latency_degraded_threshold: Duration::from_millis(750),
            error_rate_degraded_threshold_per_mille: 500,
            probe_interval: Duration::from_secs(5),
            error_window: Duration::from_secs(30),
            latency_alpha_per_mille: 200,
        }
    }
}

/// Load shedding configuration.
#[derive(Debug, Clone)]
pub struct LoadShedConfig {
    /// Start shedding at this load.
    pub shed_threshold_per_mille: u16,
    /// Shed all eligible traffic at this load.
    pub full_shed_threshold_per_mille: u16,
    /// Priority classes that may be shed.
    pub sheddable_priorities: Vec<RequestPriority>,
}

impl Default for LoadShedConfig {
    fn default() -> Self {
        Self {
            shed_threshold_per_mille: 850,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low, RequestPriority::Normal],
        }
    }
}

/// Routing decision derived from connector health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Route normally.
    Allow,
    /// Route, but the connector is degraded.
    AllowDegraded { reason: String },
    /// Route a limited probe to test recovery.
    AllowProbe,
    /// Reject due to unhealthy state.
    Reject { reason: String },
}

/// Per-connector resilience counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResilienceMetricsSnapshot {
    /// Total requests seen by the layer.
    pub requests: u64,
    /// Successful requests.
    pub successes: u64,
    /// Explicit failures from the inner operation.
    pub failures: u64,
    /// Timed out operations.
    pub timeouts: u64,
    /// Requests rejected by an open circuit.
    pub circuit_rejections: u64,
    /// Times the breaker transitioned to open.
    pub circuit_opened: u64,
    /// Requests rejected by the bulkhead.
    pub bulkhead_rejections: u64,
    /// Requests shed due to load.
    pub load_shed: u64,
    /// Probe requests allowed through.
    pub probe_requests: u64,
}

/// Host resilience layer composed from circuit breaker, bulkhead, and health routing.
#[derive(Debug)]
pub struct ResilienceLayer {
    config: ResilienceConfig,
    connectors: Mutex<HashMap<ConnectorId, Arc<ConnectorState>>>,
    health_router: HealthRouter,
    load_shedder: LoadShedder,
}

impl Default for ResilienceLayer {
    fn default() -> Self {
        Self::new(ResilienceConfig::default())
    }
}

impl ResilienceLayer {
    /// Create a resilience layer with the supplied configuration.
    #[must_use]
    pub fn new(config: ResilienceConfig) -> Self {
        Self {
            load_shedder: LoadShedder::new(config.load_shed.clone()),
            health_router: HealthRouter::new(config.health.clone()),
            config,
            connectors: Mutex::new(HashMap::new()),
        }
    }

    /// Ensure a connector has initialized resilience state.
    pub fn ensure_connector(&self, connector_id: &ConnectorId) {
        let _ = self.connector_state(connector_id);
        self.health_router.ensure_connector(connector_id);
    }

    /// Override the manual base load used by the shedder.
    pub fn set_base_load_per_mille(&self, load_per_mille: u16) {
        self.load_shedder.set_base_load_per_mille(load_per_mille);
    }

    /// Get the current health-derived routing state for a connector.
    #[must_use]
    pub fn connector_health(&self, connector_id: &ConnectorId) -> ConnectorHealth {
        self.health_router.health(connector_id)
    }

    /// Get the current circuit state for a connector.
    #[must_use]
    pub fn circuit_state(&self, connector_id: &ConnectorId) -> CircuitState {
        self.connector_state(connector_id).circuit.state()
    }

    /// Snapshot metrics for a connector.
    #[must_use]
    pub fn metrics(&self, connector_id: &ConnectorId) -> ResilienceMetricsSnapshot {
        self.connector_state(connector_id).metrics.snapshot()
    }

    /// Execute a connector operation with all resilience protections applied.
    ///
    /// # Errors
    ///
    /// Returns a [`ResilienceError`] when the operation is shed, rejected, or
    /// when the wrapped operation itself fails.
    pub async fn execute<F, T, E>(
        &self,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        future: F,
    ) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let state = self.connector_state(connector_id);
        let effective_load = self.record_request(&state);
        self.check_load_shed(&state, connector_id, priority, operation, effective_load)?;
        self.check_routing(&state, connector_id, operation)?;
        Self::check_circuit(&state, connector_id, operation)?;
        let permit = self
            .acquire_bulkhead(&state, connector_id, operation)
            .await?;
        let started_at = Instant::now();
        let result = self
            .run_operation(&state, connector_id, operation, future, started_at)
            .await;
        drop(permit);
        self.record_completion(&state, connector_id, started_at.elapsed(), &result);
        result
    }

    fn record_request(&self, state: &ConnectorState) -> u32 {
        state.metrics.requests.fetch_add(1, Ordering::Relaxed);
        self.load_shedder
            .effective_load_per_mille(state.bulkhead.pressure_per_mille())
    }

    fn check_load_shed<E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        priority: RequestPriority,
        operation: &str,
        effective_load: u32,
    ) -> Result<(), ResilienceError<E>> {
        if self.load_shedder.should_shed(priority, effective_load) {
            state.metrics.load_shed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                connector_id = %connector_id,
                operation,
                load_per_mille = effective_load,
                priority = ?priority,
                "request shed due to load"
            );
            return Err(ResilienceError::LoadShed {
                load_per_mille: to_u16(effective_load),
            });
        }

        Ok(())
    }

    fn check_routing<E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
    ) -> Result<(), ResilienceError<E>> {
        match self.health_router.can_route(connector_id) {
            RoutingDecision::Allow | RoutingDecision::AllowDegraded { .. } => Ok(()),
            RoutingDecision::AllowProbe => {
                state.metrics.probe_requests.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            RoutingDecision::Reject { reason } => {
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    reason,
                    "connector rejected by health router"
                );
                Err(ResilienceError::Unhealthy { reason })
            }
        }
    }

    fn check_circuit<E>(
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
    ) -> Result<(), ResilienceError<E>> {
        match state.circuit.before_call() {
            Ok(CircuitPermit::Regular | CircuitPermit::Probe) => Ok(()),
            Err(CircuitReject::Open { retry_after }) => {
                state
                    .metrics
                    .circuit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    retry_after_ms = retry_after.as_millis(),
                    "circuit breaker rejected request"
                );
                Err(ResilienceError::CircuitOpen { retry_after })
            }
            Err(CircuitReject::HalfOpenLimited) => {
                state
                    .metrics
                    .circuit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    "half-open probe already in flight"
                );
                Err(ResilienceError::HalfOpenLimited)
            }
        }
    }

    async fn acquire_bulkhead<E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
    ) -> Result<OwnedSemaphorePermit, ResilienceError<E>> {
        match state.bulkhead.acquire().await {
            Ok(permit) => Ok(permit),
            Err(BulkheadAcquireError::QueueFull) => {
                state.circuit.cancel_inflight_probe();
                state
                    .metrics
                    .bulkhead_rejections
                    .fetch_add(1, Ordering::Relaxed);
                self.health_router
                    .record_failure(connector_id, "bulkhead queue full");
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    "bulkhead queue full"
                );
                Err(ResilienceError::BulkheadFull)
            }
            Err(BulkheadAcquireError::QueueTimeout { timeout }) => {
                state.circuit.cancel_inflight_probe();
                state
                    .metrics
                    .bulkhead_rejections
                    .fetch_add(1, Ordering::Relaxed);
                self.health_router
                    .record_failure(connector_id, "bulkhead queue timeout");
                tracing::warn!(
                    connector_id = %connector_id,
                    operation,
                    timeout_ms = timeout.as_millis(),
                    "bulkhead queue timed out"
                );
                Err(ResilienceError::QueueTimeout { timeout })
            }
        }
    }

    async fn run_operation<F, T, E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
        future: F,
        started_at: Instant,
    ) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        if let Some(timeout) = self.config.operation_timeout {
            return self
                .run_operation_with_timeout(
                    state,
                    connector_id,
                    operation,
                    future,
                    started_at,
                    timeout,
                )
                .await;
        }

        future.await.map_err(ResilienceError::Inner)
    }

    async fn run_operation_with_timeout<F, T, E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
        future: F,
        started_at: Instant,
        timeout: Duration,
    ) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        if let Ok(inner) = time::timeout(timeout, future).await {
            return inner.map_err(ResilienceError::Inner);
        }

        self.record_timeout(
            state,
            connector_id,
            operation,
            timeout,
            started_at.elapsed(),
        );
        Err(ResilienceError::TimedOut { timeout })
    }

    fn record_timeout(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        operation: &str,
        timeout: Duration,
        latency: Duration,
    ) {
        state.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
        self.apply_circuit_outcome(state, OutcomeKind::TimedOut, latency);
        self.health_router
            .record_timeout(connector_id, timeout, latency);
        tracing::warn!(
            connector_id = %connector_id,
            operation,
            timeout_ms = timeout.as_millis(),
            "connector operation timed out"
        );
    }

    fn record_completion<T, E>(
        &self,
        state: &ConnectorState,
        connector_id: &ConnectorId,
        latency: Duration,
        result: &Result<T, ResilienceError<E>>,
    ) {
        match result {
            Ok(_) => {
                state.metrics.successes.fetch_add(1, Ordering::Relaxed);
                self.health_router.record_success(connector_id, latency);
                self.apply_circuit_outcome(state, OutcomeKind::Success, latency);
            }
            Err(ResilienceError::Inner(_)) => {
                state.metrics.failures.fetch_add(1, Ordering::Relaxed);
                self.health_router
                    .record_failure(connector_id, "connector operation failed");
                self.apply_circuit_outcome(state, OutcomeKind::Failure, latency);
            }
            Err(_) => {}
        }
    }

    fn apply_circuit_outcome(
        &self,
        state: &ConnectorState,
        outcome: OutcomeKind,
        latency: Duration,
    ) {
        if self
            .config
            .circuit_breaker
            .failure_predicate
            .matches(outcome, latency)
        {
            if state.circuit.record_failure() {
                state.metrics.circuit_opened.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            state.circuit.record_success();
        }
    }

    fn connector_state(&self, connector_id: &ConnectorId) -> Arc<ConnectorState> {
        let mut states = lock_unpoisoned(&self.connectors);
        Arc::clone(
            states
                .entry(connector_id.clone())
                .or_insert_with(|| Arc::new(ConnectorState::new(&self.config))),
        )
    }
}

/// Merge two connector health sources and keep the worst status.
#[must_use]
pub fn merge_connector_health(
    primary: ConnectorHealth,
    secondary: ConnectorHealth,
) -> ConnectorHealth {
    match (
        health_severity(&primary),
        health_severity(&secondary),
        primary,
        secondary,
    ) {
        (HealthSeverity::Healthy, HealthSeverity::Healthy, ConnectorHealth::Healthy, _) => {
            ConnectorHealth::Healthy
        }
        (HealthSeverity::Unavailable, _, ConnectorHealth::Unavailable { reason, since }, other)
        | (_, HealthSeverity::Unavailable, other, ConnectorHealth::Unavailable { reason, since }) =>
        {
            let combined =
                combine_reason_strings(&reason, health_reason(&other).unwrap_or_default());
            ConnectorHealth::Unavailable {
                reason: combined,
                since: earlier_since(Some(since), unavailable_since(&other)).unwrap_or(since),
            }
        }
        (HealthSeverity::Degraded, _, ConnectorHealth::Degraded { reason }, other)
        | (_, HealthSeverity::Degraded, other, ConnectorHealth::Degraded { reason }) => {
            ConnectorHealth::Degraded {
                reason: combine_reason_strings(&reason, health_reason(&other).unwrap_or_default()),
            }
        }
        _ => ConnectorHealth::Healthy,
    }
}

#[derive(Debug)]
struct ConnectorState {
    circuit: CircuitBreaker,
    bulkhead: Bulkhead,
    metrics: ConnectorMetrics,
}

impl ConnectorState {
    fn new(config: &ResilienceConfig) -> Self {
        Self {
            circuit: CircuitBreaker::new(config.circuit_breaker.clone()),
            bulkhead: Bulkhead::new(config.bulkhead.clone()),
            metrics: ConnectorMetrics::default(),
        }
    }
}

#[derive(Debug, Default)]
struct ConnectorMetrics {
    requests: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    timeouts: AtomicU64,
    circuit_rejections: AtomicU64,
    circuit_opened: AtomicU64,
    bulkhead_rejections: AtomicU64,
    load_shed: AtomicU64,
    probe_requests: AtomicU64,
}

impl ConnectorMetrics {
    fn snapshot(&self) -> ResilienceMetricsSnapshot {
        ResilienceMetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            circuit_rejections: self.circuit_rejections.load(Ordering::Relaxed),
            circuit_opened: self.circuit_opened.load(Ordering::Relaxed),
            bulkhead_rejections: self.bulkhead_rejections.load(Ordering::Relaxed),
            load_shed: self.load_shed.load(Ordering::Relaxed),
            probe_requests: self.probe_requests.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeKind {
    Success,
    Failure,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitPermit {
    Regular,
    Probe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitReject {
    Open { retry_after: Duration },
    HalfOpenLimited,
}

#[derive(Debug)]
struct CircuitBreaker {
    config: CircuitBreakerConfig,
    inner: Mutex<CircuitInner>,
}

#[derive(Debug)]
struct CircuitInner {
    state: CircuitState,
    failures: u32,
    successes: u32,
    window_started_at: Instant,
    opened_until: Option<Instant>,
    probe_in_flight: bool,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(CircuitInner {
                state: CircuitState::Closed,
                failures: 0,
                successes: 0,
                window_started_at: Instant::now(),
                opened_until: None,
                probe_in_flight: false,
            }),
        }
    }

    fn state(&self) -> CircuitState {
        lock_unpoisoned(&self.inner).state
    }

    fn before_call(&self) -> Result<CircuitPermit, CircuitReject> {
        let now = Instant::now();
        let mut inner = lock_unpoisoned(&self.inner);
        let decision = match inner.state {
            CircuitState::Closed => Ok(CircuitPermit::Regular),
            CircuitState::Open => {
                if let Some(until) = inner.opened_until {
                    if now < until {
                        Err(CircuitReject::Open {
                            retry_after: until.saturating_duration_since(now),
                        })
                    } else {
                        inner.state = CircuitState::HalfOpen;
                        inner.successes = 0;
                        inner.probe_in_flight = true;
                        Ok(CircuitPermit::Probe)
                    }
                } else {
                    inner.state = CircuitState::HalfOpen;
                    inner.successes = 0;
                    inner.probe_in_flight = true;
                    Ok(CircuitPermit::Probe)
                }
            }
            CircuitState::HalfOpen => {
                if inner.probe_in_flight {
                    Err(CircuitReject::HalfOpenLimited)
                } else {
                    inner.probe_in_flight = true;
                    Ok(CircuitPermit::Probe)
                }
            }
        };
        drop(inner);
        decision
    }

    fn cancel_inflight_probe(&self) {
        let mut inner = lock_unpoisoned(&self.inner);
        if inner.state == CircuitState::HalfOpen {
            inner.probe_in_flight = false;
        }
    }

    fn record_success(&self) {
        let mut inner = lock_unpoisoned(&self.inner);
        match inner.state {
            CircuitState::Closed => {
                inner.failures = 0;
                inner.window_started_at = Instant::now();
            }
            CircuitState::HalfOpen => {
                inner.probe_in_flight = false;
                inner.successes = inner.successes.saturating_add(1);
                if inner.successes >= self.config.success_threshold {
                    inner.state = CircuitState::Closed;
                    inner.failures = 0;
                    inner.successes = 0;
                    inner.opened_until = None;
                    inner.window_started_at = Instant::now();
                }
            }
            CircuitState::Open => {}
        }
    }

    fn record_failure(&self) -> bool {
        let mut inner = lock_unpoisoned(&self.inner);
        let now = Instant::now();

        if now.saturating_duration_since(inner.window_started_at) > self.config.window_duration {
            inner.failures = 0;
            inner.window_started_at = now;
        }

        inner.probe_in_flight = false;
        inner.successes = 0;

        let opened = if inner.state == CircuitState::HalfOpen {
            open_circuit(&mut inner, &self.config)
        } else {
            inner.failures = inner.failures.saturating_add(1);
            inner.failures >= self.config.failure_threshold
                && open_circuit(&mut inner, &self.config)
        };
        drop(inner);
        opened
    }
}

fn open_circuit(inner: &mut CircuitInner, config: &CircuitBreakerConfig) -> bool {
    inner.state = CircuitState::Open;
    inner.failures = 0;
    inner.successes = 0;
    inner.opened_until = Some(Instant::now() + config.open_duration);
    true
}

#[derive(Debug)]
struct Bulkhead {
    permits: Arc<Semaphore>,
    config: BulkheadConfig,
    queued: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BulkheadAcquireError {
    QueueFull,
    QueueTimeout { timeout: Duration },
}

impl Bulkhead {
    fn new(config: BulkheadConfig) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(config.max_concurrent)),
            config,
            queued: AtomicUsize::new(0),
        }
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, BulkheadAcquireError> {
        let queued_before = self.queued.fetch_add(1, Ordering::SeqCst);
        if queued_before >= self.config.max_queued {
            self.queued.fetch_sub(1, Ordering::SeqCst);
            return Err(BulkheadAcquireError::QueueFull);
        }

        let permit_result = time::timeout(
            self.config.queue_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await;

        self.queued.fetch_sub(1, Ordering::SeqCst);

        match permit_result {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => Err(BulkheadAcquireError::QueueTimeout {
                timeout: self.config.queue_timeout,
            }),
        }
    }

    fn pressure_per_mille(&self) -> u32 {
        let active = self
            .config
            .max_concurrent
            .saturating_sub(self.permits.available_permits());
        let active_pressure = ratio_per_mille(active, self.config.max_concurrent);
        let queue_pressure = ratio_per_mille(
            self.queued.load(Ordering::Relaxed),
            self.config.max_queued.max(1),
        );
        active_pressure.max(queue_pressure)
    }
}

#[derive(Debug)]
struct HealthRouter {
    config: HealthRouterConfig,
    entries: Mutex<HashMap<ConnectorId, HealthEntry>>,
}

#[derive(Debug)]
struct HealthEntry {
    status: ConnectorHealth,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_probe_at: Option<Instant>,
    unavailable_since: Option<DateTime<Utc>>,
    avg_latency: LatencyEwma,
    error_window: ErrorWindow,
}

impl HealthEntry {
    fn new(config: &HealthRouterConfig) -> Self {
        Self {
            status: ConnectorHealth::Healthy,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_probe_at: None,
            unavailable_since: None,
            avg_latency: LatencyEwma::new(config.latency_alpha_per_mille),
            error_window: ErrorWindow::new(config.error_window),
        }
    }
}

impl HealthRouter {
    fn new(config: HealthRouterConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn ensure_connector(&self, connector_id: &ConnectorId) {
        let mut entries = lock_unpoisoned(&self.entries);
        let _ = entries
            .entry(connector_id.clone())
            .or_insert_with(|| HealthEntry::new(&self.config));
    }

    fn can_route(&self, connector_id: &ConnectorId) -> RoutingDecision {
        let mut entries = lock_unpoisoned(&self.entries);
        let decision = {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));
            match &entry.status {
                ConnectorHealth::Healthy => RoutingDecision::Allow,
                ConnectorHealth::Degraded { reason } => RoutingDecision::AllowDegraded {
                    reason: reason.clone(),
                },
                ConnectorHealth::Unavailable { reason, .. } => {
                    let now = Instant::now();
                    let probe_allowed = entry.last_probe_at.is_none_or(|last| {
                        now.saturating_duration_since(last) >= self.config.probe_interval
                    });
                    if probe_allowed {
                        entry.last_probe_at = Some(now);
                        RoutingDecision::AllowProbe
                    } else {
                        RoutingDecision::Reject {
                            reason: reason.clone(),
                        }
                    }
                }
            }
        };
        drop(entries);
        decision
    }

    fn record_success(&self, connector_id: &ConnectorId, latency: Duration) {
        let mut entries = lock_unpoisoned(&self.entries);
        {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));
            entry.consecutive_failures = 0;
            entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
            entry.avg_latency.record(latency);
            entry.error_window.record_success();
            recalculate_health(entry, &self.config, Some("successful probe"));
        }
        drop(entries);
    }

    fn record_failure(&self, connector_id: &ConnectorId, reason: &str) {
        let mut entries = lock_unpoisoned(&self.entries);
        {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.consecutive_successes = 0;
            entry.error_window.record_failure();
            recalculate_health(entry, &self.config, Some(reason));
        }
        drop(entries);
    }

    fn record_timeout(&self, connector_id: &ConnectorId, timeout: Duration, latency: Duration) {
        let mut entries = lock_unpoisoned(&self.entries);
        {
            let entry = entries
                .entry(connector_id.clone())
                .or_insert_with(|| HealthEntry::new(&self.config));
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.consecutive_successes = 0;
            entry.avg_latency.record(latency.max(timeout));
            entry.error_window.record_failure();
            recalculate_health(entry, &self.config, Some("operation timed out"));
        }
        drop(entries);
    }

    fn health(&self, connector_id: &ConnectorId) -> ConnectorHealth {
        let entries = lock_unpoisoned(&self.entries);
        entries
            .get(connector_id)
            .map_or(ConnectorHealth::Healthy, |entry| entry.status.clone())
    }
}

fn recalculate_health(
    entry: &mut HealthEntry,
    config: &HealthRouterConfig,
    failure_reason: Option<&str>,
) {
    if entry.consecutive_failures >= config.unhealthy_threshold {
        let reason = failure_reason.unwrap_or("consecutive failures");
        let since = entry.unavailable_since.unwrap_or_else(Utc::now);
        if entry.unavailable_since.is_none() {
            entry.last_probe_at = Some(Instant::now());
        }
        entry.unavailable_since = Some(since);
        entry.status = ConnectorHealth::Unavailable {
            reason: format!("{reason} ({})", entry.consecutive_failures),
            since,
        };
        return;
    }

    let avg_latency = entry.avg_latency.value().unwrap_or_default();
    let error_rate = entry.error_window.error_rate_per_mille();
    let slow = avg_latency > config.latency_degraded_threshold;
    let error_prone = error_rate >= u32::from(config.error_rate_degraded_threshold_per_mille);
    let recovering = entry.unavailable_since.is_some()
        && entry.consecutive_successes < config.recovery_success_threshold;

    if recovering {
        entry.status = ConnectorHealth::Unavailable {
            reason: "recovering with probe traffic".to_string(),
            since: entry.unavailable_since.unwrap_or_else(Utc::now),
        };
        return;
    }

    if slow || error_prone || entry.consecutive_failures > 0 {
        let mut reasons = Vec::new();
        if slow {
            reasons.push(format!("avg latency {}ms", avg_latency.as_millis()));
        }
        if error_prone {
            reasons.push(format!("error rate {error_rate}‰"));
        }
        if entry.consecutive_failures > 0 {
            reasons.push(format!("{} recent failures", entry.consecutive_failures));
        }
        entry.status = ConnectorHealth::degraded(reasons.join(", "));
        entry.unavailable_since = None;
        return;
    }

    entry.status = ConnectorHealth::Healthy;
    entry.unavailable_since = None;
}

#[derive(Debug)]
struct LoadShedder {
    config: LoadShedConfig,
    base_load_per_mille: AtomicU32,
    sequence: AtomicU64,
}

impl LoadShedder {
    const fn new(config: LoadShedConfig) -> Self {
        Self {
            config,
            base_load_per_mille: AtomicU32::new(0),
            sequence: AtomicU64::new(0),
        }
    }

    fn set_base_load_per_mille(&self, load_per_mille: u16) {
        self.base_load_per_mille.store(
            u32::from(load_per_mille).min(MAX_PER_MILLE),
            Ordering::Relaxed,
        );
    }

    fn effective_load_per_mille(&self, observed_pressure_per_mille: u32) -> u32 {
        self.base_load_per_mille
            .load(Ordering::Relaxed)
            .max(observed_pressure_per_mille)
            .min(MAX_PER_MILLE)
    }

    fn should_shed(&self, priority: RequestPriority, load_per_mille: u32) -> bool {
        if !self.config.sheddable_priorities.contains(&priority) {
            return false;
        }

        let shed_threshold = u32::from(self.config.shed_threshold_per_mille);
        if load_per_mille < shed_threshold {
            return false;
        }

        let full_threshold = u32::from(self.config.full_shed_threshold_per_mille)
            .max(shed_threshold.saturating_add(1));
        let base_probability = if load_per_mille >= full_threshold {
            MAX_PER_MILLE
        } else {
            let numerator = load_per_mille.saturating_sub(shed_threshold) * MAX_PER_MILLE;
            let denominator = full_threshold.saturating_sub(shed_threshold);
            numerator / denominator
        };

        let final_probability =
            (base_probability * priority.shed_factor_per_mille()) / MAX_PER_MILLE;
        if final_probability == 0 {
            return false;
        }

        let ticket = self.sequence.fetch_add(1, Ordering::Relaxed) % u64::from(MAX_PER_MILLE);
        ticket < u64::from(final_probability)
    }
}

#[derive(Debug)]
struct ErrorWindow {
    duration: Duration,
    started_at: Instant,
    successes: u32,
    failures: u32,
}

impl ErrorWindow {
    fn new(duration: Duration) -> Self {
        Self {
            duration,
            started_at: Instant::now(),
            successes: 0,
            failures: 0,
        }
    }

    fn record_success(&mut self) {
        self.roll_if_needed();
        self.successes = self.successes.saturating_add(1);
    }

    fn record_failure(&mut self) {
        self.roll_if_needed();
        self.failures = self.failures.saturating_add(1);
    }

    fn error_rate_per_mille(&self) -> u32 {
        let total = u64::from(self.successes) + u64::from(self.failures);
        if total == 0 {
            return 0;
        }
        u32::try_from((u64::from(self.failures) * u64::from(MAX_PER_MILLE)) / total)
            .unwrap_or(MAX_PER_MILLE)
    }

    fn roll_if_needed(&mut self) {
        if self.started_at.elapsed() > self.duration {
            self.started_at = Instant::now();
            self.successes = 0;
            self.failures = 0;
        }
    }
}

#[derive(Debug)]
struct LatencyEwma {
    alpha_per_mille: u16,
    value_millis: Option<u64>,
}

impl LatencyEwma {
    const fn new(alpha_per_mille: u16) -> Self {
        Self {
            alpha_per_mille,
            value_millis: None,
        }
    }

    fn record(&mut self, latency: Duration) {
        let sample_millis = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
        self.value_millis = Some(match self.value_millis {
            None => sample_millis,
            Some(current) => {
                let alpha = u64::from(self.alpha_per_mille).min(u64::from(MAX_PER_MILLE));
                let retained = u64::from(MAX_PER_MILLE).saturating_sub(alpha);
                ((current.saturating_mul(retained)) + (sample_millis.saturating_mul(alpha)))
                    / u64::from(MAX_PER_MILLE)
            }
        });
    }

    fn value(&self) -> Option<Duration> {
        self.value_millis.map(Duration::from_millis)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum HealthSeverity {
    Healthy,
    Degraded,
    Unavailable,
}

const fn health_severity(health: &ConnectorHealth) -> HealthSeverity {
    match health {
        ConnectorHealth::Healthy => HealthSeverity::Healthy,
        ConnectorHealth::Degraded { .. } => HealthSeverity::Degraded,
        ConnectorHealth::Unavailable { .. } => HealthSeverity::Unavailable,
    }
}

#[allow(clippy::missing_const_for_fn)]
fn health_reason(health: &ConnectorHealth) -> Option<&str> {
    match health {
        ConnectorHealth::Healthy => None,
        ConnectorHealth::Degraded { reason } | ConnectorHealth::Unavailable { reason, .. } => {
            Some(reason)
        }
    }
}

const fn unavailable_since(health: &ConnectorHealth) -> Option<DateTime<Utc>> {
    match health {
        ConnectorHealth::Unavailable { since, .. } => Some(*since),
        _ => None,
    }
}

fn earlier_since(
    left: Option<DateTime<Utc>>,
    right: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn combine_reason_strings(left: &str, right: &str) -> String {
    match (left.is_empty(), right.is_empty(), left == right) {
        (true, false, _) => right.to_string(),
        (false, true, _) | (false, false, true) => left.to_string(),
        (false, false, false) => format!("{left}; {right}"),
        (true, true, _) => String::new(),
    }
}

fn ratio_per_mille(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return MAX_PER_MILLE;
    }
    let numerator = u64::try_from(numerator).unwrap_or(u64::MAX);
    let denominator = u64::try_from(denominator).unwrap_or(1);
    u32::try_from((numerator.saturating_mul(u64::from(MAX_PER_MILLE))) / denominator)
        .unwrap_or(MAX_PER_MILLE)
        .min(MAX_PER_MILLE)
}

fn to_u16(value: u32) -> u16 {
    u16::try_from(value.min(u32::from(u16::MAX))).unwrap_or(u16::MAX)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    use fcp_async_core::task;

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.host:test:v1")
    }

    #[fcp_async_core::runtime::test]
    async fn circuit_breaker_opens_after_failures() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 2,
                open_duration: Duration::from_millis(50),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        for _ in 0..2 {
            let result = layer
                .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                    Err::<(), _>("boom")
                })
                .await;
            assert!(matches!(result, Err(ResilienceError::Inner("boom"))));
        }

        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Open);
        let metrics = layer.metrics(&connector_id);
        assert_eq!(metrics.failures, 2);
        assert_eq!(metrics.circuit_opened, 1);

        let result = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::CircuitOpen { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn circuit_breaker_recovers_after_probe_successes() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                open_duration: Duration::from_millis(30),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        let _ = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Err::<(), _>("boom")
            })
            .await;
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Open);

        time::sleep(Duration::from_millis(40)).await;
        let first_probe = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(first_probe.is_ok());
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::HalfOpen);

        let second_probe = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(second_probe.is_ok());
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Closed);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_rejects_requests_beyond_queue_limit() {
        let bulkhead = Arc::new(Bulkhead::new(BulkheadConfig {
            max_concurrent: 1,
            max_queued: 2,
            queue_timeout: Duration::from_secs(1),
        }));

        let first_permit = bulkhead.acquire().await.expect("first permit");

        let second = {
            let bulkhead = Arc::clone(&bulkhead);
            task::spawn(async move { bulkhead.acquire().await })
        };
        let third = {
            let bulkhead = Arc::clone(&bulkhead);
            task::spawn(async move { bulkhead.acquire().await })
        };

        while bulkhead.queued.load(Ordering::Relaxed) < 2 {
            time::sleep(Duration::from_millis(1)).await;
        }

        let fourth = bulkhead.acquire().await;
        assert!(matches!(fourth, Err(BulkheadAcquireError::QueueFull)));

        drop(first_permit);
        drop(second.await.expect("join").expect("second permit"));
        drop(third.await.expect("join").expect("third permit"));
    }

    #[fcp_async_core::runtime::test]
    async fn health_router_allows_probe_after_unhealthy_period() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 10,
                success_threshold: 1,
                open_duration: Duration::from_millis(10),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::AnyError,
            },
            health: HealthRouterConfig {
                unhealthy_threshold: 2,
                recovery_success_threshold: 1,
                probe_interval: Duration::from_millis(30),
                ..HealthRouterConfig::default()
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        for _ in 0..2 {
            let _ = layer
                .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                    Err::<(), _>("boom")
                })
                .await;
        }

        assert!(matches!(
            layer.connector_health(&connector_id),
            ConnectorHealth::Unavailable { .. }
        ));

        let rejected = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(rejected, Err(ResilienceError::Unhealthy { .. })));

        time::sleep(Duration::from_millis(40)).await;
        let recovered = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                Ok::<(), &str>(())
            })
            .await;
        assert!(recovered.is_ok());
        assert_eq!(layer.metrics(&connector_id).probe_requests, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn load_shedding_respects_priority() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            load_shed: LoadShedConfig {
                shed_threshold_per_mille: 500,
                full_shed_threshold_per_mille: 1_000,
                sheddable_priorities: vec![
                    RequestPriority::Low,
                    RequestPriority::Normal,
                    RequestPriority::High,
                ],
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();
        layer.set_base_load_per_mille(950);

        let mut low_shed = 0_u32;
        let mut critical_shed = 0_u32;
        for _ in 0..100 {
            if matches!(
                layer
                    .execute(&connector_id, RequestPriority::Low, "invoke", async {
                        Ok::<(), &str>(())
                    },)
                    .await,
                Err(ResilienceError::LoadShed { .. })
            ) {
                low_shed = low_shed.saturating_add(1);
            }
        }

        for _ in 0..100 {
            if matches!(
                layer
                    .execute(&connector_id, RequestPriority::Critical, "invoke", async {
                        Ok::<(), &str>(())
                    },)
                    .await,
                Err(ResilienceError::LoadShed { .. })
            ) {
                critical_shed = critical_shed.saturating_add(1);
            }
        }

        assert!(low_shed >= 80);
        assert_eq!(critical_shed, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_only_failure_predicate_trips_on_timeout() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            operation_timeout: Some(Duration::from_millis(25)),
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 1,
                open_duration: Duration::from_millis(30),
                window_duration: Duration::from_secs(1),
                failure_predicate: FailurePredicate::TimeoutsOnly,
            },
            ..ResilienceConfig::default()
        });
        let connector_id = test_connector_id();

        let result = layer
            .execute(&connector_id, RequestPriority::Normal, "invoke", async {
                time::sleep(Duration::from_millis(60)).await;
                Ok::<(), &str>(())
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::TimedOut { .. })));
        assert_eq!(layer.circuit_state(&connector_id), CircuitState::Open);
        assert_eq!(layer.metrics(&connector_id).timeouts, 1);
    }

    #[test]
    fn merge_connector_health_prefers_worse_status() {
        let merged = merge_connector_health(
            ConnectorHealth::degraded("slow"),
            ConnectorHealth::unavailable("down"),
        );
        assert!(matches!(merged, ConnectorHealth::Unavailable { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 1. RequestPriority shed factors
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn critical_shed_factor_is_zero() {
        assert_eq!(RequestPriority::Critical.shed_factor_per_mille(), 0);
    }

    #[test]
    fn high_shed_factor_is_300() {
        assert_eq!(RequestPriority::High.shed_factor_per_mille(), 300);
    }

    #[test]
    fn normal_shed_factor_is_700() {
        assert_eq!(RequestPriority::Normal.shed_factor_per_mille(), 700);
    }

    #[test]
    fn low_shed_factor_is_max_per_mille() {
        assert_eq!(RequestPriority::Low.shed_factor_per_mille(), MAX_PER_MILLE);
        assert_eq!(RequestPriority::Low.shed_factor_per_mille(), 1_000);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 2. ResilienceError Display
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn resilience_error_display_load_shed() {
        let err: ResilienceError<&str> = ResilienceError::LoadShed {
            load_per_mille: 950,
        };
        let msg = format!("{err}");
        assert!(msg.contains("950"));
        assert!(msg.contains("load shed"));
    }

    #[test]
    fn resilience_error_display_unhealthy() {
        let err: ResilienceError<&str> = ResilienceError::Unhealthy {
            reason: "too many failures".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("unhealthy"));
        assert!(msg.contains("too many failures"));
    }

    #[test]
    fn resilience_error_display_circuit_open() {
        let err: ResilienceError<&str> = ResilienceError::CircuitOpen {
            retry_after: Duration::from_secs(5),
        };
        let msg = format!("{err}");
        assert!(msg.contains("circuit breaker open"));
        assert!(msg.contains("5000ms"));
    }

    #[test]
    fn resilience_error_display_half_open_limited() {
        let err: ResilienceError<&str> = ResilienceError::HalfOpenLimited;
        let msg = format!("{err}");
        assert!(msg.contains("half-open"));
        assert!(msg.contains("in flight"));
    }

    #[test]
    fn resilience_error_display_bulkhead_full() {
        let err: ResilienceError<&str> = ResilienceError::BulkheadFull;
        let msg = format!("{err}");
        assert!(msg.contains("bulkhead queue is full"));
    }

    #[test]
    fn resilience_error_display_queue_timeout() {
        let err: ResilienceError<&str> = ResilienceError::QueueTimeout {
            timeout: Duration::from_millis(250),
        };
        let msg = format!("{err}");
        assert!(msg.contains("timed out"));
        assert!(msg.contains("250ms"));
    }

    #[test]
    fn resilience_error_display_timed_out() {
        let err: ResilienceError<&str> = ResilienceError::TimedOut {
            timeout: Duration::from_secs(1),
        };
        let msg = format!("{err}");
        assert!(msg.contains("operation timed out"));
        assert!(msg.contains("1000ms"));
    }

    #[test]
    fn resilience_error_display_inner() {
        let err: ResilienceError<&str> = ResilienceError::Inner("kaboom");
        let msg = format!("{err}");
        assert!(msg.contains("inner error"));
        assert!(msg.contains("kaboom"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 3. Config defaults
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn resilience_config_default_has_none_timeout() {
        let config = ResilienceConfig::default();
        assert!(config.operation_timeout.is_none());
    }

    #[test]
    fn circuit_breaker_config_default_values() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 2);
        assert_eq!(config.open_duration, Duration::from_secs(5));
        assert_eq!(config.window_duration, Duration::from_secs(30));
        assert_eq!(config.failure_predicate, FailurePredicate::AnyError);
    }

    #[test]
    fn bulkhead_config_default_values() {
        let config = BulkheadConfig::default();
        assert_eq!(config.max_concurrent, 16);
        assert_eq!(config.max_queued, 32);
        assert_eq!(config.queue_timeout, Duration::from_millis(250));
    }

    #[test]
    fn health_router_config_default_values() {
        let config = HealthRouterConfig::default();
        assert_eq!(config.unhealthy_threshold, 3);
        assert_eq!(config.recovery_success_threshold, 2);
        assert_eq!(
            config.latency_degraded_threshold,
            Duration::from_millis(750)
        );
        assert_eq!(config.error_rate_degraded_threshold_per_mille, 500);
        assert_eq!(config.probe_interval, Duration::from_secs(5));
        assert_eq!(config.error_window, Duration::from_secs(30));
        assert_eq!(config.latency_alpha_per_mille, 200);
    }

    #[test]
    fn load_shed_config_default_values() {
        let config = LoadShedConfig::default();
        assert_eq!(config.shed_threshold_per_mille, 850);
        assert_eq!(config.full_shed_threshold_per_mille, 1_000);
        assert_eq!(
            config.sheddable_priorities,
            vec![RequestPriority::Low, RequestPriority::Normal]
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 4. FailurePredicate::matches
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn any_error_matches_failure() {
        assert!(FailurePredicate::AnyError.matches(OutcomeKind::Failure, Duration::ZERO));
    }

    #[test]
    fn any_error_matches_timed_out() {
        assert!(FailurePredicate::AnyError.matches(OutcomeKind::TimedOut, Duration::ZERO));
    }

    #[test]
    fn any_error_does_not_match_success() {
        assert!(!FailurePredicate::AnyError.matches(OutcomeKind::Success, Duration::ZERO));
    }

    #[test]
    fn timeouts_only_matches_timed_out() {
        assert!(FailurePredicate::TimeoutsOnly.matches(OutcomeKind::TimedOut, Duration::ZERO));
    }

    #[test]
    fn timeouts_only_does_not_match_failure() {
        assert!(!FailurePredicate::TimeoutsOnly.matches(OutcomeKind::Failure, Duration::ZERO));
    }

    #[test]
    fn slow_responses_matches_success_above_threshold() {
        let pred = FailurePredicate::SlowResponses {
            threshold: Duration::from_millis(100),
        };
        assert!(pred.matches(OutcomeKind::Success, Duration::from_millis(200)));
    }

    #[test]
    fn slow_responses_does_not_match_success_below_threshold() {
        let pred = FailurePredicate::SlowResponses {
            threshold: Duration::from_millis(100),
        };
        assert!(!pred.matches(OutcomeKind::Success, Duration::from_millis(50)));
    }

    #[test]
    fn error_or_slow_responses_matches_all_failure_types() {
        let pred = FailurePredicate::ErrorOrSlowResponses {
            threshold: Duration::from_millis(100),
        };
        // Matches Failure
        assert!(pred.matches(OutcomeKind::Failure, Duration::ZERO));
        // Matches TimedOut
        assert!(pred.matches(OutcomeKind::TimedOut, Duration::ZERO));
        // Matches slow Success
        assert!(pred.matches(OutcomeKind::Success, Duration::from_millis(200)));
        // Does NOT match fast Success
        assert!(!pred.matches(OutcomeKind::Success, Duration::from_millis(50)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 5. CircuitBreaker state machine
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn new_breaker_starts_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn closed_breaker_returns_regular_permit() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.before_call(), Ok(CircuitPermit::Regular));
    }

    #[test]
    fn failures_below_threshold_stay_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn failures_at_threshold_open_breaker() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let opened = cb.record_failure();
        assert!(opened);
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn half_open_with_probe_in_flight_returns_half_open_limited() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure(); // Opens
        // Transition to HalfOpen via before_call (open_duration = 0)
        let first = cb.before_call();
        assert_eq!(first, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // Second call should be rejected
        let second = cb.before_call();
        assert_eq!(second, Err(CircuitReject::HalfOpenLimited));
    }

    #[test]
    fn half_open_without_probe_gives_probe_permit() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let permit = cb.before_call();
        assert_eq!(permit, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn open_before_duration_returns_circuit_open_with_retry_after() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_mins(1),
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        let result = cb.before_call();
        assert!(
            matches!(result, Err(CircuitReject::Open { retry_after }) if retry_after > Duration::ZERO)
        );
    }

    #[test]
    fn open_after_duration_transitions_to_half_open() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // open_duration is zero so it should immediately transition
        let result = cb.before_call();
        assert_eq!(result, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn record_success_in_closed_resets_failures() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        // After success, failures are reset, so two more should not open
        cb.record_failure();
        cb.record_failure();
        let opened = cb.record_failure();
        assert!(opened); // Now it should open (3 consecutive after reset)
    }

    #[test]
    fn record_success_in_half_open_increments_successes() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 3,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call(); // Transition to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        // Still HalfOpen (need 3 successes)
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_successes_reaching_threshold_closes_breaker() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn record_failure_in_half_open_reopens_immediately() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        let opened = cb.record_failure();
        assert!(opened);
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn cancel_inflight_probe_clears_probe_flag() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        cb.record_failure();
        let _ = cb.before_call(); // HalfOpen, probe_in_flight = true
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // Would normally reject
        assert_eq!(cb.before_call(), Err(CircuitReject::HalfOpenLimited));
        cb.cancel_inflight_probe();
        // Now probe should be allowed again
        assert_eq!(cb.before_call(), Ok(CircuitPermit::Probe));
    }

    #[test]
    fn cancel_inflight_probe_is_noop_in_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.cancel_inflight_probe(); // Should not panic or change state
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn open_without_opened_until_transitions_to_half_open() {
        // This tests the edge case where opened_until is None in Open state
        // We need to manually construct this scenario
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        {
            let mut inner = lock_unpoisoned(&cb.inner);
            inner.state = CircuitState::Open;
            inner.opened_until = None;
        }
        let result = cb.before_call();
        assert_eq!(result, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 6. Bulkhead
    // ─────────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn bulkhead_allows_up_to_max_concurrent() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 3,
            max_queued: 10,
            queue_timeout: Duration::from_secs(1),
        });
        let p1 = bh.acquire().await;
        let p2 = bh.acquire().await;
        let p3 = bh.acquire().await;
        assert!(p1.is_ok());
        assert!(p2.is_ok());
        assert!(p3.is_ok());
    }

    #[test]
    fn bulkhead_pressure_per_mille_zero_when_idle() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 16,
            max_queued: 32,
            queue_timeout: Duration::from_millis(250),
        });
        assert_eq!(bh.pressure_per_mille(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_pressure_increases_under_load() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 4,
            max_queued: 32,
            queue_timeout: Duration::from_secs(1),
        });
        let _p1 = bh.acquire().await.unwrap();
        let _p2 = bh.acquire().await.unwrap();
        // 2 out of 4 = 500 per mille
        assert_eq!(bh.pressure_per_mille(), 500);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_queue_timeout_produces_error() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 1,
            max_queued: 1,
            queue_timeout: Duration::from_millis(10),
        });
        let _hold = bh.acquire().await.unwrap();
        let result = bh.acquire().await;
        assert!(matches!(
            result,
            Err(BulkheadAcquireError::QueueTimeout { .. })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_tracks_queued_count() {
        let bh = Arc::new(Bulkhead::new(BulkheadConfig {
            max_concurrent: 1,
            max_queued: 10,
            queue_timeout: Duration::from_secs(5),
        }));
        let _hold = bh.acquire().await.unwrap();
        // Spawn a waiter
        let bh2 = Arc::clone(&bh);
        let _waiter = task::spawn(async move {
            let _ = bh2.acquire().await;
        });
        // Give it a moment to enqueue
        time::sleep(Duration::from_millis(10)).await;
        assert!(bh.queued.load(Ordering::Relaxed) >= 1);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_pressure_active_vs_queue() {
        let bh = Bulkhead::new(BulkheadConfig {
            max_concurrent: 10,
            max_queued: 10,
            queue_timeout: Duration::from_secs(1),
        });
        // No load
        assert_eq!(bh.pressure_per_mille(), 0);
        // Half concurrent capacity
        let mut permits = Vec::with_capacity(10);
        for _ in 0..5 {
            permits.push(bh.acquire().await.unwrap());
        }
        assert_eq!(bh.pressure_per_mille(), 500);
        // Full concurrent capacity
        for _ in 0..5 {
            permits.push(bh.acquire().await.unwrap());
        }
        assert_eq!(bh.pressure_per_mille(), 1_000);
        assert_eq!(permits.len(), 10);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 7. HealthRouter
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_router_new_connector_routes_as_allow() {
        let router = HealthRouter::new(HealthRouterConfig::default());
        let cid = test_connector_id();
        let decision = router.can_route(&cid);
        assert_eq!(decision, RoutingDecision::Allow);
    }

    #[test]
    fn health_router_failures_below_threshold_keep_healthy() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 3,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "error");
        router.record_failure(&cid, "error");
        // 2 failures, threshold is 3 -> still degraded but not unavailable
        let health = router.health(&cid);
        assert!(!matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_failures_at_threshold_mark_unavailable() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 2,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "error");
        router.record_failure(&cid, "error");
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_record_success_resets_failure_count() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 3,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "err");
        router.record_failure(&cid, "err");
        router.record_success(&cid, Duration::from_millis(10));
        // After success, failures are reset; two more should not trip threshold
        router.record_failure(&cid, "err");
        router.record_failure(&cid, "err");
        let health = router.health(&cid);
        assert!(!matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_record_success_after_unavailable_starts_recovery() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            recovery_success_threshold: 3,
            probe_interval: Duration::ZERO,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "down");
        assert!(matches!(
            router.health(&cid),
            ConnectorHealth::Unavailable { .. }
        ));
        // One success is not enough for recovery (need 3)
        router.record_success(&cid, Duration::from_millis(10));
        // Should still be unavailable (recovering)
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_degraded_routing_includes_reason() {
        let router = HealthRouter::new(HealthRouterConfig::default());
        let cid = test_connector_id();
        // Record one failure (below unhealthy threshold) to trigger degraded
        router.record_failure(&cid, "flaky");
        let decision = router.can_route(&cid);
        assert!(matches!(
            decision,
            RoutingDecision::AllowDegraded { reason } if !reason.is_empty()
        ));
    }

    #[test]
    fn health_router_probe_interval_respected_second_probe_rejected() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            probe_interval: Duration::from_mins(1),
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "down");
        // First call after threshold is hit: recalculate_health sets last_probe_at,
        // so with a 60s interval the first can_route sees it was "just probed"
        // and rejects.
        let first = router.can_route(&cid);
        assert!(matches!(first, RoutingDecision::Reject { .. }));
        // Second call also rejected (still within 60s interval)
        let second = router.can_route(&cid);
        assert!(matches!(second, RoutingDecision::Reject { .. }));
    }

    #[test]
    fn health_router_probe_interval_respected_probe_after_interval_allowed() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            probe_interval: Duration::ZERO,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "down");
        // First probe
        let first = router.can_route(&cid);
        assert_eq!(first, RoutingDecision::AllowProbe);
        // With zero interval, second should also be allowed
        let second = router.can_route(&cid);
        assert_eq!(second, RoutingDecision::AllowProbe);
    }

    #[test]
    fn health_router_record_timeout_increments_failures() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_timeout(&cid, Duration::from_secs(5), Duration::from_secs(5));
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn health_router_degraded_from_high_error_rate() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 100, // High so we don't trip unavailable
            error_rate_degraded_threshold_per_mille: 500,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        // Record 10 failures, 0 successes -> 1000 per mille error rate
        for _ in 0..10 {
            router.record_failure(&cid, "err");
        }
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Degraded { .. }));
    }

    #[test]
    fn health_router_degraded_from_high_latency() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 100,
            latency_degraded_threshold: Duration::from_millis(100),
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        // Record successes with high latency
        for _ in 0..10 {
            router.record_success(&cid, Duration::from_millis(500));
        }
        let health = router.health(&cid);
        assert!(matches!(health, ConnectorHealth::Degraded { .. }));
    }

    #[test]
    fn health_router_recovery_from_unavailable_requires_success_threshold() {
        let router = HealthRouter::new(HealthRouterConfig {
            unhealthy_threshold: 1,
            recovery_success_threshold: 2,
            probe_interval: Duration::ZERO,
            latency_degraded_threshold: Duration::from_mins(1),
            error_rate_degraded_threshold_per_mille: 999,
            ..HealthRouterConfig::default()
        });
        let cid = test_connector_id();
        router.record_failure(&cid, "down");
        assert!(matches!(
            router.health(&cid),
            ConnectorHealth::Unavailable { .. }
        ));
        // First success — still recovering
        router.record_success(&cid, Duration::from_millis(1));
        assert!(matches!(
            router.health(&cid),
            ConnectorHealth::Unavailable { .. }
        ));
        // Second success — should recover
        router.record_success(&cid, Duration::from_millis(1));
        let health = router.health(&cid);
        assert!(!matches!(health, ConnectorHealth::Unavailable { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 8. LoadShedder
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn load_shedder_no_shedding_below_threshold() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 500,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // Load is 400, below threshold of 500
        assert!(!shedder.should_shed(RequestPriority::Low, 400));
    }

    #[test]
    fn load_shedder_non_sheddable_priority_never_shed() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // Even at max load, Critical is not in sheddable list
        assert!(!shedder.should_shed(RequestPriority::Critical, 1_000));
        assert!(!shedder.should_shed(RequestPriority::High, 1_000));
        assert!(!shedder.should_shed(RequestPriority::Normal, 1_000));
    }

    #[test]
    fn load_shedder_effective_load_takes_max_of_base_and_pressure() {
        let shedder = LoadShedder::new(LoadShedConfig::default());
        shedder.set_base_load_per_mille(600);
        // pressure=400, base=600 -> max=600
        assert_eq!(shedder.effective_load_per_mille(400), 600);
        // pressure=800, base=600 -> max=800
        assert_eq!(shedder.effective_load_per_mille(800), 800);
    }

    #[test]
    fn load_shedder_effective_load_caps_at_1000() {
        let shedder = LoadShedder::new(LoadShedConfig::default());
        shedder.set_base_load_per_mille(1_000);
        assert_eq!(shedder.effective_load_per_mille(2_000), 1_000);
    }

    #[test]
    fn load_shedder_full_shed_threshold_sheds_all_eligible() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 500,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // At full_shed threshold, all Low requests should be shed
        let mut shed_count = 0;
        for _ in 0..1_000 {
            if shedder.should_shed(RequestPriority::Low, 1_000) {
                shed_count += 1;
            }
        }
        assert_eq!(shed_count, 1_000);
    }

    #[test]
    fn load_shedder_shedding_probability_scales_linearly() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // At load=500/1000, base_probability=500, Low factor=1000
        // final_probability = (500*1000)/1000 = 500
        // Over 1000 calls, ~500 should be shed
        let mut shed_count = 0;
        for _ in 0..1_000 {
            if shedder.should_shed(RequestPriority::Low, 500) {
                shed_count += 1;
            }
        }
        assert!(
            (450..=550).contains(&shed_count),
            "expected ~500 sheds, got {shed_count}"
        );
    }

    #[test]
    fn load_shedder_set_base_load_caps_at_1000() {
        let shedder = LoadShedder::new(LoadShedConfig::default());
        shedder.set_base_load_per_mille(5_000);
        assert_eq!(shedder.effective_load_per_mille(0), 1_000);
    }

    #[test]
    fn load_shedder_critical_never_shed_even_at_max_load() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1,
            sheddable_priorities: vec![
                RequestPriority::Critical,
                RequestPriority::High,
                RequestPriority::Normal,
                RequestPriority::Low,
            ],
        });
        // Even though Critical is in the list, its shed_factor is 0
        // so final_probability = base * 0 / 1000 = 0
        for _ in 0..100 {
            assert!(!shedder.should_shed(RequestPriority::Critical, 1_000));
        }
    }

    #[test]
    fn load_shedder_mid_range_load_partially_sheds() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 800,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // load=900, threshold=800, full=1000
        // base_probability = (900-800)*1000 / (1000-800) = 100*1000/200 = 500
        // final = 500 * 1000 / 1000 = 500
        let mut shed_count = 0;
        for _ in 0..1_000 {
            if shedder.should_shed(RequestPriority::Low, 900) {
                shed_count += 1;
            }
        }
        assert!(
            (400..=600).contains(&shed_count),
            "expected ~500 sheds, got {shed_count}"
        );
    }

    #[test]
    fn load_shedder_sequence_based_deterministic_pattern() {
        let shedder = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        // Same load and priority should produce deterministic pattern based on sequence
        let results: Vec<bool> = (0..10)
            .map(|_| shedder.should_shed(RequestPriority::Low, 500))
            .collect();
        // The sequence counter increments, so results are deterministic
        // Re-create shedder to verify same results
        let shedder2 = LoadShedder::new(LoadShedConfig {
            shed_threshold_per_mille: 0,
            full_shed_threshold_per_mille: 1_000,
            sheddable_priorities: vec![RequestPriority::Low],
        });
        let results2: Vec<bool> = (0..10)
            .map(|_| shedder2.should_shed(RequestPriority::Low, 500))
            .collect();
        assert_eq!(results, results2);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 9. ErrorWindow
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_window_new_has_zero_rate() {
        let window = ErrorWindow::new(Duration::from_secs(30));
        assert_eq!(window.error_rate_per_mille(), 0);
    }

    #[test]
    fn error_window_all_failures_gives_1000() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        for _ in 0..10 {
            window.record_failure();
        }
        assert_eq!(window.error_rate_per_mille(), 1_000);
    }

    #[test]
    fn error_window_all_successes_gives_zero() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        for _ in 0..10 {
            window.record_success();
        }
        assert_eq!(window.error_rate_per_mille(), 0);
    }

    #[test]
    fn error_window_mixed_gives_proportional_rate() {
        let mut window = ErrorWindow::new(Duration::from_secs(30));
        // 3 failures out of 10 total = 300 per mille
        for _ in 0..7 {
            window.record_success();
        }
        for _ in 0..3 {
            window.record_failure();
        }
        assert_eq!(window.error_rate_per_mille(), 300);
    }

    #[test]
    fn error_window_rolls_after_duration() {
        // Create a window with zero duration so it rolls immediately
        let mut window = ErrorWindow::new(Duration::ZERO);
        window.record_failure();
        // After roll, counters should be reset, then the new failure is added
        // The window's roll_if_needed is called at the start of record_*
        // With Duration::ZERO, elapsed > duration is true, so it resets
        // Then records the failure, giving 1000 per mille
        window.record_failure();
        assert_eq!(window.error_rate_per_mille(), 1_000);
    }

    #[test]
    fn error_window_after_roll_counters_reset() {
        let mut window = ErrorWindow::new(Duration::ZERO);
        for _ in 0..10 {
            window.record_failure();
        }
        // With zero duration, each call rolls and resets.
        // Last record_failure: resets to 0, then adds 1 failure.
        // error_rate_per_mille = 1000 (1 failure, 0 successes)
        assert_eq!(window.error_rate_per_mille(), 1_000);
        // Now record a success, which will roll again
        window.record_success();
        // After roll: 0 failures, 0 successes, then adds 1 success = 0 rate
        assert_eq!(window.error_rate_per_mille(), 0);
    }

    #[test]
    fn error_window_record_success_increments() {
        let mut window = ErrorWindow::new(Duration::from_mins(1));
        window.record_success();
        window.record_success();
        window.record_success();
        assert_eq!(window.successes, 3);
        assert_eq!(window.failures, 0);
    }

    #[test]
    fn error_window_record_failure_increments() {
        let mut window = ErrorWindow::new(Duration::from_mins(1));
        window.record_failure();
        window.record_failure();
        assert_eq!(window.failures, 2);
        assert_eq!(window.successes, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 10. LatencyEwma
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn latency_ewma_new_has_none_value() {
        let ewma = LatencyEwma::new(200);
        assert!(ewma.value().is_none());
    }

    #[test]
    fn latency_ewma_first_sample_sets_exact_value() {
        let mut ewma = LatencyEwma::new(200);
        ewma.record(Duration::from_millis(100));
        assert_eq!(ewma.value(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn latency_ewma_second_sample_blends_with_alpha() {
        let mut ewma = LatencyEwma::new(500); // alpha = 500/1000 = 0.5
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(200));
        // new = (100 * 500 + 200 * 500) / 1000 = (50000 + 100000) / 1000 = 150
        assert_eq!(ewma.value(), Some(Duration::from_millis(150)));
    }

    #[test]
    fn latency_ewma_high_alpha_weights_new_sample() {
        let mut ewma = LatencyEwma::new(900); // alpha = 0.9
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(200));
        // new = (100 * 100 + 200 * 900) / 1000 = (10000 + 180000) / 1000 = 190
        assert_eq!(ewma.value(), Some(Duration::from_millis(190)));
    }

    #[test]
    fn latency_ewma_low_alpha_weights_old_sample() {
        let mut ewma = LatencyEwma::new(100); // alpha = 0.1
        ewma.record(Duration::from_millis(100));
        ewma.record(Duration::from_millis(200));
        // new = (100 * 900 + 200 * 100) / 1000 = (90000 + 20000) / 1000 = 110
        assert_eq!(ewma.value(), Some(Duration::from_millis(110)));
    }

    #[test]
    fn latency_ewma_value_returns_duration() {
        let mut ewma = LatencyEwma::new(200);
        ewma.record(Duration::from_millis(42));
        let val = ewma.value().unwrap();
        assert_eq!(val, Duration::from_millis(42));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 11. Helper functions
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn ratio_per_mille_zero_numerator() {
        assert_eq!(ratio_per_mille(0, 10), 0);
    }

    #[test]
    fn ratio_per_mille_half() {
        assert_eq!(ratio_per_mille(5, 10), 500);
    }

    #[test]
    fn ratio_per_mille_full() {
        assert_eq!(ratio_per_mille(10, 10), 1_000);
    }

    #[test]
    fn ratio_per_mille_over_capped() {
        assert_eq!(ratio_per_mille(15, 10), 1_000);
    }

    #[test]
    fn ratio_per_mille_zero_denominator() {
        assert_eq!(ratio_per_mille(0, 0), 1_000);
    }

    #[test]
    fn to_u16_zero() {
        assert_eq!(to_u16(0), 0);
    }

    #[test]
    fn to_u16_mid_value() {
        assert_eq!(to_u16(500), 500);
    }

    #[test]
    fn to_u16_max_u16() {
        assert_eq!(to_u16(65535), 65535);
    }

    #[test]
    fn to_u16_over_max_capped() {
        assert_eq!(to_u16(100_000), 65535);
    }

    #[test]
    fn health_severity_for_each_variant() {
        assert_eq!(
            health_severity(&ConnectorHealth::Healthy),
            HealthSeverity::Healthy
        );
        assert_eq!(
            health_severity(&ConnectorHealth::degraded("slow")),
            HealthSeverity::Degraded
        );
        assert_eq!(
            health_severity(&ConnectorHealth::unavailable("down")),
            HealthSeverity::Unavailable
        );
    }

    #[test]
    fn health_reason_for_each_variant() {
        assert_eq!(health_reason(&ConnectorHealth::Healthy), None);
        assert_eq!(
            health_reason(&ConnectorHealth::degraded("slow")),
            Some("slow")
        );
        assert_eq!(
            health_reason(&ConnectorHealth::unavailable("down")),
            Some("down")
        );
    }

    #[test]
    fn unavailable_since_returns_some_for_unavailable() {
        let now = Utc::now();
        let health = ConnectorHealth::Unavailable {
            reason: "test".to_string(),
            since: now,
        };
        assert_eq!(unavailable_since(&health), Some(now));
    }

    #[test]
    fn unavailable_since_returns_none_for_others() {
        assert_eq!(unavailable_since(&ConnectorHealth::Healthy), None);
        assert_eq!(unavailable_since(&ConnectorHealth::degraded("slow")), None);
    }

    #[test]
    fn earlier_since_picks_earlier_date() {
        let t1 = Utc::now() - chrono::Duration::hours(2);
        let t2 = Utc::now();
        assert_eq!(earlier_since(Some(t1), Some(t2)), Some(t1));
        assert_eq!(earlier_since(Some(t2), Some(t1)), Some(t1));
    }

    #[test]
    fn earlier_since_handles_none_variants() {
        let t1 = Utc::now();
        assert_eq!(earlier_since(Some(t1), None), Some(t1));
        assert_eq!(earlier_since(None, Some(t1)), Some(t1));
        assert_eq!(earlier_since(None, None), None);
    }

    #[test]
    fn combine_reason_strings_all_branches() {
        // left only
        assert_eq!(combine_reason_strings("left", ""), "left");
        // right only
        assert_eq!(combine_reason_strings("", "right"), "right");
        // both same
        assert_eq!(combine_reason_strings("same", "same"), "same");
        // both different
        assert_eq!(combine_reason_strings("a", "b"), "a; b");
        // both empty
        assert_eq!(combine_reason_strings("", ""), String::new());
    }

    #[test]
    fn merge_connector_health_healthy_plus_healthy() {
        let merged = merge_connector_health(ConnectorHealth::Healthy, ConnectorHealth::Healthy);
        assert!(matches!(merged, ConnectorHealth::Healthy));
    }

    #[test]
    fn merge_connector_health_degraded_plus_degraded_combines() {
        let merged = merge_connector_health(
            ConnectorHealth::degraded("slow"),
            ConnectorHealth::degraded("flaky"),
        );
        match &merged {
            ConnectorHealth::Degraded { reason } => {
                assert!(reason.contains("slow"));
                assert!(reason.contains("flaky"));
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn merge_connector_health_unavailable_plus_healthy_picks_unavailable() {
        let merged = merge_connector_health(
            ConnectorHealth::unavailable("down"),
            ConnectorHealth::Healthy,
        );
        assert!(matches!(merged, ConnectorHealth::Unavailable { .. }));
    }

    #[test]
    fn merge_connector_health_degraded_plus_unavailable_picks_unavailable() {
        let merged = merge_connector_health(
            ConnectorHealth::degraded("slow"),
            ConnectorHealth::unavailable("down"),
        );
        assert!(matches!(merged, ConnectorHealth::Unavailable { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 12. ResilienceLayer integration
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn default_layer_creates_without_panic() {
        let _layer = ResilienceLayer::default();
    }

    #[test]
    fn ensure_connector_initializes_state() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        layer.ensure_connector(&cid);
        // Should have state now
        assert_eq!(layer.circuit_state(&cid), CircuitState::Closed);
        assert!(matches!(
            layer.connector_health(&cid),
            ConnectorHealth::Healthy
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn successful_execute_increments_successes_metric() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        let result = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Ok::<_, &str>(42)
            })
            .await;
        assert!(result.is_ok());
        let metrics = layer.metrics(&cid);
        assert_eq!(metrics.successes, 1);
        assert_eq!(metrics.requests, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn failed_execute_increments_failures_metric() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        let result = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Err::<(), _>("fail")
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::Inner("fail"))));
        let metrics = layer.metrics(&cid);
        assert_eq!(metrics.failures, 1);
        assert_eq!(metrics.requests, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn metrics_snapshot_reflects_all_counters() {
        let layer = ResilienceLayer::default();
        let cid = test_connector_id();
        // 2 successes, 1 failure
        for _ in 0..2 {
            let _ = layer
                .execute(&cid, RequestPriority::Normal, "op", async {
                    Ok::<_, &str>(())
                })
                .await;
        }
        let _ = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Err::<(), _>("err")
            })
            .await;
        let metrics = layer.metrics(&cid);
        assert_eq!(metrics.requests, 3);
        assert_eq!(metrics.successes, 2);
        assert_eq!(metrics.failures, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn multiple_connectors_have_independent_state() {
        let layer = ResilienceLayer::default();
        let cid1 = ConnectorId::from_static("fcp.host:test1:v1");
        let cid2 = ConnectorId::from_static("fcp.host:test2:v1");
        let _ = layer
            .execute(&cid1, RequestPriority::Normal, "op", async {
                Ok::<_, &str>(())
            })
            .await;
        let _ = layer
            .execute(&cid2, RequestPriority::Normal, "op", async {
                Err::<(), _>("err")
            })
            .await;
        assert_eq!(layer.metrics(&cid1).successes, 1);
        assert_eq!(layer.metrics(&cid1).failures, 0);
        assert_eq!(layer.metrics(&cid2).successes, 0);
        assert_eq!(layer.metrics(&cid2).failures, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn bulkhead_full_recorded_in_metrics() {
        let layer = Arc::new(ResilienceLayer::new(ResilienceConfig {
            bulkhead: BulkheadConfig {
                max_concurrent: 1,
                max_queued: 0,
                queue_timeout: Duration::from_millis(10),
            },
            ..ResilienceConfig::default()
        }));
        let cid = test_connector_id();
        // Hold the only permit
        let (tx, rx) = fcp_async_core::channel::oneshot::channel::<()>();
        let layer2 = Arc::clone(&layer);
        let cid2 = cid.clone();
        let handle = task::spawn(async move {
            let _ = layer2
                .execute(&cid2, RequestPriority::Normal, "hold", async {
                    let _ = rx.await;
                    Ok::<_, &str>(())
                })
                .await;
        });
        time::sleep(Duration::from_millis(10)).await;
        // Now try another request — bulkhead should be full
        let result = layer
            .execute(&cid, RequestPriority::Normal, "extra", async {
                Ok::<_, &str>(())
            })
            .await;
        assert!(matches!(
            result,
            Err(ResilienceError::BulkheadFull | ResilienceError::QueueTimeout { .. })
        ));
        let metrics = layer.metrics(&cid);
        assert!(metrics.bulkhead_rejections >= 1);
        let _ = tx.send(());
        let _ = handle.await;
    }

    #[fcp_async_core::runtime::test]
    async fn circuit_open_recorded_in_circuit_rejections() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                open_duration: Duration::from_mins(1),
                ..CircuitBreakerConfig::default()
            },
            ..ResilienceConfig::default()
        });
        let cid = test_connector_id();
        // Trip the breaker
        let _ = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Err::<(), _>("fail")
            })
            .await;
        // Now try — should be rejected
        let result = layer
            .execute(&cid, RequestPriority::Normal, "op", async {
                Ok::<_, &str>(())
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::CircuitOpen { .. })));
        assert!(layer.metrics(&cid).circuit_rejections >= 1);
    }

    #[fcp_async_core::runtime::test]
    async fn load_shed_recorded_in_metrics() {
        let layer = ResilienceLayer::new(ResilienceConfig {
            load_shed: LoadShedConfig {
                shed_threshold_per_mille: 0,
                full_shed_threshold_per_mille: 1,
                sheddable_priorities: vec![RequestPriority::Low],
            },
            ..ResilienceConfig::default()
        });
        let cid = test_connector_id();
        layer.set_base_load_per_mille(1_000);
        let result = layer
            .execute(&cid, RequestPriority::Low, "op", async {
                Ok::<_, &str>(())
            })
            .await;
        assert!(matches!(result, Err(ResilienceError::LoadShed { .. })));
        assert!(layer.metrics(&cid).load_shed >= 1);
    }

    #[test]
    fn half_open_limited_rejects_second_probe() {
        // Test at the CircuitBreaker level: when a probe is in-flight,
        // the next call returns HalfOpenLimited
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 10,
            open_duration: Duration::ZERO,
            ..CircuitBreakerConfig::default()
        });
        // Trip the breaker
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // Transition to HalfOpen with first probe
        let first = cb.before_call();
        assert_eq!(first, Ok(CircuitPermit::Probe));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // Second call should be HalfOpenLimited
        let second = cb.before_call();
        assert_eq!(second, Err(CircuitReject::HalfOpenLimited));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 13. ResilienceMetricsSnapshot
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn metrics_snapshot_default_is_all_zeros() {
        let snapshot = ResilienceMetricsSnapshot::default();
        assert_eq!(snapshot.requests, 0);
        assert_eq!(snapshot.successes, 0);
        assert_eq!(snapshot.failures, 0);
        assert_eq!(snapshot.timeouts, 0);
        assert_eq!(snapshot.circuit_rejections, 0);
        assert_eq!(snapshot.circuit_opened, 0);
        assert_eq!(snapshot.bulkhead_rejections, 0);
        assert_eq!(snapshot.load_shed, 0);
        assert_eq!(snapshot.probe_requests, 0);
    }

    #[test]
    fn metrics_snapshot_partial_eq_works() {
        let a = ResilienceMetricsSnapshot::default();
        let b = ResilienceMetricsSnapshot::default();
        assert_eq!(a, b);

        let c = ResilienceMetricsSnapshot {
            requests: 1,
            ..Default::default()
        };
        assert_ne!(a, c);
    }

    #[test]
    fn metrics_snapshot_clone_preserves_all_fields() {
        let original = ResilienceMetricsSnapshot {
            requests: 10,
            successes: 8,
            failures: 1,
            timeouts: 1,
            circuit_rejections: 2,
            circuit_opened: 1,
            bulkhead_rejections: 3,
            load_shed: 4,
            probe_requests: 5,
        };
        let cloned = original;
        assert_eq!(original.requests, cloned.requests);
        assert_eq!(original.successes, cloned.successes);
        assert_eq!(original.failures, cloned.failures);
        assert_eq!(original.timeouts, cloned.timeouts);
        assert_eq!(original.circuit_rejections, cloned.circuit_rejections);
        assert_eq!(original.circuit_opened, cloned.circuit_opened);
        assert_eq!(original.bulkhead_rejections, cloned.bulkhead_rejections);
        assert_eq!(original.load_shed, cloned.load_shed);
        assert_eq!(original.probe_requests, cloned.probe_requests);
    }
}
