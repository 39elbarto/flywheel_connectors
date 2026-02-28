//! Connector migration framework for the `AsyncSuperSync` transition.
//!
//! This module provides shared helpers that all connectors use when migrating
//! from direct `tokio` usage to the `fcp-async-core` substrate. It eliminates
//! duplicated runtime bootstrap, retry loop, and error mapping code across
//! connector crates.
//!
//! # Components
//!
//! - [`ConnectorRuntime`]: Lifecycle wrapper providing `ExecutionContext` creation,
//!   shutdown coordination, and health tracking.
//! - [`RetryLoop`]: Generic retry executor using `ExecutionContext` for
//!   deadline-aware exponential backoff with jitter.
//! - [`ConnectorErrorMapping`]: Trait for consistent `AsyncError` → connector
//!   error conversion.
//! - [`HttpRetryConfig`]: Serializable retry configuration shared by HTTP connectors.
//! - [`classify_http_status`]: Canonical HTTP status → retry decision mapping.
//! - [`map_async_to_fcp_error`]: Canonical `AsyncError` → `FcpError` mapping.
//!
//! # Migration Checklist
//!
//! Every connector migration MUST satisfy all items below. Use this as
//! the acceptance gate before closing a connector migration bead.
//!
//! ## Phase 1: Runtime Bootstrap
//!
//! - [ ] Replace any direct `tokio::runtime` or `tokio::spawn` with
//!   `ConnectorRuntime::new()` during `configure()`.
//! - [ ] All request paths create contexts via `runtime.request_context()`
//!   or `runtime.request_context_with_timeout()`.
//! - [ ] Long-lived operations (streaming, polling) use `runtime.background_context()`.
//! - [ ] Connector `shutdown()` calls `runtime.shutdown()` to propagate cancellation.
//!
//! ## Phase 2: Retry & Error Mapping
//!
//! - [ ] Remove hand-rolled retry loops; replace with [`RetryLoop::execute()`].
//! - [ ] Implement [`ConnectorErrorMapping`] on the connector's error type.
//! - [ ] HTTP status classification delegates to [`classify_http_status()`].
//! - [ ] `AsyncError` mapping delegates to [`map_async_to_fcp_error()`] for
//!   the timeout/cancellation/runtime arms.
//! - [ ] Retry config stored as [`HttpRetryConfig`] (deserializable from TOML / JSON).
//!
//! ## Phase 3: Correctness & Observability
//!
//! - [ ] **No direct tokio imports** — `grep -r "tokio::" connectors/<name>/src/`
//!   must return zero matches (except `tokio_stream` for SSE if needed).
//! - [ ] All failure paths emit tracing spans with `error_type`, `attempt`,
//!   `delay_ms` fields (handled by `RetryLoop` automatically).
//! - [ ] Structured log schema matches forensics standard (bead 235t.32).
//!
//! ## Phase 4: Testing & Parity
//!
//! - [ ] Unit tests cover: success, transient-then-success, terminal error,
//!   max-attempts exhausted, cancellation, deadline expiry.
//! - [ ] Behavior matches pre-migration golden contracts from bead 235t.30.
//! - [ ] Integration tests exercise the full `configure → invoke → shutdown` lifecycle.
//! - [ ] `cargo check --workspace --all-targets` passes.
//! - [ ] `cargo clippy --workspace --all-targets` passes.
//!
//! # Reference Migration: OpenAI Connector
//!
//! Below is a condensed before/after showing how the OpenAI connector's
//! `post()` method migrates from hand-rolled retry to this framework.
//!
//! ## Before (hand-rolled retry loop)
//!
//! ```ignore
//! // connectors/openai/src/client.rs — BEFORE migration
//! async fn post<T, R>(&self, endpoint: &str, body: &T) -> OpenAIResult<R> {
//!     let url = format!("{}{endpoint}", self.base_url);
//!     let mut delay = Duration::from_millis(self.initial_delay_ms);
//!     let mut attempts = 0;
//!     let context = ExecutionContext::request_scoped(Duration::from_secs(120));
//!
//!     loop {
//!         attempts += 1;
//!         let request = self.client.post(&url).json(body);
//!         let request = self.apply_auth(request);
//!
//!         match request.send().await {
//!             Ok(response) => match self.handle_response(response).await {
//!                 Ok(data) => return Ok(data),
//!                 Err(e) if e.is_retryable() && attempts < self.max_retries => {
//!                     if let Some(retry_after) = e.retry_after() {
//!                         delay = retry_after;
//!                     }
//!                     context.sleep(delay).await.map_err(map_context_error)?;
//!                     delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
//!                 }
//!                 Err(e) => return Err(e),
//!             },
//!             Err(e) if e.is_timeout() || e.is_connect() => {
//!                 if attempts < self.max_retries {
//!                     context.sleep(delay).await.map_err(map_context_error)?;
//!                     delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
//!                 } else {
//!                     return Err(OpenAIError::Http(e));
//!                 }
//!             }
//!             Err(e) => return Err(OpenAIError::Http(e)),
//!         }
//!     }
//! }
//!
//! fn map_context_error(error: AsyncError) -> OpenAIError {
//!     match error {
//!         AsyncError::Timeout { timeout_ms } => OpenAIError::Api { /* ... */ },
//!         AsyncError::Cancelled => OpenAIError::Api { /* ... */ },
//!         other => OpenAIError::Api { message: other.to_string(), /* ... */ },
//!     }
//! }
//! ```
//!
//! ## After (using migration framework)
//!
//! ```ignore
//! // connectors/openai/src/client.rs — AFTER migration
//! use fcp_sdk::migration::{
//!     AttemptOutcome, ConnectorErrorMapping, ConnectorRuntime,
//!     HttpRetryConfig, RetryLoop, classify_http_status, map_async_to_fcp_error,
//! };
//!
//! // In OpenAIClient:
//! struct OpenAIClient {
//!     client: Client,
//!     auth: OpenAIAuth,
//!     base_url: String,
//!     runtime: ConnectorRuntime,     // NEW: replaces manual context creation
//!     retry_config: HttpRetryConfig, // NEW: replaces loose fields
//!     // ...
//! }
//!
//! // ConnectorErrorMapping impl replaces map_context_error():
//! impl ConnectorErrorMapping for OpenAIError {
//!     fn from_async_error(error: AsyncError) -> Self {
//!         match error {
//!             AsyncError::Timeout { timeout_ms } => Self::Api {
//!                 error_type: "deadline_timeout".into(),
//!                 message: format!("deadline exceeded after {timeout_ms}ms"),
//!                 status_code: Some(408),
//!             },
//!             AsyncError::Cancelled => Self::Api {
//!                 error_type: "request_cancelled".into(),
//!                 message: "cancelled".into(),
//!                 status_code: None,
//!             },
//!             other => Self::Api {
//!                 error_type: "runtime".into(),
//!                 message: other.to_string(),
//!                 status_code: None,
//!             },
//!         }
//!     }
//!     fn to_fcp_error(&self) -> FcpError { map_async_to_fcp_error(/* ... */) }
//!     fn is_retryable(&self) -> bool { matches!(self, Self::RateLimited { .. } | Self::Overloaded { .. }) }
//!     fn retry_after(&self) -> Option<Duration> { /* from error variant */ }
//! }
//!
//! // Migrated post() — 10 lines replacing 50:
//! async fn post<T, R>(&self, endpoint: &str, body: &T) -> OpenAIResult<R> {
//!     let url = format!("{}{endpoint}", self.base_url);
//!     let ctx = self.runtime.request_context();
//!     let policy = self.retry_config.to_retry_policy();
//!
//!     RetryLoop::execute(&ctx, &policy, |_attempt| {
//!         let url = &url;
//!         async move {
//!             let request = self.client.post(url).json(body);
//!             let request = self.apply_auth(request);
//!             match request.send().await {
//!                 Ok(resp) => {
//!                     let status = resp.status().as_u16();
//!                     match self.handle_response(resp).await {
//!                         Ok(data) => AttemptOutcome::Success(data),
//!                         Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
//!                             retry_after: e.retry_after(),
//!                             error: e,
//!                         },
//!                         Err(e) => AttemptOutcome::Terminal(e),
//!                     }
//!                 }
//!                 Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
//!                     error: OpenAIError::Http(e),
//!                     retry_after: None,
//!                 },
//!                 Err(e) => AttemptOutcome::Terminal(OpenAIError::Http(e)),
//!             }
//!         }
//!     }).await
//! }
//! ```
//!
//! Key improvements after migration:
//! - No manual backoff tracking (`delay`, `attempts` variables eliminated)
//! - Cancellation/deadline automatically handled by `RetryLoop` + `ExecutionContext`
//! - Structured tracing emitted for every retry (with `attempt`, `delay_ms`, `error`)
//! - Retry config serializable from connector TOML/JSON configuration
//! - Error mapping centralized in `ConnectorErrorMapping` impl

use std::fmt;
use std::time::Duration;

use fcp_async_core::{AsyncError, ExecutionContext};
use tracing::{debug, warn};

use crate::FcpError;
use crate::retry::{RetryDecision, RetryPolicy};

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorRuntime
// ─────────────────────────────────────────────────────────────────────────────

/// Shared connector runtime providing lifecycle management.
///
/// Each connector instance creates one `ConnectorRuntime` during `configure()`.
/// The runtime provides:
/// - Request-scoped `ExecutionContext` creation with configurable timeouts
/// - Background context for long-lived operations (streaming, polling)
/// - Graceful shutdown coordination
///
/// # Example
///
/// ```ignore
/// let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
///
/// // For each request:
/// let ctx = runtime.request_context();
/// let result = ctx.run(client.get(url).send()).await;
///
/// // On shutdown:
/// runtime.shutdown();
/// ```
#[derive(Debug)]
pub struct ConnectorRuntime {
    config: ConnectorRuntimeConfig,
    background_ctx: ExecutionContext,
}

/// Configuration for [`ConnectorRuntime`].
#[derive(Debug, Clone)]
pub struct ConnectorRuntimeConfig {
    /// Default timeout for request-scoped operations.
    pub request_timeout: Duration,
    /// Timeout for graceful shutdown.
    pub shutdown_timeout: Duration,
}

impl Default for ConnectorRuntimeConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(120),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

impl ConnectorRuntimeConfig {
    /// Builder: set request timeout.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Builder: set shutdown timeout.
    #[must_use]
    pub const fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }
}

impl ConnectorRuntime {
    /// Create a new connector runtime.
    #[must_use]
    pub fn new(config: ConnectorRuntimeConfig) -> Self {
        Self {
            config,
            background_ctx: ExecutionContext::background(),
        }
    }

    /// Create a request-scoped execution context with the configured timeout.
    #[must_use]
    pub fn request_context(&self) -> ExecutionContext {
        ExecutionContext::request_scoped(self.config.request_timeout)
    }

    /// Create a request-scoped context with a custom timeout.
    #[must_use]
    pub fn request_context_with_timeout(&self, timeout: Duration) -> ExecutionContext {
        ExecutionContext::request_scoped(timeout)
    }

    /// Get a child of the background context for long-lived operations.
    #[must_use]
    pub fn background_context(&self) -> ExecutionContext {
        self.background_ctx.child()
    }

    /// Trigger graceful shutdown of all contexts.
    pub fn shutdown(&self) {
        self.background_ctx.cancel();
    }

    /// Whether shutdown has been requested.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.background_ctx.is_cancelled()
    }

    /// The configured request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.config.request_timeout
    }

    /// The configured shutdown timeout.
    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        self.config.shutdown_timeout
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorErrorMapping
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for mapping `AsyncError` to connector-specific error types.
///
/// Every connector must implement this to handle deadline/cancellation
/// errors from `ExecutionContext` operations.
///
/// # Example
///
/// ```ignore
/// impl ConnectorErrorMapping for MyConnectorError {
///     fn from_async_error(error: AsyncError) -> Self {
///         match error {
///             AsyncError::Timeout { timeout_ms } => Self::DeadlineExceeded {
///                 message: format!("request deadline exceeded after {timeout_ms}ms"),
///             },
///             AsyncError::Cancelled => Self::RequestCancelled,
///             other => Self::Runtime { message: other.to_string() },
///         }
///     }
///
///     fn to_fcp_error(&self) -> FcpError { /* ... */ }
/// }
/// ```
pub trait ConnectorErrorMapping: fmt::Display + fmt::Debug + Send + Sync {
    /// Map an `AsyncError` (timeout, cancellation, etc.) to this connector's error type.
    fn from_async_error(error: AsyncError) -> Self
    where
        Self: Sized;

    /// Convert this connector error to the standard `FcpError` taxonomy.
    fn to_fcp_error(&self) -> FcpError;

    /// Whether this error is retryable.
    fn is_retryable(&self) -> bool;

    /// Suggested retry-after delay, if available.
    fn retry_after(&self) -> Option<Duration> {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RetryLoop
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a single attempt in a retry loop.
pub enum AttemptOutcome<T, E> {
    /// Operation succeeded.
    Success(T),
    /// Operation failed but may be retried.
    Retryable {
        /// The error from this attempt.
        error: E,
        /// Explicit retry-after hint from the service.
        retry_after: Option<Duration>,
    },
    /// Operation failed terminally (no retry).
    Terminal(E),
}

/// Generic retry executor using `ExecutionContext` for deadline-aware backoff.
///
/// Replaces hand-rolled retry loops in connector clients with a consistent
/// pattern that respects cancellation, deadline budgets, and structured logging.
///
/// # Example
///
/// ```ignore
/// let ctx = runtime.request_context();
/// let policy = RetryPolicy::new().with_max_attempts(Some(3));
///
/// let result = RetryLoop::execute(&ctx, &policy, |attempt| async move {
///     match client.post(url).send().await {
///         Ok(resp) if resp.status().is_success() => AttemptOutcome::Success(resp),
///         Ok(resp) if resp.status() == 429 => AttemptOutcome::Retryable {
///             error: MyError::RateLimited,
///             retry_after: Some(Duration::from_secs(30)),
///         },
///         Ok(resp) => AttemptOutcome::Terminal(MyError::Api(resp.status())),
///         Err(e) if e.is_timeout() => AttemptOutcome::Retryable {
///             error: MyError::Http(e),
///             retry_after: None,
///         },
///         Err(e) => AttemptOutcome::Terminal(MyError::Http(e)),
///     }
/// }).await;
/// ```
pub struct RetryLoop;

impl RetryLoop {
    /// Execute an operation with retry logic under an `ExecutionContext`.
    ///
    /// The `operation` closure receives the current attempt number (0-indexed)
    /// and returns an [`AttemptOutcome`]. Retries continue until:
    /// - The operation succeeds
    /// - A terminal error occurs
    /// - The retry policy's max attempts is reached
    /// - The context deadline expires or cancellation is triggered
    ///
    /// # Errors
    ///
    /// Returns the last error encountered (either from the operation or from
    /// context timeout/cancellation mapped via `E::from_async_error`).
    pub async fn execute<T, E, F, Fut>(
        ctx: &ExecutionContext,
        policy: &RetryPolicy,
        mut operation: F,
    ) -> Result<T, E>
    where
        E: ConnectorErrorMapping,
        F: FnMut(u32) -> Fut,
        Fut: std::future::Future<Output = AttemptOutcome<T, E>>,
    {
        let mut attempt: u32 = 0;
        let mut last_error: Option<E> = None;

        loop {
            // Check if we've exceeded max attempts
            if let Some(max) = policy.max_attempts {
                if attempt >= max {
                    // Safety: at least one attempt ran before `attempt` was incremented
                    return Err(last_error.unwrap_or_else(|| {
                        E::from_async_error(AsyncError::Runtime {
                            message: "retry budget exhausted with no attempts".into(),
                        })
                    }));
                }
            }

            // Check cancellation before each attempt
            if ctx.is_cancelled() {
                return Err(E::from_async_error(AsyncError::Cancelled));
            }

            debug!(attempt, "executing retry attempt");

            match operation(attempt).await {
                AttemptOutcome::Success(value) => return Ok(value),
                AttemptOutcome::Terminal(error) => return Err(error),
                AttemptOutcome::Retryable { error, retry_after } => {
                    // Compute delay: use retry-after hint or policy backoff
                    let decision = retry_after.map_or(RetryDecision::Backoff, RetryDecision::After);

                    let Some(delay) = policy.next_delay(attempt, decision, retry_after) else {
                        // Policy says no more retries
                        return Err(error);
                    };

                    warn!(
                        attempt,
                        delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        error = %error,
                        "retrying after transient error"
                    );

                    // Sleep under context (respects deadline + cancellation)
                    if let Err(async_err) = ctx.sleep(delay).await {
                        // Context expired or cancelled during sleep
                        return Err(E::from_async_error(async_err));
                    }

                    last_error = Some(error);
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Client helpers (feature-gated)
// ─────────────────────────────────────────────────────────────────────────────

/// Standard HTTP retry configuration shared across connectors.
///
/// Extracted from the common pattern found in all 6 connectors.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct HttpRetryConfig {
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds.
    pub initial_delay_ms: u64,
    /// Maximum backoff delay in milliseconds.
    pub max_delay_ms: u64,
    /// Whether to add jitter to backoff delays.
    pub jitter_enabled: bool,
}

impl Default for HttpRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 500,
            max_delay_ms: 30_000,
            jitter_enabled: true,
        }
    }
}

impl HttpRetryConfig {
    /// Convert to a [`RetryPolicy`].
    #[must_use]
    pub fn to_retry_policy(&self) -> RetryPolicy {
        RetryPolicy::new()
            .with_base_backoff_ms(self.initial_delay_ms)
            .with_max_backoff_ms(self.max_delay_ms)
            .with_jitter_enabled(self.jitter_enabled)
            .with_max_attempts(Some(self.max_retries))
    }
}

/// Classify an HTTP status code into a retry decision with standard FCP semantics.
///
/// This is the canonical classification used across all connectors:
/// - 429 → Retry after hint (or 30s default)
/// - 408, 425, 500-599 → Backoff
/// - Everything else → Terminal
#[must_use]
pub fn classify_http_status(status: u16, retry_after: Option<Duration>) -> RetryDecision {
    crate::retry::decision_from_http_status(status, retry_after)
}

/// Map an `AsyncError` from context operations to a standard `FcpError`.
///
/// This is the canonical mapping for context-level errors (timeout, cancellation).
/// Connector-specific error types should delegate to this for the `AsyncError` arm.
#[must_use]
pub fn map_async_to_fcp_error(error: &AsyncError) -> FcpError {
    match error {
        AsyncError::Timeout { timeout_ms } => FcpError::External {
            service: "runtime".into(),
            message: format!("request deadline exceeded after {timeout_ms}ms"),
            status_code: Some(408),
            retryable: false,
            retry_after: None,
        },
        AsyncError::Cancelled => FcpError::External {
            service: "runtime".into(),
            message: "request cancelled".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        other => FcpError::Internal {
            message: other.to_string(),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- ConnectorRuntime tests ------------------------------------------------

    #[test]
    fn runtime_default_config() {
        let config = ConnectorRuntimeConfig::default();
        assert_eq!(config.request_timeout, Duration::from_secs(120));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn runtime_creates_request_context() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx = runtime.request_context();
        assert!(!ctx.is_cancelled());
        assert!(ctx.remaining_budget().is_some());
    }

    #[test]
    fn runtime_creates_background_context() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx = runtime.background_context();
        assert!(!ctx.is_cancelled());
        assert!(ctx.remaining_budget().is_none()); // No deadline
    }

    #[test]
    fn runtime_shutdown_propagates() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let bg = runtime.background_context();
        assert!(!runtime.is_shutting_down());
        assert!(!bg.is_cancelled());

        runtime.shutdown();

        assert!(runtime.is_shutting_down());
        assert!(bg.is_cancelled());
    }

    #[test]
    fn runtime_custom_timeout() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(60)),
        );
        assert_eq!(runtime.request_timeout(), Duration::from_secs(60));
    }

    // -- HttpRetryConfig tests ------------------------------------------------

    #[test]
    fn http_retry_config_defaults() {
        let config = HttpRetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 30_000);
        assert!(config.jitter_enabled);
    }

    #[test]
    fn http_retry_config_to_policy() {
        let config = HttpRetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            jitter_enabled: false,
        };
        let policy = config.to_retry_policy();
        assert_eq!(policy.max_attempts, Some(5));
        assert_eq!(policy.base_backoff_ms, 1000);
        assert_eq!(policy.max_backoff_ms, 60_000);
        assert!(!policy.jitter_enabled);
    }

    // -- classify_http_status tests -------------------------------------------

    #[test]
    fn classify_429_retries() {
        let decision = classify_http_status(429, None);
        assert!(decision.is_retryable());
        assert!(decision.retry_after().is_some());
    }

    #[test]
    fn classify_500_backoff() {
        let decision = classify_http_status(500, None);
        assert!(decision.is_retryable());
        assert_eq!(decision, RetryDecision::Backoff);
    }

    #[test]
    fn classify_401_terminal() {
        let decision = classify_http_status(401, None);
        assert!(!decision.is_retryable());
        assert_eq!(decision, RetryDecision::Terminal);
    }

    // -- map_async_to_fcp_error tests -----------------------------------------

    #[test]
    fn map_timeout_to_fcp() {
        let err = AsyncError::Timeout { timeout_ms: 5000 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { status_code, .. } => {
                assert_eq!(status_code, Some(408));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_to_fcp() {
        let err = AsyncError::Cancelled;
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { message, .. } => {
                assert!(message.contains("cancelled"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // -- RetryLoop tests (async) -----------------------------------------------

    #[fcp_async_core::runtime::test]
    async fn retry_loop_succeeds_first_attempt() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let policy = RetryPolicy::new().with_max_attempts(Some(3));

        let result: Result<&str, TestError> = RetryLoop::execute(&ctx, &policy, |_attempt| async {
            AttemptOutcome::Success("ok")
        })
        .await;

        assert_eq!(result.unwrap(), "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn retry_loop_retries_then_succeeds() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
        let policy = RetryPolicy::new()
            .with_max_attempts(Some(5))
            .with_base_backoff_ms(10)
            .with_jitter_enabled(false);

        let result: Result<&str, TestError> =
            RetryLoop::execute(&ctx, &policy, |attempt| async move {
                if attempt < 2 {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("try again".into()),
                        retry_after: None,
                    }
                } else {
                    AttemptOutcome::Success("finally")
                }
            })
            .await;

        assert_eq!(result.unwrap(), "finally");
    }

    #[fcp_async_core::runtime::test]
    async fn retry_loop_terminal_error_stops() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let policy = RetryPolicy::new().with_max_attempts(Some(5));

        let result: Result<&str, TestError> = RetryLoop::execute(&ctx, &policy, |_attempt| async {
            AttemptOutcome::Terminal(TestError::Fatal("auth failed".into()))
        })
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            TestError::Fatal(msg) => assert_eq!(msg, "auth failed"),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn retry_loop_max_attempts_exhausted() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
        let policy = RetryPolicy::new()
            .with_max_attempts(Some(2))
            .with_base_backoff_ms(10)
            .with_jitter_enabled(false);

        let result: Result<&str, TestError> = RetryLoop::execute(&ctx, &policy, |_attempt| async {
            AttemptOutcome::Retryable {
                error: TestError::Transient("still failing".into()),
                retry_after: None,
            }
        })
        .await;

        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn retry_loop_respects_cancellation() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
        let policy = RetryPolicy::new()
            .with_max_attempts(Some(10))
            .with_base_backoff_ms(10)
            .with_jitter_enabled(false);

        // Cancel the context immediately
        ctx.cancel();

        let result: Result<&str, TestError> = RetryLoop::execute(&ctx, &policy, |_attempt| async {
            AttemptOutcome::Retryable {
                error: TestError::Transient("won't get here".into()),
                retry_after: None,
            }
        })
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            TestError::Cancelled => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    // -- Test error type for testing ------------------------------------------

    #[derive(Debug)]
    enum TestError {
        Transient(String),
        Fatal(String),
        DeadlineExceeded(String),
        Cancelled,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Transient(msg) => write!(f, "transient: {msg}"),
                Self::Fatal(msg) => write!(f, "fatal: {msg}"),
                Self::DeadlineExceeded(msg) => write!(f, "deadline: {msg}"),
                Self::Cancelled => write!(f, "cancelled"),
            }
        }
    }

    impl ConnectorErrorMapping for TestError {
        fn from_async_error(error: AsyncError) -> Self {
            match error {
                AsyncError::Timeout { timeout_ms } => {
                    Self::DeadlineExceeded(format!("exceeded {timeout_ms}ms"))
                }
                AsyncError::Cancelled => Self::Cancelled,
                other => Self::Fatal(other.to_string()),
            }
        }

        fn to_fcp_error(&self) -> FcpError {
            map_async_to_fcp_error(&match self {
                Self::Transient(msg) => AsyncError::ProtocolIo {
                    message: msg.clone(),
                },
                Self::Fatal(msg) => AsyncError::Runtime {
                    message: msg.clone(),
                },
                Self::DeadlineExceeded(_) => AsyncError::Timeout { timeout_ms: 0 },
                Self::Cancelled => AsyncError::Cancelled,
            })
        }

        fn is_retryable(&self) -> bool {
            matches!(self, Self::Transient(_))
        }
    }
}
