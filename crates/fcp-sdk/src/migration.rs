//! Connector migration framework for the `AsyncSuperSync` transition.
//!
//! This module provides shared helpers that all connectors use when migrating
//! from legacy runtime-specific code to the `fcp-async-core` substrate. It eliminates
//! duplicated runtime bootstrap, retry loop, and error mapping code across
//! connector crates.
//!
//! This module is an implementation helper, not the primary SDK contract.
//! New connector authoring should start from [`crate::ConnectorApp`] and use the
//! migration helpers only where they clarify runtime integration details.
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
//! - [ ] Replace any direct runtime builders or spawn calls with
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
//! - [ ] **No direct runtime imports** — scan connector sources for raw runtime paths
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
//! # Reference Migration: `OpenAI` Connector
//!
//! Below is a condensed before/after showing how the `OpenAI` connector's
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
use fcp_manifest::{ConnectorManifest, ManifestTimeouts};
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
#[derive(Debug, Clone)]
pub struct ConnectorRuntime {
    config: ConnectorRuntimeConfig,
    background_ctx: ExecutionContext,
}

const MANIFEST_REQUEST_TIMEOUT_ENV_VAR: &str = "FCP_REQUEST_TIMEOUT_MS";

/// Errors produced while loading runtime settings from an embedded manifest.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorRuntimeConfigError {
    /// The connector manifest could not be parsed or validated.
    #[error(transparent)]
    Manifest(#[from] fcp_manifest::ManifestError),

    /// The request-timeout override env var was present but unusable.
    #[error("{env_var} must be a positive integer number of milliseconds, got `{value}`")]
    InvalidRequestTimeoutEnvVar {
        /// The env var name.
        env_var: &'static str,
        /// The invalid value observed at load time.
        value: String,
    },
}

/// Configuration for [`ConnectorRuntime`].
#[derive(Debug, Clone)]
pub struct ConnectorRuntimeConfig {
    /// Default timeout for request-scoped operations.
    pub request_timeout: Duration,
    /// Default timeout for establishing outbound connections.
    pub connect_timeout: Duration,
    /// Default wall-clock budget for a single operation.
    pub wall_clock_timeout: Duration,
    /// Timeout for graceful shutdown.
    pub shutdown_timeout: Duration,
}

impl Default for ConnectorRuntimeConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(10),
            wall_clock_timeout: Duration::from_secs(120),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

impl ConnectorRuntimeConfig {
    /// Manifest-aligned defaults used by newly scaffolded connectors.
    #[must_use]
    pub const fn manifest_defaults() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            wall_clock_timeout: Duration::from_secs(60),
            shutdown_timeout: Duration::from_secs(30),
        }
    }

    /// Build runtime settings from a manifest `[timeouts]` section.
    #[must_use]
    pub const fn from_manifest_timeouts(timeouts: &ManifestTimeouts) -> Self {
        Self::manifest_defaults()
            .with_request_timeout(Duration::from_millis(timeouts.request_timeout_ms))
            .with_connect_timeout(Duration::from_millis(timeouts.connect_timeout_ms))
            .with_wall_clock_timeout(Duration::from_millis(timeouts.wall_clock_timeout_ms))
    }

    /// Build runtime settings from a parsed connector manifest.
    ///
    /// If the manifest omits `[timeouts]`, scaffold defaults are used. An
    /// optional `FCP_REQUEST_TIMEOUT_MS` env var overrides the request timeout.
    ///
    /// # Errors
    /// Returns an error when `FCP_REQUEST_TIMEOUT_MS` is present but invalid.
    pub fn from_manifest(
        manifest: &ConnectorManifest,
    ) -> Result<Self, ConnectorRuntimeConfigError> {
        let request_timeout_override = std::env::var_os(MANIFEST_REQUEST_TIMEOUT_ENV_VAR)
            .map(|value| value.to_string_lossy().into_owned());
        Self::from_manifest_with_request_timeout_override(
            manifest,
            request_timeout_override.as_deref(),
        )
    }

    /// Build runtime settings from embedded manifest TOML.
    ///
    /// # Errors
    /// Returns an error when the manifest is invalid or the request-timeout
    /// env override cannot be parsed.
    pub fn from_manifest_str(manifest_toml: &str) -> Result<Self, ConnectorRuntimeConfigError> {
        let manifest = ConnectorManifest::parse_str(manifest_toml)?;
        Self::from_manifest(&manifest)
    }

    /// Builder: set request timeout.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Builder: set connect timeout.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Builder: set wall-clock timeout.
    #[must_use]
    pub const fn with_wall_clock_timeout(mut self, timeout: Duration) -> Self {
        self.wall_clock_timeout = timeout;
        self
    }

    /// Builder: set shutdown timeout.
    #[must_use]
    pub const fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    fn from_manifest_with_request_timeout_override(
        manifest: &ConnectorManifest,
        request_timeout_override: Option<&str>,
    ) -> Result<Self, ConnectorRuntimeConfigError> {
        let mut config = manifest
            .timeouts
            .as_ref()
            .map_or_else(Self::manifest_defaults, Self::from_manifest_timeouts);

        if let Some(timeout) = parse_request_timeout_override(request_timeout_override)? {
            config = config.with_request_timeout(timeout);
        }

        Ok(config)
    }
}

fn parse_request_timeout_override(
    request_timeout_override: Option<&str>,
) -> Result<Option<Duration>, ConnectorRuntimeConfigError> {
    let Some(raw) = request_timeout_override else {
        return Ok(None);
    };

    let timeout_ms: u64 =
        raw.parse().map_err(
            |_| ConnectorRuntimeConfigError::InvalidRequestTimeoutEnvVar {
                env_var: MANIFEST_REQUEST_TIMEOUT_ENV_VAR,
                value: raw.to_string(),
            },
        )?;
    if timeout_ms == 0 {
        return Err(ConnectorRuntimeConfigError::InvalidRequestTimeoutEnvVar {
            env_var: MANIFEST_REQUEST_TIMEOUT_ENV_VAR,
            value: raw.to_string(),
        });
    }

    Ok(Some(Duration::from_millis(timeout_ms)))
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

    /// The configured connect timeout.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.config.connect_timeout
    }

    /// The configured wall-clock timeout.
    #[must_use]
    pub const fn wall_clock_timeout(&self) -> Duration {
        self.config.wall_clock_timeout
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
// Canonical HTTP → FCP Error Mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Map an HTTP status code to the canonical FCP error.
///
/// Provides a single source of truth for the HTTP-to-FCP error taxonomy so
/// connectors do not each invent ad-hoc mappings. Connectors MAY override
/// specific codes when the service assigns non-standard semantics (e.g., a
/// 403 that means "resource not found" rather than "capability denied").
///
/// The `message` parameter is included in the resulting `FcpError` for
/// diagnostics. Pass the upstream response body or a short summary.
#[must_use]
pub fn map_http_status(status: u16, service: &str, message: String) -> FcpError {
    match status {
        400 => FcpError::InvalidRequest {
            code: 1001,
            message,
        },
        401 => FcpError::Unauthorized {
            code: 2001,
            message,
        },
        403 => FcpError::CapabilityDenied {
            capability: String::new(),
            reason: message,
        },
        404 => FcpError::ResourceNotFound { resource: message },
        408 => FcpError::UpstreamTimeout {
            service: service.to_string(),
        },
        409 => FcpError::Conflict { message },
        429 => FcpError::RateLimited {
            retry_after_ms: 0,
            violation: None,
        },
        // Server errors → External (upstream fault, retryable)
        500..=599 => FcpError::External {
            service: service.to_string(),
            message,
            status_code: Some(status),
            retryable: matches!(status, 500 | 502 | 503 | 504),
            retry_after: None,
        },
        // Everything else → External with status context
        _ => FcpError::External {
            service: service.to_string(),
            message: format!("HTTP {status}: {message}"),
            status_code: Some(status),
            retryable: false,
            retry_after: None,
        },
    }
}

/// Whether an HTTP status code is retryable per standard semantics.
///
/// - 408 Request Timeout: transient, retry
/// - 429 Too Many Requests: retry after delay
/// - 500 Internal Server Error: transient, retry
/// - 502 Bad Gateway: transient, retry
/// - 503 Service Unavailable: transient, retry
/// - 504 Gateway Timeout: transient, retry
#[must_use]
pub const fn is_http_status_retryable(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
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
        operation: F,
    ) -> Result<T, E>
    where
        E: ConnectorErrorMapping,
        F: FnMut(u32) -> Fut,
        Fut: std::future::Future<Output = AttemptOutcome<T, E>>,
    {
        Self::execute_from_attempt(ctx, policy, 0, operation).await
    }

    async fn execute_from_attempt<T, E, F, Fut>(
        ctx: &ExecutionContext,
        policy: &RetryPolicy,
        start_attempt: u32,
        mut operation: F,
    ) -> Result<T, E>
    where
        E: ConnectorErrorMapping,
        F: FnMut(u32) -> Fut,
        Fut: std::future::Future<Output = AttemptOutcome<T, E>>,
    {
        let mut attempt = start_attempt;
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

                    let Some(next_attempt) = attempt.checked_add(1) else {
                        return Err(error);
                    };
                    last_error = Some(error);
                    attempt = next_attempt;
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
    /// Maximum retry attempts after the initial request.
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
        let max_attempts = if self.max_retries == u32::MAX {
            None
        } else {
            Some(self.max_retries + 1)
        };

        RetryPolicy::new()
            .with_base_backoff_ms(self.initial_delay_ms)
            .with_max_backoff_ms(self.max_delay_ms)
            .with_jitter_enabled(self.jitter_enabled)
            .with_max_attempts(max_attempts)
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

    fn manifest_toml_with_optional_timeouts(timeouts: Option<&str>) -> String {
        let placeholder = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";
        let timeouts_block = timeouts.unwrap_or_default();
        let raw = format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{placeholder}"

[connector]
id = "fcp.test"
name = "Test Connector"
version = "0.1.0"
description = "runtime config test manifest"
archetypes = ["operational"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
home = "z:project:test"
allowed_sources = ["z:project:test"]
allowed_targets = ["z:project:test"]
forbidden = ["z:public"]

[capabilities]
required = ["network.dns", "network.outbound"]
optional = []
forbidden = ["system.exec"]

[provides.operations.placeholder_operation]
description = "Placeholder operation"
capability = "test.placeholder"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "best_effort"
input_schema = {{ type = "object", properties = {{ }} }}
output_schema = {{ type = "object", properties = {{ }} }}

[provides.operations.placeholder_operation.network_constraints]
host_allow = ["example.invalid"]
port_allow = [443]
require_sni = true

{timeouts_block}
[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 25
wall_clock_timeout_ms = 60000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
        );
        let unchecked = ConnectorManifest::parse_str_unchecked(&raw).unwrap();
        let interface_hash = unchecked.compute_interface_hash().unwrap();
        raw.replace(placeholder, &interface_hash.to_string())
    }

    // -- ConnectorRuntime tests ------------------------------------------------

    #[test]
    fn runtime_default_config() {
        let config = ConnectorRuntimeConfig::default();
        assert_eq!(config.request_timeout, Duration::from_secs(120));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(120));
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

    #[test]
    fn runtime_connect_and_wall_clock_accessors() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_connect_timeout(Duration::from_secs(7))
                .with_wall_clock_timeout(Duration::from_secs(75)),
        );
        assert_eq!(runtime.connect_timeout(), Duration::from_secs(7));
        assert_eq!(runtime.wall_clock_timeout(), Duration::from_secs(75));
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
        assert_eq!(policy.max_attempts, Some(6));
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

    #[test]
    fn retry_loop_succeeds_first_attempt() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new().with_max_attempts(Some(3));

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Success("ok")
                })
                .await;

            assert_eq!(result.unwrap(), "ok");
        })
        .expect("runtime should execute first-attempt retry test");
    }

    #[test]
    fn retry_loop_retries_then_succeeds() {
        fcp_async_core::runtime::block_on_sync(async {
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
        })
        .expect("runtime should execute retry-then-success test");
    }

    #[test]
    fn retry_loop_terminal_error_stops() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new().with_max_attempts(Some(5));

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Terminal(TestError::Fatal("auth failed".into()))
                })
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                TestError::Fatal(msg) => assert_eq!(msg, "auth failed"),
                other => panic!("expected Fatal, got {other:?}"),
            }
        })
        .expect("runtime should execute terminal-error retry test");
    }

    #[test]
    fn retry_loop_max_attempts_exhausted() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(2))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("still failing".into()),
                        retry_after: None,
                    }
                })
                .await;

            assert!(result.is_err());
        })
        .expect("runtime should execute max-attempts retry test");
    }

    #[test]
    fn retry_loop_respects_cancellation() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(10))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            // Cancel the context immediately
            ctx.cancel();

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
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
        })
        .expect("runtime should execute cancellation-aware retry test");
    }

    // -- ConnectorRuntimeConfig builder tests --------------------------------

    #[test]
    fn config_with_shutdown_timeout() {
        let config =
            ConnectorRuntimeConfig::default().with_shutdown_timeout(Duration::from_secs(10));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(10));
        // request_timeout unchanged
        assert_eq!(config.request_timeout, Duration::from_secs(120));
    }

    #[test]
    fn config_builder_chain_both() {
        let config = ConnectorRuntimeConfig::default()
            .with_request_timeout(Duration::from_secs(60))
            .with_shutdown_timeout(Duration::from_secs(5));
        assert_eq!(config.request_timeout, Duration::from_secs(60));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(5));
    }

    #[test]
    fn config_manifest_defaults_match_scaffold_expectations() {
        let config = ConnectorRuntimeConfig::manifest_defaults();
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(60));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn config_from_manifest_timeouts_uses_manifest_values() {
        let config = ConnectorRuntimeConfig::from_manifest_timeouts(&ManifestTimeouts {
            request_timeout_ms: 45_000,
            connect_timeout_ms: 7_000,
            wall_clock_timeout_ms: 90_000,
        });
        assert_eq!(config.request_timeout, Duration::from_secs(45));
        assert_eq!(config.connect_timeout, Duration::from_secs(7));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(90));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn config_from_manifest_without_timeouts_uses_manifest_defaults() {
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(None))
            .expect("manifest should parse");
        let config =
            ConnectorRuntimeConfig::from_manifest_with_request_timeout_override(&manifest, None)
                .expect("manifest defaults should load");
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(60));
    }

    #[test]
    fn config_from_manifest_with_timeouts_uses_manifest_section() {
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(Some(
            "[timeouts]\nrequest_timeout_ms = 48000\nconnect_timeout_ms = 8000\nwall_clock_timeout_ms = 95000\n\n",
        )))
        .expect("manifest should parse");
        let config =
            ConnectorRuntimeConfig::from_manifest_with_request_timeout_override(&manifest, None)
                .expect("manifest timeouts should load");
        assert_eq!(config.request_timeout, Duration::from_secs(48));
        assert_eq!(config.connect_timeout, Duration::from_secs(8));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(95));
    }

    #[test]
    fn config_from_manifest_override_uses_request_timeout_env_value() {
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(Some(
            "[timeouts]\nrequest_timeout_ms = 48000\nconnect_timeout_ms = 8000\nwall_clock_timeout_ms = 95000\n\n",
        )))
        .expect("manifest should parse");
        let config = ConnectorRuntimeConfig::from_manifest_with_request_timeout_override(
            &manifest,
            Some("61000"),
        )
        .expect("override should parse");
        assert_eq!(config.request_timeout, Duration::from_secs(61));
        assert_eq!(config.connect_timeout, Duration::from_secs(8));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(95));
    }

    #[test]
    fn config_from_manifest_override_rejects_invalid_env_value() {
        let manifest = ConnectorManifest::parse_str(&manifest_toml_with_optional_timeouts(None))
            .expect("manifest should parse");
        let err = ConnectorRuntimeConfig::from_manifest_with_request_timeout_override(
            &manifest,
            Some("invalid"),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("FCP_REQUEST_TIMEOUT_MS must be a positive integer")
        );
    }

    #[test]
    fn config_from_manifest_str_parses_embedded_manifest() {
        let request_timeout_override = std::env::var_os(MANIFEST_REQUEST_TIMEOUT_ENV_VAR)
            .map(|value| value.to_string_lossy().into_owned());
        let expected_request_timeout =
            parse_request_timeout_override(request_timeout_override.as_deref())
                .expect("ambient override should be valid if present")
                .unwrap_or(Duration::from_secs(52));
        let config = ConnectorRuntimeConfig::from_manifest_str(
            &manifest_toml_with_optional_timeouts(Some(
                "[timeouts]\nrequest_timeout_ms = 52000\nconnect_timeout_ms = 6000\nwall_clock_timeout_ms = 88000\n\n",
            )),
        )
        .expect("embedded manifest should parse");
        assert_eq!(config.request_timeout, expected_request_timeout);
        assert_eq!(config.connect_timeout, Duration::from_secs(6));
        assert_eq!(config.wall_clock_timeout, Duration::from_secs(88));
    }

    #[test]
    fn config_debug() {
        let config = ConnectorRuntimeConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("ConnectorRuntimeConfig"));
    }

    #[test]
    fn config_clone() {
        let config =
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(77));
        let moved = config;
        assert_eq!(moved.request_timeout, Duration::from_secs(77));
    }

    // -- ConnectorRuntime additional tests ------------------------------------

    #[test]
    fn runtime_request_context_with_custom_timeout() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx = runtime.request_context_with_timeout(Duration::from_secs(5));
        assert!(!ctx.is_cancelled());
        assert!(ctx.remaining_budget().is_some());
    }

    #[test]
    fn runtime_shutdown_timeout_accessor() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_shutdown_timeout(Duration::from_secs(15)),
        );
        assert_eq!(runtime.shutdown_timeout(), Duration::from_secs(15));
    }

    #[test]
    fn runtime_multiple_background_contexts_independent() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let bg1 = runtime.background_context();
        let bg2 = runtime.background_context();
        assert!(!bg1.is_cancelled());
        assert!(!bg2.is_cancelled());
        // Shutting down cancels both
        runtime.shutdown();
        assert!(bg1.is_cancelled());
        assert!(bg2.is_cancelled());
    }

    #[test]
    fn runtime_shutdown_idempotent() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        runtime.shutdown();
        assert!(runtime.is_shutting_down());
        runtime.shutdown(); // second call should not panic
        assert!(runtime.is_shutting_down());
    }

    #[test]
    fn runtime_debug() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let debug = format!("{runtime:?}");
        assert!(debug.contains("ConnectorRuntime"));
    }

    #[test]
    fn runtime_clone() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(42)),
        );
        let moved = runtime;
        assert_eq!(moved.request_timeout(), Duration::from_secs(42));
    }

    // -- HttpRetryConfig serde tests ------------------------------------------

    #[test]
    fn http_retry_config_serde_roundtrip() {
        let config = HttpRetryConfig {
            max_retries: 7,
            initial_delay_ms: 250,
            max_delay_ms: 15_000,
            jitter_enabled: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: HttpRetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_retries, 7);
        assert_eq!(deserialized.initial_delay_ms, 250);
        assert_eq!(deserialized.max_delay_ms, 15_000);
        assert!(!deserialized.jitter_enabled);
    }

    #[test]
    fn http_retry_config_serde_default_from_empty() {
        let deserialized: HttpRetryConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(deserialized.max_retries, 3);
        assert_eq!(deserialized.initial_delay_ms, 500);
        assert_eq!(deserialized.max_delay_ms, 30_000);
        assert!(deserialized.jitter_enabled);
    }

    #[test]
    fn http_retry_config_debug_and_clone() {
        let config = HttpRetryConfig::default();
        let cloned = config.clone();
        let debug = format!("{config:?}");
        assert!(debug.contains("HttpRetryConfig"));
        assert_eq!(cloned.max_retries, config.max_retries);
    }

    // -- classify_http_status additional tests --------------------------------

    #[test]
    fn classify_408_backoff() {
        assert_eq!(classify_http_status(408, None), RetryDecision::Backoff);
    }

    #[test]
    fn classify_425_backoff() {
        assert_eq!(classify_http_status(425, None), RetryDecision::Backoff);
    }

    #[test]
    fn classify_503_backoff() {
        assert_eq!(classify_http_status(503, None), RetryDecision::Backoff);
    }

    #[test]
    fn classify_200_terminal() {
        assert_eq!(classify_http_status(200, None), RetryDecision::Terminal);
    }

    #[test]
    fn classify_429_with_custom_retry_after() {
        let hint = Duration::from_secs(60);
        let decision = classify_http_status(429, Some(hint));
        assert_eq!(decision, RetryDecision::After(hint));
    }

    // -- map_async_to_fcp_error additional tests ------------------------------

    #[test]
    fn map_runtime_error_to_fcp_internal() {
        let err = AsyncError::Runtime {
            message: "thread pool exhausted".into(),
        };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::Internal { message } => {
                assert!(message.contains("thread pool exhausted"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn map_protocol_io_error_to_fcp_internal() {
        let err = AsyncError::ProtocolIo {
            message: "broken pipe".into(),
        };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::Internal { message } => {
                assert!(message.contains("broken pipe"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn map_channel_closed_to_fcp_internal() {
        let err = AsyncError::ChannelClosed;
        let fcp_err = map_async_to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }

    #[test]
    fn map_timeout_message_contains_ms() {
        let err = AsyncError::Timeout { timeout_ms: 12_345 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { message, .. } => {
                assert!(message.contains("12345"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_not_retryable() {
        let err = AsyncError::Cancelled;
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { retryable, .. } => {
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // -- RetryLoop additional tests -------------------------------------------

    #[test]
    fn retry_loop_with_explicit_retry_after() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(5))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt == 0 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("rate limited".into()),
                            retry_after: Some(Duration::from_millis(50)),
                        }
                    } else {
                        AttemptOutcome::Success("recovered")
                    }
                })
                .await;

            assert_eq!(result.unwrap(), "recovered");
        })
        .expect("runtime should execute retry-after retry test");
    }

    #[test]
    fn retry_loop_max_attempts_zero() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new().with_max_attempts(Some(0));

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Success("should not run")
                })
                .await;

            // With 0 max attempts, no attempt runs
            assert!(result.is_err());
        })
        .expect("runtime should execute zero-max-attempts test");
    }

    // -- TestError and ConnectorErrorMapping coverage --------------------------

    #[test]
    fn test_error_display_all_variants() {
        assert_eq!(
            TestError::Transient("oops".into()).to_string(),
            "transient: oops"
        );
        assert_eq!(TestError::Fatal("bad".into()).to_string(), "fatal: bad");
        assert_eq!(
            TestError::DeadlineExceeded("5s".into()).to_string(),
            "deadline: 5s"
        );
        assert_eq!(TestError::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_error_from_async_timeout() {
        let err = TestError::from_async_error(AsyncError::Timeout { timeout_ms: 3000 });
        match err {
            TestError::DeadlineExceeded(msg) => assert!(msg.contains("3000")),
            other => panic!("expected DeadlineExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_error_from_async_cancelled() {
        let err = TestError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, TestError::Cancelled));
    }

    #[test]
    fn test_error_from_async_runtime() {
        let err = TestError::from_async_error(AsyncError::Runtime {
            message: "pool died".into(),
        });
        match err {
            TestError::Fatal(msg) => assert!(msg.contains("pool died")),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn test_error_from_async_channel_closed() {
        let err = TestError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, TestError::Fatal(_)));
    }

    #[test]
    fn test_error_to_fcp_all_variants() {
        let transient = TestError::Transient("net".into());
        assert!(matches!(
            transient.to_fcp_error(),
            FcpError::Internal { .. }
        ));

        let fatal = TestError::Fatal("auth".into());
        assert!(matches!(fatal.to_fcp_error(), FcpError::Internal { .. }));

        let deadline = TestError::DeadlineExceeded("5s".into());
        assert!(matches!(deadline.to_fcp_error(), FcpError::External { .. }));

        let cancelled = TestError::Cancelled;
        assert!(matches!(
            cancelled.to_fcp_error(),
            FcpError::External { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(TestError::Transient("x".into()).is_retryable());
        assert!(!TestError::Fatal("x".into()).is_retryable());
        assert!(!TestError::DeadlineExceeded("x".into()).is_retryable());
        assert!(!TestError::Cancelled.is_retryable());
    }

    #[test]
    fn test_error_retry_after_default_none() {
        let err = TestError::Transient("x".into());
        assert!(err.retry_after().is_none());
    }

    // -- AttemptOutcome coverage ----------------------------------------------

    #[test]
    fn attempt_outcome_success_variant() {
        let outcome: AttemptOutcome<i32, String> = AttemptOutcome::Success(42);
        match outcome {
            AttemptOutcome::Success(v) => assert_eq!(v, 42),
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn attempt_outcome_retryable_variant() {
        let outcome: AttemptOutcome<i32, String> = AttemptOutcome::Retryable {
            error: "transient".into(),
            retry_after: Some(Duration::from_secs(5)),
        };
        match outcome {
            AttemptOutcome::Retryable { error, retry_after } => {
                assert_eq!(error, "transient");
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            _ => panic!("expected Retryable"),
        }
    }

    #[test]
    fn attempt_outcome_terminal_variant() {
        let outcome: AttemptOutcome<i32, String> = AttemptOutcome::Terminal("fatal".into());
        match outcome {
            AttemptOutcome::Terminal(e) => assert_eq!(e, "fatal"),
            _ => panic!("expected Terminal"),
        }
    }

    #[test]
    fn attempt_outcome_retryable_no_retry_after() {
        let outcome: AttemptOutcome<(), &str> = AttemptOutcome::Retryable {
            error: "err",
            retry_after: None,
        };
        match outcome {
            AttemptOutcome::Retryable { retry_after, .. } => assert!(retry_after.is_none()),
            _ => panic!("expected Retryable"),
        }
    }

    // -- NEW: ConnectorRuntime deep edge cases --------------------------------

    #[test]
    fn runtime_request_context_not_cancelled() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let ctx = runtime.request_context();
        assert!(!ctx.is_cancelled());
        // Request context should have a finite budget
        let budget = ctx.remaining_budget();
        assert!(budget.is_some());
        // Budget should be close to request timeout (120s default)
        assert!(budget.unwrap() <= Duration::from_secs(120));
    }

    #[test]
    fn runtime_custom_timeout_propagates_to_context() {
        let timeout = Duration::from_millis(500);
        let runtime =
            ConnectorRuntime::new(ConnectorRuntimeConfig::default().with_request_timeout(timeout));
        let ctx = runtime.request_context();
        let budget = ctx.remaining_budget().unwrap();
        // Budget should be at most the configured timeout
        assert!(budget <= timeout);
    }

    #[test]
    fn runtime_background_context_has_no_deadline() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let bg = runtime.background_context();
        assert!(bg.remaining_budget().is_none());
    }

    #[test]
    fn runtime_shutdown_cancels_all_background_children() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let bg1 = runtime.background_context();
        let bg2 = runtime.background_context();
        let bg3 = runtime.background_context();
        assert!(!bg1.is_cancelled());
        assert!(!bg2.is_cancelled());
        assert!(!bg3.is_cancelled());
        runtime.shutdown();
        assert!(bg1.is_cancelled());
        assert!(bg2.is_cancelled());
        assert!(bg3.is_cancelled());
    }

    #[test]
    fn runtime_request_context_independent_of_shutdown() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        // Request contexts created before shutdown are independent
        let ctx_before = runtime.request_context();
        assert!(!ctx_before.is_cancelled());
        runtime.shutdown();
        // Request context created before shutdown is NOT cancelled
        // (it has its own deadline, not tied to background)
        assert!(!ctx_before.is_cancelled());
    }

    #[test]
    fn runtime_with_zero_request_timeout() {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::ZERO),
        );
        assert_eq!(runtime.request_timeout(), Duration::ZERO);
        let ctx = runtime.request_context();
        // Zero-duration context should still be valid
        assert!(ctx.remaining_budget().is_some());
    }

    #[test]
    fn runtime_with_large_timeout() {
        let timeout = Duration::from_secs(86_400); // 24 hours
        let runtime =
            ConnectorRuntime::new(ConnectorRuntimeConfig::default().with_request_timeout(timeout));
        assert_eq!(runtime.request_timeout(), timeout);
    }

    #[test]
    fn runtime_config_clone_preserves_values() {
        let config = ConnectorRuntimeConfig::default()
            .with_request_timeout(Duration::from_secs(42))
            .with_shutdown_timeout(Duration::from_secs(7));
        let cloned = config.clone();
        // Use original after clone to avoid redundant_clone
        assert_eq!(config.request_timeout, Duration::from_secs(42));
        assert_eq!(cloned.shutdown_timeout, Duration::from_secs(7));
    }

    #[test]
    fn runtime_clone_shares_background_ctx() {
        let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
        let cloned = runtime.clone();
        // Both should report same shutdown state
        assert!(!runtime.is_shutting_down());
        assert!(!cloned.is_shutting_down());
        // Shutting down original propagates to clone
        runtime.shutdown();
        assert!(cloned.is_shutting_down());
    }

    // -- NEW: HttpRetryConfig edge cases --------------------------------------

    #[test]
    fn http_retry_config_zero_retries_policy() {
        let config = HttpRetryConfig {
            max_retries: 0,
            initial_delay_ms: 100,
            max_delay_ms: 1000,
            jitter_enabled: false,
        };
        let policy = config.to_retry_policy();
        assert_eq!(policy.max_attempts, Some(1));
        // With 0 retries, the initial request still runs but no retry delay is produced.
        assert!(policy.next_delay(0, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn http_retry_config_max_retries_one() {
        let config = HttpRetryConfig {
            max_retries: 1,
            initial_delay_ms: 200,
            max_delay_ms: 5000,
            jitter_enabled: false,
        };
        let policy = config.to_retry_policy();
        assert_eq!(policy.max_attempts, Some(2));
        assert!(policy.next_delay(0, RetryDecision::Backoff, None).is_some());
        assert!(policy.next_delay(1, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn http_retry_config_serde_partial_override() {
        let json = r#"{"max_retries": 10}"#;
        let config: HttpRetryConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_retries, 10);
        // Other fields should use defaults
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 30_000);
        assert!(config.jitter_enabled);
    }

    #[test]
    fn http_retry_config_serde_jitter_false() {
        let json = r#"{"jitter_enabled": false}"#;
        let config: HttpRetryConfig = serde_json::from_str(json).unwrap();
        assert!(!config.jitter_enabled);
        // Other fields should use defaults
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn http_retry_config_serde_roundtrip_all_fields() {
        let config = HttpRetryConfig {
            max_retries: 11,
            initial_delay_ms: 123,
            max_delay_ms: 45_678,
            jitter_enabled: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: HttpRetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_retries, config.max_retries);
        assert_eq!(back.initial_delay_ms, config.initial_delay_ms);
        assert_eq!(back.max_delay_ms, config.max_delay_ms);
        assert_eq!(back.jitter_enabled, config.jitter_enabled);
    }

    #[test]
    fn http_retry_config_large_values() {
        let config = HttpRetryConfig {
            max_retries: u32::MAX,
            initial_delay_ms: u64::MAX,
            max_delay_ms: u64::MAX,
            jitter_enabled: true,
        };
        let policy = config.to_retry_policy();
        assert!(policy.max_attempts.is_none());
        assert_eq!(policy.base_backoff_ms, u64::MAX);
    }

    #[test]
    fn http_retry_config_policy_jitter_flag_propagates() {
        let config_with = HttpRetryConfig {
            jitter_enabled: true,
            ..HttpRetryConfig::default()
        };
        let config_without = HttpRetryConfig {
            jitter_enabled: false,
            ..HttpRetryConfig::default()
        };
        assert!(config_with.to_retry_policy().jitter_enabled);
        assert!(!config_without.to_retry_policy().jitter_enabled);
    }

    // -- NEW: classify_http_status comprehensive edge cases -------------------

    #[test]
    fn classify_all_5xx_range() {
        for status in 500..=599 {
            let decision = classify_http_status(status, None);
            assert!(
                decision.is_retryable(),
                "status {status} should be retryable"
            );
        }
    }

    #[test]
    fn classify_non_retryable_4xx_codes() {
        for status in [400, 401, 402, 403, 404, 405, 406, 409, 410, 422] {
            let decision = classify_http_status(status, None);
            assert_eq!(
                decision,
                RetryDecision::Terminal,
                "status {status} should be terminal"
            );
        }
    }

    #[test]
    fn classify_429_default_retry_after_is_30s() {
        let decision = classify_http_status(429, None);
        assert_eq!(decision, RetryDecision::After(Duration::from_secs(30)));
    }

    #[test]
    fn classify_429_with_zero_retry_after() {
        let decision = classify_http_status(429, Some(Duration::ZERO));
        assert_eq!(decision, RetryDecision::After(Duration::ZERO));
    }

    #[test]
    fn classify_200_range_terminal() {
        for status in [200, 201, 204, 301, 302, 304] {
            assert_eq!(
                classify_http_status(status, None),
                RetryDecision::Terminal,
                "status {status} should be terminal"
            );
        }
    }

    // -- NEW: map_async_to_fcp_error comprehensive ----------------------------

    #[test]
    fn map_timeout_zero_ms() {
        let err = AsyncError::Timeout { timeout_ms: 0 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External {
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(status_code, Some(408));
                assert!(!retryable);
                assert!(message.contains('0'));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_timeout_large_ms() {
        let err = AsyncError::Timeout {
            timeout_ms: 999_999,
        };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { message, .. } => {
                assert!(message.contains("999999"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_has_no_status_code() {
        let err = AsyncError::Cancelled;
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { status_code, .. } => {
                assert!(status_code.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_cancelled_service_is_runtime() {
        let err = AsyncError::Cancelled;
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { service, .. } => {
                assert_eq!(service, "runtime");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_channel_full_to_fcp_internal() {
        let err = AsyncError::ChannelFull;
        let fcp_err = map_async_to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }

    #[test]
    fn map_join_error_to_fcp_internal() {
        let err = AsyncError::Join {
            message: "task panicked".into(),
        };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::Internal { message } => {
                assert!(message.contains("task panicked"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn map_timeout_not_retryable() {
        let err = AsyncError::Timeout { timeout_ms: 5000 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { retryable, .. } => {
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn map_timeout_has_no_retry_after() {
        let err = AsyncError::Timeout { timeout_ms: 5000 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { retry_after, .. } => {
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // -- NEW: RetryLoop advanced tests ----------------------------------------

    #[test]
    fn retry_loop_single_attempt_policy() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(1))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt == 0 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("first fail".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Success("should not reach")
                    }
                })
                .await;

            // Only 1 attempt allowed, so retry is not permitted
            assert!(result.is_err());
        })
        .expect("runtime should execute single-attempt test");
    }

    #[test]
    fn retry_loop_terminal_on_second_attempt() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(5))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt == 0 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("transient".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Terminal(TestError::Fatal("permanent".into()))
                    }
                })
                .await;

            match result.unwrap_err() {
                TestError::Fatal(msg) => assert_eq!(msg, "permanent"),
                other => panic!("expected Fatal, got {other:?}"),
            }
        })
        .expect("runtime should execute terminal-on-second test");
    }

    #[test]
    fn retry_loop_success_on_last_attempt() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(3))
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt < 2 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("not yet".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Success("made it")
                    }
                })
                .await;

            assert_eq!(result.unwrap(), "made it");
        })
        .expect("runtime should execute success-on-last test");
    }

    #[test]
    fn retry_loop_unlimited_attempts_succeeds() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
            let policy = RetryPolicy::new()
                .with_max_attempts(None)
                .with_base_backoff_ms(10)
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |attempt| async move {
                    if attempt < 5 {
                        AttemptOutcome::Retryable {
                            error: TestError::Transient("keep going".into()),
                            retry_after: None,
                        }
                    } else {
                        AttemptOutcome::Success("unlimited works")
                    }
                })
                .await;

            assert_eq!(result.unwrap(), "unlimited works");
        })
        .expect("runtime should execute unlimited-attempts test");
    }

    #[test]
    fn retry_loop_unlimited_attempts_stop_at_u32_max_without_repeating_attempt() {
        use std::sync::{Arc, Mutex};

        fcp_async_core::runtime::block_on_sync(async {
            // Background context (no deadline) — this test validates that the
            // retry loop stops at the u32::MAX attempt ceiling, not deadline
            // enforcement. A request-scoped deadline races with tokio's 0ms
            // sleep and causes spurious DeadlineExceeded failures.
            let ctx = ExecutionContext::background();
            let policy = RetryPolicy::new()
                .with_max_attempts(None)
                .with_base_backoff_ms(0)
                .with_jitter_enabled(false);
            let seen_attempts = Arc::new(Mutex::new(Vec::new()));

            let result: Result<&str, TestError> =
                RetryLoop::execute_from_attempt(&ctx, &policy, u32::MAX - 1, {
                    let seen_attempts = Arc::clone(&seen_attempts);
                    move |attempt| {
                        let seen_attempts = Arc::clone(&seen_attempts);
                        async move {
                            seen_attempts.lock().unwrap().push(attempt);
                            AttemptOutcome::Retryable {
                                error: TestError::Transient(format!("attempt {attempt}")),
                                retry_after: None,
                            }
                        }
                    }
                })
                .await;

            match result.unwrap_err() {
                TestError::Transient(message) => {
                    assert!(message.contains(&u32::MAX.to_string()));
                }
                other => panic!("expected Transient, got {other:?}"),
            }
            assert_eq!(
                seen_attempts.lock().unwrap().as_slice(),
                &[u32::MAX - 1, u32::MAX]
            );
        })
        .expect("runtime should stop unlimited retries at the u32 attempt ceiling");
    }

    // -- NEW: ConnectorErrorMapping trait coverage -----------------------------

    #[test]
    fn test_error_from_async_protocol_io() {
        let err = TestError::from_async_error(AsyncError::ProtocolIo {
            message: "socket reset".into(),
        });
        match err {
            TestError::Fatal(msg) => assert!(msg.contains("socket reset")),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn test_error_from_async_channel_full() {
        let err = TestError::from_async_error(AsyncError::ChannelFull);
        assert!(matches!(err, TestError::Fatal(_)));
    }

    #[test]
    fn test_error_from_async_join() {
        let err = TestError::from_async_error(AsyncError::Join {
            message: "task panicked".into(),
        });
        match err {
            TestError::Fatal(msg) => assert!(msg.contains("task panicked")),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn test_error_to_fcp_transient_maps_to_internal() {
        let err = TestError::Transient("network flap".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.contains("network flap"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn test_error_to_fcp_deadline_maps_to_external() {
        let err = TestError::DeadlineExceeded("10s".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { status_code, .. } => {
                assert_eq!(status_code, Some(408));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn test_error_to_fcp_cancelled_maps_to_external() {
        let err = TestError::Cancelled;
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                message, retryable, ..
            } => {
                assert!(message.contains("cancelled"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn test_error_debug_format() {
        let err = TestError::Transient("test msg".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Transient"));
        assert!(debug.contains("test msg"));
    }

    #[test]
    fn test_error_display_cancelled() {
        let err = TestError::Cancelled;
        assert_eq!(err.to_string(), "cancelled");
    }

    #[test]
    fn test_error_display_deadline() {
        let err = TestError::DeadlineExceeded("timeout after 5s".into());
        let display = err.to_string();
        assert!(display.contains("deadline"));
        assert!(display.contains("timeout after 5s"));
    }

    // -- NEW: AttemptOutcome additional coverage --------------------------------

    #[test]
    fn attempt_outcome_success_with_complex_type() {
        let outcome: AttemptOutcome<Vec<u8>, String> = AttemptOutcome::Success(vec![1, 2, 3]);
        match outcome {
            AttemptOutcome::Success(v) => assert_eq!(v.len(), 3),
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn attempt_outcome_retryable_with_large_retry_after() {
        let outcome: AttemptOutcome<(), String> = AttemptOutcome::Retryable {
            error: "overloaded".into(),
            retry_after: Some(Duration::from_secs(3600)),
        };
        match outcome {
            AttemptOutcome::Retryable { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(3600)));
            }
            _ => panic!("expected Retryable"),
        }
    }

    #[test]
    fn attempt_outcome_retryable_zero_retry_after() {
        let outcome: AttemptOutcome<(), String> = AttemptOutcome::Retryable {
            error: "retry now".into(),
            retry_after: Some(Duration::ZERO),
        };
        match outcome {
            AttemptOutcome::Retryable { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::ZERO));
            }
            _ => panic!("expected Retryable"),
        }
    }

    #[test]
    fn attempt_outcome_terminal_with_structured_error() {
        #[derive(Debug, PartialEq)]
        struct DetailedError {
            code: u16,
            msg: String,
        }
        let outcome: AttemptOutcome<(), DetailedError> = AttemptOutcome::Terminal(DetailedError {
            code: 403,
            msg: "forbidden".into(),
        });
        match outcome {
            AttemptOutcome::Terminal(e) => {
                assert_eq!(e.code, 403);
                assert_eq!(e.msg, "forbidden");
            }
            _ => panic!("expected Terminal"),
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
