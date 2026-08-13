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
//! - [`RetryLoop`]: Generic retry executor using `ExecutionContext` for
//!   deadline-aware exponential backoff with jitter.
//! - [`crate::ConnectorErrorMapping`]: Trait for consistent `AsyncError` →
//!   connector error conversion.
//! - [`HttpRetryConfig`]: Serializable retry configuration shared by HTTP connectors.
//! - [`classify_http_status`]: Canonical HTTP status → retry decision mapping.
//! - [`map_async_to_fcp_error`]: Canonical `AsyncError` → `FcpError` mapping.
//!
//! # Migration Checklist
//!
//! Every connector migration MUST satisfy all items below. Use this as
//! the acceptance gate before closing a connector migration bead.
//!
//! Runtime bootstrap helpers graduated to [`crate::runtime::ConnectorRuntime`],
//! and the connector error-mapping contract graduated to
//! [`crate::error_mapping`]. Connector authors should import
//! [`crate::ConnectorErrorMapping`] from the SDK root.
//!
//! ## Retry & Error Mapping
//!
//! - [ ] Remove hand-rolled retry loops; replace with [`RetryLoop::execute()`].
//! - [ ] Implement [`crate::ConnectorErrorMapping`] on the connector's error type.
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
//! use fcp_sdk::{ConnectorErrorMapping, ConnectorRuntime};
//! use fcp_sdk::migration::{
//!     AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
//!     map_async_to_fcp_error,
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
//!                 status_code: Some(504),
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

use std::time::Duration;

use fcp_async_core::http::HttpClientError;
use fcp_async_core::{AsyncError, ExecutionContext};
#[cfg(feature = "connector-http")]
pub use fcp_manifest::{
    HOST_EGRESS_WIRE_MAX_FRAME_BYTES, HOST_EGRESS_WIRE_SCHEMA_VERSION, HostEgressHttpRequest,
    HostEgressHttpResponse, HostEgressTcpRequest, HostEgressTcpResponse, HostEgressWireError,
    HostEgressWireRequest, HostEgressWireRequestPayload, HostEgressWireResponse,
    HostEgressWireResponseBody, HostEgressWireRoute,
};
#[cfg(feature = "connector-http")]
use serde::Serialize;
use tracing::{debug, warn};

use crate::FcpError;
use crate::error_mapping::ConnectorErrorMapping;
pub use crate::error_mapping::map_async_to_fcp_error;
use crate::retry::{RetryDecision, RetryPolicy};

#[cfg(feature = "connector-http")]
use std::{
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[cfg(all(feature = "connector-http", target_os = "linux"))]
use std::sync::Arc;

#[cfg(all(feature = "connector-http", target_os = "linux"))]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(all(feature = "connector-http", target_os = "linux"))]
use fcp_async_core::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

#[cfg(all(test, not(feature = "connector-http")))]
use std::fmt;

/// Connector-side client for the host egress proxy.
#[cfg(feature = "connector-http")]
#[derive(Clone)]
pub struct HostEgressProxyClient {
    base_url: reqwest::Url,
    client: reqwest::Client,
    max_outer_envelope_bytes: usize,
    transport: HostEgressTransport,
    auth_token: Option<String>,
    socket_path: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    inherited_channel: Option<Arc<InheritedFdChannel>>,
}

/// Transport selected for a host-egress proxy client.
#[cfg(feature = "connector-http")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEgressTransport {
    /// Host-launch-injected Unix-domain-socket transport.
    UnixDomainSocket,
    /// Host-launch-injected connected Unix-domain-socket file descriptor.
    InheritedFd,
    /// Explicit compatibility transport for tests and legacy callers.
    LegacyLoopback,
}

#[cfg(feature = "connector-http")]
impl fmt::Debug for HostEgressProxyClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let auth_token = self.auth_token.as_ref().map(|_| "[redacted]");
        let socket_path = self.socket_path.as_ref().map(|_| "[redacted]");
        #[cfg(target_os = "linux")]
        let inherited_channel = self.inherited_channel.as_ref().map(|_| "[configured]");
        let mut debug = formatter.debug_struct("HostEgressProxyClient");
        debug
            .field("base_url", &"[redacted]")
            .field("client", &"[configured]")
            .field("transport", &self.transport)
            .field("max_outer_envelope_bytes", &self.max_outer_envelope_bytes)
            .field("auth_token", &auth_token)
            .field("socket_path", &socket_path);
        #[cfg(target_os = "linux")]
        {
            debug.field("inherited_channel", &inherited_channel);
        }
        debug.finish()
    }
}

/// Connector-side limits for the host-egress proxy transport.
#[cfg(feature = "connector-http")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEgressProxyLimits {
    /// Total wait budget for proxy request upload plus response download.
    pub request_timeout: Duration,
    /// Maximum JSON envelope received from the proxy. This is intentionally
    /// larger than the inner provider-body limit because base64 and JSON add
    /// overhead around the provider payload.
    pub max_outer_envelope_bytes: usize,
}

#[cfg(feature = "connector-http")]
impl Default for HostEgressProxyLimits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            max_outer_envelope_bytes: HOST_EGRESS_WIRE_MAX_FRAME_BYTES,
        }
    }
}

/// Safe configuration errors for [`HostEgressProxyClient`].
#[cfg(feature = "connector-http")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostEgressProxyConfigError {
    /// Proxy URL was malformed or used a forbidden URL component.
    #[error("invalid host egress proxy endpoint")]
    InvalidEndpoint,
    /// Proxy endpoint was not a literal loopback IP authority.
    #[error("host egress proxy endpoint must use a literal loopback IP")]
    NonLoopbackEndpoint,
    /// Proxy transport limits were zero or otherwise unusable.
    #[error("invalid host egress proxy limits")]
    InvalidLimits,
    /// The bounded reqwest client could not be constructed.
    #[error("host egress proxy client configuration failed")]
    ClientConfiguration,
    /// The launch transport selector was missing or invalid.
    #[error("invalid host egress transport selection")]
    InvalidTransport,
    /// The launch selector requested a transport unsupported by this target.
    #[error("host egress transport is unsupported on this platform")]
    UnsupportedPlatform,
    /// The launch environment attempted to configure two transports.
    #[error("host egress transport configuration conflicts")]
    TransportConflict,
    /// The launch environment did not provide a socket path.
    #[error("host egress socket path is required")]
    MissingSocket,
    /// The socket path was not safe for host-mediated transport.
    #[error("invalid host egress socket path")]
    InvalidSocketPath,
    /// The configured socket path does not exist.
    #[error("host egress socket was not found")]
    SocketNotFound,
    /// The socket path could not be inspected safely.
    #[error("host egress socket could not be inspected")]
    SocketUnavailable,
    /// The configured path is not a Unix socket.
    #[error("host egress path is not a Unix socket")]
    SocketNotSocket,
    /// The configured socket or one of its path components is a symlink.
    #[error("host egress socket path must not contain symlinks")]
    SocketSymlink,
    /// The socket or its parent directory has unsafe permissions.
    #[error("host egress socket permissions are unsafe")]
    SocketPermissions,
    /// The launch environment did not provide an auth token.
    #[error("host egress auth token is required")]
    MissingAuthToken,
    /// The auth token was empty, malformed, or exceeded the bound.
    #[error("invalid host egress auth token")]
    InvalidAuthToken,
    /// The inherited channel file descriptor was not provided.
    #[error("host egress inherited channel file descriptor is required")]
    MissingFd,
    /// The inherited channel file descriptor value was malformed or unsafe.
    #[error("invalid host egress inherited channel file descriptor")]
    InvalidFd,
    /// The inherited channel file descriptor could not be claimed.
    #[error("host egress inherited channel is unavailable")]
    InheritedFdUnavailable,
    /// The inherited descriptor was not a connected Unix stream.
    #[error("host egress inherited channel is not a connected Unix stream")]
    InheritedFdNotUnixStream,
}

#[cfg(feature = "connector-http")]
impl HostEgressProxyClient {
    /// Construct a bounded legacy loopback client using conservative defaults.
    ///
    /// This is retained for existing callers and tests only. Production host
    /// launches must use [`Self::from_unix_socket`] instead.
    ///
    /// # Errors
    /// Returns a redaction-safe error when the endpoint is not an HTTP(S)
    /// literal loopback origin or the client cannot be configured.
    pub fn new(base_url: &str) -> Result<Self, HostEgressProxyConfigError> {
        Self::legacy_loopback_with_limits(base_url, HostEgressProxyLimits::default())
    }

    /// Construct a bounded legacy loopback client with explicit limits.
    ///
    /// This compatibility API is intentionally URL-based and must not be used
    /// by the host-launch production path.
    ///
    /// # Errors
    /// Returns a redaction-safe error for invalid endpoints or limits.
    pub fn with_limits(
        base_url: &str,
        limits: HostEgressProxyLimits,
    ) -> Result<Self, HostEgressProxyConfigError> {
        Self::legacy_loopback_with_limits(base_url, limits)
    }

    /// Construct a production client over a validated Unix-domain socket.
    ///
    /// Requests use reqwest's native `ClientBuilder::unix_socket` transport,
    /// a fixed internal origin, and fixed `/rpc/egress/http` and
    /// `/rpc/egress/tcp` routes. The socket path and auth token are never
    /// included in this client's debug representation or returned errors.
    ///
    /// # Errors
    /// Returns a redaction-safe error when the socket, token, limits, or
    /// platform transport are invalid.
    pub fn from_unix_socket(
        socket_path: PathBuf,
        auth_token: &str,
        limits: HostEgressProxyLimits,
    ) -> Result<Self, HostEgressProxyConfigError> {
        if limits.request_timeout.is_zero() || limits.max_outer_envelope_bytes == 0 {
            return Err(HostEgressProxyConfigError::InvalidLimits);
        }
        let auth_token = validate_host_egress_auth_token(auth_token)?;

        #[cfg(not(target_os = "linux"))]
        {
            let _ = socket_path;
            return Err(HostEgressProxyConfigError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            validate_unix_socket_path(&socket_path)?;
            let base_url = fixed_unix_socket_origin()?;
            let client = reqwest::Client::builder()
                .timeout(limits.request_timeout)
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .unix_socket(socket_path.clone())
                .build()
                .map_err(|_| HostEgressProxyConfigError::ClientConfiguration)?;
            Ok(Self {
                base_url,
                client,
                max_outer_envelope_bytes: limits.max_outer_envelope_bytes,
                transport: HostEgressTransport::UnixDomainSocket,
                auth_token: Some(auth_token),
                socket_path: Some(socket_path),
                #[cfg(target_os = "linux")]
                inherited_channel: None,
            })
        }
    }

    /// Construct the production client from one host-owned connected Unix
    /// stream file descriptor. This constructor is crate-internal so a
    /// connector cannot turn arbitrary model input into an FD capability;
    /// production callers must use the reserved host-launch environment
    /// loader.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_inherited_fd(
        fd: i32,
        auth_token: &str,
        limits: HostEgressProxyLimits,
    ) -> Result<Self, HostEgressProxyConfigError> {
        if limits.request_timeout.is_zero() || limits.max_outer_envelope_bytes == 0 {
            return Err(HostEgressProxyConfigError::InvalidLimits);
        }
        let auth_token = validate_host_egress_auth_token(auth_token)?;
        let stream = claim_inherited_unix_stream(fd)?;
        let base_url = fixed_unix_socket_origin()?;
        let client = reqwest::Client::builder()
            .timeout(limits.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| HostEgressProxyConfigError::ClientConfiguration)?;
        let inherited_channel = Arc::new(InheritedFdChannel::new(
            stream,
            auth_token.clone(),
            limits.request_timeout,
            limits.max_outer_envelope_bytes,
        ));
        Ok(Self {
            base_url,
            client,
            max_outer_envelope_bytes: limits.max_outer_envelope_bytes,
            transport: HostEgressTransport::InheritedFd,
            auth_token: Some(auth_token),
            socket_path: None,
            inherited_channel: Some(inherited_channel),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn from_inherited_fd(
        _fd: i32,
        _auth_token: &str,
        _limits: HostEgressProxyLimits,
    ) -> Result<Self, HostEgressProxyConfigError> {
        Err(HostEgressProxyConfigError::UnsupportedPlatform)
    }

    /// Construct an explicitly selected legacy loopback client.
    ///
    /// This is the only URL-based constructor. It accepts literal loopback
    /// authorities only and is intended for compatibility and tests.
    ///
    /// # Errors
    /// Returns a redaction-safe error when the endpoint or limits are invalid,
    /// or the bounded client cannot be constructed.
    pub fn legacy_loopback_with_limits(
        base_url: &str,
        limits: HostEgressProxyLimits,
    ) -> Result<Self, HostEgressProxyConfigError> {
        if limits.request_timeout.is_zero() || limits.max_outer_envelope_bytes == 0 {
            return Err(HostEgressProxyConfigError::InvalidLimits);
        }
        let base_url = validate_host_egress_proxy_endpoint(base_url)?;
        let client = reqwest::Client::builder()
            .timeout(limits.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| HostEgressProxyConfigError::ClientConfiguration)?;
        Ok(Self {
            base_url,
            client,
            max_outer_envelope_bytes: limits.max_outer_envelope_bytes,
            transport: HostEgressTransport::LegacyLoopback,
            auth_token: None,
            socket_path: None,
            #[cfg(target_os = "linux")]
            inherited_channel: None,
        })
    }

    /// Return the selected transport kind without exposing endpoint details.
    #[must_use]
    pub const fn transport(&self) -> HostEgressTransport {
        self.transport
    }

    /// Absolute host RPC endpoint for mediated HTTP egress.
    #[must_use]
    pub fn http_endpoint(&self) -> String {
        format!("{}rpc/egress/http", self.base_url)
    }

    /// Absolute host RPC endpoint for mediated TCP egress.
    #[must_use]
    pub fn tcp_endpoint(&self) -> String {
        format!("{}rpc/egress/tcp", self.base_url)
    }

    /// Send an HTTP request through the host egress proxy.
    ///
    /// # Errors
    ///
    /// Returns [`HostEgressProxyError`] when transport fails, the host rejects
    /// the status code, or the response body does not match the contract.
    pub async fn http(
        &self,
        request: &HostEgressHttpRequest,
    ) -> Result<HostEgressHttpResponse, HostEgressProxyError> {
        #[cfg(target_os = "linux")]
        if let Some(channel) = self.inherited_channel.as_ref() {
            let response = channel
                .exchange(
                    HostEgressWireRoute::Http,
                    HostEgressWireRequestPayload::Http(request.clone()),
                )
                .await?;
            return decode_inherited_http_response(request, response);
        }
        let request_body = serialize_bounded_proxy_request(request)?;
        let response = self
            .apply_auth(
                self.client
                    .post(self.http_endpoint())
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(request_body),
            )
            .send()
            .await
            .map_err(HostEgressProxyError::Transport)?;
        let status = response.status();
        let body = read_bounded_proxy_body(response, self.max_outer_envelope_bytes).await?;
        if !status.is_success() {
            return Err(HostEgressProxyError::Rejected {
                status: status.as_u16(),
                body: redact_http_host_egress_rejection_body(
                    request,
                    self.redact_transport_sensitive(String::from_utf8_lossy(&body).into_owned()),
                ),
            });
        }
        serde_json::from_slice(&body).map_err(|_| HostEgressProxyError::MalformedEnvelope)
    }

    /// Send a bounded TCP exchange through the host egress proxy.
    ///
    /// # Errors
    ///
    /// Returns [`HostEgressProxyError`] when transport fails, the host rejects
    /// the status code, or the response body does not match the contract.
    pub async fn tcp(
        &self,
        request: &HostEgressTcpRequest,
    ) -> Result<HostEgressTcpResponse, HostEgressProxyError> {
        #[cfg(target_os = "linux")]
        if let Some(channel) = self.inherited_channel.as_ref() {
            let response = channel
                .exchange(
                    HostEgressWireRoute::Tcp,
                    HostEgressWireRequestPayload::Tcp(request.clone()),
                )
                .await?;
            return decode_inherited_tcp_response(request, response);
        }
        let request_body = serialize_bounded_proxy_request(request)?;
        let response = self
            .apply_auth(
                self.client
                    .post(self.tcp_endpoint())
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(request_body),
            )
            .send()
            .await
            .map_err(HostEgressProxyError::Transport)?;
        let status = response.status();
        let body = read_bounded_proxy_body(response, self.max_outer_envelope_bytes).await?;
        if !status.is_success() {
            return Err(HostEgressProxyError::Rejected {
                status: status.as_u16(),
                body: redact_tcp_host_egress_rejection_body(
                    request,
                    self.redact_transport_sensitive(String::from_utf8_lossy(&body).into_owned()),
                ),
            });
        }
        serde_json::from_slice(&body).map_err(|_| HostEgressProxyError::MalformedEnvelope)
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth_token.as_deref() {
            Some(token) => request.header(HOST_EGRESS_AUTH_HEADER, token),
            None => request,
        }
    }

    fn redact_transport_sensitive(&self, mut body: String) -> String {
        if let Some(token) = self.auth_token.as_deref() {
            redact_exact_sensitive_fragment(&mut body, token);
        }
        if let Some(path) = self.socket_path.as_deref() {
            let path = path.to_string_lossy();
            redact_exact_sensitive_fragment(&mut body, &path);
        }
        body
    }
}

#[cfg(feature = "connector-http")]
const HOST_EGRESS_AUTH_HEADER: &str = "X-FCP-Host-Egress-Auth";

#[cfg(feature = "connector-http")]
const HOST_EGRESS_UDS_ORIGIN: &str = "http://fcp-host-egress.invalid/";

#[cfg(feature = "connector-http")]
const MAX_HOST_EGRESS_AUTH_TOKEN_BYTES: usize = 4096;

#[cfg(feature = "connector-http")]
const MAX_HOST_EGRESS_REQUEST_ENVELOPE_BYTES: usize = HOST_EGRESS_WIRE_MAX_FRAME_BYTES;

#[cfg(all(feature = "connector-http", target_os = "linux"))]
struct InheritedFdChannel {
    state: fcp_async_core::sync::Mutex<InheritedFdChannelState>,
    auth_token: String,
    next_request_id: AtomicU64,
    poisoned: std::sync::atomic::AtomicBool,
    request_timeout: Duration,
    max_envelope_bytes: usize,
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
struct InheritedFdChannelState {
    stream: Option<UnixStream>,
    retained_read_buffer: Vec<u8>,
    poisoned: bool,
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
struct InheritedFdExchangeGuard<'a> {
    channel: &'a InheritedFdChannel,
    validated_response: bool,
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
impl Drop for InheritedFdExchangeGuard<'_> {
    fn drop(&mut self) {
        if !self.validated_response {
            self.channel.poisoned.store(true, Ordering::Release);
            if let Ok(mut state) = self.channel.state.try_lock() {
                state.poisoned = true;
                let _ = state.stream.take();
                state.retained_read_buffer.clear();
            }
        }
    }
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
impl InheritedFdChannel {
    fn new(
        stream: UnixStream,
        auth_token: String,
        request_timeout: Duration,
        max_envelope_bytes: usize,
    ) -> Self {
        Self {
            state: fcp_async_core::sync::Mutex::new(InheritedFdChannelState {
                stream: Some(stream),
                retained_read_buffer: Vec::new(),
                poisoned: false,
            }),
            auth_token,
            next_request_id: AtomicU64::new(1),
            poisoned: std::sync::atomic::AtomicBool::new(false),
            request_timeout,
            max_envelope_bytes,
        }
    }

    async fn exchange(
        &self,
        route: HostEgressWireRoute,
        payload: HostEgressWireRequestPayload,
    ) -> Result<HostEgressWireResponse, HostEgressProxyError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        if request_id == 0 {
            return Err(HostEgressProxyError::InheritedChannel);
        }
        let request = HostEgressWireRequest {
            schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
            request_id,
            auth_token: self.auth_token.clone(),
            route,
            payload,
        };
        let frame = serialize_bounded_wire_frame(&request, MAX_HOST_EGRESS_REQUEST_ENVELOPE_BYTES)?;

        let mut state = self.state.lock().await;
        if self.poisoned.load(Ordering::Acquire) || state.poisoned || state.stream.is_none() {
            return Err(HostEgressProxyError::InheritedChannel);
        }

        // Arm cancellation poisoning only after this caller owns the
        // serialization lock. Waiting for the lock is not an in-flight wire
        // exchange and must not poison a healthy channel if that wait is
        // cancelled by the surrounding runtime.
        let mut exchange_guard = InheritedFdExchangeGuard {
            channel: self,
            validated_response: false,
        };

        let InheritedFdChannelState {
            stream,
            retained_read_buffer,
            ..
        } = &mut *state;
        let operation = async {
            let stream = stream.as_mut().ok_or(())?;
            stream.write_all(&frame).await.map_err(|_| ())?;
            let response =
                read_bounded_wire_frame(stream, retained_read_buffer, self.max_envelope_bytes)
                    .await
                    .map_err(|_| ())?;
            let response =
                serde_json::from_slice::<HostEgressWireResponse>(&response).map_err(|_| ())?;
            validate_inherited_wire_response(response, request_id, route).map_err(|_| ())
        };

        match fcp_async_core::time::timeout(self.request_timeout, operation).await {
            Ok(Ok(response)) => {
                exchange_guard.validated_response = true;
                Ok(response)
            }
            Ok(Err(())) | Err(_) => Err(HostEgressProxyError::InheritedChannel),
        }
    }
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
fn serialize_bounded_wire_frame<T: Serialize>(
    value: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, HostEgressProxyError> {
    let mut frame =
        serde_json::to_vec(value).map_err(|_| HostEgressProxyError::MalformedRequestEnvelope)?;
    if frame.len() >= max_bytes {
        return Err(HostEgressProxyError::RequestEnvelopeTooLarge);
    }
    frame.push(b'\n');
    Ok(frame)
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
async fn read_bounded_wire_frame(
    stream: &mut UnixStream,
    retained_read_buffer: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<Vec<u8>, ()> {
    loop {
        if let Some(newline) = retained_read_buffer.iter().position(|byte| *byte == b'\n') {
            let frame_len = newline + 1;
            if frame_len > max_bytes || newline == 0 || retained_read_buffer.len() != frame_len {
                return Err(());
            }
            let mut frame = retained_read_buffer.drain(..frame_len).collect::<Vec<_>>();
            frame.pop();
            if frame.contains(&b'\n') {
                return Err(());
            }
            return Ok(frame);
        }
        if retained_read_buffer.len() >= max_bytes {
            return Err(());
        }
        let remaining = max_bytes - retained_read_buffer.len();
        let mut chunk = [0_u8; 1024];
        let read_len = remaining.min(chunk.len());
        let count = stream.read(&mut chunk[..read_len]).await.map_err(|_| ())?;
        if count == 0 {
            return Err(());
        }
        retained_read_buffer.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
fn validate_inherited_wire_response(
    response: HostEgressWireResponse,
    request_id: u64,
    route: HostEgressWireRoute,
) -> Result<HostEgressWireResponse, ()> {
    if response.schema_version != HOST_EGRESS_WIRE_SCHEMA_VERSION
        || response.request_id != request_id
        || response.route != route
    {
        return Err(());
    }
    if (200..=299).contains(&response.status) {
        if response.error.is_some() {
            return Err(());
        }
        let body_matches = matches!(
            (&route, response.body.as_ref()),
            (
                HostEgressWireRoute::Http,
                Some(HostEgressWireResponseBody::Http(_)),
            ) | (
                HostEgressWireRoute::Tcp,
                Some(HostEgressWireResponseBody::Tcp(_)),
            )
        );
        if !body_matches {
            return Err(());
        }
    } else if response.body.is_some() || response.error.is_none() {
        return Err(());
    }
    Ok(response)
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
fn decode_inherited_http_response(
    request: &HostEgressHttpRequest,
    response: HostEgressWireResponse,
) -> Result<HostEgressHttpResponse, HostEgressProxyError> {
    if !(200..=299).contains(&response.status) {
        return Err(HostEgressProxyError::Rejected {
            status: response.status,
            body: redact_http_host_egress_rejection_body(
                request,
                "host egress request rejected".to_string(),
            ),
        });
    }
    match response.body {
        Some(HostEgressWireResponseBody::Http(body)) => Ok(body),
        _ => Err(HostEgressProxyError::MalformedEnvelope),
    }
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
fn decode_inherited_tcp_response(
    request: &HostEgressTcpRequest,
    response: HostEgressWireResponse,
) -> Result<HostEgressTcpResponse, HostEgressProxyError> {
    if !(200..=299).contains(&response.status) {
        return Err(HostEgressProxyError::Rejected {
            status: response.status,
            body: redact_tcp_host_egress_rejection_body(
                request,
                "host egress request rejected".to_string(),
            ),
        });
    }
    match response.body {
        Some(HostEgressWireResponseBody::Tcp(body)) => Ok(body),
        _ => Err(HostEgressProxyError::MalformedEnvelope),
    }
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
fn claim_inherited_unix_stream(fd: i32) -> Result<UnixStream, HostEgressProxyConfigError> {
    if !(3..=i32::MAX).contains(&fd) {
        return Err(HostEgressProxyConfigError::InvalidFd);
    }
    let stream = fcp_sandbox::claim_inherited_host_egress_channel(fd).map_err(|error| {
        if matches!(error, fcp_sandbox::ProcessGroupError::InvalidSpec) {
            HostEgressProxyConfigError::InheritedFdNotUnixStream
        } else {
            HostEgressProxyConfigError::InheritedFdUnavailable
        }
    })?;
    UnixStream::from_std(stream).map_err(|_| HostEgressProxyConfigError::InheritedFdUnavailable)
}

#[cfg(feature = "connector-http")]
fn fixed_unix_socket_origin() -> Result<reqwest::Url, HostEgressProxyConfigError> {
    reqwest::Url::parse(HOST_EGRESS_UDS_ORIGIN)
        .map_err(|_| HostEgressProxyConfigError::ClientConfiguration)
}

#[cfg(feature = "connector-http")]
fn validate_host_egress_proxy_endpoint(
    endpoint: &str,
) -> Result<reqwest::Url, HostEgressProxyConfigError> {
    let url =
        reqwest::Url::parse(endpoint).map_err(|_| HostEgressProxyConfigError::InvalidEndpoint)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port_or_known_default().is_none()
    {
        return Err(HostEgressProxyConfigError::InvalidEndpoint);
    }
    let host = url
        .host_str()
        .ok_or(HostEgressProxyConfigError::InvalidEndpoint)?;
    let ip = host
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .map_err(|_| HostEgressProxyConfigError::NonLoopbackEndpoint)?;
    if !ip.is_loopback() {
        return Err(HostEgressProxyConfigError::NonLoopbackEndpoint);
    }
    Ok(url)
}

#[cfg(feature = "connector-http")]
fn validate_host_egress_auth_token(token: &str) -> Result<String, HostEgressProxyConfigError> {
    if token.is_empty()
        || token.len() > MAX_HOST_EGRESS_AUTH_TOKEN_BYTES
        || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(HostEgressProxyConfigError::InvalidAuthToken);
    }
    Ok(token.to_owned())
}

#[cfg(feature = "connector-http")]
fn validate_unix_socket_path(path: &Path) -> Result<(), HostEgressProxyConfigError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        return Err(HostEgressProxyConfigError::UnsupportedPlatform);
    }

    #[cfg(target_os = "linux")]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        const UNIX_SOCKET_PATH_MAX: usize = 107;

        if !path.is_absolute()
            || path.as_os_str().is_empty()
            || path.as_os_str().as_bytes().len() > UNIX_SOCKET_PATH_MAX
            || path
                .as_os_str()
                .as_bytes()
                .iter()
                .any(|byte| *byte == 0 || byte.is_ascii_control())
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(HostEgressProxyConfigError::InvalidSocketPath);
        }

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(HostEgressProxyConfigError::InvalidSocketPath)?;

        let mut component_path = PathBuf::from(OsStr::new("/"));
        for component in path.components() {
            let std::path::Component::Normal(part) = component else {
                continue;
            };
            component_path.push(part);
            if std::fs::symlink_metadata(&component_path)
                .map_err(|_| HostEgressProxyConfigError::SocketNotFound)?
                .file_type()
                .is_symlink()
            {
                return Err(HostEgressProxyConfigError::SocketSymlink);
            }
        }

        let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                HostEgressProxyConfigError::SocketNotFound
            } else {
                HostEgressProxyConfigError::SocketUnavailable
            }
        })?;
        if parent_metadata.file_type().is_symlink() {
            return Err(HostEgressProxyConfigError::SocketSymlink);
        }
        if !parent_metadata.is_dir() {
            return Err(HostEgressProxyConfigError::SocketUnavailable);
        }
        if parent_metadata.permissions().mode() & 0o7777 != 0o700 {
            return Err(HostEgressProxyConfigError::SocketPermissions);
        }

        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                HostEgressProxyConfigError::SocketNotFound
            } else {
                HostEgressProxyConfigError::SocketUnavailable
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(HostEgressProxyConfigError::SocketSymlink);
        }
        if !metadata.file_type().is_socket() {
            return Err(HostEgressProxyConfigError::SocketNotSocket);
        }
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(HostEgressProxyConfigError::SocketPermissions);
        }
        Ok(())
    }
}

#[cfg(feature = "connector-http")]
pub(crate) enum HostEgressLaunchValues {
    UnixDomainSocket {
        socket_path: PathBuf,
        auth_token: String,
    },
    InheritedFd {
        fd: i32,
        auth_token: String,
    },
}

#[cfg(feature = "connector-http")]
pub(crate) fn validate_host_egress_launch_values(
    transport: Option<&str>,
    socket_path: Option<&str>,
    auth_token: Option<&str>,
    inherited_fd: Option<&str>,
) -> Result<Option<HostEgressLaunchValues>, HostEgressProxyConfigError> {
    let any_value = transport.is_some()
        || socket_path.is_some()
        || auth_token.is_some()
        || inherited_fd.is_some();
    match transport {
        None if any_value => Err(HostEgressProxyConfigError::InvalidTransport),
        None => Ok(None),
        Some("uds-v1") => {
            if inherited_fd.is_some() {
                return Err(HostEgressProxyConfigError::TransportConflict);
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(HostEgressProxyConfigError::UnsupportedPlatform);
            }
            #[cfg(target_os = "linux")]
            {
                let socket_path = socket_path.ok_or(HostEgressProxyConfigError::MissingSocket)?;
                let auth_token = auth_token.ok_or(HostEgressProxyConfigError::MissingAuthToken)?;
                let auth_token = validate_host_egress_auth_token(auth_token)?;
                let socket_path = PathBuf::from(socket_path);
                validate_unix_socket_path(&socket_path)?;
                Ok(Some(HostEgressLaunchValues::UnixDomainSocket {
                    socket_path,
                    auth_token,
                }))
            }
        }
        Some("inherited-fd-v1") => {
            if socket_path.is_some() {
                return Err(HostEgressProxyConfigError::TransportConflict);
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(HostEgressProxyConfigError::UnsupportedPlatform);
            }
            #[cfg(target_os = "linux")]
            {
                let inherited_fd = inherited_fd.ok_or(HostEgressProxyConfigError::MissingFd)?;
                let auth_token = auth_token.ok_or(HostEgressProxyConfigError::MissingAuthToken)?;
                let auth_token = validate_host_egress_auth_token(auth_token)?;
                let fd = parse_inherited_fd(inherited_fd)?;
                Ok(Some(HostEgressLaunchValues::InheritedFd { fd, auth_token }))
            }
        }
        Some(_) => Err(HostEgressProxyConfigError::InvalidTransport),
    }
}

#[cfg(all(feature = "connector-http", target_os = "linux"))]
fn parse_inherited_fd(value: &str) -> Result<i32, HostEgressProxyConfigError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| HostEgressProxyConfigError::InvalidFd)?;
    if !(3..=i32::MAX as u64).contains(&parsed) {
        return Err(HostEgressProxyConfigError::InvalidFd);
    }
    i32::try_from(parsed).map_err(|_| HostEgressProxyConfigError::InvalidFd)
}

#[cfg(feature = "connector-http")]
fn redact_exact_sensitive_fragment(redacted: &mut String, fragment: &str) {
    if !fragment.is_empty() && redacted.contains(fragment) {
        *redacted = redacted.replace(fragment, HOST_EGRESS_REDACTION_MARKER);
    }
}

#[cfg(feature = "connector-http")]
async fn read_bounded_proxy_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, HostEgressProxyError> {
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > max_bytes))
    {
        return Err(HostEgressProxyError::EnvelopeTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(HostEgressProxyError::Transport)?
    {
        if chunk.len() > max_bytes.saturating_sub(body.len()) {
            return Err(HostEgressProxyError::EnvelopeTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "connector-http")]
fn serialize_bounded_proxy_request<T: Serialize>(
    request: &T,
) -> Result<Vec<u8>, HostEgressProxyError> {
    let body =
        serde_json::to_vec(request).map_err(|_| HostEgressProxyError::MalformedRequestEnvelope)?;
    if body.len() > MAX_HOST_EGRESS_REQUEST_ENVELOPE_BYTES {
        return Err(HostEgressProxyError::RequestEnvelopeTooLarge);
    }
    Ok(body)
}

#[cfg(feature = "connector-http")]
const HOST_EGRESS_REDACTION_MARKER: &str = "[redacted-host-egress-sensitive]";

#[cfg(feature = "connector-http")]
fn redact_sensitive_fragment(redacted: &mut String, fragment: &str) {
    if !fragment.is_empty() && redacted.contains(fragment) {
        *redacted = redacted.replace(fragment, HOST_EGRESS_REDACTION_MARKER);
    }
}

#[cfg(feature = "connector-http")]
fn redact_request_body_fragment(redacted: &mut String, bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        redact_sensitive_fragment(redacted, text);
    }
}

#[cfg(feature = "connector-http")]
fn redact_header_value_fragments(redacted: &mut String, header_value: &str) {
    redact_sensitive_fragment(redacted, header_value);
    for fragment in header_value.split_ascii_whitespace() {
        redact_sensitive_fragment(redacted, fragment);
    }
}

#[cfg(feature = "connector-http")]
fn redact_http_host_egress_rejection_body(request: &HostEgressHttpRequest, body: String) -> String {
    let mut redacted = body;
    redact_sensitive_fragment(&mut redacted, &request.context.capability_token_cbor_b64);
    redact_sensitive_fragment(&mut redacted, &request.context.resource_uri);
    redact_sensitive_fragment(&mut redacted, &request.url);
    if let Some(credential_id) = request.credential_id.as_deref() {
        redact_sensitive_fragment(&mut redacted, credential_id);
    }
    for header in &request.headers {
        redact_header_value_fragments(&mut redacted, &header.value);
    }
    if let Some(request_body) = request.body.as_ref() {
        let encoded: String = request_body.clone().into();
        redact_sensitive_fragment(&mut redacted, &encoded);
        redact_request_body_fragment(&mut redacted, request_body.as_bytes());
    }
    redacted
}

#[cfg(feature = "connector-http")]
fn redact_tcp_host_egress_rejection_body(request: &HostEgressTcpRequest, body: String) -> String {
    let mut redacted = body;
    redact_sensitive_fragment(&mut redacted, &request.context.capability_token_cbor_b64);
    redact_sensitive_fragment(&mut redacted, &request.context.resource_uri);
    if let Some(credential_id) = request.credential_id.as_deref() {
        redact_sensitive_fragment(&mut redacted, credential_id);
    }
    if let Some(write) = request.write.as_ref() {
        let encoded: String = write.clone().into();
        redact_sensitive_fragment(&mut redacted, &encoded);
        redact_request_body_fragment(&mut redacted, write.as_bytes());
    }
    redacted
}

/// Errors returned by [`HostEgressProxyClient`].
#[cfg(feature = "connector-http")]
#[derive(thiserror::Error)]
pub enum HostEgressProxyError {
    /// The connector could not reach the host proxy or decode its response.
    #[error("host egress proxy transport failed")]
    Transport(reqwest::Error),
    /// The inherited host channel was closed, poisoned, malformed, or timed out.
    #[error("host egress inherited channel failed")]
    InheritedChannel,
    /// The serialized request exceeded the fixed connector-to-host cap.
    #[error("host egress proxy request exceeded the configured envelope limit")]
    RequestEnvelopeTooLarge,
    /// The request could not be serialized into the host-egress envelope.
    #[error("host egress proxy request envelope could not be serialized")]
    MalformedRequestEnvelope,
    /// The proxy response exceeded the configured outer-envelope limit.
    #[error("host egress proxy response exceeded the configured envelope limit")]
    EnvelopeTooLarge,
    /// The successful proxy response was not a valid strict JSON envelope.
    #[error("host egress proxy returned a malformed response envelope")]
    MalformedEnvelope,
    /// The host proxy rejected the request before returning a contract payload.
    #[error("host egress proxy rejected request with HTTP {status}: {body}")]
    Rejected {
        /// HTTP status returned by the host proxy.
        status: u16,
        /// Redacted rejection body returned by the host proxy.
        body: String,
    },
}

#[cfg(feature = "connector-http")]
impl fmt::Debug for HostEgressProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("Transport([redacted])"),
            Self::InheritedChannel => formatter.write_str("InheritedChannel"),
            Self::RequestEnvelopeTooLarge => formatter.write_str("RequestEnvelopeTooLarge"),
            Self::MalformedRequestEnvelope => formatter.write_str("MalformedRequestEnvelope"),
            Self::EnvelopeTooLarge => formatter.write_str("EnvelopeTooLarge"),
            Self::MalformedEnvelope => formatter.write_str("MalformedEnvelope"),
            Self::Rejected { status, body } => formatter
                .debug_struct("Rejected")
                .field("status", status)
                .field("body", body)
                .finish(),
        }
    }
}

#[cfg(feature = "connector-http")]
impl HostEgressProxyError {
    /// HTTP status for host rejections, when the proxy returned one.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Transport(_)
            | Self::InheritedChannel
            | Self::RequestEnvelopeTooLarge
            | Self::MalformedRequestEnvelope
            | Self::EnvelopeTooLarge
            | Self::MalformedEnvelope => None,
            Self::Rejected { status, .. } => Some(*status),
        }
    }

    /// Redacted rejection body returned by the host proxy.
    #[must_use]
    pub fn rejection_body(&self) -> Option<&str> {
        match self {
            Self::Transport(_)
            | Self::InheritedChannel
            | Self::RequestEnvelopeTooLarge
            | Self::MalformedRequestEnvelope
            | Self::EnvelopeTooLarge
            | Self::MalformedEnvelope => None,
            Self::Rejected { body, .. } => Some(body),
        }
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
            retry_after_ms: default_rate_limit_retry_after_ms(),
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

fn default_rate_limit_retry_after_ms() -> u64 {
    u64::try_from(crate::retry::default_rate_limit_retry_after().as_millis()).unwrap_or(u64::MAX)
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
    /// Operation failed and is SAFE TO REPLAY.
    ///
    /// "Retryable" is a claim about **side effects**, not just about whether
    /// the error looks transient. Returning this asserts one of:
    /// - the request provably never reached the service (a connect error), or
    /// - the operation is idempotent, or
    /// - the request carries an idempotency key the provider honours.
    ///
    /// It is NOT enough that the status code is in the 5xx family or that the
    /// transport reported a timeout. A 5xx means the service *received* the
    /// request, and `reqwest::Error::is_timeout()` covers the total-request
    /// timeout, which fires after the body was fully sent — so for a
    /// non-idempotent operation either one may mean the work already
    /// happened. Replaying it then performs the side effect again.
    ///
    /// The host's receipt/idempotency-key deduplication does NOT cover this:
    /// it deduplicates repeated *invokes*, while this retry happens inside the
    /// connector process, below that boundary. The host sees one invoke and
    /// writes one receipt while the provider saw N requests.
    ///
    /// Use [`AttemptOutcome::retryable_if_replayable`] when the safety of a
    /// replay depends on whether the request was transmitted.
    Retryable {
        /// The error from this attempt.
        error: E,
        /// Explicit retry-after hint from the service.
        retry_after: Option<Duration>,
    },
    /// Operation failed terminally (no retry).
    Terminal(E),
}

impl<T, E> AttemptOutcome<T, E> {
    /// Classify a transient failure for an operation whose replay safety
    /// depends on whether the request was actually transmitted.
    ///
    /// `replayable` must be `true` only when replaying the request cannot
    /// duplicate a side effect — because the request never left the client,
    /// because the operation is idempotent, or because it carries an
    /// idempotency key. When it is `false` the failure is reported as
    /// [`AttemptOutcome::Terminal`]: giving the caller one honest error beats
    /// silently performing the side effect up to `max_retries` more times.
    ///
    /// See [`transport_error_reached_service`] for classifying a
    /// `reqwest::Error` on that axis, or
    /// [`http_client_error_reached_service`] for the asupersync
    /// `HttpClientError`.
    pub const fn retryable_if_replayable(
        error: E,
        retry_after: Option<Duration>,
        replayable: bool,
    ) -> Self {
        if replayable {
            Self::Retryable { error, retry_after }
        } else {
            Self::Terminal(error)
        }
    }
}

/// Whether a `reqwest` transport error leaves it POSSIBLE that the service
/// received and acted on the request.
///
/// Only a connect-phase failure proves the request never left the client. A
/// timeout, a body/decode error, or a response-phase failure can all occur
/// after the request was fully written, so for a non-idempotent operation they
/// must be treated as "may already have executed".
///
/// Conservative by construction: an unrecognised error class returns `true`
/// (assume it reached the service) so a new upstream variant fails closed.
#[cfg(feature = "connector-http")]
#[must_use]
pub fn transport_error_reached_service(error: &reqwest::Error) -> bool {
    !(error.is_connect() || error.is_builder())
}

/// Whether an asupersync [`HttpClientError`] leaves it POSSIBLE that the
/// service received and acted on the request.
///
/// The asupersync counterpart of [`transport_error_reached_service`], for
/// connectors built on `fcp_async_core::http` rather than `reqwest`. Unlike the
/// `reqwest` helper this needs no feature gate: `fcp-async-core` is an
/// unconditional dependency of this crate.
///
/// Returns `false` only for the variants that are raised while the connection
/// is still being established, which proves no request bytes were written:
/// URL parsing, DNS, TCP connect, the TLS handshake, proxy negotiation
/// (SOCKS5 and HTTP `CONNECT`), and pool exhaustion.
///
/// Everything else returns `true`. In particular:
/// - `Io` may be a mid-body write failure *or* a response-read failure that
///   happens after the body was fully sent. The two are the same variant, so
///   the ambiguous case decides it.
/// - `HttpError` and `TooManyRedirects` are response-phase: the service
///   answered, so it necessarily received the request.
/// - `Cancelled` can be observed at any point, including after transmission.
///
/// Conservative by construction: the classification is an allowlist of
/// pre-transmission variants, so an error class added upstream returns `true`
/// (assume it reached the service) and fails closed without a compile break.
/// Asupersync after 0.3.4 adds `DeadlineExceeded` — the total-request
/// deadline, which fires after the request may have been fully transmitted —
/// and this helper already classifies it correctly.
#[must_use]
pub const fn http_client_error_reached_service(error: &HttpClientError) -> bool {
    !matches!(
        error,
        HttpClientError::InvalidUrl(_)
            | HttpClientError::DnsError(_)
            | HttpClientError::ConnectError(_)
            | HttpClientError::TlsError(_)
            | HttpClientError::ConnectTunnelRefused { .. }
            | HttpClientError::InvalidConnectInput(_)
            | HttpClientError::ProxyError(_)
            | HttpClientError::PoolExhausted { .. }
    )
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
/// // `replayable` is the whole safety question: a POST that creates a
/// // resource must NOT be replayed once the request has left the client,
/// // because a 5xx or a timeout can both be reported after the service
/// // already did the work. Set it to `true` unconditionally only for an
/// // operation that is idempotent or that carries an idempotency key.
/// let create_is_replayable = false;
///
/// let result = RetryLoop::execute(&ctx, &policy, |attempt| async move {
///     match client.post(url).send().await {
///         Ok(resp) if resp.status().is_success() => AttemptOutcome::Success(resp),
///         Ok(resp) if resp.status() == 429 => AttemptOutcome::Retryable {
///             error: MyError::RateLimited,
///             retry_after: Some(Duration::from_secs(30)),
///         },
///         // A 5xx means the service RECEIVED the request.
///         Ok(resp) if resp.status().is_server_error() => {
///             AttemptOutcome::retryable_if_replayable(
///                 MyError::Api(resp.status()),
///                 None,
///                 create_is_replayable,
///             )
///         }
///         Ok(resp) => AttemptOutcome::Terminal(MyError::Api(resp.status())),
///         // Only a connect-phase failure proves the request never left the
///         // client; `is_timeout()` covers the TOTAL request timeout, which
///         // fires after the body was fully sent.
///         Err(e) => {
///             let replayable = create_is_replayable || !transport_error_reached_service(&e);
///             AttemptOutcome::retryable_if_replayable(MyError::Http(e), None, replayable)
///         }
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

                    // `redacted_summary()`, never `%error`: a connector error
                    // that forwards a `reqwest::Error` renders the full URL,
                    // and providers that authenticate via `?key=…` would leak
                    // the credential into this line on every retry.
                    warn!(
                        attempt,
                        delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        error = %error.redacted_summary(),
                        "retrying after transient error"
                    );

                    // Sleep under context (respects deadline + cancellation)
                    if let Err(async_err) = ctx.sleep(delay).await {
                        return match async_err {
                            AsyncError::Timeout { .. } => Err(error),
                            other => Err(E::from_async_error(other)),
                        };
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Replay safety (br-kxd3e) ─────────────────────────────────

    /// `Retryable` is a claim about SIDE EFFECTS, not about how transient the
    /// error looks. When a replay could duplicate one, the honest outcome is a
    /// single terminal error rather than up to `max_retries` more executions.
    #[test]
    fn retryable_if_replayable_downgrades_an_unsafe_replay_to_terminal() {
        let unsafe_replay: AttemptOutcome<(), &str> =
            AttemptOutcome::retryable_if_replayable("boom", Some(Duration::from_secs(1)), false);
        assert!(
            matches!(unsafe_replay, AttemptOutcome::Terminal("boom")),
            "a non-replayable failure must not be retried"
        );

        let safe_replay: AttemptOutcome<(), &str> =
            AttemptOutcome::retryable_if_replayable("boom", Some(Duration::from_secs(1)), true);
        assert!(matches!(
            safe_replay,
            AttemptOutcome::Retryable {
                error: "boom",
                retry_after: Some(_)
            }
        ));
    }

    /// Only the connection-establishment failures prove no request bytes were
    /// written. These are the variants a non-idempotent operation may replay.
    #[test]
    fn http_client_error_pre_transmission_variants_did_not_reach_the_service() {
        let pre_transmission = [
            HttpClientError::InvalidUrl("not a url".to_string()),
            HttpClientError::DnsError(std::io::Error::other("nxdomain")),
            HttpClientError::ConnectError(std::io::Error::other("refused")),
            HttpClientError::TlsError("handshake failed".to_string()),
            HttpClientError::ConnectTunnelRefused {
                status: 403,
                reason: "Forbidden".to_string(),
            },
            HttpClientError::InvalidConnectInput("bad authority".to_string()),
            HttpClientError::ProxyError("SOCKS5 auth rejected".to_string()),
            HttpClientError::PoolExhausted {
                host: "api.example.com".to_string(),
                port: 443,
            },
        ];

        for error in &pre_transmission {
            assert!(
                !http_client_error_reached_service(error),
                "{error:?} is raised while connecting, so no request bytes were written"
            );
        }
    }

    /// Everything else may be observed after the body was fully sent, so a
    /// non-idempotent operation must treat it as "may already have executed".
    #[test]
    fn http_client_error_post_transmission_variants_may_have_reached_the_service() {
        let may_have_reached = [
            // A mid-body write failure and a response-read failure are the
            // same variant; only the latter proves transmission, so both must
            // fail closed.
            HttpClientError::Io(std::io::Error::other("connection reset")),
            // Redirects imply the service answered at least once.
            HttpClientError::TooManyRedirects { count: 11, max: 10 },
            // Cancellation can land at any point, including post-send.
            HttpClientError::Cancelled,
        ];

        for error in &may_have_reached {
            assert!(
                http_client_error_reached_service(error),
                "{error:?} can occur after transmission and must fail closed"
            );
        }
    }

    #[cfg(feature = "connector-http")]
    fn br_b0qqv_host_egress_context(
        operation_id: &str,
        request_id: &str,
    ) -> fcp_manifest::HostEgressContext {
        fcp_manifest::HostEgressContext {
            connector_id: "fcp.test.b0qqv:utility:1.0.0".to_string(),
            operation_id: operation_id.to_string(),
            resource_uri: format!("fcp-test://b0qqv/{operation_id}"),
            zone_id: "z:work".to_string(),
            request_id: request_id.to_string(),
            correlation_id: Some(format!("corr-{request_id}")),
            capability_token_cbor_b64: "capability-material-redaction-sentinel".to_string(),
        }
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn br_b0qqv_host_egress_proxy_http_request_serialization_preserves_strict_contract() {
        let request = HostEgressHttpRequest {
            context: br_b0qqv_host_egress_context("messages.create", "req-b0qqv-http"),
            url: "https://api.example.test/v1/messages".to_string(),
            method: "POST".to_string(),
            headers: vec![fcp_manifest::HostEgressHttpHeader {
                name: "x-fcp-request".to_string(),
                value: "req-b0qqv-http".to_string(),
            }],
            body: Some(fcp_manifest::Base64Bytes::from_vec(
                br#"{"message":"hello"}"#.to_vec(),
            )),
            credential_id: Some("cred-b0qqv-redacted-id".to_string()),
        };

        let value = serde_json::to_value(&request).expect("serialize HTTP host-egress request");
        assert_eq!(
            value["context"]["connector_id"],
            "fcp.test.b0qqv:utility:1.0.0"
        );
        assert_eq!(value["context"]["operation_id"], "messages.create");
        assert_eq!(
            value["context"]["resource_uri"],
            "fcp-test://b0qqv/messages.create"
        );
        assert_eq!(value["context"]["zone_id"], "z:work");
        assert_eq!(value["context"]["request_id"], "req-b0qqv-http");
        assert_eq!(value["context"]["correlation_id"], "corr-req-b0qqv-http");
        assert_eq!(value["url"], "https://api.example.test/v1/messages");
        assert_eq!(value["method"], "POST");
        assert_eq!(value["headers"][0]["name"], "x-fcp-request");
        assert_eq!(value["headers"][0]["value"], "req-b0qqv-http");
        assert_eq!(value["body"], "base64:eyJtZXNzYWdlIjoiaGVsbG8ifQ==");
        assert_eq!(value["credential_id"], "cred-b0qqv-redacted-id");

        let decoded: HostEgressHttpRequest =
            serde_json::from_value(value).expect("decode HTTP host-egress request");
        assert_eq!(
            decoded.body.expect("request body").as_bytes(),
            br#"{"message":"hello"}"#
        );
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn br_b0qqv_host_egress_proxy_tcp_request_serialization_preserves_strict_contract() {
        let request = HostEgressTcpRequest {
            context: br_b0qqv_host_egress_context("socket.exchange", "req-b0qqv-tcp"),
            host: "api.example.test".to_string(),
            port: 443,
            tls: true,
            sni_override: Some("api.example.test".to_string()),
            write: Some(fcp_manifest::Base64Bytes::from_vec(b"PING".to_vec())),
            read_limit_bytes: Some(1024),
            credential_id: Some("cred-b0qqv-redacted-id".to_string()),
        };

        let value = serde_json::to_value(&request).expect("serialize TCP host-egress request");
        assert_eq!(value["context"]["operation_id"], "socket.exchange");
        assert_eq!(
            value["context"]["resource_uri"],
            "fcp-test://b0qqv/socket.exchange"
        );
        assert_eq!(value["context"]["request_id"], "req-b0qqv-tcp");
        assert_eq!(value["host"], "api.example.test");
        assert_eq!(value["port"], 443);
        assert_eq!(value["tls"], true);
        assert_eq!(value["sni_override"], "api.example.test");
        assert_eq!(value["write"], "base64:UElORw==");
        assert_eq!(value["read_limit_bytes"], 1024);
        assert_eq!(value["credential_id"], "cred-b0qqv-redacted-id");

        let decoded: HostEgressTcpRequest =
            serde_json::from_value(value).expect("decode TCP host-egress request");
        assert_eq!(decoded.write.expect("write payload").as_bytes(), b"PING");
    }

    #[cfg(feature = "connector-http")]
    #[test]
    fn br_b0qqv_host_egress_proxy_rejection_redacts_request_material() {
        let request = HostEgressHttpRequest {
            context: br_b0qqv_host_egress_context("messages.create", "req-b0qqv-redact"),
            url: "https://api.example.test/v1/messages?proof_marker=url-redaction-sentinel"
                .to_string(),
            method: "POST".to_string(),
            headers: vec![fcp_manifest::HostEgressHttpHeader {
                name: "authorization".to_string(),
                value: "Bearer header-redaction-sentinel".to_string(),
            }],
            body: Some(fcp_manifest::Base64Bytes::from_vec(
                b"body-redaction-sentinel".to_vec(),
            )),
            credential_id: Some("credential-redaction-sentinel".to_string()),
        };
        let echoed_body = "deny_reason=denied_host; capability-material-redaction-sentinel; \
            fcp-test://b0qqv/messages.create; \
            https://api.example.test/v1/messages?proof_marker=url-redaction-sentinel; \
            Bearer header-redaction-sentinel; body-redaction-sentinel; \
            base64:Ym9keS1yZWRhY3Rpb24tc2VudGluZWw=; credential-redaction-sentinel";

        let redacted = redact_http_host_egress_rejection_body(&request, echoed_body.to_string());
        assert!(redacted.contains("deny_reason=denied_host"));
        for leaked in [
            "capability-material-redaction-sentinel",
            "fcp-test://b0qqv/messages.create",
            "url-redaction-sentinel",
            "header-redaction-sentinel",
            "body-redaction-sentinel",
            "base64:Ym9keS1yZWRhY3Rpb24tc2VudGluZWw=",
            "credential-redaction-sentinel",
        ] {
            assert!(
                !redacted.contains(leaked),
                "redacted rejection body leaked {leaked}: {redacted}"
            );
        }
        let mut short_fragment = "x".to_string();
        redact_sensitive_fragment(&mut short_fragment, "x");
        assert_eq!(short_fragment, HOST_EGRESS_REDACTION_MARKER);

        let error = HostEgressProxyError::Rejected {
            status: 403,
            body: redacted,
        };
        assert_eq!(error.status(), Some(403));
        assert!(
            error
                .rejection_body()
                .expect("rejection body")
                .contains("deny_reason=denied_host")
        );
    }

    #[cfg(all(feature = "connector-http", target_os = "linux"))]
    fn inherited_test_response(request: &HostEgressWireRequest) -> HostEgressWireResponse {
        let egress =
            |context: &fcp_manifest::HostEgressContext| fcp_manifest::HostEgressDecisionMetadata {
                connector_id: context.connector_id.clone(),
                operation_id: context.operation_id.clone(),
                zone_id: context.zone_id.clone(),
                request_id: context.request_id.clone(),
                correlation_id: context.correlation_id.clone(),
                execution_mode: "host_egress_proxy".to_string(),
                constraint_source: "test".to_string(),
                decision: "allow".to_string(),
                resolved_host: "api.example.test".to_string(),
                resolved_port: 443,
                credential_injected: true,
                elapsed_ms: 1,
            };
        let body = match &request.payload {
            HostEgressWireRequestPayload::Http(request) => {
                HostEgressWireResponseBody::Http(fcp_manifest::HostEgressHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: fcp_manifest::Base64Bytes::from_vec(b"ok".to_vec()),
                    egress: egress(&request.context),
                })
            }
            HostEgressWireRequestPayload::Tcp(request) => {
                HostEgressWireResponseBody::Tcp(fcp_manifest::HostEgressTcpResponse {
                    bytes_written: request
                        .write
                        .as_ref()
                        .map_or(0, |bytes| bytes.as_bytes().len() as u64),
                    bytes_read: 2,
                    read: fcp_manifest::Base64Bytes::from_vec(b"ok".to_vec()),
                    egress: egress(&request.context),
                })
            }
        };
        HostEgressWireResponse {
            schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
            request_id: request.request_id,
            route: request.route,
            status: 200,
            body: Some(body),
            error: None,
        }
    }

    #[cfg(all(feature = "connector-http", target_os = "linux"))]
    fn read_wire_test_frame(
        stream: &mut std::os::unix::net::UnixStream,
    ) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut frame = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                return Ok(frame);
            }
            frame.push(byte[0]);
            if frame.len() > MAX_HOST_EGRESS_REQUEST_ENVELOPE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "test frame too large",
                ));
            }
        }
    }

    #[cfg(all(feature = "connector-http", target_os = "linux"))]
    #[test]
    fn inherited_fd_channel_round_trips_http_tcp_and_auth_serially() {
        use std::io::Write;
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream as StdUnixStream;
        use std::sync::mpsc;
        use std::thread;

        let (client_stream, mut peer) = StdUnixStream::pair().expect("socketpair");
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let frame = read_wire_test_frame(&mut peer).expect("read request frame");
                let request: HostEgressWireRequest =
                    serde_json::from_slice(&frame).expect("decode request frame");
                assert_eq!(request.auth_token, "inherited-auth-test");
                sender.send(request.clone()).expect("send captured request");
                let response = serde_json::to_vec(&inherited_test_response(&request))
                    .expect("encode response frame");
                peer.write_all(&response).expect("write response payload");
                peer.write_all(b"\n").expect("write response delimiter");
            }
        });
        let client = HostEgressProxyClient::from_inherited_fd(
            client_stream.into_raw_fd(),
            "inherited-auth-test",
            HostEgressProxyLimits::default(),
        )
        .expect("claim socketpair endpoint");
        let debug = format!("{client:?}");
        assert!(!debug.contains("inherited-auth-test"));
        let http = fcp_manifest::HostEgressHttpRequest {
            context: br_b0qqv_host_egress_context("messages.create", "req-wire-http"),
            url: "https://api.example.test".to_string(),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        };
        let tcp = fcp_manifest::HostEgressTcpRequest {
            context: br_b0qqv_host_egress_context("socket.exchange", "req-wire-tcp"),
            host: "api.example.test".to_string(),
            port: 443,
            tls: true,
            sni_override: None,
            write: None,
            read_limit_bytes: Some(16),
            credential_id: None,
        };
        fcp_async_core::runtime::block_on_sync(async {
            let (http_response, tcp_response) =
                futures_util::future::join(client.http(&http), client.tcp(&tcp)).await;
            assert_eq!(http_response.expect("HTTP response").status, 200);
            assert_eq!(tcp_response.expect("TCP response").read.as_bytes(), b"ok");
        })
        .expect("inherited channel calls must complete");
        let first = receiver.recv().expect("capture HTTP request");
        let second = receiver.recv().expect("capture TCP request");
        assert_eq!(first.route, HostEgressWireRoute::Http);
        assert_eq!(second.route, HostEgressWireRoute::Tcp);
        handle.join().expect("wire peer thread");
    }

    #[cfg(all(feature = "connector-http", target_os = "linux"))]
    #[test]
    fn inherited_fd_channel_poisoning_and_fd_validation_are_deterministic() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, IntoRawFd};
        use std::os::unix::net::UnixStream as StdUnixStream;
        use std::thread;

        for response in [b"not-json\n".to_vec(), b"{".to_vec()] {
            let (client_stream, mut peer) = StdUnixStream::pair().expect("socketpair");
            let handle = thread::spawn(move || {
                let _ = read_wire_test_frame(&mut peer);
                peer.write_all(&response).expect("write malformed response");
            });
            let client = HostEgressProxyClient::from_inherited_fd(
                client_stream.into_raw_fd(),
                "inherited-auth-test",
                HostEgressProxyLimits::default(),
            )
            .expect("claim socketpair endpoint");
            let request = fcp_manifest::HostEgressHttpRequest {
                context: br_b0qqv_host_egress_context("messages.create", "req-wire-bad"),
                url: "https://api.example.test".to_string(),
                method: "GET".to_string(),
                headers: Vec::new(),
                body: None,
                credential_id: None,
            };
            let error = fcp_async_core::runtime::block_on_sync(client.http(&request))
                .expect("runtime layer")
                .expect_err("bad response must fail");
            assert!(matches!(error, HostEgressProxyError::InheritedChannel));
            let error = fcp_async_core::runtime::block_on_sync(client.http(&request))
                .expect("runtime layer")
                .expect_err("poisoned channel must stay closed");
            assert!(matches!(error, HostEgressProxyError::InheritedChannel));
            handle.join().expect("wire peer thread");
        }

        let request = fcp_manifest::HostEgressHttpRequest {
            context: br_b0qqv_host_egress_context("messages.create", "req-wire-bounds"),
            url: "https://api.example.test".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        };

        let (client_stream, mut peer) = StdUnixStream::pair().expect("socketpair");
        let handle = thread::spawn(move || {
            let frame = read_wire_test_frame(&mut peer).expect("read request frame");
            let request: HostEgressWireRequest =
                serde_json::from_slice(&frame).expect("decode request frame");
            let mut response = inherited_test_response(&request);
            response.request_id = response.request_id.saturating_add(1);
            let response = serde_json::to_vec(&response).expect("encode response frame");
            peer.write_all(&response).expect("write response payload");
            peer.write_all(b"\n").expect("write response delimiter");
        });
        let client = HostEgressProxyClient::from_inherited_fd(
            client_stream.into_raw_fd(),
            "inherited-auth-test",
            HostEgressProxyLimits::default(),
        )
        .expect("claim socketpair endpoint");
        let error = fcp_async_core::runtime::block_on_sync(client.http(&request))
            .expect("runtime layer")
            .expect_err("wrong response id must fail closed");
        assert!(matches!(error, HostEgressProxyError::InheritedChannel));
        handle.join().expect("wire peer thread");

        let (client_stream, mut peer) = StdUnixStream::pair().expect("socketpair");
        let handle = thread::spawn(move || {
            let _ = read_wire_test_frame(&mut peer);
            let _ = peer.write_all(&vec![b'x'; 65]);
            let _ = peer.write_all(b"\n");
        });
        let client = HostEgressProxyClient::from_inherited_fd(
            client_stream.into_raw_fd(),
            "inherited-auth-test",
            HostEgressProxyLimits {
                request_timeout: Duration::from_secs(1),
                max_outer_envelope_bytes: 64,
            },
        )
        .expect("claim socketpair endpoint");
        let error = fcp_async_core::runtime::block_on_sync(client.http(&request))
            .expect("runtime layer")
            .expect_err("oversized response must fail closed");
        assert!(matches!(error, HostEgressProxyError::InheritedChannel));
        handle.join().expect("wire peer thread");

        let (client_stream, mut peer) = StdUnixStream::pair().expect("socketpair");
        let handle = thread::spawn(move || {
            let _ = read_wire_test_frame(&mut peer);
            thread::sleep(Duration::from_millis(100));
        });
        let client = HostEgressProxyClient::from_inherited_fd(
            client_stream.into_raw_fd(),
            "inherited-auth-test",
            HostEgressProxyLimits {
                request_timeout: Duration::from_millis(10),
                max_outer_envelope_bytes: 1024,
            },
        )
        .expect("claim socketpair endpoint");
        let error = fcp_async_core::runtime::block_on_sync(client.http(&request))
            .expect("runtime layer")
            .expect_err("response timeout must poison channel");
        assert!(matches!(error, HostEgressProxyError::InheritedChannel));
        handle.join().expect("wire peer thread");

        let (closed, peer) = StdUnixStream::pair().expect("socketpair");
        let closed_fd = closed.as_raw_fd();
        drop(closed);
        drop(peer);
        let closed_error = HostEgressProxyClient::from_inherited_fd(
            closed_fd,
            "inherited-auth-test",
            HostEgressProxyLimits::default(),
        )
        .expect_err("closed FD must fail");
        assert!(matches!(
            closed_error,
            HostEgressProxyConfigError::InheritedFdUnavailable
        ));

        let file = std::fs::File::open("/dev/null").expect("open non-socket FD");
        let non_socket_error = HostEgressProxyClient::from_inherited_fd(
            file.as_raw_fd(),
            "inherited-auth-test",
            HostEgressProxyLimits::default(),
        )
        .expect_err("non-socket FD must fail");
        assert!(matches!(
            non_socket_error,
            HostEgressProxyConfigError::InheritedFdNotUnixStream
        ));

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind TCP listener");
        let address = listener.local_addr().expect("listener address");
        let tcp_client = std::net::TcpStream::connect(address).expect("connect TCP stream");
        let (tcp_peer, _) = listener.accept().expect("accept TCP stream");
        let tcp_error = HostEgressProxyClient::from_inherited_fd(
            tcp_client.as_raw_fd(),
            "inherited-auth-test",
            HostEgressProxyLimits::default(),
        )
        .expect_err("connected non-UNIX stream must fail");
        assert!(matches!(
            tcp_error,
            HostEgressProxyConfigError::InheritedFdNotUnixStream
        ));
        drop(tcp_peer);

        let udp = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind UDP socket");
        let udp_error = HostEgressProxyClient::from_inherited_fd(
            udp.as_raw_fd(),
            "inherited-auth-test",
            HostEgressProxyLimits::default(),
        )
        .expect_err("wrong socket type must fail");
        assert!(matches!(
            udp_error,
            HostEgressProxyConfigError::InheritedFdNotUnixStream
        ));
    }

    #[cfg(all(feature = "connector-http", target_os = "linux"))]
    #[test]
    fn inherited_fd_channel_cancellation_poisoning_is_deterministic() {
        use futures_util::future::{AbortHandle, Abortable};
        use std::io::Write;
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream as StdUnixStream;
        use std::sync::mpsc;
        use std::thread;

        let (client_stream, mut peer) = StdUnixStream::pair().expect("socketpair");
        let (request_seen_sender, request_seen_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let peer_handle = thread::spawn(move || {
            read_wire_test_frame(&mut peer).expect("read request before cancellation");
            request_seen_sender
                .send(())
                .expect("signal request receipt");
            release_receiver
                .recv()
                .expect("wait for cancelled caller to drop");
            let _ = peer.write_all(b"late response must not be consumed\n");
        });

        let client = HostEgressProxyClient::from_inherited_fd(
            client_stream.into_raw_fd(),
            "inherited-auth-test",
            HostEgressProxyLimits::default(),
        )
        .expect("claim socketpair endpoint");
        let request = fcp_manifest::HostEgressHttpRequest {
            context: br_b0qqv_host_egress_context("messages.create", "req-wire-cancel"),
            url: "https://api.example.test".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            credential_id: None,
        };
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let call_client = client.clone();
        let call_request = request.clone();
        let call_handle = thread::spawn(move || {
            fcp_async_core::runtime::block_on_sync(Abortable::new(
                call_client.http(&call_request),
                abort_registration,
            ))
        });

        request_seen_receiver
            .recv()
            .expect("request must be in flight before abort");
        abort_handle.abort();
        let aborted = call_handle
            .join()
            .expect("cancelled call thread")
            .expect("runtime layer");
        assert!(matches!(aborted, Err(futures_util::future::Aborted)));
        release_sender.send(()).expect("release peer thread");
        peer_handle.join().expect("peer thread");

        let error = fcp_async_core::runtime::block_on_sync(client.http(&request))
            .expect("runtime layer")
            .expect_err("cancelled in-flight exchange must poison channel");
        assert!(matches!(error, HostEgressProxyError::InheritedChannel));
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
                assert_eq!(status_code, Some(504));
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
    fn retry_loop_preserves_retryable_error_when_deadline_expires_during_backoff() {
        fcp_async_core::runtime::block_on_sync(async {
            let ctx = ExecutionContext::request_scoped(Duration::from_millis(5));
            let policy = RetryPolicy::new()
                .with_max_attempts(Some(3))
                .with_jitter_enabled(false);

            let result: Result<&str, TestError> =
                RetryLoop::execute(&ctx, &policy, |_attempt| async {
                    AttemptOutcome::Retryable {
                        error: TestError::Transient("service overloaded".into()),
                        retry_after: Some(Duration::from_millis(50)),
                    }
                })
                .await;

            match result.unwrap_err() {
                TestError::Transient(message) => assert_eq!(message, "service overloaded"),
                other => panic!("expected original retryable error, got {other:?}"),
            }
        })
        .expect("runtime should preserve retryable error on backoff deadline expiry");
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
                assert_eq!(status_code, Some(504));
                assert!(retryable);
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
    fn map_timeout_is_retryable_timeout() {
        let err = AsyncError::Timeout { timeout_ms: 5000 };
        let fcp_err = map_async_to_fcp_error(&err);
        match fcp_err {
            FcpError::External { retryable, .. } => {
                assert!(retryable);
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
    fn test_error_to_fcp_deadline_maps_to_retryable_timeout() {
        let err = TestError::DeadlineExceeded("10s".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(504));
                assert!(retryable);
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

    // ── Canonical HTTP → FCP mapping tests ──────────────────────────────────

    #[test]
    fn map_http_400_to_invalid_request() {
        let err = map_http_status(400, "test", "bad input".into());
        assert!(matches!(err, FcpError::InvalidRequest { code: 1001, .. }));
    }

    #[test]
    fn map_http_401_to_unauthorized() {
        let err = map_http_status(401, "test", "invalid token".into());
        assert!(matches!(err, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn map_http_403_to_capability_denied() {
        let err = map_http_status(403, "test", "forbidden".into());
        assert!(matches!(err, FcpError::CapabilityDenied { .. }));
    }

    #[test]
    fn map_http_404_to_resource_not_found() {
        let err = map_http_status(404, "test", "not found".into());
        assert!(matches!(err, FcpError::ResourceNotFound { .. }));
    }

    #[test]
    fn map_http_408_to_upstream_timeout() {
        let err = map_http_status(408, "api.example.com", "timeout".into());
        assert!(matches!(err, FcpError::UpstreamTimeout { .. }));
    }

    #[test]
    fn map_http_429_to_rate_limited() {
        let err = map_http_status(429, "test", "too many".into());
        assert!(matches!(
            err,
            FcpError::RateLimited {
                retry_after_ms,
                ..
            } if retry_after_ms == default_rate_limit_retry_after_ms()
        ));
    }

    #[test]
    fn map_http_500_to_external_retryable() {
        let err = map_http_status(500, "svc", "internal".into());
        assert!(matches!(
            err,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn map_http_502_to_external_retryable() {
        let err = map_http_status(502, "svc", "bad gateway".into());
        assert!(matches!(
            err,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn map_http_501_to_external_not_retryable() {
        let err = map_http_status(501, "svc", "not implemented".into());
        assert!(matches!(
            err,
            FcpError::External {
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn map_http_unknown_to_external() {
        let err = map_http_status(418, "svc", "teapot".into());
        assert!(matches!(err, FcpError::External { .. }));
    }

    #[test]
    fn is_http_retryable_standard_codes() {
        assert!(is_http_status_retryable(408));
        assert!(is_http_status_retryable(429));
        assert!(is_http_status_retryable(500));
        assert!(is_http_status_retryable(502));
        assert!(is_http_status_retryable(503));
        assert!(is_http_status_retryable(504));
        assert!(!is_http_status_retryable(400));
        assert!(!is_http_status_retryable(401));
        assert!(!is_http_status_retryable(404));
        assert!(!is_http_status_retryable(501));
    }
}
