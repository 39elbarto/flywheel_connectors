//! Telemetry context for correlation and field injection.
//!
//! Provides context propagation for correlation IDs, zone IDs, connector IDs,
//! and request IDs across log entries and trace spans.
//!
//! # W3C Trace Context
//!
//! This module implements W3C Trace Context propagation for distributed tracing.
//! The [`TraceContext`] struct provides:
//! - 16-byte trace ID (W3C traceparent format)
//! - 8-byte span ID (W3C traceparent format)
//! - Trace flags (sampled, etc.)
//! - Optional tracestate for vendor-specific context

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use parking_lot::{Mutex, RwLock};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::Span;
use uuid::Uuid;

fn context_stacks() -> &'static Mutex<HashMap<String, Vec<Arc<TelemetryContext>>>> {
    static STACKS: OnceLock<Mutex<HashMap<String, Vec<Arc<TelemetryContext>>>>> = OnceLock::new();
    STACKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn context_slot_key() -> String {
    asupersync::Cx::current().map_or_else(
        || format!("thread:{:?}", std::thread::current().id()),
        |cx| format!("task:{:?}", cx.task_id()),
    )
}

fn push_context(ctx: Arc<TelemetryContext>) -> String {
    let key = context_slot_key();
    context_stacks()
        .lock()
        .entry(key.clone())
        .or_default()
        .push(ctx);
    key
}

fn pop_context(key: &str) {
    let mut stacks = context_stacks().lock();
    if let Some(stack) = stacks.get_mut(key) {
        stack.pop();
        if stack.is_empty() {
            stacks.remove(key);
        }
    }
}

/// W3C Trace Context size constants.
pub const TRACE_ID_SIZE: usize = 16;
/// W3C Span ID size in bytes.
pub const SPAN_ID_SIZE: usize = 8;

/// Trace flags - sampled bit.
pub const TRACE_FLAG_SAMPLED: u8 = 0x01;

/// W3C Trace Context for distributed tracing (NORMATIVE).
///
/// Enables stitching mesh routing, connector execution, receipts, and audit together.
/// Implements the W3C Trace Context specification for interoperability.
///
/// # Format
///
/// When serialized to `traceparent` header format:
/// ```text
/// {version}-{trace-id}-{span-id}-{trace-flags}
/// 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    /// 16-byte trace ID (W3C traceparent format).
    /// Identifies the entire distributed trace.
    #[serde(with = "hex_16")]
    pub trace_id: [u8; TRACE_ID_SIZE],

    /// 8-byte span ID (W3C traceparent format).
    /// Identifies this specific span within the trace.
    #[serde(with = "hex_8")]
    pub span_id: [u8; SPAN_ID_SIZE],

    /// Trace flags (sampled, etc.).
    /// Bit 0: sampled flag (0x01 = sampled)
    pub trace_flags: u8,

    /// Optional tracestate for vendor-specific context.
    /// Format: `key1=value1,key2=value2`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_state: Option<String>,
}

mod hex_16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom("invalid trace_id length"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod hex_8 {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)] // serde requires reference
    pub fn serialize<S>(bytes: &[u8; 8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 8], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 8 {
            return Err(serde::de::Error::custom("invalid span_id length"));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl TraceContext {
    /// Generate a new trace context with random IDs.
    ///
    /// The trace is marked as sampled by default.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        Self {
            trace_id: rng.random(),
            span_id: rng.random(),
            trace_flags: TRACE_FLAG_SAMPLED,
            trace_state: None,
        }
    }

    /// Create a new span within the same trace.
    ///
    /// Generates a new span ID while preserving the trace ID.
    #[must_use]
    pub fn new_span(&self) -> Self {
        let mut rng = rand::rng();
        Self {
            trace_id: self.trace_id,
            span_id: rng.random(),
            trace_flags: self.trace_flags,
            trace_state: self.trace_state.clone(),
        }
    }

    /// Create from specific trace and span IDs.
    #[must_use]
    pub const fn new(trace_id: [u8; TRACE_ID_SIZE], span_id: [u8; SPAN_ID_SIZE]) -> Self {
        Self {
            trace_id,
            span_id,
            trace_flags: TRACE_FLAG_SAMPLED,
            trace_state: None,
        }
    }

    /// Set the sampled flag.
    #[must_use]
    pub const fn with_sampled(mut self, sampled: bool) -> Self {
        if sampled {
            self.trace_flags |= TRACE_FLAG_SAMPLED;
        } else {
            self.trace_flags &= !TRACE_FLAG_SAMPLED;
        }
        self
    }

    /// Set the trace state.
    #[must_use]
    pub fn with_trace_state(mut self, state: impl Into<String>) -> Self {
        self.trace_state = Some(state.into());
        self
    }

    /// Check if the trace is sampled.
    #[must_use]
    pub const fn is_sampled(&self) -> bool {
        self.trace_flags & TRACE_FLAG_SAMPLED != 0
    }

    /// Format as W3C traceparent header value.
    ///
    /// Format: `{version}-{trace-id}-{span-id}-{trace-flags}`
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            hex::encode(self.trace_id),
            hex::encode(self.span_id),
            self.trace_flags
        )
    }

    /// Parse from W3C traceparent header value.
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid.
    pub fn from_traceparent(header: &str) -> Result<Self, TraceContextError> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return Err(TraceContextError::InvalidFormat(
                "expected 4 parts separated by '-'".to_string(),
            ));
        }

        // Version must be "00"
        if parts[0] != "00" {
            return Err(TraceContextError::UnsupportedVersion(parts[0].to_string()));
        }

        // Parse trace ID (32 hex chars = 16 bytes)
        let trace_id_hex = parts[1];
        if trace_id_hex.len() != 32 {
            return Err(TraceContextError::InvalidFormat(
                "trace_id must be 32 hex characters".to_string(),
            ));
        }
        let trace_id_bytes = hex::decode(trace_id_hex)
            .map_err(|e| TraceContextError::InvalidFormat(e.to_string()))?;
        let mut trace_id = [0u8; TRACE_ID_SIZE];
        trace_id.copy_from_slice(&trace_id_bytes);

        // Validate trace ID is not all zeros
        if trace_id == [0u8; TRACE_ID_SIZE] {
            return Err(TraceContextError::InvalidFormat(
                "trace_id cannot be all zeros".to_string(),
            ));
        }

        // Parse span ID (16 hex chars = 8 bytes)
        let span_id_hex = parts[2];
        if span_id_hex.len() != 16 {
            return Err(TraceContextError::InvalidFormat(
                "span_id must be 16 hex characters".to_string(),
            ));
        }
        let span_id_bytes = hex::decode(span_id_hex)
            .map_err(|e| TraceContextError::InvalidFormat(e.to_string()))?;
        let mut span_id = [0u8; SPAN_ID_SIZE];
        span_id.copy_from_slice(&span_id_bytes);

        // Validate span ID is not all zeros
        if span_id == [0u8; SPAN_ID_SIZE] {
            return Err(TraceContextError::InvalidFormat(
                "span_id cannot be all zeros".to_string(),
            ));
        }

        // Parse trace flags (2 hex chars = 1 byte)
        let flags_hex = parts[3];
        if flags_hex.len() != 2 {
            return Err(TraceContextError::InvalidFormat(
                "trace_flags must be 2 hex characters".to_string(),
            ));
        }
        let trace_flags = u8::from_str_radix(flags_hex, 16)
            .map_err(|e| TraceContextError::InvalidFormat(e.to_string()))?;

        Ok(Self {
            trace_id,
            span_id,
            trace_flags,
            trace_state: None,
        })
    }

    /// Get trace ID as hex string.
    #[must_use]
    pub fn trace_id_hex(&self) -> String {
        hex::encode(self.trace_id)
    }

    /// Get span ID as hex string.
    #[must_use]
    pub fn span_id_hex(&self) -> String {
        hex::encode(self.span_id)
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::generate()
    }
}

impl std::fmt::Display for TraceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_traceparent())
    }
}

/// Error type for trace context operations.
#[derive(Debug, thiserror::Error)]
pub enum TraceContextError {
    /// Invalid traceparent format.
    #[error("Invalid traceparent format: {0}")]
    InvalidFormat(String),

    /// Unsupported version.
    #[error("Unsupported traceparent version: {0}")]
    UnsupportedVersion(String),
}

/// Telemetry context containing correlation fields.
#[derive(Debug)]
pub struct TelemetryContext {
    /// W3C Trace Context for distributed tracing.
    /// When present, `correlation_id` is derived from the `trace_id`.
    pub trace_context: Option<TraceContext>,

    /// Unique correlation ID for request tracing.
    /// If `trace_context` is present, this is derived from `trace_id`.
    pub correlation_id: Option<String>,

    /// Zone ID from FCP capability token.
    pub zone_id: Option<String>,

    /// Connector ID.
    pub connector_id: Option<String>,

    /// Operation ID (schema ID of the operation being performed).
    pub operation_id: Option<String>,

    /// Current request ID.
    pub request_id: Option<Uuid>,

    /// Principal ID (user/service making the request).
    pub principal_id: Option<String>,

    /// Node ID (local `TailscaleNodeId` when available).
    pub node_id: Option<String>,

    /// Decision result for policy decisions.
    pub decision: Option<String>,

    /// Reason code for policy decisions.
    pub reason_code: Option<String>,

    /// Additional custom fields.
    fields: RwLock<Vec<(String, String)>>,
}

impl Default for TelemetryContext {
    fn default() -> Self {
        Self {
            trace_context: None,
            correlation_id: None,
            zone_id: None,
            connector_id: None,
            operation_id: None,
            request_id: None,
            principal_id: None,
            node_id: None,
            decision: None,
            reason_code: None,
            fields: RwLock::new(Vec::new()),
        }
    }
}

impl Clone for TelemetryContext {
    fn clone(&self) -> Self {
        Self {
            trace_context: self.trace_context.clone(),
            correlation_id: self.correlation_id.clone(),
            zone_id: self.zone_id.clone(),
            connector_id: self.connector_id.clone(),
            operation_id: self.operation_id.clone(),
            request_id: self.request_id,
            principal_id: self.principal_id.clone(),
            node_id: self.node_id.clone(),
            decision: self.decision.clone(),
            reason_code: self.reason_code.clone(),
            fields: RwLock::new(self.fields.read().clone()),
        }
    }
}

impl TelemetryContext {
    /// Create a new empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a context with a new W3C trace context.
    ///
    /// This generates new trace and span IDs and derives the `correlation_id` from `trace_id`.
    #[must_use]
    pub fn with_trace() -> Self {
        let trace_ctx = TraceContext::generate();
        let correlation_id = trace_ctx.trace_id_hex();
        Self {
            trace_context: Some(trace_ctx),
            correlation_id: Some(correlation_id),
            ..Default::default()
        }
    }

    /// Create a context with a new correlation ID (UUID v4).
    ///
    /// Use `with_trace()` for W3C-compliant distributed tracing.
    #[must_use]
    pub fn with_correlation_id() -> Self {
        Self {
            correlation_id: Some(Uuid::new_v4().to_string()),
            ..Default::default()
        }
    }

    /// Set the W3C trace context.
    ///
    /// This also sets the `correlation_id` from the `trace_id`.
    #[must_use]
    pub fn trace_context(mut self, ctx: TraceContext) -> Self {
        self.correlation_id = Some(ctx.trace_id_hex());
        self.trace_context = Some(ctx);
        self
    }

    /// Set the correlation ID.
    #[must_use]
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set the zone ID.
    #[must_use]
    pub fn zone_id(mut self, id: impl Into<String>) -> Self {
        self.zone_id = Some(id.into());
        self
    }

    /// Set the connector ID.
    #[must_use]
    pub fn connector_id(mut self, id: impl Into<String>) -> Self {
        self.connector_id = Some(id.into());
        self
    }

    /// Set the operation ID (schema ID).
    #[must_use]
    pub fn operation_id(mut self, id: impl Into<String>) -> Self {
        self.operation_id = Some(id.into());
        self
    }

    /// Set the request ID.
    #[must_use]
    pub const fn request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Set the principal ID.
    #[must_use]
    pub fn principal_id(mut self, id: impl Into<String>) -> Self {
        self.principal_id = Some(id.into());
        self
    }

    /// Set the node ID (`TailscaleNodeId`).
    #[must_use]
    pub fn node_id(mut self, id: impl Into<String>) -> Self {
        self.node_id = Some(id.into());
        self
    }

    /// Set the decision result for policy decisions.
    #[must_use]
    pub fn decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    /// Set the reason code for policy decisions.
    #[must_use]
    pub fn reason_code(mut self, code: impl Into<String>) -> Self {
        self.reason_code = Some(code.into());
        self
    }

    /// Add a custom field.
    pub fn add_field(&self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.write().push((key.into(), value.into()));
    }

    /// Get all fields as key-value pairs.
    ///
    /// Includes all context fields required by FCP2 spec:
    /// - timestamp (RFC3339) - handled by logging layer
    /// - level - handled by logging layer
    /// - `correlation_id` (16-byte UUID; same as `trace_id` when available)
    /// - `zone_id` (when applicable)
    /// - `connector_id` + `operation_id` (when applicable)
    /// - decision + `reason_code` for policy decisions
    /// - `node_id` (local `TailscaleNodeId`)
    #[must_use]
    pub fn all_fields(&self) -> Vec<(String, String)> {
        let mut fields = Vec::new();

        // W3C trace context fields
        if let Some(ref trace_ctx) = self.trace_context {
            fields.push(("trace_id".to_string(), trace_ctx.trace_id_hex()));
            fields.push(("span_id".to_string(), trace_ctx.span_id_hex()));
            if let Some(ref state) = trace_ctx.trace_state {
                fields.push(("trace_state".to_string(), state.clone()));
            }
        }

        if let Some(ref id) = self.correlation_id {
            fields.push(("correlation_id".to_string(), id.clone()));
        }
        if let Some(ref id) = self.zone_id {
            fields.push(("zone_id".to_string(), id.clone()));
        }
        if let Some(ref id) = self.connector_id {
            fields.push(("connector_id".to_string(), id.clone()));
        }
        if let Some(ref id) = self.operation_id {
            fields.push(("operation_id".to_string(), id.clone()));
        }
        if let Some(id) = self.request_id {
            fields.push(("request_id".to_string(), id.to_string()));
        }
        if let Some(ref id) = self.principal_id {
            fields.push(("principal_id".to_string(), id.clone()));
        }
        if let Some(ref id) = self.node_id {
            fields.push(("node_id".to_string(), id.clone()));
        }
        if let Some(ref d) = self.decision {
            fields.push(("decision".to_string(), d.clone()));
        }
        if let Some(ref code) = self.reason_code {
            fields.push(("reason_code".to_string(), code.clone()));
        }

        fields.extend(self.fields.read().clone());
        fields
    }

    /// Apply context fields to the current tracing span.
    pub fn apply_to_span(&self) {
        let span = Span::current();

        if let Some(ref trace_ctx) = self.trace_context {
            span.record("trace_id", trace_ctx.trace_id_hex().as_str());
            span.record("span_id", trace_ctx.span_id_hex().as_str());
        }
        if let Some(ref id) = self.correlation_id {
            span.record("correlation_id", id.as_str());
        }
        if let Some(ref id) = self.zone_id {
            span.record("zone_id", id.as_str());
        }
        if let Some(ref id) = self.connector_id {
            span.record("connector_id", id.as_str());
        }
        if let Some(ref id) = self.operation_id {
            span.record("operation_id", id.as_str());
        }
        if let Some(id) = self.request_id {
            span.record("request_id", id.to_string().as_str());
        }
        if let Some(ref id) = self.principal_id {
            span.record("principal_id", id.as_str());
        }
        if let Some(ref id) = self.node_id {
            span.record("node_id", id.as_str());
        }
        if let Some(ref d) = self.decision {
            span.record("decision", d.as_str());
        }
        if let Some(ref code) = self.reason_code {
            span.record("reason_code", code.as_str());
        }
    }

    /// Get the trace context, if present.
    #[must_use]
    pub const fn get_trace_context(&self) -> Option<&TraceContext> {
        self.trace_context.as_ref()
    }

    /// Create a child context with a new span ID.
    ///
    /// If this context has a trace context, the child will have the same `trace_id`
    /// but a new `span_id`. Otherwise returns a clone of this context.
    #[must_use]
    pub fn child_span(&self) -> Self {
        let mut child = self.clone();
        if let Some(ref trace_ctx) = self.trace_context {
            let new_trace = trace_ctx.new_span();
            child.trace_context = Some(new_trace);
        }
        child
    }
}

/// Run a future with the given telemetry context.
pub async fn with_context<F, T>(ctx: TelemetryContext, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let key = push_context(Arc::new(ctx));
    let result = f.await;
    pop_context(&key);
    result
}

/// Get a clone of the current telemetry context.
///
/// Returns `None` if no context is set.
#[must_use]
pub fn current_context() -> Option<Arc<TelemetryContext>> {
    context_stacks()
        .lock()
        .get(&context_slot_key())
        .and_then(|stack| stack.last().cloned())
}

/// Get the current correlation ID.
#[must_use]
pub fn current_correlation_id() -> Option<String> {
    current_context().and_then(|ctx| ctx.correlation_id.clone())
}

/// Get the current connector ID.
#[must_use]
pub fn current_connector_id() -> Option<String> {
    current_context().and_then(|ctx| ctx.connector_id.clone())
}

/// Get the current request ID.
#[must_use]
pub fn current_request_id() -> Option<Uuid> {
    current_context().and_then(|ctx| ctx.request_id)
}

/// Get the current trace context.
#[must_use]
pub fn current_trace_context() -> Option<TraceContext> {
    current_context().and_then(|ctx| ctx.trace_context.clone())
}

/// Get the current trace ID as hex string.
#[must_use]
pub fn current_trace_id() -> Option<String> {
    current_trace_context().map(|ctx| ctx.trace_id_hex())
}

/// Get the current span ID as hex string.
#[must_use]
pub fn current_span_id() -> Option<String> {
    current_trace_context().map(|ctx| ctx.span_id_hex())
}

/// Context guard for RAII-style context management.
pub struct ContextGuard {
    _span: tracing::span::EnteredSpan,
}

impl ContextGuard {
    /// Create a new context guard with a span.
    #[must_use]
    pub fn new(ctx: &TelemetryContext, operation: &str) -> Self {
        let span = tracing::info_span!(
            "fcp_operation",
            operation = operation,
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            correlation_id = tracing::field::Empty,
            zone_id = tracing::field::Empty,
            connector_id = tracing::field::Empty,
            operation_id = tracing::field::Empty,
            request_id = tracing::field::Empty,
            principal_id = tracing::field::Empty,
            node_id = tracing::field::Empty,
            decision = tracing::field::Empty,
            reason_code = tracing::field::Empty,
        );

        let entered = span.entered();
        ctx.apply_to_span();

        Self { _span: entered }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let ctx = TelemetryContext::new()
            .correlation_id("test-123")
            .zone_id("work")
            .connector_id("my-connector");

        assert_eq!(ctx.correlation_id, Some("test-123".to_string()));
        assert_eq!(ctx.zone_id, Some("work".to_string()));
        assert_eq!(ctx.connector_id, Some("my-connector".to_string()));
    }

    #[test]
    fn test_all_fields() {
        let ctx = TelemetryContext::new()
            .correlation_id("corr-123")
            .connector_id("conn-456");

        ctx.add_field("custom", "value");

        let fields = ctx.all_fields();
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "correlation_id" && v == "corr-123")
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "connector_id" && v == "conn-456")
        );
        assert!(fields.iter().any(|(k, v)| k == "custom" && v == "value"));
    }

    #[test]
    fn test_with_correlation_id_generates_uuid() {
        let ctx = TelemetryContext::with_correlation_id();
        assert!(ctx.correlation_id.is_some());
        let id = ctx.correlation_id.unwrap();
        // UUID v4 format: 8-4-4-4-12 = 36 chars
        assert_eq!(id.len(), 36);
        assert!(id.contains('-'));
    }

    #[test]
    fn test_request_id_field() {
        let uuid = Uuid::new_v4();
        let ctx = TelemetryContext::new().request_id(uuid);
        assert_eq!(ctx.request_id, Some(uuid));
    }

    #[test]
    fn test_principal_id_field() {
        let ctx = TelemetryContext::new().principal_id("user@example.com");
        assert_eq!(ctx.principal_id, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_all_fields_complete() {
        let uuid = Uuid::new_v4();
        let ctx = TelemetryContext::new()
            .correlation_id("corr-1")
            .zone_id("zone-1")
            .connector_id("conn-1")
            .request_id(uuid)
            .principal_id("principal-1");

        let fields = ctx.all_fields();

        // Should have 5 standard fields
        assert_eq!(fields.len(), 5);
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "correlation_id" && v == "corr-1")
        );
        assert!(fields.iter().any(|(k, v)| k == "zone_id" && v == "zone-1"));
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "connector_id" && v == "conn-1")
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "request_id" && v == &uuid.to_string())
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "principal_id" && v == "principal-1")
        );
    }

    #[test]
    fn test_context_clone() {
        let ctx = TelemetryContext::new()
            .correlation_id("test-clone")
            .zone_id("work");
        ctx.add_field("custom_key", "custom_value");

        let cloned = ctx.clone();

        assert_eq!(cloned.correlation_id, ctx.correlation_id);
        assert_eq!(cloned.zone_id, ctx.zone_id);
        assert_eq!(cloned.all_fields().len(), ctx.all_fields().len());
    }

    #[test]
    fn test_multiple_custom_fields() {
        let ctx = TelemetryContext::new();
        ctx.add_field("field1", "value1");
        ctx.add_field("field2", "value2");
        ctx.add_field("field3", "value3");

        let fields = ctx.all_fields();
        assert_eq!(fields.len(), 3);
        assert!(fields.iter().any(|(k, v)| k == "field1" && v == "value1"));
        assert!(fields.iter().any(|(k, v)| k == "field2" && v == "value2"));
        assert!(fields.iter().any(|(k, v)| k == "field3" && v == "value3"));
    }

    #[test]
    fn test_context_default() {
        let ctx = TelemetryContext::default();
        assert!(ctx.correlation_id.is_none());
        assert!(ctx.zone_id.is_none());
        assert!(ctx.connector_id.is_none());
        assert!(ctx.request_id.is_none());
        assert!(ctx.principal_id.is_none());
        assert!(ctx.all_fields().is_empty());
    }

    #[test]
    fn test_context_guard_creation() {
        let ctx = TelemetryContext::new()
            .correlation_id("test-guard")
            .connector_id("test-connector");

        // ContextGuard creation should not panic
        let _guard = ContextGuard::new(&ctx, "test_operation");
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_context_async() {
        let ctx = TelemetryContext::new().correlation_id("async-test-123");

        let result = with_context(ctx, async {
            // Inside the context, we should be able to get the correlation ID
            let current = current_correlation_id();
            current.unwrap_or_default()
        })
        .await;

        assert_eq!(result, "async-test-123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_current_context_outside_scope() {
        // Outside of with_context, current_context should return None
        let ctx = current_context();
        assert!(ctx.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_current_connector_id() {
        let ctx = TelemetryContext::new().connector_id("my-connector-123");

        let result = with_context(ctx, async { current_connector_id().unwrap_or_default() }).await;

        assert_eq!(result, "my-connector-123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_current_request_id() {
        let uuid = Uuid::new_v4();
        let ctx = TelemetryContext::new().request_id(uuid);

        let result = with_context(ctx, async { current_request_id() }).await;

        assert_eq!(result, Some(uuid));
    }

    // ============ TraceContext tests ============

    #[test]
    fn test_trace_context_generate() {
        let ctx = TraceContext::generate();
        assert_eq!(ctx.trace_id.len(), TRACE_ID_SIZE);
        assert_eq!(ctx.span_id.len(), SPAN_ID_SIZE);
        assert!(ctx.is_sampled());
        assert!(ctx.trace_state.is_none());
    }

    #[test]
    fn test_trace_context_generate_unique() {
        let ctx1 = TraceContext::generate();
        let ctx2 = TraceContext::generate();
        assert_ne!(ctx1.trace_id, ctx2.trace_id);
        assert_ne!(ctx1.span_id, ctx2.span_id);
    }

    #[test]
    fn test_trace_context_new_span() {
        let parent = TraceContext::generate();
        let child = parent.new_span();

        // Same trace ID, different span ID
        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.span_id, child.span_id);
        assert_eq!(parent.trace_flags, child.trace_flags);
    }

    #[test]
    fn test_trace_context_new() {
        let trace_id = [1u8; TRACE_ID_SIZE];
        let span_id = [2u8; SPAN_ID_SIZE];
        let ctx = TraceContext::new(trace_id, span_id);

        assert_eq!(ctx.trace_id, trace_id);
        assert_eq!(ctx.span_id, span_id);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_trace_context_with_sampled() {
        let ctx = TraceContext::generate().with_sampled(false);
        assert!(!ctx.is_sampled());

        let ctx2 = ctx.with_sampled(true);
        assert!(ctx2.is_sampled());
    }

    #[test]
    fn test_trace_context_with_trace_state() {
        let ctx = TraceContext::generate().with_trace_state("vendor=value");
        assert_eq!(ctx.trace_state, Some("vendor=value".to_string()));
    }

    #[test]
    fn test_trace_context_to_traceparent() {
        let ctx = TraceContext::new([0xab; TRACE_ID_SIZE], [0xcd; SPAN_ID_SIZE]);
        let traceparent = ctx.to_traceparent();

        // Format: 00-{trace_id}-{span_id}-{flags}
        assert!(traceparent.starts_with("00-"));
        assert!(traceparent.contains("abababababababababababababababab"));
        assert!(traceparent.contains("cdcdcdcdcdcdcdcd"));
        assert!(traceparent.ends_with("-01")); // sampled
    }

    #[test]
    fn test_trace_context_from_traceparent_valid() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::from_traceparent(traceparent).unwrap();

        assert_eq!(ctx.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.span_id_hex(), "00f067aa0ba902b7");
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_trace_context_from_traceparent_unsampled() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let ctx = TraceContext::from_traceparent(traceparent).unwrap();
        assert!(!ctx.is_sampled());
    }

    #[test]
    fn test_trace_context_from_traceparent_invalid_version() {
        let traceparent = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let result = TraceContext::from_traceparent(traceparent);
        assert!(matches!(
            result,
            Err(TraceContextError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn test_trace_context_from_traceparent_invalid_parts() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7";
        let result = TraceContext::from_traceparent(traceparent);
        assert!(matches!(result, Err(TraceContextError::InvalidFormat(_))));
    }

    #[test]
    fn test_trace_context_from_traceparent_invalid_trace_id_length() {
        let traceparent = "00-4bf92f3577b34da6-00f067aa0ba902b7-01";
        let result = TraceContext::from_traceparent(traceparent);
        assert!(matches!(result, Err(TraceContextError::InvalidFormat(_))));
    }

    #[test]
    fn test_trace_context_from_traceparent_zero_trace_id() {
        let traceparent = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        let result = TraceContext::from_traceparent(traceparent);
        assert!(matches!(result, Err(TraceContextError::InvalidFormat(_))));
    }

    #[test]
    fn test_trace_context_from_traceparent_zero_span_id() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        let result = TraceContext::from_traceparent(traceparent);
        assert!(matches!(result, Err(TraceContextError::InvalidFormat(_))));
    }

    #[test]
    fn test_trace_context_roundtrip() {
        let original = TraceContext::generate().with_trace_state("k=v");
        let traceparent = original.to_traceparent();
        let parsed = TraceContext::from_traceparent(&traceparent).unwrap();

        assert_eq!(original.trace_id, parsed.trace_id);
        assert_eq!(original.span_id, parsed.span_id);
        assert_eq!(original.trace_flags, parsed.trace_flags);
        // Note: trace_state is not in traceparent
    }

    #[test]
    fn test_trace_context_default() {
        let ctx = TraceContext::default();
        assert_eq!(ctx.trace_id.len(), TRACE_ID_SIZE);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_trace_context_display() {
        let ctx = TraceContext::generate();
        let display = format!("{ctx}");
        assert!(display.starts_with("00-"));
    }

    #[test]
    fn test_trace_context_clone() {
        let ctx = TraceContext::generate().with_trace_state("test=value");
        let cloned = ctx.clone();

        assert_eq!(ctx.trace_id, cloned.trace_id);
        assert_eq!(ctx.span_id, cloned.span_id);
        assert_eq!(ctx.trace_state, cloned.trace_state);
    }

    #[test]
    fn test_trace_context_eq() {
        let trace_id = [42u8; TRACE_ID_SIZE];
        let span_id = [24u8; SPAN_ID_SIZE];
        let ctx1 = TraceContext::new(trace_id, span_id);
        let ctx2 = TraceContext::new(trace_id, span_id);
        assert_eq!(ctx1, ctx2);
    }

    #[test]
    fn test_trace_context_serde_roundtrip() {
        let ctx = TraceContext::generate().with_trace_state("serde=test");
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: TraceContext = serde_json::from_str(&json).unwrap();

        assert_eq!(ctx.trace_id, parsed.trace_id);
        assert_eq!(ctx.span_id, parsed.span_id);
        assert_eq!(ctx.trace_flags, parsed.trace_flags);
        assert_eq!(ctx.trace_state, parsed.trace_state);
    }

    #[test]
    fn test_trace_context_error_display() {
        let err = TraceContextError::InvalidFormat("test".to_string());
        assert!(format!("{err}").contains("test"));

        let err = TraceContextError::UnsupportedVersion("01".to_string());
        assert!(format!("{err}").contains("01"));
    }

    // ============ TelemetryContext with TraceContext tests ============

    #[test]
    fn test_telemetry_context_with_trace() {
        let ctx = TelemetryContext::with_trace();

        assert!(ctx.trace_context.is_some());
        assert!(ctx.correlation_id.is_some());

        // correlation_id should match trace_id hex
        let trace_ctx = ctx.trace_context.as_ref().unwrap();
        assert_eq!(
            ctx.correlation_id.as_ref().unwrap(),
            &trace_ctx.trace_id_hex()
        );
    }

    #[test]
    fn test_telemetry_context_trace_context_builder() {
        let trace_ctx = TraceContext::generate();
        let trace_id_hex = trace_ctx.trace_id_hex();

        let ctx = TelemetryContext::new().trace_context(trace_ctx);

        assert!(ctx.trace_context.is_some());
        // correlation_id should be set from trace_id
        assert_eq!(ctx.correlation_id, Some(trace_id_hex));
    }

    #[test]
    fn test_telemetry_context_operation_id() {
        let ctx = TelemetryContext::new().operation_id("fcp://schema/read");
        assert_eq!(ctx.operation_id, Some("fcp://schema/read".to_string()));
    }

    #[test]
    fn test_telemetry_context_node_id() {
        let ctx = TelemetryContext::new().node_id("n123456");
        assert_eq!(ctx.node_id, Some("n123456".to_string()));
    }

    #[test]
    fn test_telemetry_context_decision() {
        let ctx = TelemetryContext::new().decision("allow");
        assert_eq!(ctx.decision, Some("allow".to_string()));
    }

    #[test]
    fn test_telemetry_context_reason_code() {
        let ctx = TelemetryContext::new().reason_code("POLICY_EXPIRED");
        assert_eq!(ctx.reason_code, Some("POLICY_EXPIRED".to_string()));
    }

    #[test]
    fn test_telemetry_context_get_trace_context() {
        let trace_ctx = TraceContext::generate();
        let ctx = TelemetryContext::new().trace_context(trace_ctx.clone());

        let retrieved = ctx.get_trace_context().unwrap();
        assert_eq!(retrieved.trace_id, trace_ctx.trace_id);
    }

    #[test]
    fn test_telemetry_context_child_span() {
        let ctx = TelemetryContext::with_trace()
            .zone_id("test-zone")
            .connector_id("test-connector");

        let child = ctx.child_span();

        // Same trace_id, different span_id
        let parent_trace = ctx.trace_context.as_ref().unwrap();
        let child_trace = child.trace_context.as_ref().unwrap();
        assert_eq!(parent_trace.trace_id, child_trace.trace_id);
        assert_ne!(parent_trace.span_id, child_trace.span_id);

        // Other fields preserved
        assert_eq!(child.zone_id, ctx.zone_id);
        assert_eq!(child.connector_id, ctx.connector_id);
    }

    #[test]
    fn test_telemetry_context_all_fields_with_trace() {
        let ctx = TelemetryContext::with_trace()
            .zone_id("zone-1")
            .decision("deny")
            .reason_code("EXPIRED");

        let fields = ctx.all_fields();

        // Should include trace_id, span_id, correlation_id, zone_id, decision, reason_code
        assert!(fields.iter().any(|(k, _)| k == "trace_id"));
        assert!(fields.iter().any(|(k, _)| k == "span_id"));
        assert!(fields.iter().any(|(k, _)| k == "correlation_id"));
        assert!(fields.iter().any(|(k, v)| k == "zone_id" && v == "zone-1"));
        assert!(fields.iter().any(|(k, v)| k == "decision" && v == "deny"));
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "reason_code" && v == "EXPIRED")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_current_trace_context() {
        let ctx = TelemetryContext::with_trace();
        let expected_trace_id = ctx.trace_context.as_ref().unwrap().trace_id_hex();

        let result = with_context(ctx, async {
            current_trace_context().map(|t| t.trace_id_hex())
        })
        .await;

        assert_eq!(result, Some(expected_trace_id));
    }

    #[fcp_async_core::runtime::test]
    async fn test_current_trace_id() {
        let ctx = TelemetryContext::with_trace();
        let expected_trace_id = ctx.trace_context.as_ref().unwrap().trace_id_hex();

        let result = with_context(ctx, async { current_trace_id() }).await;

        assert_eq!(result, Some(expected_trace_id));
    }

    #[fcp_async_core::runtime::test]
    async fn test_current_span_id() {
        let ctx = TelemetryContext::with_trace();
        let expected_span_id = ctx.trace_context.as_ref().unwrap().span_id_hex();

        let result = with_context(ctx, async { current_span_id() }).await;

        assert_eq!(result, Some(expected_span_id));
    }

    // ============ Serde deserialization error tests ============

    #[test]
    fn test_trace_context_serde_invalid_trace_id_length() {
        // trace_id too short
        let json = r#"{"trace_id":"abcd","span_id":"0123456789abcdef","trace_flags":1}"#;
        let result: Result<TraceContext, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_trace_context_serde_invalid_span_id_length() {
        // span_id too short
        let json =
            r#"{"trace_id":"0123456789abcdef0123456789abcdef","span_id":"abcd","trace_flags":1}"#;
        let result: Result<TraceContext, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_trace_context_serde_invalid_hex() {
        // Invalid hex in trace_id
        let json = r#"{"trace_id":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","span_id":"0123456789abcdef","trace_flags":1}"#;
        let result: Result<TraceContext, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_trace_context_serde_missing_fields() {
        // Missing span_id
        let json = r#"{"trace_id":"0123456789abcdef0123456789abcdef","trace_flags":1}"#;
        let result: Result<TraceContext, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_trace_context_serde_skip_none_trace_state() {
        let ctx = TraceContext::generate(); // No trace_state
        let json = serde_json::to_string(&ctx).unwrap();
        // trace_state should not appear in JSON when None
        assert!(!json.contains("trace_state"));
    }

    #[test]
    fn test_trace_context_serde_with_trace_state() {
        let ctx = TraceContext::generate().with_trace_state("vendor=test,foo=bar");
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("trace_state"));
        assert!(json.contains("vendor=test,foo=bar"));

        let parsed: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.trace_state, Some("vendor=test,foo=bar".to_string()));
    }

    // ============ TraceContextError additional tests ============

    #[test]
    fn test_trace_context_error_debug() {
        let err = TraceContextError::InvalidFormat("test debug".to_string());
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("InvalidFormat"));
        assert!(debug_str.contains("test debug"));

        let err2 = TraceContextError::UnsupportedVersion("02".to_string());
        let debug_str2 = format!("{err2:?}");
        assert!(debug_str2.contains("UnsupportedVersion"));
        assert!(debug_str2.contains("02"));
    }

    // ============ TraceContext edge cases ============

    #[test]
    fn test_trace_context_from_traceparent_invalid_hex_in_span_id() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-gggggggggggggggg-01";
        let result = TraceContext::from_traceparent(traceparent);
        assert!(matches!(result, Err(TraceContextError::InvalidFormat(_))));
    }

    #[test]
    fn test_trace_context_from_traceparent_invalid_flags_length() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1";
        let result = TraceContext::from_traceparent(traceparent);
        assert!(matches!(result, Err(TraceContextError::InvalidFormat(_))));
    }

    #[test]
    fn test_trace_context_all_flags_set() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-ff";
        let ctx = TraceContext::from_traceparent(traceparent).unwrap();
        assert_eq!(ctx.trace_flags, 0xff);
        assert!(ctx.is_sampled()); // bit 0 is set
    }

    #[test]
    fn test_trace_context_trace_id_hex_format() {
        let ctx = TraceContext::new(
            [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ],
            [0xaa; SPAN_ID_SIZE],
        );
        assert_eq!(ctx.trace_id_hex(), "123456789abcdef01122334455667788");
    }

    #[test]
    fn test_trace_context_span_id_hex_format() {
        let ctx = TraceContext::new(
            [0xaa; TRACE_ID_SIZE],
            [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        );
        assert_eq!(ctx.span_id_hex(), "123456789abcdef0");
    }

    // ============ TelemetryContext additional edge cases ============

    #[test]
    fn test_telemetry_context_child_span_without_trace() {
        let ctx = TelemetryContext::new().zone_id("zone-1");
        let child = ctx.child_span();

        // Without trace_context, child_span just clones
        assert!(child.trace_context.is_none());
        assert_eq!(child.zone_id, Some("zone-1".to_string()));
    }

    #[test]
    fn test_telemetry_context_all_fields_with_trace_state() {
        let trace_ctx = TraceContext::generate().with_trace_state("vendor=value");
        let ctx = TelemetryContext::new().trace_context(trace_ctx);

        let fields = ctx.all_fields();
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "trace_state" && v == "vendor=value")
        );
    }

    #[test]
    fn test_telemetry_context_full_fcp_spec_fields() {
        // Test all fields required by FCP2 observability spec
        let uuid = Uuid::new_v4();
        let trace_ctx = TraceContext::generate();

        let ctx = TelemetryContext::new()
            .trace_context(trace_ctx)
            .zone_id("work-zone")
            .connector_id("github-connector")
            .operation_id("fcp://github/list-repos")
            .request_id(uuid)
            .principal_id("user@example.com")
            .node_id("n1234567890")
            .decision("allow")
            .reason_code("CAPABILITY_VALID");

        ctx.add_field("custom_field", "custom_value");

        let fields = ctx.all_fields();

        // Verify all FCP2-required fields are present
        assert!(fields.iter().any(|(k, _)| k == "trace_id"));
        assert!(fields.iter().any(|(k, _)| k == "span_id"));
        assert!(fields.iter().any(|(k, _)| k == "correlation_id"));
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "zone_id" && v == "work-zone")
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "connector_id" && v == "github-connector")
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "operation_id" && v == "fcp://github/list-repos")
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "request_id" && v == &uuid.to_string())
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "principal_id" && v == "user@example.com")
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "node_id" && v == "n1234567890")
        );
        assert!(fields.iter().any(|(k, v)| k == "decision" && v == "allow"));
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "reason_code" && v == "CAPABILITY_VALID")
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "custom_field" && v == "custom_value")
        );
    }

    #[test]
    fn test_context_guard_with_all_fields() {
        let trace_ctx = TraceContext::generate();
        let uuid = Uuid::new_v4();

        let ctx = TelemetryContext::new()
            .trace_context(trace_ctx)
            .zone_id("test-zone")
            .connector_id("test-connector")
            .operation_id("test-operation")
            .request_id(uuid)
            .principal_id("test-principal")
            .node_id("test-node")
            .decision("allow")
            .reason_code("TEST_REASON");

        // ContextGuard creation with all fields should not panic
        let _guard = ContextGuard::new(&ctx, "test_operation_with_all_fields");
    }

    #[fcp_async_core::runtime::test]
    async fn test_nested_context_propagation() {
        let outer_ctx = TelemetryContext::with_trace().zone_id("outer-zone");
        let outer_trace_id = outer_ctx.trace_context.as_ref().unwrap().trace_id_hex();

        let result = with_context(outer_ctx, async {
            let inner_ctx = TelemetryContext::with_trace().zone_id("inner-zone");

            with_context(inner_ctx, async {
                // Inside inner context, we should see inner values
                current_context()
                    .and_then(|c| c.zone_id.clone())
                    .unwrap_or_default()
            })
            .await
        })
        .await;

        // Inner context should have been active
        assert_eq!(result, "inner-zone");

        // Outer trace_id should be different from inner
        let _ = outer_trace_id; // Just verify we captured it
    }

    #[fcp_async_core::runtime::test]
    async fn test_context_not_leaked_after_scope() {
        let ctx = TelemetryContext::new().zone_id("scoped-zone");

        with_context(ctx, async {
            assert!(current_context().is_some());
        })
        .await;

        // After scope ends, context should not be available
        assert!(current_context().is_none());
    }

    #[test]
    fn test_telemetry_context_debug() {
        let ctx = TelemetryContext::with_trace()
            .zone_id("debug-zone")
            .connector_id("debug-connector");

        let debug_str = format!("{ctx:?}");
        assert!(debug_str.contains("TelemetryContext"));
        assert!(debug_str.contains("debug-zone"));
        assert!(debug_str.contains("debug-connector"));
    }
}
