//! Distributed tracing with span creation and context propagation.
//!
//! Provides W3C Trace Context compliant distributed tracing.

use std::collections::HashMap;
use std::hash::BuildHasher;

use opentelemetry::{
    KeyValue, global,
    trace::{Span, SpanKind, Status, Tracer},
};
use rand::Rng;

/// W3C Trace Context header names.
pub const TRACEPARENT_HEADER: &str = "traceparent";
pub const TRACESTATE_HEADER: &str = "tracestate";

/// Extract trace context from headers (W3C Trace Context format).
#[must_use]
pub fn extract_trace_context<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
) -> Option<TraceContext> {
    let traceparent = headers.get(TRACEPARENT_HEADER)?;
    TraceContext::from_traceparent(traceparent)
}

/// Inject trace context into headers.
pub fn inject_trace_context<S: BuildHasher>(
    ctx: &TraceContext,
    headers: &mut HashMap<String, String, S>,
) {
    headers.insert(TRACEPARENT_HEADER.to_string(), ctx.to_traceparent());
    if let Some(ref state) = ctx.trace_state {
        headers.insert(TRACESTATE_HEADER.to_string(), state.clone());
    }
}

/// W3C Trace Context representation.
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Trace ID (32 hex chars).
    pub trace_id: String,

    /// Parent span ID (16 hex chars).
    pub parent_span_id: String,

    /// Trace flags.
    pub trace_flags: u8,

    /// Optional trace state.
    pub trace_state: Option<String>,
}

impl TraceContext {
    /// Create a new trace context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trace_id: generate_trace_id(),
            parent_span_id: generate_span_id(),
            trace_flags: 0x01, // Sampled
            trace_state: None,
        }
    }

    /// Parse from traceparent header value.
    ///
    /// Format: `{version}-{trace_id}-{parent_span_id}-{trace_flags}`
    #[must_use]
    pub fn from_traceparent(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = parts[0];
        if version != "00" {
            return None; // Only support version 00
        }

        let trace_id = parts[1];
        let parent_span_id = parts[2];
        let trace_flags = u8::from_str_radix(parts[3], 16).ok()?;

        if trace_id.len() != 32 || parent_span_id.len() != 16 {
            return None;
        }

        Some(Self {
            trace_id: trace_id.to_string(),
            parent_span_id: parent_span_id.to_string(),
            trace_flags,
            trace_state: None,
        })
    }

    /// Convert to traceparent header value.
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.parent_span_id, self.trace_flags
        )
    }

    /// Check if this trace is sampled.
    #[must_use]
    pub const fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }

    /// Create a child context with a new span ID.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            parent_span_id: generate_span_id(),
            trace_flags: self.trace_flags,
            trace_state: self.trace_state.clone(),
        }
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random trace ID (32 hex chars).
fn generate_trace_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());

    let random: u64 = rand::rng().random();
    let timestamp = u64::try_from(timestamp).unwrap_or(u64::MAX);
    format!("{timestamp:016x}{random:016x}")
}

/// Generate a random span ID (16 hex chars).
fn generate_span_id() -> String {
    format!("{:016x}", rand::rng().random::<u64>())
}

/// FCP operation span builder.
pub struct FcpSpan {
    name: String,
    kind: SpanKind,
    attributes: Vec<KeyValue>,
}

impl FcpSpan {
    /// Create a new span builder.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: SpanKind::Internal,
            attributes: Vec::new(),
        }
    }

    /// Set span kind.
    #[must_use]
    pub const fn kind(mut self, kind: SpanKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set as client span.
    #[must_use]
    pub const fn client(mut self) -> Self {
        self.kind = SpanKind::Client;
        self
    }

    /// Set as server span.
    #[must_use]
    pub const fn server(mut self) -> Self {
        self.kind = SpanKind::Server;
        self
    }

    /// Add an attribute.
    #[must_use]
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes
            .push(KeyValue::new(key.into(), value.into()));
        self
    }

    /// Set connector ID attribute.
    #[must_use]
    pub fn connector_id(self, id: impl Into<String>) -> Self {
        self.attribute("fcp.connector_id", id)
    }

    /// Set operation attribute.
    #[must_use]
    pub fn operation(self, op: impl Into<String>) -> Self {
        self.attribute("fcp.operation", op)
    }

    /// Set request ID attribute.
    #[must_use]
    pub fn request_id(self, id: impl Into<String>) -> Self {
        self.attribute("fcp.request_id", id)
    }

    /// Start the span and return a guard.
    #[must_use]
    pub fn start(self) -> SpanGuard {
        let tracer = global::tracer("fcp-telemetry");

        let mut span_builder = tracer.span_builder(self.name);
        span_builder.span_kind = Some(self.kind);

        let mut span = span_builder.start(&tracer);

        for attr in &self.attributes {
            span.set_attribute(attr.clone());
        }

        SpanGuard { span: Some(span) }
    }
}

/// RAII guard for a span.
pub struct SpanGuard {
    span: Option<opentelemetry::global::BoxedSpan>,
}

impl SpanGuard {
    /// Set an attribute on the span.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        if let Some(ref mut span) = self.span {
            span.set_attribute(KeyValue::new(key.into(), value.into()));
        }
    }

    /// Record an error on the span.
    pub fn record_error(&mut self, error: &str) {
        if let Some(ref mut span) = self.span {
            span.set_status(Status::error(error.to_string()));
        }
    }

    /// Mark the span as successful.
    pub fn set_ok(&mut self) {
        if let Some(ref mut span) = self.span {
            span.set_status(Status::Ok);
        }
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        if let Some(mut span) = self.span.take() {
            span.end();
        }
    }
}

/// Create a tracing span with FCP context.
#[macro_export]
macro_rules! fcp_span {
    ($name:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::info_span!(
            $name,
            $($key = %$value,)*
            otel.kind = "internal",
        )
    };
}

/// Create a client span.
#[macro_export]
macro_rules! fcp_client_span {
    ($name:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::info_span!(
            $name,
            $($key = %$value,)*
            otel.kind = "client",
        )
    };
}

/// Create a server span.
#[macro_export]
macro_rules! fcp_server_span {
    ($name:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::info_span!(
            $name,
            $($key = %$value,)*
            otel.kind = "server",
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_roundtrip() {
        let ctx = TraceContext::new();
        let traceparent = ctx.to_traceparent();
        let parsed = TraceContext::from_traceparent(&traceparent).unwrap();

        assert_eq!(ctx.trace_id, parsed.trace_id);
        assert_eq!(ctx.parent_span_id, parsed.parent_span_id);
        assert_eq!(ctx.trace_flags, parsed.trace_flags);
    }

    #[test]
    fn test_parse_traceparent() {
        let value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::from_traceparent(value).unwrap();

        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent_span_id, "00f067aa0ba902b7");
        assert_eq!(ctx.trace_flags, 0x01);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_child_context() {
        let parent = TraceContext::new();
        let child = parent.child();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.parent_span_id, child.parent_span_id);
    }

    #[test]
    fn test_inject_extract() {
        let ctx = TraceContext::new();
        let mut headers = HashMap::new();
        inject_trace_context(&ctx, &mut headers);

        let extracted = extract_trace_context(&headers).unwrap();
        assert_eq!(ctx.trace_id, extracted.trace_id);
    }

    #[test]
    fn test_trace_context_default() {
        let ctx = TraceContext::default();
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.parent_span_id.len(), 16);
        assert_eq!(ctx.trace_flags, 0x01); // Sampled by default
    }

    #[test]
    fn test_trace_context_new_generates_unique_ids() {
        let ctx1 = TraceContext::new();
        let ctx2 = TraceContext::new();

        // Different contexts should have different trace IDs
        assert_ne!(ctx1.trace_id, ctx2.trace_id);
    }

    #[test]
    fn test_trace_id_format() {
        let ctx = TraceContext::new();
        // Trace ID should be 32 hex chars
        assert_eq!(ctx.trace_id.len(), 32);
        assert!(ctx.trace_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_span_id_format() {
        let ctx = TraceContext::new();
        // Span ID should be 16 hex chars
        assert_eq!(ctx.parent_span_id.len(), 16);
        assert!(ctx.parent_span_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_traceparent_format() {
        let ctx = TraceContext::new();
        let traceparent = ctx.to_traceparent();

        // Format: 00-{trace_id}-{span_id}-{flags}
        let parts: Vec<&str> = traceparent.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "00"); // version
        assert_eq!(parts[1].len(), 32); // trace_id
        assert_eq!(parts[2].len(), 16); // span_id
        assert_eq!(parts[3].len(), 2); // flags (hex byte)
    }

    #[test]
    fn test_parse_traceparent_invalid_version() {
        let value = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(TraceContext::from_traceparent(value).is_none());
    }

    #[test]
    fn test_parse_traceparent_invalid_parts() {
        // Too few parts
        let value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7";
        assert!(TraceContext::from_traceparent(value).is_none());

        // Too many parts
        let value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra";
        assert!(TraceContext::from_traceparent(value).is_none());
    }

    #[test]
    fn test_parse_traceparent_invalid_trace_id_length() {
        // Short trace ID
        let value = "00-4bf92f3577b34da6a3ce929d0e-00f067aa0ba902b7-01";
        assert!(TraceContext::from_traceparent(value).is_none());
    }

    #[test]
    fn test_parse_traceparent_invalid_span_id_length() {
        // Short span ID
        let value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba9-01";
        assert!(TraceContext::from_traceparent(value).is_none());
    }

    #[test]
    fn test_parse_traceparent_invalid_flags() {
        // Invalid hex in flags
        let value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz";
        assert!(TraceContext::from_traceparent(value).is_none());
    }

    #[test]
    fn test_is_sampled_true() {
        let mut ctx = TraceContext::new();
        ctx.trace_flags = 0x01;
        assert!(ctx.is_sampled());

        ctx.trace_flags = 0x03; // Multiple flags set including sampled
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_is_sampled_false() {
        let mut ctx = TraceContext::new();
        ctx.trace_flags = 0x00;
        assert!(!ctx.is_sampled());

        ctx.trace_flags = 0x02; // Other flag, but not sampled
        assert!(!ctx.is_sampled());
    }

    #[test]
    fn test_child_preserves_trace_state() {
        let mut parent = TraceContext::new();
        parent.trace_state = Some("vendor=value".to_string());

        let child = parent.child();
        assert_eq!(child.trace_state, Some("vendor=value".to_string()));
    }

    #[test]
    fn test_child_preserves_trace_flags() {
        let mut parent = TraceContext::new();
        parent.trace_flags = 0x03;

        let child = parent.child();
        assert_eq!(child.trace_flags, 0x03);
    }

    #[test]
    fn test_inject_with_trace_state() {
        let mut ctx = TraceContext::new();
        ctx.trace_state = Some("vendor1=value1,vendor2=value2".to_string());

        let mut headers = HashMap::new();
        inject_trace_context(&ctx, &mut headers);

        assert!(headers.contains_key(TRACEPARENT_HEADER));
        assert!(headers.contains_key(TRACESTATE_HEADER));
        assert_eq!(
            headers.get(TRACESTATE_HEADER).unwrap(),
            "vendor1=value1,vendor2=value2"
        );
    }

    #[test]
    fn test_inject_without_trace_state() {
        let ctx = TraceContext::new(); // No trace_state

        let mut headers = HashMap::new();
        inject_trace_context(&ctx, &mut headers);

        assert!(headers.contains_key(TRACEPARENT_HEADER));
        assert!(!headers.contains_key(TRACESTATE_HEADER));
    }

    #[test]
    fn test_extract_missing_traceparent() {
        let headers = HashMap::new();
        assert!(extract_trace_context(&headers).is_none());
    }

    #[test]
    fn test_extract_invalid_traceparent() {
        let mut headers = HashMap::new();
        headers.insert(TRACEPARENT_HEADER.to_string(), "invalid".to_string());
        assert!(extract_trace_context(&headers).is_none());
    }

    #[test]
    fn test_header_constants() {
        assert_eq!(TRACEPARENT_HEADER, "traceparent");
        assert_eq!(TRACESTATE_HEADER, "tracestate");
    }

    #[test]
    fn test_fcp_span_builder() {
        let span = FcpSpan::new("test_operation")
            .connector_id("my-connector")
            .operation("read")
            .request_id("req-123");

        // Verify attributes were added
        assert_eq!(span.name, "test_operation");
        assert_eq!(span.attributes.len(), 3);
    }

    #[test]
    fn test_fcp_span_kind_client() {
        let span = FcpSpan::new("client_call").client();
        assert!(matches!(span.kind, SpanKind::Client));
    }

    #[test]
    fn test_fcp_span_kind_server() {
        let span = FcpSpan::new("server_handler").server();
        assert!(matches!(span.kind, SpanKind::Server));
    }

    #[test]
    fn test_fcp_span_kind_internal() {
        let span = FcpSpan::new("internal_op");
        assert!(matches!(span.kind, SpanKind::Internal));
    }

    #[test]
    fn test_fcp_span_kind_explicit() {
        let span = FcpSpan::new("custom").kind(SpanKind::Producer);
        assert!(matches!(span.kind, SpanKind::Producer));
    }

    #[test]
    fn test_fcp_span_custom_attribute() {
        let span = FcpSpan::new("test")
            .attribute("custom_key", "custom_value")
            .attribute("another_key", "another_value");

        assert_eq!(span.attributes.len(), 2);
    }

    #[test]
    fn test_fcp_span_start() {
        let span = FcpSpan::new("test_span")
            .connector_id("test")
            .operation("read");

        // Start should return a SpanGuard
        let _guard = span.start();
    }

    #[test]
    fn test_span_guard_set_attribute() {
        let span = FcpSpan::new("test_span");
        let mut guard = span.start();

        // Should not panic
        guard.set_attribute("dynamic_key", "dynamic_value");
    }

    #[test]
    fn test_span_guard_record_error() {
        let span = FcpSpan::new("test_span");
        let mut guard = span.start();

        // Should not panic
        guard.record_error("Something went wrong");
    }

    #[test]
    fn test_span_guard_set_ok() {
        let span = FcpSpan::new("test_span");
        let mut guard = span.start();

        // Should not panic
        guard.set_ok();
    }

    #[test]
    fn test_span_guard_drop() {
        {
            let span = FcpSpan::new("drop_test");
            let _guard = span.start();
            // Guard is dropped here
        }
        // If we reach here without panic, drop worked
    }

    #[test]
    fn test_trace_context_clone() {
        let ctx = TraceContext {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            parent_span_id: "00f067aa0ba902b7".to_string(),
            trace_flags: 0x01,
            trace_state: Some("key=value".to_string()),
        };

        let cloned = ctx.clone();
        assert_eq!(ctx.trace_id, cloned.trace_id);
        assert_eq!(ctx.parent_span_id, cloned.parent_span_id);
        assert_eq!(ctx.trace_flags, cloned.trace_flags);
        assert_eq!(ctx.trace_state, cloned.trace_state);
    }

    #[test]
    fn test_trace_context_debug() {
        let ctx = TraceContext::new();
        let debug_str = format!("{ctx:?}");
        assert!(debug_str.contains("TraceContext"));
        assert!(debug_str.contains("trace_id"));
    }

    #[test]
    fn test_multiple_child_contexts() {
        let parent = TraceContext::new();
        let child1 = parent.child();
        let child2 = parent.child();

        // Children should have same trace_id as parent
        assert_eq!(child1.trace_id, parent.trace_id);
        assert_eq!(child2.trace_id, parent.trace_id);

        // But different span IDs from each other
        assert_ne!(child1.parent_span_id, child2.parent_span_id);
    }

    #[test]
    fn test_grandchild_context() {
        let parent = TraceContext::new();
        let child = parent.child();
        let grandchild = child.child();

        // All should have same trace_id
        assert_eq!(parent.trace_id, grandchild.trace_id);

        // Grandchild should have different span_id from both parent and child
        assert_ne!(grandchild.parent_span_id, parent.parent_span_id);
        assert_ne!(grandchild.parent_span_id, child.parent_span_id);
    }

    #[test]
    fn test_w3c_traceparent_example_unsampled() {
        let value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let ctx = TraceContext::from_traceparent(value).unwrap();

        assert_eq!(ctx.trace_flags, 0x00);
        assert!(!ctx.is_sampled());
    }

    #[test]
    fn test_roundtrip_with_all_fields() {
        let mut original = TraceContext::new();
        original.trace_state = Some("vendor=data".to_string());

        let mut headers = HashMap::new();
        inject_trace_context(&original, &mut headers);

        let extracted = extract_trace_context(&headers).unwrap();

        assert_eq!(original.trace_id, extracted.trace_id);
        assert_eq!(original.parent_span_id, extracted.parent_span_id);
        assert_eq!(original.trace_flags, extracted.trace_flags);
        // Note: extract doesn't preserve trace_state as it's not in traceparent
    }
}
