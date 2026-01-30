//! SDK Prelude - Import everything you need for connector development.
//!
//! # Usage
//!
//! ```ignore
//! use fcp_sdk::prelude::*;
//! ```
//!
//! This imports all commonly used types for implementing FCP connectors.

// Core traits
pub use crate::{
    BaseConnector, Bidirectional, FcpConnector, Polling, RequestResponse, Streaming, Webhook,
    async_trait,
};

// Error types
pub use crate::{FcpError, FcpResult};

// Protocol messages
pub use crate::{
    HandshakeRequest, HandshakeResponse, Introspection, InvokeContext, InvokeRequest,
    InvokeResponse, InvokeStatus, ShutdownAck, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};

// Cost and availability
pub use crate::{
    CostEstimate, CostEstimateConfidence, CurrencyCost, ResourceAvailability, UsageMetric,
    UsageMetricKind,
};

// Rate limits
pub use crate::{
    RateLimitConfig, RateLimitDeclarations, RateLimitEnforcement, RateLimitPool, RateLimitScope,
    RateLimitStatus, RateLimitUnit,
};

// Rate limit SDK helpers
pub use crate::ratelimit::{RateLimitError, RateLimitPoolBuilder, RateLimitTracker};

// Events
pub use crate::{EventAck, EventCaps, EventData, EventEnvelope, EventNack, EventStream};
pub use fcp_core::{ThreadInfo, ThreadKind};

// Health
pub use crate::{ConnectorMetrics, HealthSnapshot, HealthState, SelfCheckReport, SelfCheckStatus};

// Identifiers
pub use crate::{ConnectorId, InstanceId, ObjectId, RequestId, ZoneId};

// Capability tokens
pub use crate::CapabilityToken;

// Provenance
pub use crate::{Provenance, TaintFlag, TaintLevel, TrustLevel};

// Principal
pub use crate::Principal;

// Archetypes and state models
pub use crate::{
    ConnectorArchetype, ConnectorCrdtType, ConnectorRuntimeFormat, ConnectorStateModel, CursorState,
};

// Streaming helpers
pub use crate::streaming::{
    AckResult, BufferLimits, EventStreamManager, NackResult, ReplayError, SubscribeOutcome,
};

// Runtime supervision helpers
pub use crate::runtime::{
    CursorLease, CursorStore, CursorStoreBackend, CursorStoreError, HealthTracker,
    HealthTransition, InMemoryCursorStoreBackend, InMemoryPollingCursor, InMemoryStreamingSession,
    PollResult, PollingCursor, PollingSupervisor, PollingSupervisorStats, StreamingConnection,
    StreamingError, StreamingHealthState, StreamingSession, StreamingSupervisor,
    StreamingSupervisorStats, SupervisorConfig, SupervisorOutcome,
};

// Schema validation helpers
pub use crate::{
    Limits, SchemaValidationError, SchemaValidator, enforce_limits, validate_input,
    validate_input_with_limits, validate_json_schema, validate_output, validate_output_with_limits,
};

// Formatting helpers
pub use crate::{
    ErrorClass, FormatError, FormatMode, Formatter, RenderResult, classify_error_message,
    is_parse_error_message,
};

// Retry helpers
pub use crate::{RetryDecision, RetryPolicy};

// External crates commonly needed
pub use serde::{Deserialize, Serialize};
pub use serde_json::json;
pub use tracing::{debug, error, info, instrument, trace, warn};
