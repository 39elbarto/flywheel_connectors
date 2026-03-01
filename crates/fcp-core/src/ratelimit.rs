//! Rate limiting primitives for FCP2.
//!
//! This module defines the canonical, platform-facing types used to represent rate limit
//! violations and backpressure signals. Enforcement algorithms live in `fcp-ratelimit`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::{ConnectorId, ObjectId, OperationId, ZoneId};
use thiserror::Error;

/// The type of limit that was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitType {
    /// Requests per time window (e.g., RPM/RPS).
    Rpm,
    /// Maximum number of concurrent operations.
    Concurrent,
    /// Burst allowance exceeded (token bucket capacity depleted).
    Burst,
    /// Quota exceeded (tokens/bytes/compute budget).
    Quota,
}

/// Rate limit backpressure level.
///
/// These levels are intended to be computed from utilization and used to drive:
/// - warning logs/metrics (`warning`),
/// - soft shaping (`soft_limit`),
/// - hard rejection (`hard_limit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureLevel {
    Normal,
    Warning,
    SoftLimit,
    HardLimit,
}

/// Errors for rate limit declaration validation.
#[derive(Debug, Error)]
pub enum RateLimitDeclarationError {
    #[error("rate limit pool id must not be empty")]
    EmptyPoolId,
    #[error("duplicate rate limit pool id `{id}`")]
    DuplicatePoolId { id: String },
    #[error("rate limit pool id must not be empty for tool `{tool}`")]
    EmptyToolPoolId { tool: String },
    #[error("tool name must not be empty")]
    EmptyToolName,
    #[error("tool `{tool}` must map to at least one pool id")]
    EmptyToolPools { tool: String },
    #[error("tool `{tool}` references unknown pool id `{pool}`")]
    UnknownPool { tool: String, pool: String },
    #[error("rate limit requests must be > 0")]
    ZeroRequests,
    #[error("rate limit window must be > 0")]
    ZeroWindow,
    #[error("rate limit burst must be > 0 when provided")]
    ZeroBurst,
}

/// Declarative rate limit configuration for connectors.
///
/// This is used by SDKs/hosts to surface operator-visible limits and to
/// align tool planning with external service constraints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitDeclarations {
    /// Named rate limit pools.
    pub limits: Vec<RateLimitPool>,
    /// Tool name -> pool ids that the tool consumes.
    pub tool_pool_map: HashMap<String, Vec<String>>,
}

impl RateLimitDeclarations {
    /// Return true if there are no declared limits or tool mappings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.limits.is_empty() && self.tool_pool_map.is_empty()
    }

    /// Validate declarations for internal consistency.
    ///
    /// # Errors
    /// Returns `RateLimitDeclarationError` if any declaration is invalid.
    pub fn validate(&self) -> Result<(), RateLimitDeclarationError> {
        let mut pool_ids = HashSet::new();
        for pool in &self.limits {
            pool.validate()?;
            if !pool_ids.insert(pool.id.clone()) {
                return Err(RateLimitDeclarationError::DuplicatePoolId {
                    id: pool.id.clone(),
                });
            }
        }

        for (tool, pools) in &self.tool_pool_map {
            if tool.is_empty() {
                return Err(RateLimitDeclarationError::EmptyToolName);
            }
            if pools.is_empty() {
                return Err(RateLimitDeclarationError::EmptyToolPools { tool: tool.clone() });
            }
            for pool_id in pools {
                if pool_id.is_empty() {
                    return Err(RateLimitDeclarationError::EmptyToolPoolId { tool: tool.clone() });
                }
                if !pool_ids.contains(pool_id) {
                    return Err(RateLimitDeclarationError::UnknownPool {
                        tool: tool.clone(),
                        pool: pool_id.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

/// A named rate limit pool declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPool {
    /// Unique identifier for this limit (e.g., "`discord_api`", "`openai_tokens`").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Rate limit configuration.
    pub config: RateLimitConfig,
    /// How the limit is enforced.
    pub enforcement: RateLimitEnforcement,
    /// Scope of the limit across instances/credentials.
    pub scope: RateLimitScope,
}

impl RateLimitPool {
    /// Validate a pool declaration.
    ///
    /// # Errors
    /// Returns `RateLimitDeclarationError` for invalid fields.
    pub fn validate(&self) -> Result<(), RateLimitDeclarationError> {
        if self.id.is_empty() {
            return Err(RateLimitDeclarationError::EmptyPoolId);
        }
        self.config.validate()?;
        Ok(())
    }
}

/// Rate limit configuration (declarative).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per window.
    pub requests: u32,
    /// Window duration.
    pub window: Duration,
    /// Optional burst allowance (token bucket).
    pub burst: Option<u32>,
    /// Unit of measurement.
    pub unit: RateLimitUnit,
}

impl RateLimitConfig {
    /// Validate a rate limit configuration.
    ///
    /// # Errors
    /// Returns `RateLimitDeclarationError` for invalid config.
    pub const fn validate(&self) -> Result<(), RateLimitDeclarationError> {
        if self.requests == 0 {
            return Err(RateLimitDeclarationError::ZeroRequests);
        }
        if self.window.is_zero() {
            return Err(RateLimitDeclarationError::ZeroWindow);
        }
        if let Some(burst) = self.burst {
            if burst == 0 {
                return Err(RateLimitDeclarationError::ZeroBurst);
            }
        }
        Ok(())
    }
}

/// Unit of measurement for rate limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitUnit {
    /// Number of API requests.
    Requests,
    /// Tokens (for LLM APIs).
    Tokens,
    /// Bytes transferred.
    Bytes,
    /// Custom unit (connector-specific).
    Custom,
}

/// Enforcement semantics for declared limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitEnforcement {
    /// Block operations that would exceed limit.
    Hard,
    /// Allow but emit warning metrics.
    Soft,
    /// Advisory only (for external limits we can't enforce).
    Advisory,
}

/// Scope for rate limit pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    /// Per-connector instance.
    Instance,
    /// Per-credential (API key).
    Credential,
    /// Global across all instances.
    Global,
}

/// Aggregated rate limit view across connectors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedRateLimits {
    pub limits: Vec<RateLimitInfo>,
}

/// Aggregated rate limit entry for a connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub connector_id: ConnectorId,
    pub pool: RateLimitPool,
    pub tools: Vec<String>,
}

/// Aggregate declared limits for multiple connectors.
#[must_use]
pub fn aggregate_rate_limits<'a, I>(iter: I) -> AggregatedRateLimits
where
    I: IntoIterator<Item = (&'a ConnectorId, &'a RateLimitDeclarations)>,
{
    let mut limits = Vec::new();
    for (connector_id, decls) in iter {
        for pool in &decls.limits {
            let mut tools: Vec<String> = decls
                .tool_pool_map
                .iter()
                .filter(|(_, pools)| pools.iter().any(|id| id == &pool.id))
                .map(|(tool, _)| format!("{connector_id}.{tool}"))
                .collect();
            tools.sort();
            tools.dedup();

            limits.push(RateLimitInfo {
                connector_id: connector_id.clone(),
                pool: pool.clone(),
                tools,
            });
        }
    }

    AggregatedRateLimits { limits }
}

/// A platform-facing signal that the caller should slow down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackpressureSignal {
    /// The computed backpressure level.
    pub level: BackpressureLevel,

    /// Utilization in basis points (`0..=10_000`).
    pub utilization_bps: u16,

    /// Suggested delay (if any) to shape traffic proactively.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Input fields for creating a `ThrottleViolation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleViolationInput {
    /// Timestamp (milliseconds since Unix epoch).
    pub timestamp_ms: u64,

    /// Zone where the violation occurred.
    pub zone_id: ZoneId,

    /// Connector (type) implicated in the violation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<ConnectorId>,

    /// Operation implicated in the violation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,

    /// The limit category.
    pub limit_type: LimitType,

    /// Configured maximum.
    pub limit_value: u32,

    /// Observed current value when the violation was triggered.
    pub current_value: u32,

    /// Suggested retry delay.
    pub retry_after_ms: u64,
}

/// A structured rate limit violation.
///
/// This object is designed to be:
/// - recorded in the audit chain (as an object/event),
/// - returned in structured error details,
/// - used to drive backpressure decisions and metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleViolation {
    /// Unique identifier for the violation record.
    pub violation_id: ObjectId,

    /// Timestamp (milliseconds since Unix epoch).
    pub timestamp_ms: u64,

    /// Zone where the violation occurred.
    pub zone_id: ZoneId,

    /// Connector (type) implicated in the violation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<ConnectorId>,

    /// Operation implicated in the violation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,

    /// The limit category.
    pub limit_type: LimitType,

    /// Configured maximum.
    pub limit_value: u32,

    /// Observed current value when the violation was triggered.
    pub current_value: u32,

    /// Suggested retry delay.
    pub retry_after_ms: u64,
}

#[cfg(test)]
mod declaration_tests {
    use super::*;

    fn sample_pool(id: &str) -> RateLimitPool {
        RateLimitPool {
            id: id.to_string(),
            description: "test pool".to_string(),
            config: RateLimitConfig {
                requests: 10,
                window: Duration::from_secs(60),
                burst: Some(5),
                unit: RateLimitUnit::Requests,
            },
            enforcement: RateLimitEnforcement::Hard,
            scope: RateLimitScope::Credential,
        }
    }

    #[test]
    fn test_rate_limit_declaration_complete() {
        let decls = RateLimitDeclarations {
            limits: vec![sample_pool("pool_a"), sample_pool("pool_b")],
            tool_pool_map: HashMap::from([
                ("tool1".to_string(), vec!["pool_a".to_string()]),
                (
                    "tool2".to_string(),
                    vec!["pool_a".to_string(), "pool_b".to_string()],
                ),
            ]),
        };

        assert!(decls.validate().is_ok());
    }

    #[test]
    fn test_rate_limit_serialization_roundtrip() {
        let decls = RateLimitDeclarations {
            limits: vec![sample_pool("test")],
            tool_pool_map: HashMap::from([("tool1".to_string(), vec!["test".to_string()])]),
        };

        let json = serde_json::to_string(&decls).unwrap();
        let parsed: RateLimitDeclarations = serde_json::from_str(&json).unwrap();
        assert_eq!(decls, parsed);
    }

    #[test]
    fn test_rate_limit_pool_validation() {
        let mut pool = sample_pool("bad");
        pool.config.requests = 0;
        assert!(matches!(
            pool.validate().unwrap_err(),
            RateLimitDeclarationError::ZeroRequests
        ));

        let mut pool = sample_pool("bad2");
        pool.config.window = Duration::from_secs(0);
        assert!(matches!(
            pool.validate().unwrap_err(),
            RateLimitDeclarationError::ZeroWindow
        ));
    }

    #[test]
    fn test_rate_limit_scope_semantics() {
        assert_eq!(
            serde_json::to_string(&RateLimitScope::Instance).unwrap(),
            "\"instance\""
        );
        assert_eq!(
            serde_json::to_string(&RateLimitScope::Credential).unwrap(),
            "\"credential\""
        );
        assert_eq!(
            serde_json::to_string(&RateLimitScope::Global).unwrap(),
            "\"global\""
        );
    }

    #[test]
    fn test_rate_limit_enforcement_levels() {
        assert_eq!(
            serde_json::to_string(&RateLimitEnforcement::Hard).unwrap(),
            "\"hard\""
        );
        assert_eq!(
            serde_json::to_string(&RateLimitEnforcement::Soft).unwrap(),
            "\"soft\""
        );
        assert_eq!(
            serde_json::to_string(&RateLimitEnforcement::Advisory).unwrap(),
            "\"advisory\""
        );
    }

    #[test]
    fn test_rate_limit_unit_types() {
        assert_eq!(
            serde_json::to_string(&RateLimitUnit::Requests).unwrap(),
            "\"requests\""
        );
        assert_eq!(
            serde_json::to_string(&RateLimitUnit::Tokens).unwrap(),
            "\"tokens\""
        );
        assert_eq!(
            serde_json::to_string(&RateLimitUnit::Bytes).unwrap(),
            "\"bytes\""
        );
        assert_eq!(
            serde_json::to_string(&RateLimitUnit::Custom).unwrap(),
            "\"custom\""
        );
    }

    #[test]
    fn test_declarations_is_empty() {
        let empty = RateLimitDeclarations::default();
        assert!(empty.is_empty());

        let non_empty = RateLimitDeclarations {
            limits: vec![sample_pool("p")],
            tool_pool_map: HashMap::new(),
        };
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_validate_empty_pool_id() {
        let decls = RateLimitDeclarations {
            limits: vec![sample_pool("")],
            tool_pool_map: HashMap::new(),
        };
        assert!(matches!(
            decls.validate().unwrap_err(),
            RateLimitDeclarationError::EmptyPoolId
        ));
    }

    #[test]
    fn test_validate_duplicate_pool_id() {
        let decls = RateLimitDeclarations {
            limits: vec![sample_pool("dup"), sample_pool("dup")],
            tool_pool_map: HashMap::new(),
        };
        assert!(matches!(
            decls.validate().unwrap_err(),
            RateLimitDeclarationError::DuplicatePoolId { .. }
        ));
    }

    #[test]
    fn test_validate_empty_tool_name() {
        let decls = RateLimitDeclarations {
            limits: vec![sample_pool("p")],
            tool_pool_map: HashMap::from([(String::new(), vec!["p".to_string()])]),
        };
        assert!(matches!(
            decls.validate().unwrap_err(),
            RateLimitDeclarationError::EmptyToolName
        ));
    }

    #[test]
    fn test_validate_empty_tool_pools() {
        let decls = RateLimitDeclarations {
            limits: vec![sample_pool("p")],
            tool_pool_map: HashMap::from([("tool".to_string(), vec![])]),
        };
        assert!(matches!(
            decls.validate().unwrap_err(),
            RateLimitDeclarationError::EmptyToolPools { .. }
        ));
    }

    #[test]
    fn test_validate_empty_tool_pool_id() {
        let decls = RateLimitDeclarations {
            limits: vec![sample_pool("p")],
            tool_pool_map: HashMap::from([("tool".to_string(), vec![String::new()])]),
        };
        assert!(matches!(
            decls.validate().unwrap_err(),
            RateLimitDeclarationError::EmptyToolPoolId { .. }
        ));
    }

    #[test]
    fn test_validate_unknown_pool() {
        let decls = RateLimitDeclarations {
            limits: vec![sample_pool("p")],
            tool_pool_map: HashMap::from([("tool".to_string(), vec!["nonexistent".to_string()])]),
        };
        assert!(matches!(
            decls.validate().unwrap_err(),
            RateLimitDeclarationError::UnknownPool { .. }
        ));
    }

    #[test]
    fn test_validate_zero_burst() {
        let mut pool = sample_pool("p");
        pool.config.burst = Some(0);
        assert!(matches!(
            pool.validate().unwrap_err(),
            RateLimitDeclarationError::ZeroBurst
        ));
    }

    #[test]
    fn test_validate_no_burst_is_ok() {
        let mut pool = sample_pool("p");
        pool.config.burst = None;
        assert!(pool.validate().is_ok());
    }

    #[test]
    fn test_aggregated_rate_limits_default() {
        let agg = AggregatedRateLimits::default();
        assert!(agg.limits.is_empty());
    }

    #[test]
    fn test_aggregate_empty_input() {
        let agg = aggregate_rate_limits(std::iter::empty());
        assert!(agg.limits.is_empty());
    }

    #[test]
    fn test_aggregate_rate_limits() {
        let connector_a = ConnectorId::from_static("discord");
        let connector_b = ConnectorId::from_static("openai");

        let decls_a = RateLimitDeclarations {
            limits: vec![sample_pool("discord_api")],
            tool_pool_map: HashMap::from([(
                "send_message".to_string(),
                vec!["discord_api".to_string()],
            )]),
        };
        let decls_b = RateLimitDeclarations {
            limits: vec![sample_pool("openai_rpm"), sample_pool("openai_tpm")],
            tool_pool_map: HashMap::from([
                (
                    "chat_completion".to_string(),
                    vec!["openai_rpm".to_string(), "openai_tpm".to_string()],
                ),
                (
                    "embedding".to_string(),
                    vec!["openai_rpm".to_string(), "openai_tpm".to_string()],
                ),
            ]),
        };

        let aggregated =
            aggregate_rate_limits([(&connector_a, &decls_a), (&connector_b, &decls_b)]);
        assert_eq!(aggregated.limits.len(), 3);
        assert!(
            aggregated
                .limits
                .iter()
                .any(|limit| limit.pool.id == "discord_api")
        );
        assert!(
            aggregated
                .limits
                .iter()
                .any(|limit| limit.pool.id == "openai_rpm")
        );
        assert!(
            aggregated
                .limits
                .iter()
                .any(|limit| limit.pool.id == "openai_tpm")
        );
    }
}

impl ThrottleViolation {
    /// Create a new `ThrottleViolation` and derive a deterministic `violation_id`.
    ///
    /// Note: The `violation_id` is currently derived as an unkeyed, domain-separated digest over
    /// the violation fields for stable correlation. When persisted into the audit object store,
    /// the stored object id MUST follow the object-id derivation rules from `fcp-core::object`.
    #[must_use]
    pub fn new(input: ThrottleViolationInput) -> Self {
        let violation_id = derive_violation_id(&input);

        Self {
            violation_id,
            timestamp_ms: input.timestamp_ms,
            zone_id: input.zone_id,
            connector_id: input.connector_id,
            operation_id: input.operation_id,
            limit_type: input.limit_type,
            limit_value: input.limit_value,
            current_value: input.current_value,
            retry_after_ms: input.retry_after_ms,
        }
    }
}

fn derive_violation_id(input: &ThrottleViolationInput) -> ObjectId {
    // Length-prefixed encoding to avoid ambiguity.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"FCP2-THROTTLE-V1");
    bytes.extend_from_slice(&input.timestamp_ms.to_le_bytes());

    // ZoneId
    let z_bytes = input.zone_id.as_bytes();
    bytes.extend_from_slice(
        &u32::try_from(z_bytes.len())
            .expect("zone_id too long")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(z_bytes);

    if let Some(id) = input.connector_id.as_ref() {
        bytes.push(1);
        let s = id.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(s.len())
                .expect("connector_id too long")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(s);
    } else {
        bytes.push(0);
    }

    if let Some(id) = input.operation_id.as_ref() {
        bytes.push(1);
        let s = id.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(s.len())
                .expect("operation_id too long")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(s);
    } else {
        bytes.push(0);
    }

    bytes.push(match input.limit_type {
        LimitType::Rpm => 1,
        LimitType::Concurrent => 2,
        LimitType::Burst => 3,
        LimitType::Quota => 4,
    });
    bytes.extend_from_slice(&input.limit_value.to_le_bytes());
    bytes.extend_from_slice(&input.current_value.to_le_bytes());
    bytes.extend_from_slice(&input.retry_after_ms.to_le_bytes());

    ObjectId::from_unscoped_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn violation_id_determinism() {
        let ts = 1000_u64;
        let zone: ZoneId = "z:work".parse().unwrap();
        let conn: ConnectorId = "test:conn:v1".parse().unwrap();
        let op: OperationId = "test.op".parse().unwrap();

        let v1 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: ts,
            zone_id: zone.clone(),
            connector_id: Some(conn.clone()),
            operation_id: Some(op.clone()),
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });

        let v2 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: ts,
            zone_id: zone,
            connector_id: Some(conn),
            operation_id: Some(op),
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });

        assert_eq!(v1.violation_id, v2.violation_id);
    }

    #[test]
    fn violation_new_populates_fields() {
        let input = ThrottleViolationInput {
            timestamp_ms: 42_000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("test:conn:v1".parse().unwrap()),
            operation_id: Some("test.op".parse().unwrap()),
            limit_type: LimitType::Quota,
            limit_value: 200,
            current_value: 250,
            retry_after_ms: 1000,
        };
        let v = ThrottleViolation::new(input);
        assert_eq!(v.timestamp_ms, 42_000);
        assert_eq!(v.limit_type, LimitType::Quota);
        assert_eq!(v.limit_value, 200);
        assert_eq!(v.current_value, 250);
        assert_eq!(v.retry_after_ms, 1000);
        assert!(v.connector_id.is_some());
        assert!(v.operation_id.is_some());
    }

    #[test]
    fn violation_without_optional_fields() {
        let v = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Concurrent,
            limit_value: 10,
            current_value: 11,
            retry_after_ms: 0,
        });
        assert!(v.connector_id.is_none());
        assert!(v.operation_id.is_none());
    }

    #[test]
    fn throttle_violation_serde_roundtrip() {
        let v = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 5000,
            zone_id: "z:private".parse().unwrap(),
            connector_id: Some("gmail:fcp2:1.0".parse().unwrap()),
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 60,
            current_value: 61,
            retry_after_ms: 2000,
        });
        let json = serde_json::to_string(&v).unwrap();
        let back: ThrottleViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.violation_id, v.violation_id);
        assert_eq!(back.limit_type, LimitType::Rpm);
        assert_eq!(back.retry_after_ms, 2000);
    }

    #[test]
    fn limit_type_serde_roundtrip() {
        for lt in [
            LimitType::Rpm,
            LimitType::Concurrent,
            LimitType::Burst,
            LimitType::Quota,
        ] {
            let json = serde_json::to_string(&lt).unwrap();
            let back: LimitType = serde_json::from_str(&json).unwrap();
            assert_eq!(lt, back);
        }
    }

    #[test]
    fn backpressure_level_serde_roundtrip() {
        for level in [
            BackpressureLevel::Normal,
            BackpressureLevel::Warning,
            BackpressureLevel::SoftLimit,
            BackpressureLevel::HardLimit,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: BackpressureLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn backpressure_signal_serde_roundtrip() {
        let signal = BackpressureSignal {
            level: BackpressureLevel::Warning,
            utilization_bps: 7500,
            retry_after_ms: Some(500),
        };
        let json = serde_json::to_string(&signal).unwrap();
        let back: BackpressureSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.level, BackpressureLevel::Warning);
        assert_eq!(back.utilization_bps, 7500);
        assert_eq!(back.retry_after_ms, Some(500));
    }

    #[test]
    fn backpressure_signal_no_retry_after() {
        let signal = BackpressureSignal {
            level: BackpressureLevel::Normal,
            utilization_bps: 1000,
            retry_after_ms: None,
        };
        let json = serde_json::to_string(&signal).unwrap();
        assert!(!json.contains("retry_after_ms")); // skipped when None
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LimitType – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn limit_type_copy() {
        let a = LimitType::Rpm;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn limit_type_inequality() {
        assert_ne!(LimitType::Rpm, LimitType::Concurrent);
        assert_ne!(LimitType::Burst, LimitType::Quota);
    }

    #[test]
    fn limit_type_serde_values() {
        assert_eq!(serde_json::to_string(&LimitType::Rpm).unwrap(), "\"rpm\"");
        assert_eq!(
            serde_json::to_string(&LimitType::Concurrent).unwrap(),
            "\"concurrent\""
        );
        assert_eq!(
            serde_json::to_string(&LimitType::Burst).unwrap(),
            "\"burst\""
        );
        assert_eq!(
            serde_json::to_string(&LimitType::Quota).unwrap(),
            "\"quota\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BackpressureLevel – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn backpressure_level_copy() {
        let a = BackpressureLevel::Warning;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn backpressure_level_inequality() {
        assert_ne!(BackpressureLevel::Normal, BackpressureLevel::Warning);
        assert_ne!(BackpressureLevel::SoftLimit, BackpressureLevel::HardLimit);
    }

    #[test]
    fn backpressure_level_serde_values() {
        assert_eq!(
            serde_json::to_string(&BackpressureLevel::Normal).unwrap(),
            "\"normal\""
        );
        assert_eq!(
            serde_json::to_string(&BackpressureLevel::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&BackpressureLevel::SoftLimit).unwrap(),
            "\"soft_limit\""
        );
        assert_eq!(
            serde_json::to_string(&BackpressureLevel::HardLimit).unwrap(),
            "\"hard_limit\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RateLimitDeclarationError – Display
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn declaration_error_display_empty_pool_id() {
        let err = RateLimitDeclarationError::EmptyPoolId;
        assert_eq!(err.to_string(), "rate limit pool id must not be empty");
    }

    #[test]
    fn declaration_error_display_duplicate_pool_id() {
        let err = RateLimitDeclarationError::DuplicatePoolId {
            id: "dup".to_string(),
        };
        assert!(err.to_string().contains("dup"));
    }

    #[test]
    fn declaration_error_display_empty_tool_name() {
        let err = RateLimitDeclarationError::EmptyToolName;
        assert!(err.to_string().contains("tool name"));
    }

    #[test]
    fn declaration_error_display_zero_requests() {
        let err = RateLimitDeclarationError::ZeroRequests;
        assert!(err.to_string().contains("requests"));
    }

    #[test]
    fn declaration_error_display_zero_window() {
        let err = RateLimitDeclarationError::ZeroWindow;
        assert!(err.to_string().contains("window"));
    }

    #[test]
    fn declaration_error_display_zero_burst() {
        let err = RateLimitDeclarationError::ZeroBurst;
        assert!(err.to_string().contains("burst"));
    }

    #[test]
    fn declaration_error_display_unknown_pool() {
        let err = RateLimitDeclarationError::UnknownPool {
            tool: "mytool".to_string(),
            pool: "missing".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("mytool"));
        assert!(msg.contains("missing"));
    }

    #[test]
    fn declaration_error_display_empty_tool_pools() {
        let err = RateLimitDeclarationError::EmptyToolPools {
            tool: "t".to_string(),
        };
        assert!(err.to_string().contains('t'));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RateLimitDeclarations – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn declarations_default_is_empty() {
        let d = RateLimitDeclarations::default();
        assert!(d.is_empty());
        assert!(d.limits.is_empty());
        assert!(d.tool_pool_map.is_empty());
    }

    #[test]
    fn declarations_clone() {
        let d = RateLimitDeclarations {
            limits: vec![RateLimitPool {
                id: "p1".to_string(),
                description: "pool".to_string(),
                config: RateLimitConfig {
                    requests: 10,
                    window: Duration::from_secs(60),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Soft,
                scope: RateLimitScope::Instance,
            }],
            tool_pool_map: HashMap::from([("t".to_string(), vec!["p1".to_string()])]),
        };
        let cloned = d.clone();
        assert_eq!(d, cloned);
    }

    #[test]
    fn declarations_not_empty_with_only_tool_map() {
        let d = RateLimitDeclarations {
            limits: vec![],
            tool_pool_map: HashMap::from([("t".to_string(), vec!["p".to_string()])]),
        };
        assert!(!d.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RateLimitConfig – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_config_clone() {
        let c = RateLimitConfig {
            requests: 100,
            window: Duration::from_secs(120),
            burst: Some(50),
            unit: RateLimitUnit::Tokens,
        };
        let cloned = c.clone();
        assert_eq!(c, cloned);
    }

    #[test]
    fn rate_limit_config_valid() {
        let c = RateLimitConfig {
            requests: 1,
            window: Duration::from_millis(1),
            burst: None,
            unit: RateLimitUnit::Bytes,
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rate_limit_config_valid_with_burst() {
        let c = RateLimitConfig {
            requests: 100,
            window: Duration::from_secs(60),
            burst: Some(1),
            unit: RateLimitUnit::Custom,
        };
        assert!(c.validate().is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RateLimitScope/Enforcement/Unit – Copy and roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_scope_copy() {
        let a = RateLimitScope::Global;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn rate_limit_enforcement_copy() {
        let a = RateLimitEnforcement::Advisory;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn rate_limit_unit_copy() {
        let a = RateLimitUnit::Tokens;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn rate_limit_scope_roundtrip_all() {
        for scope in [
            RateLimitScope::Instance,
            RateLimitScope::Credential,
            RateLimitScope::Global,
        ] {
            let json = serde_json::to_string(&scope).unwrap();
            let decoded: RateLimitScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, decoded);
        }
    }

    #[test]
    fn rate_limit_enforcement_roundtrip_all() {
        for enf in [
            RateLimitEnforcement::Hard,
            RateLimitEnforcement::Soft,
            RateLimitEnforcement::Advisory,
        ] {
            let json = serde_json::to_string(&enf).unwrap();
            let decoded: RateLimitEnforcement = serde_json::from_str(&json).unwrap();
            assert_eq!(enf, decoded);
        }
    }

    #[test]
    fn rate_limit_unit_roundtrip_all() {
        for unit in [
            RateLimitUnit::Requests,
            RateLimitUnit::Tokens,
            RateLimitUnit::Bytes,
            RateLimitUnit::Custom,
        ] {
            let json = serde_json::to_string(&unit).unwrap();
            let decoded: RateLimitUnit = serde_json::from_str(&json).unwrap();
            assert_eq!(unit, decoded);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BackpressureSignal – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn backpressure_signal_clone() {
        let signal = BackpressureSignal {
            level: BackpressureLevel::SoftLimit,
            utilization_bps: 8500,
            retry_after_ms: Some(200),
        };
        let cloned = signal.clone();
        assert_eq!(cloned.level, signal.level);
        assert_eq!(cloned.utilization_bps, signal.utilization_bps);
        assert_eq!(cloned.retry_after_ms, signal.retry_after_ms);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ThrottleViolation – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn throttle_violation_clone() {
        let v = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("test:conn:v1".parse().unwrap()),
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 60,
            current_value: 61,
            retry_after_ms: 500,
        });
        let cloned = v.clone();
        assert_eq!(cloned.violation_id, v.violation_id);
        assert_eq!(cloned.timestamp_ms, v.timestamp_ms);
        assert_eq!(cloned.limit_type, v.limit_type);
    }

    #[test]
    fn throttle_violation_serde_omits_none_fields() {
        let v = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 100,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Concurrent,
            limit_value: 5,
            current_value: 6,
            retry_after_ms: 0,
        });
        let json = serde_json::to_string(&v).unwrap();
        assert!(!json.contains("connector_id"));
        assert!(!json.contains("operation_id"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ThrottleViolationInput – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn throttle_violation_input_clone() {
        let input = ThrottleViolationInput {
            timestamp_ms: 500,
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("c:v1".parse().unwrap()),
            operation_id: Some("op.x".parse().unwrap()),
            limit_type: LimitType::Quota,
            limit_value: 1000,
            current_value: 1001,
            retry_after_ms: 2000,
        };
        let cloned = input.clone();
        assert_eq!(cloned.timestamp_ms, input.timestamp_ms);
        assert_eq!(cloned.limit_type, input.limit_type);
    }

    #[test]
    fn throttle_violation_input_serde_roundtrip() {
        let input = ThrottleViolationInput {
            timestamp_ms: 42_000,
            zone_id: "z:private".parse().unwrap(),
            connector_id: Some("gmail:fcp2:1.0".parse().unwrap()),
            operation_id: Some("send.email".parse().unwrap()),
            limit_type: LimitType::Burst,
            limit_value: 50,
            current_value: 55,
            retry_after_ms: 1500,
        };
        let json = serde_json::to_string(&input).unwrap();
        let decoded: ThrottleViolationInput = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.timestamp_ms, 42_000);
        assert_eq!(decoded.limit_type, LimitType::Burst);
        assert_eq!(decoded.limit_value, 50);
    }

    #[test]
    fn throttle_violation_input_serde_omits_none() {
        let input = ThrottleViolationInput {
            timestamp_ms: 100,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 10,
            current_value: 11,
            retry_after_ms: 0,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(!json.contains("connector_id"));
        assert!(!json.contains("operation_id"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RateLimitInfo – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_info_clone() {
        let info = RateLimitInfo {
            connector_id: ConnectorId::from_static("test:conn:v1"),
            pool: RateLimitPool {
                id: "pool".to_string(),
                description: "desc".to_string(),
                config: RateLimitConfig {
                    requests: 10,
                    window: Duration::from_secs(60),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Hard,
                scope: RateLimitScope::Instance,
            },
            tools: vec!["tool_a".to_string()],
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn rate_limit_info_serde_roundtrip() {
        let info = RateLimitInfo {
            connector_id: ConnectorId::from_static("discord"),
            pool: RateLimitPool {
                id: "api".to_string(),
                description: "Discord API".to_string(),
                config: RateLimitConfig {
                    requests: 50,
                    window: Duration::from_secs(60),
                    burst: Some(10),
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Soft,
                scope: RateLimitScope::Credential,
            },
            tools: vec!["discord.send".to_string(), "discord.edit".to_string()],
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: RateLimitInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AggregatedRateLimits – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn aggregated_rate_limits_clone() {
        let agg = AggregatedRateLimits {
            limits: vec![RateLimitInfo {
                connector_id: ConnectorId::from_static("c"),
                pool: RateLimitPool {
                    id: "p".to_string(),
                    description: "d".to_string(),
                    config: RateLimitConfig {
                        requests: 1,
                        window: Duration::from_secs(1),
                        burst: None,
                        unit: RateLimitUnit::Requests,
                    },
                    enforcement: RateLimitEnforcement::Advisory,
                    scope: RateLimitScope::Global,
                },
                tools: vec![],
            }],
        };
        let cloned = agg.clone();
        assert_eq!(agg, cloned);
    }

    #[test]
    fn aggregated_rate_limits_serde_roundtrip() {
        let agg = AggregatedRateLimits::default();
        let json = serde_json::to_string(&agg).unwrap();
        let decoded: AggregatedRateLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(agg, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // aggregate_rate_limits – tool name qualification
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn aggregate_qualifies_tool_names_with_connector() {
        let cid = ConnectorId::from_static("myconn");
        let decls = RateLimitDeclarations {
            limits: vec![RateLimitPool {
                id: "pool1".to_string(),
                description: "test".to_string(),
                config: RateLimitConfig {
                    requests: 10,
                    window: Duration::from_secs(60),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Hard,
                scope: RateLimitScope::Instance,
            }],
            tool_pool_map: HashMap::from([("do_stuff".to_string(), vec!["pool1".to_string()])]),
        };
        let agg = aggregate_rate_limits([(&cid, &decls)]);
        assert_eq!(agg.limits.len(), 1);
        assert_eq!(agg.limits[0].tools, vec!["myconn.do_stuff".to_string()]);
    }

    #[test]
    fn aggregate_pool_with_no_tools() {
        let cid = ConnectorId::from_static("orphan");
        let decls = RateLimitDeclarations {
            limits: vec![RateLimitPool {
                id: "unused_pool".to_string(),
                description: "no tools".to_string(),
                config: RateLimitConfig {
                    requests: 5,
                    window: Duration::from_secs(30),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Advisory,
                scope: RateLimitScope::Global,
            }],
            tool_pool_map: HashMap::new(),
        };
        let agg = aggregate_rate_limits([(&cid, &decls)]);
        assert_eq!(agg.limits.len(), 1);
        assert!(agg.limits[0].tools.is_empty());
    }

    #[test]
    fn violation_id_sensitivity() {
        let base = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });

        // Change timestamp
        let v2 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1001,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(base.violation_id, v2.violation_id);

        // Change zone
        let v3 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:private".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(base.violation_id, v3.violation_id);

        // Change limit type
        let v4 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Burst,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(base.violation_id, v4.violation_id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Violation ID sensitivity: connector_id, operation_id, limit/current values
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn violation_id_sensitive_to_connector_id_presence() {
        let v_none = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        let v_some = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("discord:fcp2:1.0".parse().unwrap()),
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(v_none.violation_id, v_some.violation_id);
    }

    #[test]
    fn violation_id_sensitive_to_operation_id_presence() {
        let v_none = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        let v_some = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: Some("send_msg".parse().unwrap()),
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(v_none.violation_id, v_some.violation_id);
    }

    #[test]
    fn violation_id_sensitive_to_limit_value() {
        let v1 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        let v2 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 200,
            current_value: 101,
            retry_after_ms: 500,
        });
        assert_ne!(v1.violation_id, v2.violation_id);
    }

    #[test]
    fn violation_id_sensitive_to_current_value() {
        let v1 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        let v2 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 999,
            retry_after_ms: 500,
        });
        assert_ne!(v1.violation_id, v2.violation_id);
    }

    #[test]
    fn violation_id_sensitive_to_retry_after() {
        let v1 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 500,
        });
        let v2 = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 1000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 999,
        });
        assert_ne!(v1.violation_id, v2.violation_id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // All four limit types yield distinct violation IDs
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn violation_id_all_limit_types_distinct() {
        let types = [
            LimitType::Rpm,
            LimitType::Concurrent,
            LimitType::Burst,
            LimitType::Quota,
        ];
        let ids: Vec<_> = types
            .iter()
            .map(|lt| {
                ThrottleViolation::new(ThrottleViolationInput {
                    timestamp_ms: 1000,
                    zone_id: "z:work".parse().unwrap(),
                    connector_id: None,
                    operation_id: None,
                    limit_type: *lt,
                    limit_value: 100,
                    current_value: 101,
                    retry_after_ms: 500,
                })
                .violation_id
            })
            .collect();
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "limit types {i} and {j} collide");
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Boundary values
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn violation_zero_boundary() {
        let v = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 0,
            zone_id: "z:owner".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Quota,
            limit_value: 0,
            current_value: 0,
            retry_after_ms: 0,
        });
        assert_eq!(v.timestamp_ms, 0);
        assert_eq!(v.limit_value, 0);
        assert_eq!(v.retry_after_ms, 0);
    }

    #[test]
    fn violation_max_boundary() {
        let v = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: u64::MAX,
            zone_id: "z:public".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: LimitType::Concurrent,
            limit_value: u32::MAX,
            current_value: u32::MAX,
            retry_after_ms: u64::MAX,
        });
        assert_eq!(v.timestamp_ms, u64::MAX);
        assert_eq!(v.limit_value, u32::MAX);
    }

    #[test]
    fn violation_serde_with_all_fields() {
        let v = ThrottleViolation::new(ThrottleViolationInput {
            timestamp_ms: 5000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("openai:fcp2:1.0".parse().unwrap()),
            operation_id: Some("chat".parse().unwrap()),
            limit_type: LimitType::Rpm,
            limit_value: 60,
            current_value: 61,
            retry_after_ms: 2000,
        });
        let json = serde_json::to_string(&v).unwrap();
        let back: ThrottleViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.violation_id, v.violation_id);
        assert!(back.connector_id.is_some());
        assert!(back.operation_id.is_some());
        assert_eq!(back.connector_id.unwrap().as_str(), "openai:fcp2:1.0");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Aggregate: multiple connectors produce correct counts
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn aggregate_multiple_connectors_pool_count() {
        let c1 = ConnectorId::from_static("c1");
        let c2 = ConnectorId::from_static("c2");

        let d1 = RateLimitDeclarations {
            limits: vec![RateLimitPool {
                id: "p1".to_string(),
                description: "d".to_string(),
                config: RateLimitConfig {
                    requests: 10,
                    window: Duration::from_secs(60),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Hard,
                scope: RateLimitScope::Instance,
            }],
            tool_pool_map: HashMap::new(),
        };
        let d2 = RateLimitDeclarations {
            limits: vec![
                RateLimitPool {
                    id: "p2".to_string(),
                    description: "d".to_string(),
                    config: RateLimitConfig {
                        requests: 20,
                        window: Duration::from_secs(60),
                        burst: None,
                        unit: RateLimitUnit::Tokens,
                    },
                    enforcement: RateLimitEnforcement::Soft,
                    scope: RateLimitScope::Global,
                },
                RateLimitPool {
                    id: "p3".to_string(),
                    description: "d".to_string(),
                    config: RateLimitConfig {
                        requests: 5,
                        window: Duration::from_secs(10),
                        burst: Some(2),
                        unit: RateLimitUnit::Bytes,
                    },
                    enforcement: RateLimitEnforcement::Advisory,
                    scope: RateLimitScope::Credential,
                },
            ],
            tool_pool_map: HashMap::new(),
        };

        let agg = aggregate_rate_limits([(&c1, &d1), (&c2, &d2)]);
        assert_eq!(agg.limits.len(), 3);
    }
}
