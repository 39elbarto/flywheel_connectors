//! SDK Rate Limit Declaration Tests
//!
//! Validates:
//! - `RateLimitDeclarations` structure and JSON round-trips
//! - Tool-to-pool mapping invariants
//! - Basic config sanity checks
//! - Enum serialization for scope/enforcement/unit
//! - Connector `rate_limits()` unknown-default + explicit override behavior

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use fcp_sdk::SessionId;
use fcp_sdk::SubscribeResult;
use fcp_sdk::prelude::*;
use serde_json::json;

fn sample_declarations() -> RateLimitDeclarations {
    let mut tool_pool_map = HashMap::new();
    tool_pool_map.insert(
        "chat.completions.create".to_string(),
        vec!["openai_tokens".to_string()],
    );
    tool_pool_map.insert(
        "chat.completions.stream".to_string(),
        vec!["openai_tokens".to_string(), "openai_requests".to_string()],
    );

    RateLimitDeclarations {
        limits: vec![
            RateLimitPool {
                id: "openai_tokens".to_string(),
                description: "Token budget per API key".to_string(),
                config: RateLimitConfig {
                    requests: 120_000,
                    window: Duration::from_secs(60),
                    burst: Some(10_000),
                    unit: RateLimitUnit::Tokens,
                },
                enforcement: RateLimitEnforcement::Hard,
                scope: RateLimitScope::Credential,
            },
            RateLimitPool {
                id: "openai_requests".to_string(),
                description: "Request budget per API key".to_string(),
                config: RateLimitConfig {
                    requests: 3_000,
                    window: Duration::from_secs(60),
                    burst: Some(300),
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Soft,
                scope: RateLimitScope::Credential,
            },
        ],
        tool_pool_map,
    }
}

fn empty_subscribe_response() -> SubscribeResponse {
    SubscribeResponse {
        r#type: "response".to_string(),
        id: RequestId::random(),
        result: SubscribeResult {
            confirmed_topics: Vec::new(),
            cursors: HashMap::new(),
            replay_supported: false,
            buffer: None,
        },
    }
}

fn validate_declarations(decls: &RateLimitDeclarations) -> Result<(), String> {
    let mut pool_ids = HashSet::new();
    for pool in &decls.limits {
        if pool.id.trim().is_empty() {
            return Err("pool id must not be empty".to_string());
        }
        if !pool_ids.insert(pool.id.as_str()) {
            return Err(format!("duplicate pool id: {}", pool.id));
        }
        if pool.config.requests == 0 {
            return Err(format!("pool {} has zero requests", pool.id));
        }
        if pool.config.window.is_zero() {
            return Err(format!("pool {} has zero window", pool.id));
        }
        if let Some(burst) = pool.config.burst {
            if burst == 0 {
                return Err(format!("pool {} has zero burst", pool.id));
            }
        }
    }

    for (tool, pools) in &decls.tool_pool_map {
        if pools.is_empty() {
            return Err(format!("tool {tool} has empty pool list"));
        }
        for pool_id in pools {
            if !pool_ids.contains(pool_id.as_str()) {
                return Err(format!("tool {tool} references unknown pool {pool_id}"));
            }
        }
    }

    Ok(())
}

#[test]
fn rate_limit_declarations_json_roundtrip() {
    let decls = sample_declarations();
    let value = serde_json::to_value(&decls).expect("serialize declarations");
    let parsed: RateLimitDeclarations =
        serde_json::from_value(value.clone()).expect("deserialize declarations");
    let parsed_value = serde_json::to_value(&parsed).expect("serialize parsed");
    assert_eq!(value, parsed_value);
}

#[test]
fn rate_limit_declarations_tool_requires_pool_mapping() {
    let mut decls = sample_declarations();
    decls.tool_pool_map.insert("tool.empty".to_string(), vec![]);

    let err = validate_declarations(&decls).expect_err("empty pool list should fail");
    assert!(err.contains("empty pool list"));
}

#[test]
fn rate_limit_declarations_unknown_pool_is_rejected() {
    let mut decls = sample_declarations();
    decls
        .tool_pool_map
        .insert("tool.unknown".to_string(), vec!["missing_pool".to_string()]);

    let err = validate_declarations(&decls).expect_err("unknown pool should fail");
    assert!(err.contains("unknown pool"));
}

#[test]
fn rate_limit_declarations_validate_config() {
    let mut decls = sample_declarations();
    decls.limits[0].config.requests = 0;

    let err = validate_declarations(&decls).expect_err("zero requests should fail");
    assert!(err.contains("zero requests"));

    let mut decls = sample_declarations();
    decls.limits[0].config.window = Duration::from_secs(0);

    let err = validate_declarations(&decls).expect_err("zero window should fail");
    assert!(err.contains("zero window"));

    let mut decls = sample_declarations();
    decls.limits[0].config.burst = Some(0);

    let err = validate_declarations(&decls).expect_err("zero burst should fail");
    assert!(err.contains("zero burst"));
}

#[test]
fn rate_limit_scope_serialization_distinct() {
    let scopes = [
        RateLimitScope::Instance,
        RateLimitScope::Credential,
        RateLimitScope::Global,
    ];
    let mut seen = HashSet::new();
    for scope in scopes {
        let s = serde_json::to_string(&scope).unwrap();
        assert!(seen.insert(s));
    }
}

#[test]
fn rate_limit_enforcement_serialization_distinct() {
    let levels = [
        RateLimitEnforcement::Hard,
        RateLimitEnforcement::Soft,
        RateLimitEnforcement::Advisory,
    ];
    let mut seen = HashSet::new();
    for level in levels {
        let s = serde_json::to_string(&level).unwrap();
        assert!(seen.insert(s));
    }
}

#[test]
fn rate_limit_unit_serialization_distinct() {
    let units = [
        RateLimitUnit::Requests,
        RateLimitUnit::Tokens,
        RateLimitUnit::Bytes,
        RateLimitUnit::Custom,
    ];
    let mut seen = HashSet::new();
    for unit in units {
        let s = serde_json::to_string(&unit).unwrap();
        assert!(seen.insert(s));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector behavior
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct MinimalConnector {
    base: BaseConnector,
}

impl MinimalConnector {
    fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("test:minimal:v1")),
        }
    }
}

#[derive(Debug)]
struct RateLimitedConnector {
    base: BaseConnector,
    declarations: RateLimitDeclarations,
}

impl RateLimitedConnector {
    fn new(declarations: RateLimitDeclarations) -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("test:ratelimit:v1")),
            declarations,
        }
    }
}

fcp_core::impl_fcp_sealed!(MinimalConnector);

#[async_trait]
impl FcpConnector for MinimalConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot::ready()
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        Ok(InvokeResponse::ok(req.id, json!({"status": "ok"})))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(empty_subscribe_response())
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}
fcp_core::impl_fcp_sealed!(RateLimitedConnector);


#[async_trait]
impl FcpConnector for RateLimitedConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot::ready()
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    fn rate_limits(&self) -> Option<RateLimitDeclarations> {
        Some(self.declarations.clone())
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        Ok(InvokeResponse::ok(req.id, json!({"status": "ok"})))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(empty_subscribe_response())
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

#[test]
fn connector_rate_limits_default_is_unknown() {
    let connector = MinimalConnector::new();
    assert!(
        connector.rate_limits().is_none(),
        "default connector rate limits must remain unknown until explicitly declared"
    );
}

#[test]
fn connector_rate_limits_override_valid() {
    let decls = sample_declarations();
    let connector = RateLimitedConnector::new(decls.clone());
    let returned = connector
        .rate_limits()
        .expect("connector should surface explicit rate-limit declarations");
    validate_declarations(&returned).expect("declarations should validate");

    let value = serde_json::to_value(&decls).unwrap();
    let returned_value = serde_json::to_value(&returned).unwrap();
    assert_eq!(value, returned_value);
}
