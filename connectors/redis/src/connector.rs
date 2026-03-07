//! FCP Redis Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, RedisAuth, RedisClient},
    error::RedisError,
};

/// Parsed and validated Redis connector configuration.
#[derive(Debug, Clone)]
struct RedisConfig {
    auth: RedisAuth,
    base_url: String,
}

impl RedisConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_token = params
            .get("api_token")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let auth = match (api_token, credential_id) {
            (Some(token), None) => RedisAuth::ApiToken(token),
            (None, Some(cred_id)) => RedisAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP Redis Connector.
pub struct RedisConnector {
    base: Arc<BaseConnector>,
    config: Option<RedisConfig>,
    client: Option<Arc<RedisClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl RedisConnector {
    /// Create a new Redis connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("redis"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for RedisConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl RedisConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = RedisConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Redis connector");

        let client = RedisClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.redis",
            "connector_version": "0.1.0",
            "capabilities": [
                "redis.get",
                "redis.set",
                "redis.del",
                "redis.exists",
                "redis.expire",
                "redis.ttl",
                "redis.incr",
                "redis.hget",
                "redis.hset",
                "redis.hgetall",
                "redis.lpush",
                "redis.lrange",
                "redis.sadd",
                "redis.smembers"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();

        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured — call configure first".into())
            } else {
                None
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("API client not initialized".into())
            } else {
                None
            },
            critical: true,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.redis",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.redis",
            "version": "0.1.0",
            "operations": operations_info(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "redis.get" => self.invoke_get(client, &input).await,
            "redis.set" => self.invoke_set(client, &input).await,
            "redis.del" => self.invoke_del(client, &input).await,
            "redis.exists" => self.invoke_exists(client, &input).await,
            "redis.expire" => self.invoke_expire(client, &input).await,
            "redis.ttl" => self.invoke_ttl(client, &input).await,
            "redis.incr" => self.invoke_incr(client, &input).await,
            "redis.hget" => self.invoke_hget(client, &input).await,
            "redis.hset" => self.invoke_hset(client, &input).await,
            "redis.hgetall" => self.invoke_hgetall(client, &input).await,
            "redis.lpush" => self.invoke_lpush(client, &input).await,
            "redis.lrange" => self.invoke_lrange(client, &input).await,
            "redis.sadd" => self.invoke_sadd(client, &input).await,
            "redis.smembers" => self.invoke_smembers(client, &input).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Redis connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_get(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let result = client.get(key).await?;
        Ok(json!({ "value": result }))
    }

    async fn invoke_set(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let value = require_str(input, "value")?;
        let ttl_seconds = input
            .get("ttl_seconds")
            .and_then(serde_json::Value::as_u64);
        let nx = input
            .get("nx")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let xx = input
            .get("xx")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let result = client.set(key, value, ttl_seconds, nx, xx).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_del(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let keys = require_str_array(input, "keys")?;
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let result = client.del(&key_refs).await?;
        Ok(json!({ "deleted": result }))
    }

    async fn invoke_exists(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let keys = require_str_array(input, "keys")?;
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let result = client.exists(&key_refs).await?;
        Ok(json!({ "count": result }))
    }

    async fn invoke_expire(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let seconds = input
            .get("seconds")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| RedisError::Command {
                message: "Missing required field: seconds".into(),
            })?;
        let result = client.expire(key, seconds).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_ttl(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let result = client.ttl(key).await?;
        Ok(json!({ "ttl": result }))
    }

    async fn invoke_incr(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let result = client.incr(key).await?;
        Ok(json!({ "value": result }))
    }

    async fn invoke_hget(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let field = require_str(input, "field")?;
        let result = client.hget(key, field).await?;
        Ok(json!({ "value": result }))
    }

    async fn invoke_hset(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let fields_val = input.get("fields").ok_or_else(|| RedisError::Command {
            message: "Missing required field: fields".into(),
        })?;
        let fields_obj = fields_val
            .as_object()
            .ok_or_else(|| RedisError::Command {
                message: "fields must be an object".into(),
            })?;

        let field_pairs: Vec<(String, String)> = fields_obj
            .iter()
            .map(|(k, v)| {
                let val = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                (k.clone(), val)
            })
            .collect();

        let field_refs: Vec<(&str, &str)> = field_pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let result = client.hset(key, &field_refs).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_hgetall(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let result = client.hgetall(key).await?;
        Ok(json!({ "fields": result }))
    }

    async fn invoke_lpush(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let elements = require_str_array(input, "elements")?;
        let elem_refs: Vec<&str> = elements.iter().map(String::as_str).collect();
        let result = client.lpush(key, &elem_refs).await?;
        Ok(json!({ "length": result }))
    }

    async fn invoke_lrange(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let start = input
            .get("start")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let stop = input
            .get("stop")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1);
        let result = client.lrange(key, start, stop).await?;
        Ok(json!({ "values": result }))
    }

    async fn invoke_sadd(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let members = require_str_array(input, "members")?;
        let member_refs: Vec<&str> = members.iter().map(String::as_str).collect();
        let result = client.sadd(key, &member_refs).await?;
        Ok(json!({ "added": result }))
    }

    async fn invoke_smembers(
        &self,
        client: &RedisClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedisError> {
        let key = require_str(input, "key")?;
        let result = client.smembers(key).await?;
        Ok(json!({ "members": result }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, RedisError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RedisError::Command {
            message: format!("Missing required field: {field}"),
        })
}

/// Extract a required string array field from input.
fn require_str_array(
    input: &serde_json::Value,
    field: &str,
) -> Result<Vec<String>, RedisError> {
    let arr = input
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| RedisError::Command {
            message: format!("Missing required field: {field}"),
        })?;

    arr.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| RedisError::Command {
                    message: format!("All elements of {field} must be strings"),
                })
        })
        .collect()
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "redis.get",
            "summary": "Get the value of a key",
            "capability": "redis.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The key to get" }
                },
                "required": ["key"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "value": { "description": "The value stored at the key, or null if not found" }
                }
            }
        },
        {
            "id": "redis.set",
            "summary": "Set the value of a key with optional TTL and NX/XX flags",
            "capability": "redis.write",
            "risk_level": "medium",
            "safety_tier": "moderate",
            "idempotency": "best_effort",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The key to set" },
                    "value": { "type": "string", "description": "The value to set" },
                    "ttl_seconds": { "type": "integer", "description": "Time-to-live in seconds" },
                    "nx": { "type": "boolean", "description": "Only set if key does not exist" },
                    "xx": { "type": "boolean", "description": "Only set if key already exists" }
                },
                "required": ["key", "value"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "result": { "description": "OK on success, null if NX/XX condition not met" }
                }
            }
        },
        {
            "id": "redis.del",
            "summary": "Delete one or more keys",
            "capability": "redis.write",
            "risk_level": "high",
            "safety_tier": "moderate",
            "idempotency": "none",
            "input_schema": {
                "type": "object",
                "properties": {
                    "keys": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "The keys to delete"
                    }
                },
                "required": ["keys"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "deleted": { "type": "integer", "description": "Number of keys deleted" }
                }
            }
        },
        {
            "id": "redis.exists",
            "summary": "Check if one or more keys exist",
            "capability": "redis.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "properties": {
                    "keys": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "The keys to check"
                    }
                },
                "required": ["keys"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "count": { "type": "integer", "description": "Number of keys that exist" }
                }
            }
        },
        {
            "id": "redis.expire",
            "summary": "Set a timeout on a key",
            "capability": "redis.write",
            "risk_level": "medium",
            "safety_tier": "moderate",
            "idempotency": "best_effort",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The key to set expiry on" },
                    "seconds": { "type": "integer", "description": "TTL in seconds" }
                },
                "required": ["key", "seconds"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "result": { "type": "integer", "description": "1 if timeout was set, 0 if key does not exist" }
                }
            }
        },
        {
            "id": "redis.ttl",
            "summary": "Get the remaining time to live of a key",
            "capability": "redis.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The key to check" }
                },
                "required": ["key"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "ttl": { "type": "integer", "description": "TTL in seconds, -1 if no expiry, -2 if key does not exist" }
                }
            }
        },
        {
            "id": "redis.incr",
            "summary": "Atomically increment the integer value of a key by one",
            "capability": "redis.write",
            "risk_level": "medium",
            "safety_tier": "moderate",
            "idempotency": "none",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The key to increment" }
                },
                "required": ["key"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "value": { "type": "integer", "description": "The value after incrementing" }
                }
            }
        },
        {
            "id": "redis.hget",
            "summary": "Get the value of a hash field",
            "capability": "redis.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The hash key" },
                    "field": { "type": "string", "description": "The field to get" }
                },
                "required": ["key", "field"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "value": { "description": "The value of the field, or null" }
                }
            }
        },
        {
            "id": "redis.hset",
            "summary": "Set one or more hash fields",
            "capability": "redis.write",
            "risk_level": "medium",
            "safety_tier": "moderate",
            "idempotency": "best_effort",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The hash key" },
                    "fields": {
                        "type": "object",
                        "description": "Field-value pairs to set"
                    }
                },
                "required": ["key", "fields"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "result": { "type": "integer", "description": "Number of new fields added" }
                }
            }
        },
        {
            "id": "redis.hgetall",
            "summary": "Get all fields and values in a hash",
            "capability": "redis.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The hash key" }
                },
                "required": ["key"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "fields": { "description": "All field-value pairs in the hash" }
                }
            }
        },
        {
            "id": "redis.lpush",
            "summary": "Prepend one or more elements to a list",
            "capability": "redis.write",
            "risk_level": "medium",
            "safety_tier": "moderate",
            "idempotency": "none",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The list key" },
                    "elements": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Elements to prepend"
                    }
                },
                "required": ["key", "elements"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "length": { "type": "integer", "description": "Length of the list after push" }
                }
            }
        },
        {
            "id": "redis.lrange",
            "summary": "Get a range of elements from a list",
            "capability": "redis.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The list key" },
                    "start": { "type": "integer", "description": "Start index (default 0)" },
                    "stop": { "type": "integer", "description": "Stop index (default -1 for all)" }
                },
                "required": ["key"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "values": {
                        "type": "array",
                        "description": "List elements in the range"
                    }
                }
            }
        },
        {
            "id": "redis.sadd",
            "summary": "Add one or more members to a set",
            "capability": "redis.write",
            "risk_level": "medium",
            "safety_tier": "moderate",
            "idempotency": "best_effort",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The set key" },
                    "members": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Members to add"
                    }
                },
                "required": ["key", "members"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "added": { "type": "integer", "description": "Number of new members added" }
                }
            }
        },
        {
            "id": "redis.smembers",
            "summary": "Get all members of a set",
            "capability": "redis.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The set key" }
                },
                "required": ["key"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "members": {
                        "type": "array",
                        "description": "All members of the set"
                    }
                }
            }
        }
    ])
}
