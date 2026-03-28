//! Redis REST API client (Upstash-compatible).

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{RedisError, RedisResult},
    types::{ApiErrorResponse, UpstashResponse},
};

/// Default Redis REST API base URL.
///
/// Users must configure this to their actual Upstash Redis endpoint.
pub const DEFAULT_BASE_URL: &str = "https://redis.example.com";

/// Authentication mode for the Redis REST API.
#[derive(Clone)]
pub enum RedisAuth {
    /// API token (passed as Bearer token).
    ApiToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl RedisAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiToken(_) => "api_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for RedisAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiToken(_) => f.debug_tuple("ApiToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Redis REST API client.
///
/// Sends commands as JSON arrays via POST to the Upstash-compatible REST endpoint.
pub struct RedisClient {
    client: Client,
    auth: RedisAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for RedisClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl RedisClient {
    /// Create a new Redis REST API client.
    pub fn new(auth: RedisAuth, base_url: Option<&str>) -> RedisResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-redis/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Shut down the client runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            RedisAuth::ApiToken(token) => req.bearer_auth(token),
            RedisAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> RedisResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(json!({}));
            }
            let parsed: UpstashResponse = serde_json::from_str(&body)?;
            if let Some(error) = parsed.error {
                return Err(RedisError::Command { message: error });
            }
            Ok(parsed.result.unwrap_or(serde_json::Value::Null))
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> RedisResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);

        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(RedisError::Unauthorized),
            403 => Err(RedisError::Forbidden),
            429 => Err(RedisError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(RedisError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Execute a Redis command via the REST API.
    ///
    /// The command is sent as a JSON array, e.g. `["SET", "mykey", "myvalue"]`.
    #[instrument(skip(self, args), fields(cmd = args.first().copied().unwrap_or("UNKNOWN")))]
    pub async fn execute_command(&self, args: &[&str]) -> RedisResult<serde_json::Value> {
        let url = &self.base_url;
        debug!(url = %url, "POST Redis command");
        let req = self
            .add_auth(self.client.post(url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&args);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Convenience methods for each command --

    /// GET key
    pub async fn get(&self, key: &str) -> RedisResult<serde_json::Value> {
        self.execute_command(&["GET", key]).await
    }

    /// SET key value [EX seconds] [NX|XX]
    pub async fn set(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: Option<u64>,
        nx: bool,
        xx: bool,
    ) -> RedisResult<serde_json::Value> {
        let mut args: Vec<&str> = vec!["SET", key, value];

        // We need to hold these as Strings so references remain valid
        let ttl_str;
        if let Some(ttl) = ttl_seconds {
            ttl_str = ttl.to_string();
            args.push("EX");
            args.push(&ttl_str);
        }
        if nx {
            args.push("NX");
        }
        if xx {
            args.push("XX");
        }

        self.execute_command(&args).await
    }

    /// DEL key [key ...]
    pub async fn del(&self, keys: &[&str]) -> RedisResult<serde_json::Value> {
        let mut args: Vec<&str> = vec!["DEL"];
        args.extend_from_slice(keys);
        self.execute_command(&args).await
    }

    /// EXISTS key [key ...]
    pub async fn exists(&self, keys: &[&str]) -> RedisResult<serde_json::Value> {
        let mut args: Vec<&str> = vec!["EXISTS"];
        args.extend_from_slice(keys);
        self.execute_command(&args).await
    }

    /// EXPIRE key seconds
    pub async fn expire(&self, key: &str, seconds: u64) -> RedisResult<serde_json::Value> {
        let secs_str = seconds.to_string();
        self.execute_command(&["EXPIRE", key, &secs_str]).await
    }

    /// TTL key
    pub async fn ttl(&self, key: &str) -> RedisResult<serde_json::Value> {
        self.execute_command(&["TTL", key]).await
    }

    /// INCR key
    pub async fn incr(&self, key: &str) -> RedisResult<serde_json::Value> {
        self.execute_command(&["INCR", key]).await
    }

    /// HGET key field
    pub async fn hget(&self, key: &str, field: &str) -> RedisResult<serde_json::Value> {
        self.execute_command(&["HGET", key, field]).await
    }

    /// HSET key field value [field value ...]
    pub async fn hset(&self, key: &str, fields: &[(&str, &str)]) -> RedisResult<serde_json::Value> {
        let mut args: Vec<&str> = vec!["HSET", key];
        for (f, v) in fields {
            args.push(f);
            args.push(v);
        }
        self.execute_command(&args).await
    }

    /// HGETALL key
    pub async fn hgetall(&self, key: &str) -> RedisResult<serde_json::Value> {
        self.execute_command(&["HGETALL", key]).await
    }

    /// LPUSH key element [element ...]
    pub async fn lpush(&self, key: &str, elements: &[&str]) -> RedisResult<serde_json::Value> {
        let mut args: Vec<&str> = vec!["LPUSH", key];
        args.extend_from_slice(elements);
        self.execute_command(&args).await
    }

    /// LRANGE key start stop
    pub async fn lrange(&self, key: &str, start: i64, stop: i64) -> RedisResult<serde_json::Value> {
        let start_str = start.to_string();
        let stop_str = stop.to_string();
        self.execute_command(&["LRANGE", key, &start_str, &stop_str])
            .await
    }

    /// SADD key member [member ...]
    pub async fn sadd(&self, key: &str, members: &[&str]) -> RedisResult<serde_json::Value> {
        let mut args: Vec<&str> = vec!["SADD", key];
        args.extend_from_slice(members);
        self.execute_command(&args).await
    }

    /// SMEMBERS key
    pub async fn smembers(&self, key: &str) -> RedisResult<serde_json::Value> {
        self.execute_command(&["SMEMBERS", key]).await
    }
}
