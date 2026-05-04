use std::sync::Arc;
use std::time::Duration;

use fcp_prelude::{
    BaseConnector, ConnectorId, FcpError, FcpResult, RequestId, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde_json::{Value, json};
use tracing::info;

use crate::client::FirecrawlClient;
use crate::types::{CrawlRequest, ScrapeRequest};

const CONNECTOR_ID: &str = "fcp.firecrawl";
const CONNECTOR_VERSION: &str = "0.1.0";

const OP_SCRAPE: &str = "firecrawl.scrape";
const OP_CRAWL_START: &str = "firecrawl.crawl.start";
const OP_CRAWL_STATUS: &str = "firecrawl.crawl.status";

const FIRECRAWL_ALLOWED_HOSTS: &[&str] = &["api.firecrawl.dev"];

#[derive(Clone, serde::Deserialize)]
pub struct FirecrawlConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub api_key: String,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_base_url() -> String {
    "https://api.firecrawl.dev/v1".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

fn trim_config_string(value: &mut String) {
    *value = value.trim().to_owned();
}

impl std::fmt::Debug for FirecrawlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirecrawlConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl FirecrawlConfig {
    fn validate(&self) -> Result<(), String> {
        if self.api_key.trim().is_empty() {
            return Err("api_key is required".into());
        }
        if self.base_url.is_empty() {
            return Err("base_url cannot be empty".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than zero".into());
        }
        let (network_ok, network_message) = base_url_policy(&self.base_url);
        if !network_ok {
            return Err(network_message);
        }
        Ok(())
    }

    fn from_value(val: Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;
        trim_config_string(&mut config.base_url);
        trim_config_string(&mut config.api_key);
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost")
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match url::Url::parse(base_url) {
        Ok(url) => url,
        Err(error) => return (false, format!("base_url must be an absolute URL: {error}")),
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return (false, "base_url must not include userinfo".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return (
            false,
            "base_url must not include a query string or fragment".into(),
        );
    }

    if is_local_test_host(host) {
        return (
            true,
            format!("localhost test endpoint accepted for verification: {base_url}"),
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if !FIRECRAWL_ALLOWED_HOSTS.contains(&host) {
        problems.push(format!(
            "host must be one of {FIRECRAWL_ALLOWED_HOSTS:?}, got {host}"
        ));
    }

    if problems.is_empty() {
        (true, "Firecrawl production API endpoint accepted".into())
    } else {
        (false, problems.join("; "))
    }
}

pub struct FirecrawlConnector {
    base: Arc<BaseConnector>,
    config: Option<FirecrawlConfig>,
    client: Option<FirecrawlClient>,
    runtime: Option<ConnectorRuntime>,
    configured: bool,
    handshaken: bool,
}

// Public async methods mirror the connector runtime contract even for local state transitions.
#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl FirecrawlConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            runtime: None,
            configured: false,
            handshaken: false,
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let cfg = FirecrawlConfig::from_value(params)?;
        let timeout = Duration::from_millis(cfg.request_timeout_ms);

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(timeout),
        ));

        let client = FirecrawlClient::new(&cfg.base_url, &cfg.api_key, cfg.retry.clone(), timeout)
            .await
            .map_err(|e| FcpError::Internal {
                message: format!("Client init: {e}"),
            })?;

        self.client = Some(client);
        self.config = Some(cfg);
        self.configured = true;
        self.base.set_configured(true);

        info!(
            event = "firecrawl.configure",
            "Configured Firecrawl connector"
        );
        Ok(json!({"connector_id": CONNECTOR_ID, "configured": true}))
    }

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if !self.configured {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["firecrawl.scrape", "firecrawl.crawl"],
            "surface_status": "live"
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let has_client = self.client.is_some();
        Ok(json!({
            "status": if has_client && self.configured { "ready" } else if self.configured { "degraded" } else { "unconfigured" },
            "configured": self.configured,
            "handshaken": self.handshaken,
            "live_requests_supported": has_client,
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let has_client = self.client.is_some();
        let has_runtime = self.runtime.is_some();
        Ok(json!({
            "status": if self.configured && has_client && has_runtime { "healthy" } else if self.configured { "degraded" } else { "unhealthy" },
            "checks": [
                { "name": "configuration", "passed": self.configured, "critical": true },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "client_initialized", "passed": has_client, "critical": true },
                { "name": "runtime_initialized", "passed": has_runtime, "critical": true },
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        if !self.configured {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "Connector is not configured"
            }));
        }
        if !self.handshaken {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_handshaken",
                "message": "Connector configured, but handshake has not completed yet."
            }));
        }
        if self.client.is_none() {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "no_client",
                "message": "HTTP client not initialized"
            }));
        }
        Ok(json!({
            "status": "ready",
            "reason_code": "operational",
            "message": "Firecrawl connector is ready for requests"
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        let live = self.client.is_some() && self.configured;
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": [
                { "id": OP_SCRAPE, "summary": "Scrape a single URL with Firecrawl", "capability": "firecrawl.scrape", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict", "implemented": live },
                { "id": OP_CRAWL_START, "summary": "Start a Firecrawl crawl job", "capability": "firecrawl.crawl", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": live },
                { "id": OP_CRAWL_STATUS, "summary": "Check Firecrawl crawl status", "capability": "firecrawl.crawl", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict", "implemented": live }
            ],
            "surface_status": if live { "live" } else { "planned_only" },
            "events": [],
            "resource_types": []
        }))
    }

    // Keep dispatch validation and operation execution together so capability checks stay local.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Firecrawl client".into(),
        })?;

        let output = match operation {
            OP_SCRAPE => {
                let url = require_str(&input, "url")?;
                let mut req = ScrapeRequest::new(url);
                if let Some(formats) = input.get("formats").and_then(Value::as_array) {
                    req.formats = formats
                        .iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect();
                }
                if let Some(v) = input.get("only_main_content").and_then(Value::as_bool) {
                    req.only_main_content = Some(v);
                }
                if let Some(tags) = input.get("include_tags").and_then(Value::as_array) {
                    req.include_tags = Some(
                        tags.iter()
                            .filter_map(Value::as_str)
                            .map(String::from)
                            .collect(),
                    );
                }
                if let Some(tags) = input.get("exclude_tags").and_then(Value::as_array) {
                    req.exclude_tags = Some(
                        tags.iter()
                            .filter_map(Value::as_str)
                            .map(String::from)
                            .collect(),
                    );
                }
                if let Some(v) = input.get("wait_for").and_then(Value::as_u64) {
                    req.wait_for = Some(u32::try_from(v).unwrap_or(u32::MAX));
                }
                if let Some(v) = input.get("timeout").and_then(Value::as_u64) {
                    req.timeout = Some(u32::try_from(v).unwrap_or(u32::MAX));
                }

                let resp = client
                    .scrape(runtime, &req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                if !resp.success {
                    return Err(FcpError::External {
                        service: "firecrawl".into(),
                        message: resp.error.unwrap_or_else(|| "scrape failed".into()),
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    });
                }

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CRAWL_START => {
                let url = require_str(&input, "url")?;
                let mut req = CrawlRequest::new(url);
                if let Some(v) = input.get("limit").and_then(Value::as_u64) {
                    req.limit = Some(u32::try_from(v).unwrap_or(u32::MAX));
                }
                if let Some(v) = input.get("max_depth").and_then(Value::as_u64) {
                    req.max_depth = Some(u32::try_from(v).unwrap_or(u32::MAX));
                }
                if let Some(paths) = input.get("exclude_paths").and_then(Value::as_array) {
                    req.exclude_paths = paths
                        .iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect();
                }
                if let Some(paths) = input.get("include_paths").and_then(Value::as_array) {
                    req.include_paths = paths
                        .iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect();
                }
                if let Some(v) = input.get("allow_external_links").and_then(Value::as_bool) {
                    req.allow_external_links = Some(v);
                }

                let resp = client
                    .start_crawl(runtime, &req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                if !resp.success {
                    return Err(FcpError::External {
                        service: "firecrawl".into(),
                        message: resp.error.unwrap_or_else(|| "crawl start failed".into()),
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    });
                }

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CRAWL_STATUS => {
                let crawl_id = require_str(&input, "crawl_id")?;
                let resp = client
                    .get_crawl_status(runtime, crawl_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(json!({
            "operation": operation,
            "output": output
        }))
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let parsed = serde_json::from_value::<SimulateRequest>(params.clone()).ok();
        let id = parsed
            .as_ref()
            .map(|req| req.id.clone())
            .or_else(|| params.get("id").and_then(Value::as_str).map(RequestId::new))
            .unwrap_or_else(|| RequestId::new("firecrawl-simulate"));
        let operation = parsed
            .as_ref()
            .map(|req| req.operation.as_str())
            .or_else(|| {
                params
                    .get("operation_id")
                    .or_else(|| params.get("operation"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("");

        let known = matches!(operation, OP_SCRAPE | OP_CRAWL_START | OP_CRAWL_STATUS);
        let response = if known {
            SimulateResponse::denied(
                id,
                "Firecrawl API does not support dry-run mode.",
                "dry_run_not_supported",
            )
        } else {
            SimulateResponse::denied(id, "Unknown operation.", "unknown_operation")
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize simulate response: {e}"),
        })
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = false;
        self.handshaken = false;
        self.config = None;
        self.client = None;
        self.runtime = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for FirecrawlConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a Value, key: &str) -> FcpResult<&'a str> {
    let value = input
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing required field: {key}"),
        })?;
    if value.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("Field '{key}' must not be empty"),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST_TOML: &str = include_str!("../manifest.toml");

    fn test_config() -> Value {
        json!({
            "api_key": "fc-test-key-123",
            "base_url": "http://localhost:9999/v1"
        })
    }

    #[test]
    fn manifest_matches_scrape_and_crawl_first_slice() {
        assert!(
            MANIFEST_TOML.contains(
                "description = \"Firecrawl connector for scrape and crawl orchestration\""
            )
        );
        assert!(MANIFEST_TOML.contains(
            "migration_hint = \"First slice: scrape, crawl.start, and crawl.status. Search and extract are deferred.\""
        ));
        assert!(!MANIFEST_TOML.contains("First slice: search, scrape, extract"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_and_handshake_succeed() {
        let mut connector = FirecrawlConnector::new();
        let result = connector.handle_configure(test_config()).await;
        assert!(result.is_ok());
        let cfg_resp = result.unwrap();
        assert_eq!(cfg_resp["configured"], true);

        let hs = connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");
        assert_eq!(hs["surface_status"], "live");
        assert_eq!(hs["connector_version"], CONNECTOR_VERSION);
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_before_configure_fails() {
        let mut connector = FirecrawlConnector::new();
        let result = connector.handle_handshake(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_reports_ready_when_configured() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "ready");
        assert_eq!(health["live_requests_supported"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn health_reports_unconfigured() {
        let connector = FirecrawlConnector::new();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "unconfigured");
        assert_eq!(health["live_requests_supported"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_ready_after_configure_and_handshake() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let check = connector.handle_self_check().await.unwrap();
        assert_eq!(check["status"], "ready");
        assert_eq!(check["reason_code"], "operational");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_degraded_before_handshake() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();

        let check = connector.handle_self_check().await.unwrap();
        assert_eq!(check["status"], "degraded");
        assert_eq!(check["reason_code"], "not_handshaken");
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_shows_live_operations_when_configured() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();

        let intro = connector.handle_introspect().await.unwrap();
        assert_eq!(intro["surface_status"], "live");
        let ops = intro["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 3);
        assert!(ops.iter().all(|op| op["implemented"] == true));
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_shows_planned_when_unconfigured() {
        let connector = FirecrawlConnector::new();
        let intro = connector.handle_introspect().await.unwrap();
        assert_eq!(intro["surface_status"], "planned_only");
        let ops = intro["operations"].as_array().unwrap();
        assert!(ops.iter().all(|op| op["implemented"] == false));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unknown_operation_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({"operation_id": "firecrawl.nope"}))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Unknown operation"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_scrape_missing_url_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation_id": "firecrawl.scrape",
                "input": {}
            }))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("url"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_crawl_start_missing_url_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation_id": "firecrawl.crawl.start",
                "input": {}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_crawl_status_missing_crawl_id_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation_id": "firecrawl.crawl.status",
                "input": {}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operation_refuses() {
        let connector = FirecrawlConnector::new();
        let sim = connector
            .handle_simulate(json!({"operation_id": "firecrawl.scrape"}))
            .await
            .unwrap();
        let response: SimulateResponse = serde_json::from_value(sim).unwrap();
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code.as_deref(),
            Some("dry_run_not_supported")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation() {
        let connector = FirecrawlConnector::new();
        let sim = connector
            .handle_simulate(json!({"operation_id": "firecrawl.nope"}))
            .await
            .unwrap();
        let response: SimulateResponse = serde_json::from_value(sim).unwrap();
        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("unknown_operation"));
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        connector.handle_shutdown(json!({})).await.unwrap();

        assert!(!connector.configured);
        assert!(!connector.handshaken);
        assert!(connector.client.is_none());
        assert!(connector.runtime.is_none());
        assert!(connector.config.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_healthy_when_fully_configured() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();

        let doc = connector.handle_doctor().await.unwrap();
        assert_eq!(doc["status"], "healthy");
        let checks = doc["checks"].as_array().unwrap();
        assert!(
            checks
                .iter()
                .all(|c| c["passed"] == true || !c["critical"].as_bool().unwrap_or(false))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unhealthy_when_unconfigured() {
        let connector = FirecrawlConnector::new();
        let doc = connector.handle_doctor().await.unwrap();
        assert_eq!(doc["status"], "unhealthy");
    }

    #[test]
    fn configure_rejects_empty_api_key() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "",
                    "base_url": "https://api.firecrawl.dev/v1"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn configure_rejects_invalid_base_url() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "fc-key",
                    "base_url": "http://evil.example.com/v1"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn configure_rejects_ambiguous_base_url_components() {
        for base_url in [
            "https://user:pass@api.firecrawl.dev/v1",
            "https://api.firecrawl.dev/v1?trace=1",
            "https://api.firecrawl.dev/v1#frag",
            "http://localhost:8080/v1?trace=1",
        ] {
            let result = fcp_async_core::runtime::block_on_sync(async {
                let mut connector = FirecrawlConnector::new();
                connector
                    .handle_configure(json!({
                        "api_key": "fc-key",
                        "base_url": base_url
                    }))
                    .await
            })
            .unwrap();
            assert!(result.is_err(), "{base_url} should be rejected");
        }
    }

    #[test]
    fn configure_accepts_localhost() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "fc-key",
                    "base_url": "http://localhost:8080/v1"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn configure_accepts_production_url() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "fc-key",
                    "base_url": "https://api.firecrawl.dev/v1"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn require_str_rejects_empty() {
        let input = json!({"url": ""});
        assert!(require_str(&input, "url").is_err());
    }

    #[test]
    fn require_str_rejects_missing() {
        let input = json!({});
        assert!(require_str(&input, "url").is_err());
    }

    #[test]
    fn require_str_accepts_valid() {
        let input = json!({"url": "https://example.com"});
        assert_eq!(require_str(&input, "url").unwrap(), "https://example.com");
    }

    #[test]
    fn base_url_policy_rejects_http_production() {
        let (ok, _) = base_url_policy("http://api.firecrawl.dev/v1");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, _) = base_url_policy("https://not-firecrawl.example.com/v1");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_rejects_ambiguous_components() {
        for base_url in [
            "https://user:pass@api.firecrawl.dev/v1",
            "https://api.firecrawl.dev/v1?trace=1",
            "https://api.firecrawl.dev/v1#frag",
            "http://localhost:9999/v1?trace=1",
        ] {
            let (ok, message) = base_url_policy(base_url);
            assert!(!ok, "{base_url} should be rejected");
            assert!(
                message.contains("userinfo")
                    || message.contains("query string")
                    || message.contains("fragment"),
                "unexpected rejection message for {base_url}: {message}"
            );
        }
    }

    #[test]
    fn base_url_policy_accepts_production() {
        let (ok, _) = base_url_policy("https://api.firecrawl.dev/v1");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9999/v1");
        assert!(ok);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_without_configure_fails() {
        let connector = FirecrawlConnector::new();
        let result = connector
            .handle_invoke(json!({"operation_id": "firecrawl.scrape", "input": {"url": "https://example.com"}}))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_zero_timeout_rejected() {
        let mut connector = FirecrawlConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "fc-key",
                "base_url": "http://localhost:8080/v1",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }
}
