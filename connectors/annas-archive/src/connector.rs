use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{AnnasArchiveClient, DEFAULT_BASE_URL},
    error::AnnasArchiveError,
};

/// FCP Anna's Archive Connector.
pub struct AnnasArchiveConnector {
    base: Arc<BaseConnector>,
    client: Option<Arc<AnnasArchiveClient>>,
    base_url: String,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl AnnasArchiveConnector {
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("annas-archive"))),
            client: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for AnnasArchiveConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnnasArchiveConnector {
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        let client = AnnasArchiveClient::new(Some(&base_url)).map_err(|e| e.to_fcp_error())?;

        info!(base_url = %base_url, "Configuring Anna's Archive connector");

        self.client = Some(Arc::new(client));
        self.base_url = base_url;
        self.base.set_configured(true);
        Ok(json!({}))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.client.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        self.session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.annas-archive",
            "connector_version": "0.1.0",
            "capabilities": [
                "annas.search",
                "annas.read"
            ]
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let handshaken = self.base.handshaken.load(Ordering::Relaxed);

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

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "status": if self.client.is_some() { "healthy" } else { "unconfigured" },
            "checks": [
                {
                    "name": "configuration",
                    "passed": self.client.is_some(),
                    "critical": true
                },
                {
                    "name": "no_auth_required",
                    "passed": true,
                    "message": "No authentication required",
                    "critical": false
                }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.annas-archive",
            "version": "0.1.0",
            "status": if self.client.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.annas-archive",
            "version": "0.1.0",
            "operations": operations_info(),
        }))
    }

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
            "annas.search" => self.invoke_search(client, &input).await,
            "annas.metadata" => self.invoke_metadata(client, &input).await,
            "annas.lookup.isbn" => self.invoke_lookup_isbn(client, &input).await,
            "annas.lookup.md5" => self.invoke_lookup_md5(client, &input).await,
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

    pub async fn handle_simulate(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Anna's Archive connector shutting down");
        self.client = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_search(
        &self,
        client: &AnnasArchiveClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AnnasArchiveError> {
        let query = require_str(input, "query")?;
        let lang = input.get("lang").and_then(serde_json::Value::as_str);
        let ext = input.get("ext").and_then(serde_json::Value::as_str);
        let sort = input.get("sort").and_then(serde_json::Value::as_str);
        client.search(query, lang, ext, sort).await
    }

    async fn invoke_metadata(
        &self,
        client: &AnnasArchiveClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AnnasArchiveError> {
        let md5 = require_str(input, "md5")?;
        client.get_metadata(md5).await
    }

    async fn invoke_lookup_isbn(
        &self,
        client: &AnnasArchiveClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AnnasArchiveError> {
        let isbn = require_str(input, "isbn")?;
        client.lookup_isbn(isbn).await
    }

    async fn invoke_lookup_md5(
        &self,
        client: &AnnasArchiveClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AnnasArchiveError> {
        let md5 = require_str(input, "md5")?;
        client.lookup_md5(md5).await
    }
}

fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, AnnasArchiveError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AnnasArchiveError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "annas.search",
            "summary": "Search books and documents by keyword",
            "capability": "annas.search",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "annas.metadata",
            "summary": "Get detailed metadata for a book by MD5 hash",
            "capability": "annas.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "annas.lookup.isbn",
            "summary": "Look up a book by ISBN",
            "capability": "annas.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "annas.lookup.md5",
            "summary": "Look up a book by MD5 hash",
            "capability": "annas.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connector() -> AnnasArchiveConnector {
        AnnasArchiveConnector::new()
    }

    #[tokio::test]
    async fn configure_succeeds() {
        let mut c = connector();
        let resp = c.handle_configure(json!({})).await.unwrap();
        assert_eq!(resp, json!({}));
    }

    #[tokio::test]
    async fn configure_with_custom_url() {
        let mut c = connector();
        let resp = c
            .handle_configure(json!({"base_url": "https://custom.example.com"}))
            .await
            .unwrap();
        assert_eq!(resp, json!({}));
        assert_eq!(c.base_url, "https://custom.example.com");
    }

    #[tokio::test]
    async fn handshake_fails_without_configure() {
        let mut c = connector();
        let err = c.handle_handshake(json!({})).await.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[tokio::test]
    async fn handshake_succeeds_after_configure() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_handshake(json!({})).await.unwrap();
        assert_eq!(resp["connector_id"], "fcp.annas-archive");
        assert_eq!(resp["connector_version"], "0.1.0");
    }

    #[tokio::test]
    async fn health_unconfigured() {
        let c = connector();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "unconfigured");
        assert_eq!(resp["configured"], false);
    }

    #[tokio::test]
    async fn health_configured_not_handshaken() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "degraded");
    }

    #[tokio::test]
    async fn health_fully_ready() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "healthy");
    }

    #[tokio::test]
    async fn doctor_checks() {
        let c = connector();
        let resp = c.handle_doctor().await.unwrap();
        assert!(resp["checks"].is_array());
    }

    #[tokio::test]
    async fn self_check() {
        let c = connector();
        let resp = c.handle_self_check().await.unwrap();
        assert_eq!(resp["connector_id"], "fcp.annas-archive");
    }

    #[tokio::test]
    async fn introspect_has_operations() {
        let c = connector();
        let resp = c.handle_introspect().await.unwrap();
        let ops = resp["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 4);
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"annas.search"));
        assert!(ids.contains(&"annas.metadata"));
        assert!(ids.contains(&"annas.lookup.isbn"));
        assert!(ids.contains(&"annas.lookup.md5"));
    }

    #[tokio::test]
    async fn introspect_all_safe() {
        let c = connector();
        let resp = c.handle_introspect().await.unwrap();
        for op in resp["operations"].as_array().unwrap() {
            assert_eq!(op["safety_tier"], "safe");
            assert_eq!(op["risk_level"], "low");
        }
    }

    #[tokio::test]
    async fn invoke_requires_ready() {
        let c = connector();
        let err = c.handle_invoke(json!({"operation_id": "annas.search", "input": {}})).await.unwrap_err();
        assert!(matches!(err, FcpError::NotConfigured | FcpError::NotHandshaken));
    }

    #[tokio::test]
    async fn invoke_unknown_operation() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let err = c
            .handle_invoke(json!({"operation_id": "annas.nonexistent", "input": {}}))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[tokio::test]
    async fn invoke_missing_operation_id() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let err = c.handle_invoke(json!({"input": {}})).await.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[tokio::test]
    async fn simulate_known_operation() {
        let c = connector();
        let resp = c
            .handle_simulate(json!({"operation_id": "annas.search"}))
            .await
            .unwrap();
        assert_eq!(resp["allowed"], true);
    }

    #[tokio::test]
    async fn simulate_unknown_operation() {
        let c = connector();
        let resp = c
            .handle_simulate(json!({"operation_id": "annas.fake"}))
            .await
            .unwrap();
        assert_eq!(resp["allowed"], false);
    }

    #[tokio::test]
    async fn shutdown() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(resp, json!({}));
        assert!(c.client.is_none());
    }

    #[test]
    fn operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.as_array().unwrap().len(), 4);
    }

    #[test]
    fn operations_info_deterministic() {
        let ops1 = operations_info();
        let ops2 = operations_info();
        assert_eq!(ops1, ops2);
    }

    #[test]
    fn require_str_present() {
        let input = json!({"query": "test"});
        assert_eq!(require_str(&input, "query").unwrap(), "test");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"query": 42});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"query": null});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn request_count_increments() {
        // Verify the atomic is properly initialized
        let c = connector();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        c.request_count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(c.request_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn error_count_increments() {
        let c = connector();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
        c.error_count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 1);
    }
}
