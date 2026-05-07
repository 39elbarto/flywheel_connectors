//! Wolfram Alpha FCP connector implementation.

use std::sync::Arc;

use fcp_manifest::{ConnectorManifest, OperationSection};
use fcp_prelude::{
    BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, Introspection,
    OperationId, OperationInfo, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::WolframClient;
use crate::types::{WolframConfig, validate_wolfram_base_url};

const WOLFRAM_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CONNECTOR_ID: &str = "wolfram";
const CONNECTOR_VERSION: &str = "0.1.0";
const OP_QUERY: &str = "wolfram.query";
const OP_SHORT_ANSWER: &str = "wolfram.short_answer";
const OP_SPOKEN_RESULT: &str = "wolfram.spoken_result";
const OPERATION_ORDER: [&str; 3] = [OP_QUERY, OP_SHORT_ANSWER, OP_SPOKEN_RESULT];

/// Result of a doctor check run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
    pub critical: bool,
}

/// Aggregate result of all doctor checks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    /// Create a `DoctorResult` from a list of checks.
    /// The overall result passes when all critical checks pass.
    #[must_use]
    pub fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().all(|c| !c.critical || c.passed);
        Self { passed, checks }
    }
}

/// FCP Wolfram Alpha Connector.
pub struct WolframConnector {
    base: Arc<BaseConnector>,
    config: Option<WolframConfig>,
    client: Option<WolframClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    runtime: Option<ConnectorRuntime>,
}

impl Default for WolframConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl WolframConnector {
    /// Create a new Wolfram Alpha connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            runtime: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let mut config: WolframConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            })?;

        let policy = validate_wolfram_base_url(&config.base_url, config.allow_mock_base_url)
            .map_err(|message| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid base_url: {message}"),
            })?;
        config.base_url = policy.canonical_url;

        let client = WolframClient::try_new(&config).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: error.to_string(),
        })?;
        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        self.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));

        info!("Wolfram Alpha connector configured");
        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    #[allow(clippy::unused_async)]
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:wolfram-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {e}"),
        })
    }

    /// Handle health check.
    #[must_use]
    pub fn handle_health(&self) -> serde_json::Value {
        json!({
            "status": if self.config.is_some() { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": self.base.metrics().requests_total,
                "requests_error": self.base.metrics().requests_error,
            }
        })
    }

    /// Run structured doctor checks and return a typed `DoctorResult`.
    #[must_use]
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // Check 1: Configuration loaded
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: Some(if self.config.is_some() {
                "Configured".into()
            } else {
                "Not configured".into()
            }),
            critical: true,
        });

        if let Some(config) = &self.config {
            let policy = validate_wolfram_base_url(&config.base_url, config.allow_mock_base_url);
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: policy.is_ok(),
                message: Some(match policy {
                    Ok(policy) => format!("Base URL: {}", policy.canonical_url),
                    Err(message) => format!("Invalid base URL: {message}"),
                }),
                critical: true,
            });
        }

        // Check 2: Client initialised
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "HTTP client ready".into()
            } else {
                "HTTP client not initialised".into()
            }),
            critical: true,
        });

        // Check 3: Runtime initialised
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.runtime.is_some(),
            message: Some(if self.runtime.is_some() {
                "Runtime initialised".into()
            } else {
                "Runtime not initialised".into()
            }),
            critical: true,
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle doctor checks.
    #[allow(clippy::unused_async)]
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Configuration
        let config_ok = self.config.is_some();
        checks.push(json!({
            "name": "configuration",
            "passed": config_ok,
            "message": if config_ok { "Configuration loaded" } else { "Not configured" },
            "critical": true
        }));

        if let Some(config) = &self.config {
            // Check 2: Base URL policy
            let policy = validate_wolfram_base_url(&config.base_url, config.allow_mock_base_url);
            checks.push(json!({
                "name": "base_url",
                "passed": policy.is_ok(),
                "message": match policy {
                    Ok(policy) => format!("Base URL: {}", policy.canonical_url),
                    Err(message) => format!("Invalid base URL: {message}"),
                },
                "critical": true
            }));

            // Check 3: Credential ID
            let cred_str = config.credential_id.to_string();
            let cred_prefix = if cred_str.len() >= 8 {
                &cred_str[..8]
            } else {
                &cred_str
            };
            checks.push(json!({
                "name": "credential",
                "passed": true,
                "message": format!("Credential ID: {cred_prefix}..."),
                "critical": true
            }));

            // Check 4: Runtime
            let runtime_ok = self.runtime.is_some();
            checks.push(json!({
                "name": "runtime",
                "passed": runtime_ok,
                "message": if runtime_ok { "Runtime initialised" } else { "Runtime not initialised" },
                "critical": true
            }));

            // Check 5: Client
            let client_ok = self.client.is_some();
            checks.push(json!({
                "name": "client",
                "passed": client_ok,
                "message": if client_ok { "HTTP client ready" } else { "HTTP client not initialised" },
                "critical": true
            }));
        }

        let all_critical_pass = checks.iter().all(|c| {
            !c["critical"].as_bool().unwrap_or(false) || c["passed"].as_bool().unwrap_or(false)
        });

        Ok(json!({
            "status": if all_critical_pass { "healthy" } else { "unhealthy" },
            "checks": checks
        }))
    }

    /// Handle self-check.
    #[allow(clippy::unused_async)]
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if self.session_id.is_none() {
            let report = SelfCheckReport::degraded(
                "not_handshaken",
                "Session not established — run handshake first",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        if let Err(message) =
            validate_wolfram_base_url(&config.base_url, config.allow_mock_base_url)
        {
            let mut report = SelfCheckReport::failed(
                "base_url_mismatch",
                format!("Base URL '{}' is invalid: {message}", config.base_url),
            );
            report.details = Some(json!({"base_url": config.base_url}));
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({
            "base_url": config.base_url,
            "runtime_ready": self.runtime.is_some(),
            "client_ready": self.client.is_some(),
        }));

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle simulate.
    #[allow(clippy::unused_async)]
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        if self.config.is_none() {
            let mut resp = SimulateResponse::allowed(req.id);
            resp.would_succeed = false;
            resp.failure_reason = Some("Connector is not configured".into());
            resp.denial_code = Some("not_configured".into());
            return serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize simulate response: {e}"),
            });
        }

        if !operation_supported(req.operation.as_ref()) {
            let mut resp = SimulateResponse::allowed(req.id);
            resp.would_succeed = false;
            resp.failure_reason = Some(format!("Unknown operation: {}", req.operation));
            resp.denial_code = Some("unknown_operation".into());
            return serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize simulate response: {e}"),
            });
        }

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize simulate response: {e}"),
        })
    }

    /// Handle invoke.
    #[allow(clippy::unused_async)]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        let operation = params
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        // Verify capability token if verifier is set
        if let (Some(verifier), Some(token)) = (&self.verifier, params.get("capability_token")) {
            let capability =
                serde_json::from_value::<CapabilityToken>(token.clone()).map_err(|e| {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid capability token: {e}"),
                    }
                })?;
            let required_cap = required_capability_for_operation(operation).ok_or_else(|| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown operation: {operation}"),
                }
            })?;
            let op_id = OperationId::from_static(match operation {
                OP_QUERY => OP_QUERY,
                OP_SHORT_ANSWER => OP_SHORT_ANSWER,
                OP_SPOKEN_RESULT => OP_SPOKEN_RESULT,
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            });
            let _bound = verifier.verify_bound(capability, &required_cap, &op_id, &[])?;
        }

        let query = input
            .get("input")
            .or_else(|| input.get("query"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing 'input' or 'query' field".into(),
            })?;

        if query.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Query cannot be empty".into(),
            });
        }

        let app_id = input
            .get("app_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing 'app_id'; credential injection is not wired for this connector"
                    .into(),
            })?;

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        match operation {
            OP_QUERY => {
                let qr = client.query(query, app_id).await.map_err(|e| {
                    use fcp_sdk::migration::ConnectorErrorMapping;
                    e.to_fcp_error()
                })?;
                serde_json::to_value(qr).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize query result: {e}"),
                })
            }
            OP_SHORT_ANSWER => client.short_answer(query, app_id).await.map_err(|e| {
                use fcp_sdk::migration::ConnectorErrorMapping;
                e.to_fcp_error()
            }),
            OP_SPOKEN_RESULT => client.spoken_result(query, app_id).await.map_err(|e| {
                use fcp_sdk::migration::ConnectorErrorMapping;
                e.to_fcp_error()
            }),
            _ => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    /// Handle introspect.
    pub fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": wolfram_operation_values()?,
            "events": [],
            "resource_types": []
        }))
    }

    /// Return typed core introspection for `FcpConnector` adapters.
    #[must_use]
    pub fn typed_introspection(&self) -> Introspection {
        wolfram_typed_introspection()
    }

    /// Graceful shutdown.
    pub fn shutdown(&self) {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
    }
}

/// Define the Wolfram Alpha operations from the embedded manifest.
///
/// # Panics
///
/// Panics if the embedded connector manifest is invalid. The manifest is
/// compiled into the binary and validated by provider-contract tests and the
/// `fwc manifest fix --check` lane.
#[must_use]
pub fn wolfram_operations() -> Vec<OperationInfo> {
    manifest_operations()
        .expect("embedded Wolfram manifest should validate")
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(&id, operation))
        .collect()
}

fn required_capability_for_operation(operation: &str) -> Option<CapabilityId> {
    match operation {
        OP_QUERY | OP_SHORT_ANSWER | OP_SPOKEN_RESULT => Some(CapabilityId::from_static(OP_QUERY)),
        _ => None,
    }
}

fn wolfram_typed_introspection() -> Introspection {
    Introspection {
        operations: wolfram_operations(),
        events: vec![],
        resource_types: vec![],
        auth_caps: None,
        event_caps: None,
    }
}

fn operation_supported(operation: &str) -> bool {
    OPERATION_ORDER.contains(&operation)
}

fn manifest_operations() -> FcpResult<Vec<(String, OperationSection)>> {
    let manifest = ConnectorManifest::parse_str(WOLFRAM_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded Wolfram manifest is invalid: {error}"),
        }
    })?;
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    Ok(operations)
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn wolfram_operation_values() -> FcpResult<Vec<serde_json::Value>> {
    Ok(manifest_operations()?
        .into_iter()
        .map(|(id, operation)| operation_value_from_manifest(&id, operation))
        .collect())
}

fn operation_value_from_manifest(id: &str, operation: OperationSection) -> serde_json::Value {
    let description = operation.description;
    let mut metadata = json!({
        "id": id,
        "summary": description,
        "description": description,
        "capability": operation.capability.as_str(),
        "risk_level": operation.risk_level,
        "safety_tier": operation.safety_tier,
        "requires_approval": operation.requires_approval,
        "idempotency": operation.idempotency,
        "revocation_freshness": operation.revocation_freshness,
        "input_schema": operation.input_schema,
        "output_schema": operation.output_schema,
        "network_constraints": operation.network_constraints,
        "ai_hints": operation.ai_hints
    });
    if let Some(rate_limit) = operation.rate_limit {
        metadata["rate_limit"] = json!(rate_limit.0);
    }
    metadata
}

fn operation_info_from_manifest(id: &str, operation: OperationSection) -> OperationInfo {
    OperationInfo {
        id: operation_id_from_manifest(id),
        summary: operation.description.clone(),
        description: Some(operation.description),
        input_schema: operation.input_schema,
        output_schema: operation.output_schema,
        capability: operation.capability,
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints,
        rate_limit: operation.rate_limit.map(|rate_limit| rate_limit.0),
        requires_approval: Some(operation.requires_approval.into()),
    }
}

fn operation_id_from_manifest(id: &str) -> OperationId {
    match id {
        OP_QUERY => OperationId::from_static(OP_QUERY),
        OP_SHORT_ANSWER => OperationId::from_static(OP_SHORT_ANSWER),
        OP_SPOKEN_RESULT => OperationId::from_static(OP_SPOKEN_RESULT),
        _ => OperationId::new(id.to_owned()).expect("manifest operation id should be canonical"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use ciborium::into_writer;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{
        CapabilityConstraints, IdempotencyClass, InstanceId, RiskLevel, SafetyTier, ZoneId,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn generate_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &InstanceId,
        cap: &str,
        ops: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
        let principal = ["fixture", "principal"].join("-");
        let issuer = ["fixture", "issuer"].join("-");
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal(principal.as_str())
            .operations(ops)
            .issuer(issuer.as_str())
            .target_instance(instance_id.as_str())
            .try_constraints_cbor(&constraints_cbor)
            .expect("valid constraints cbor")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .expect("sign capability");
        CapabilityToken::from_raw(cose)
    }

    fn fixture_app_id() -> String {
        ["fixture", "app"].join("-")
    }

    fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested: capabilities
                .iter()
                .map(|cap| cap.parse::<CapabilityId>().expect("capability id"))
                .collect(),
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

    async fn setup_connector(
        base_url: &str,
        caps: &[&str],
    ) -> (WolframConnector, Ed25519SigningKey) {
        let mut connector = WolframConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let mut config = json!({
            "credential_id": fcp_core::CredentialId::new(),
            "base_url": base_url
        });
        if base_url.starts_with("http://127.0.0.1")
            || base_url.starts_with("http://localhost")
            || base_url.starts_with("http://[::1]")
        {
            config["allow_mock_base_url"] = json!(true);
        }

        connector
            .handle_configure(config)
            .await
            .expect("configure should succeed");

        let hs = handshake_request(signing_key.verifying_key().to_bytes(), caps);
        connector
            .handle_handshake(serde_json::to_value(hs).expect("serialize"))
            .await
            .expect("handshake should succeed");

        (connector, signing_key)
    }

    #[fcp_async_core::runtime::test]
    async fn configure_success() {
        let mut connector = WolframConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new()
            }))
            .await
            .expect("configure");
        assert_eq!(result["status"], "configured");
        assert_eq!(
            connector.config.as_ref().expect("config").base_url,
            "https://api.wolframalpha.com"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_https_production_url() {
        let mut connector = WolframConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new(),
                "base_url": "https://api.wolframalpha.com"
            }))
            .await
            .expect("configure");
        assert_eq!(result["status"], "configured");
        assert_eq!(
            connector.config.as_ref().expect("config").base_url,
            "https://api.wolframalpha.com"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_http_production_url() {
        let mut connector = WolframConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new(),
                "base_url": "http://api.wolframalpha.com"
            }))
            .await
            .expect_err("http production URL must fail");
        assert!(matches!(result, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_substring_userinfo_and_local_hosts() {
        for base_url in [
            "https://api.wolframalpha.com.evil.example",
            "https://user@api.wolframalpha.com",
            "http://127.0.0.1:4321",
            "http://localhost:4321",
            "http://10.0.0.1:4321",
        ] {
            let mut connector = WolframConnector::new();
            let result = connector
                .handle_configure(json!({
                    "credential_id": fcp_core::CredentialId::new(),
                    "base_url": base_url
                }))
                .await;
            assert!(result.is_err(), "{base_url} should be rejected");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_loopback_only_with_explicit_mock_seam() {
        let mut connector = WolframConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new(),
                "base_url": "http://127.0.0.1:4321",
                "allow_mock_base_url": true
            }))
            .await
            .expect("loopback mock configure");
        assert_eq!(
            connector.config.as_ref().expect("config").base_url,
            "http://127.0.0.1:4321"
        );

        let mut private_connector = WolframConnector::new();
        let result = private_connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new(),
                "base_url": "http://192.168.1.12:4321",
                "allow_mock_base_url": true
            }))
            .await;
        assert!(result.is_err(), "private IP is not a mock loopback");
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let connector = WolframConnector::new();
        let health = connector.handle_health();
        assert_eq!(health["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn health_configured() {
        let mut connector = WolframConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new()
            }))
            .await
            .expect("configure");
        let health = connector.handle_health();
        assert_eq!(health["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unconfigured() {
        let connector = WolframConnector::new();
        let result = connector.handle_doctor().await.expect("doctor");
        assert_eq!(result["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured() {
        let mut connector = WolframConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new()
            }))
            .await
            .expect("configure");
        let result = connector.handle_doctor().await.expect("doctor");
        assert_eq!(result["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = WolframConnector::new();
        let result = connector.handle_self_check().await.expect("self_check");
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_no_handshake() {
        let mut connector = WolframConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new()
            }))
            .await
            .expect("configure");
        let result = connector.handle_self_check().await.expect("self_check");
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "not_handshaken");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_ok() {
        let (connector, _key) = setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let result = connector.handle_self_check().await.expect("self_check");
        assert_eq!(result["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_and_self_check_use_base_url_policy_consistently() {
        let mut connector = WolframConnector::new();
        connector.config = Some(
            serde_json::from_value(json!({
                "credential_id": fcp_core::CredentialId::new(),
                "base_url": "https://api.wolframalpha.com.evil.example"
            }))
            .expect("stale config"),
        );
        connector.client = Some(WolframClient::with_base_url("http://unused".into()));
        connector.session_id = Some(SessionId::new());
        connector.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));

        let typed_doctor = connector.doctor();
        let typed_base_url = typed_doctor
            .checks
            .iter()
            .find(|check| check.name == "base_url")
            .expect("base_url check");
        assert!(!typed_doctor.passed);
        assert!(!typed_base_url.passed);

        let doctor = connector.handle_doctor().await.expect("doctor");
        assert_eq!(doctor["status"], "unhealthy");
        let base_url_check = doctor["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .find(|check| check["name"] == "base_url")
            .expect("base_url check");
        assert_eq!(base_url_check["passed"], false);
        assert_eq!(base_url_check["critical"], true);

        let self_check = connector.handle_self_check().await.expect("self_check");
        assert_eq!(self_check["status"], "failed");
        assert_eq!(self_check["reason_code"], "base_url_mismatch");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operation() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.query"],
        );
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-001",
                "connector_id": "wolfram",
                "operation": "wolfram.query",
                "zone_id": "z:work",
                "input": {"input": "2+2"},
                "capability_token": capability
            }))
            .await
            .expect("simulate");
        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.nonexistent"],
        );
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-002",
                "connector_id": "wolfram",
                "operation": "wolfram.nonexistent",
                "zone_id": "z:work",
                "input": {},
                "capability_token": capability
            }))
            .await
            .expect("simulate");
        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], "unknown_operation");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unconfigured() {
        let connector = WolframConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.query"],
        );
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-003",
                "connector_id": "wolfram",
                "operation": "wolfram.query",
                "zone_id": "z:work",
                "input": {},
                "capability_token": capability
            }))
            .await
            .expect("simulate");
        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_query() {
        let server = MockServer::start().await;
        let body = json!({
            "queryresult": {
                "success": true,
                "numpods": 1,
                "pods": [{
                    "title": "Result",
                    "id": "Result",
                    "primary": true,
                    "subpods": [{"plaintext": "4"}]
                }],
                "assumptions": []
            }
        });
        Mock::given(method("GET"))
            .and(path("/v2/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        // Use the server URI without the protocol for configure
        let base_url = server.uri();
        let (connector, signing_key) = setup_connector(&base_url, &["wolfram.query"]).await;

        // Override the client to use the mock server with protocol
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.query"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.query",
                "input": {"input": "2+2", "app_id": fixture_app_id()},
                "capability_token": capability
            }))
            .await
            .expect("invoke");
        assert_eq!(result["success"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_short_answer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/result"))
            .respond_with(ResponseTemplate::new(200).set_body_string("42"))
            .mount(&server)
            .await;

        let base_url = server.uri();
        let (connector, signing_key) = setup_connector(&base_url, &["wolfram.query"]).await;
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.short_answer"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.short_answer",
                "input": {"input": "meaning of life", "app_id": fixture_app_id()},
                "capability_token": capability
            }))
            .await
            .expect("invoke");
        assert_eq!(result["answer"], "42");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_spoken_result() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/spoken"))
            .respond_with(ResponseTemplate::new(200).set_body_string("The answer is 4"))
            .mount(&server)
            .await;

        let base_url = server.uri();
        let (connector, signing_key) = setup_connector(&base_url, &["wolfram.query"]).await;
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.spoken_result"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.spoken_result",
                "input": {"input": "2+2", "app_id": fixture_app_id()},
                "capability_token": capability
            }))
            .await
            .expect("invoke");
        assert_eq!(result["spoken"], "The answer is 4");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unconfigured() {
        let connector = WolframConnector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.query",
                "input": {"input": "test"}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_app_id() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.query"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.query",
                "input": {"input": "2+2"},
                "capability_token": capability
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { ref message, .. }) if message.contains("Missing 'app_id'")),
            "expected missing app_id error, got {result:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_empty_query_rejected() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.query"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.query",
                "input": {"input": ""},
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unknown_operation() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let capability = generate_token(
            &signing_key,
            &connector.base.instance_id,
            "wolfram.query",
            &["wolfram.nonexistent"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.nonexistent",
                "input": {"input": "test", "app_id": fixture_app_id()},
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_returns_three_operations() {
        let connector = WolframConnector::new();
        let introspection = connector
            .handle_introspect()
            .expect("introspection should serialize");
        let operations = introspection["operations"]
            .as_array()
            .expect("operations should be an array");
        assert_eq!(operations.len(), 3);
        let op_ids: Vec<&str> = operations
            .iter()
            .map(|operation| operation["id"].as_str().expect("operation id"))
            .collect();
        assert!(op_ids.contains(&"wolfram.query"));
        assert!(op_ids.contains(&"wolfram.short_answer"));
        assert!(op_ids.contains(&"wolfram.spoken_result"));
    }

    #[test]
    fn doctor_unconfigured_fails() {
        let connector = WolframConnector::new();
        let result = connector.doctor();
        assert!(!result.passed, "unconfigured connector should fail doctor");
        let config_check = result
            .checks
            .iter()
            .find(|c| c.name == "configuration")
            .unwrap();
        assert!(!config_check.passed);
        assert!(config_check.critical);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured_passes() {
        let mut connector = WolframConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new()
            }))
            .await
            .expect("configure");
        let result = connector.doctor();
        assert!(result.passed, "configured connector should pass doctor");
        assert!(result.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn doctor_result_from_checks_critical_failure() {
        let checks = vec![
            DoctorCheck {
                name: "ok_check".into(),
                passed: true,
                message: Some("Good".into()),
                critical: false,
            },
            DoctorCheck {
                name: "critical_fail".into(),
                passed: false,
                message: Some("Bad".into()),
                critical: true,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert!(!result.passed, "should fail when critical check fails");
    }

    #[test]
    fn doctor_result_from_checks_noncritical_failure_ok() {
        let checks = vec![
            DoctorCheck {
                name: "critical_ok".into(),
                passed: true,
                message: Some("Good".into()),
                critical: true,
            },
            DoctorCheck {
                name: "noncritical_fail".into(),
                passed: false,
                message: Some("Warning".into()),
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert!(
            result.passed,
            "should pass when only non-critical check fails"
        );
    }

    #[test]
    fn all_operations_are_safe() {
        let ops = wolfram_operations();
        for op in &ops {
            assert_eq!(
                op.safety_tier,
                SafetyTier::Safe,
                "op {} should be safe",
                op.id
            );
            assert_eq!(
                op.risk_level,
                RiskLevel::Low,
                "op {} should be low risk",
                op.id
            );
        }
    }

    #[test]
    fn all_operations_are_idempotent() {
        let ops = wolfram_operations();
        for op in &ops {
            assert_eq!(
                op.idempotency,
                IdempotencyClass::Strict,
                "op {} should be strict",
                op.id
            );
        }
    }

    #[test]
    fn all_operations_have_schemas() {
        let ops = wolfram_operations();
        for op in &ops {
            assert!(
                op.input_schema.is_object(),
                "op {} missing input schema",
                op.id
            );
            assert!(
                op.output_schema.is_object(),
                "op {} missing output schema",
                op.id
            );
        }
    }
}
