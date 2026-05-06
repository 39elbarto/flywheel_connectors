//! FCP Webhook Receiver Connector implementation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_PUBLIC_BASE_URL, WebhookStore},
    error::WebhookReceiverError,
    types::{WebhookEndpoint, WebhookEvent, WebhookProvider},
};

const INGRESS_LISTENER_STATUS: &str = "deferred";
const INGRESS_LISTENER_MESSAGE: &str = "Native HTTP ingress listener is not implemented in this connector build; endpoint URLs are provisioning metadata until a host or gateway ingress adapter binds them.";
const HOST_FORWARDED_INGRESS_STATUS: &str = "available";
const HOST_FORWARDED_INGRESS_MESSAGE: &str = "Host-forwarded webhook.events.ingest is available for gateway adapters; this connector still opens no socket itself.";
const GATEWAY_BINDING_STATUS: &str = "unbound";
const GATEWAY_BINDING_MESSAGE: &str =
    "No host or gateway HTTP adapter binding is reported by this connector instance.";
const WEBHOOK_EVENTS_INGEST_OPERATION: &str = "webhook.events.ingest";
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_BODY_TIMEOUT_MS: u64 = 15_000;
const MAX_BODY_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const DEFAULT_RATE_LIMIT_MAX: u64 = 120;
const MAX_RATE_LIMIT_MAX: u64 = 10_000;
const DEFAULT_IN_FLIGHT_MAX: u64 = 8;
const MAX_IN_FLIGHT_MAX: u64 = 1024;
const DEFAULT_SIGNATURE_TOLERANCE_SECONDS: i64 = 300;
const MAX_SIGNATURE_TOLERANCE_SECONDS: i64 = 24 * 60 * 60;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// Parsed and validated webhook receiver configuration.
#[derive(Debug, Clone)]
struct WebhookReceiverConfig {
    public_base_url: String,
    max_body_bytes: usize,
    body_timeout_ms: u64,
    rate_limit_window_ms: u64,
    rate_limit_max: u64,
    in_flight_max: u64,
    signature_tolerance_seconds: i64,
}

impl WebhookReceiverConfig {
    fn from_params(params: &serde_json::Value) -> Self {
        let public_base_url = params
            .get("public_base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_PUBLIC_BASE_URL)
            .to_string();

        Self {
            public_base_url,
            max_body_bytes: optional_usize_param(
                params,
                "max_body_bytes",
                DEFAULT_MAX_BODY_BYTES,
                MAX_BODY_BYTES,
            ),
            body_timeout_ms: optional_u64_param(
                params,
                "body_timeout_ms",
                DEFAULT_BODY_TIMEOUT_MS,
                MAX_BODY_TIMEOUT_MS,
            ),
            rate_limit_window_ms: optional_u64_param(
                params,
                "rate_limit_window_ms",
                DEFAULT_RATE_LIMIT_WINDOW_MS,
                u64::MAX,
            )
            .max(1),
            rate_limit_max: optional_u64_param(
                params,
                "rate_limit_max",
                DEFAULT_RATE_LIMIT_MAX,
                MAX_RATE_LIMIT_MAX,
            )
            .max(1),
            in_flight_max: optional_u64_param(
                params,
                "in_flight_max",
                DEFAULT_IN_FLIGHT_MAX,
                MAX_IN_FLIGHT_MAX,
            )
            .max(1),
            signature_tolerance_seconds: optional_i64_param(
                params,
                "signature_tolerance_seconds",
                DEFAULT_SIGNATURE_TOLERANCE_SECONDS,
                MAX_SIGNATURE_TOLERANCE_SECONDS,
            )
            .max(1),
        }
    }

    fn provisioning_readiness(&self, store: &WebhookStore) -> ProvisioningReadiness {
        let (public_base_url_accepted, publicly_routable, public_base_url_message) =
            public_base_url_policy(&self.public_base_url);
        let endpoints_with_issues = store
            .endpoint_snapshots()
            .into_iter()
            .filter_map(|endpoint| {
                let issues = endpoint.validation_issues();
                if issues.is_empty() {
                    None
                } else {
                    Some(EndpointProvisioningIssue {
                        endpoint_id: endpoint.endpoint_id,
                        provider: endpoint.provider.label().to_string(),
                        issues,
                    })
                }
            })
            .collect::<Vec<_>>();

        ProvisioningReadiness {
            public_base_url: self.public_base_url.clone(),
            public_base_url_accepted,
            publicly_routable,
            public_base_url_message,
            ingress_listener_status: INGRESS_LISTENER_STATUS.to_string(),
            ingress_listener_message: INGRESS_LISTENER_MESSAGE.to_string(),
            host_forwarded_ingress_status: HOST_FORWARDED_INGRESS_STATUS.to_string(),
            host_forwarded_ingress_message: HOST_FORWARDED_INGRESS_MESSAGE.to_string(),
            gateway_binding_status: GATEWAY_BINDING_STATUS.to_string(),
            gateway_binding_message: GATEWAY_BINDING_MESSAGE.to_string(),
            endpoint_count: store.endpoint_count(),
            active_endpoint_count: store.active_endpoint_count(),
            invalid_endpoint_count: endpoints_with_issues.len(),
            endpoints_with_issues,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EndpointProvisioningIssue {
    endpoint_id: String,
    provider: String,
    issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    public_base_url: String,
    public_base_url_accepted: bool,
    publicly_routable: bool,
    public_base_url_message: String,
    ingress_listener_status: String,
    ingress_listener_message: String,
    host_forwarded_ingress_status: String,
    host_forwarded_ingress_message: String,
    gateway_binding_status: String,
    gateway_binding_message: String,
    endpoint_count: usize,
    active_endpoint_count: usize,
    invalid_endpoint_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    endpoints_with_issues: Vec<EndpointProvisioningIssue>,
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

#[derive(Debug, Clone)]
struct RateWindow {
    count: u64,
    window_start_ms: u64,
}

#[derive(Debug, Default)]
struct IngressState {
    authenticated_rate: HashMap<String, RateWindow>,
    unauthenticated_rate: HashMap<String, RateWindow>,
    in_flight: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct IngestBody {
    payload: Value,
    raw_body: String,
    body_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
struct SignatureProof {
    provider: String,
    algorithm: String,
    header: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<i64>,
}

impl IngressState {
    fn enforce_rate_limit(
        &mut self,
        stage: &'static str,
        key: &str,
        config: &WebhookReceiverConfig,
        now_ms: u64,
    ) -> Result<Value, WebhookReceiverError> {
        let map = if stage == "authenticated" {
            &mut self.authenticated_rate
        } else {
            &mut self.unauthenticated_rate
        };
        let window = map.entry(key.to_string()).or_insert(RateWindow {
            count: 0,
            window_start_ms: now_ms,
        });
        if now_ms.saturating_sub(window.window_start_ms) >= config.rate_limit_window_ms {
            window.count = 0;
            window.window_start_ms = now_ms;
        }
        window.count = window.count.saturating_add(1);
        let limited = window.count > config.rate_limit_max;
        let snapshot = json!({
            "stage": stage,
            "key_hash": redacted_hash(key),
            "count": window.count,
            "max": config.rate_limit_max,
            "window_ms": config.rate_limit_window_ms,
            "limited": limited,
        });
        if limited {
            return Err(WebhookReceiverError::CapacityExceeded {
                message: format!("{stage} webhook ingest rate limit exceeded"),
            });
        }
        Ok(snapshot)
    }

    fn try_acquire(
        &mut self,
        key: &str,
        config: &WebhookReceiverConfig,
    ) -> Result<u64, WebhookReceiverError> {
        let current = self.in_flight.get(key).copied().unwrap_or(0);
        if current >= config.in_flight_max {
            return Err(WebhookReceiverError::CapacityExceeded {
                message: "webhook ingest in-flight limit exceeded".into(),
            });
        }
        let next = current + 1;
        self.in_flight.insert(key.to_string(), next);
        Ok(next)
    }

    fn release(&mut self, key: &str) {
        let Some(current) = self.in_flight.get_mut(key) else {
            return;
        };
        if *current <= 1 {
            self.in_flight.remove(key);
        } else {
            *current -= 1;
        }
    }
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

/// FCP Webhook Receiver Connector.
pub struct WebhookReceiverConnector {
    base: Arc<BaseConnector>,
    config: Option<WebhookReceiverConfig>,
    store: WebhookStore,
    ingress_state: IngressState,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl WebhookReceiverConnector {
    /// Create a new Webhook Receiver connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "webhook-receiver",
            ))),
            config: None,
            store: WebhookStore::new(),
            ingress_state: IngressState::default(),
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for WebhookReceiverConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookReceiverConnector {
    /// Handle the `configure` method.
    ///
    /// The webhook receiver is a local meta-connector so configuration is
    /// minimal. No external API credentials are needed.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = WebhookReceiverConfig::from_params(&params);
        info!(public_base_url = %config.public_base_url, "Configuring Webhook Receiver connector");
        self.store.set_public_base_url(&config.public_base_url);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({
            "public_base_url": self.store.public_base_url(),
            "ingress_listener_status": INGRESS_LISTENER_STATUS,
            "ingress_listener_message": INGRESS_LISTENER_MESSAGE,
            "host_forwarded_ingress_status": HOST_FORWARDED_INGRESS_STATUS,
            "host_forwarded_ingress_message": HOST_FORWARDED_INGRESS_MESSAGE,
            "gateway_binding_status": GATEWAY_BINDING_STATUS,
            "gateway_binding_message": GATEWAY_BINDING_MESSAGE,
        }))
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
            "connector_id": "fcp.webhook-receiver",
            "connector_version": "0.1.0",
            "capabilities": [
                "webhook.endpoints.read",
                "webhook.endpoints.write",
                "webhook.events.read",
                "webhook.events.write"
            ],
            "event_caps": webhook_event_caps(),
            "ingress_binding": ingress_binding_info()
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
            "endpoints": self.store.endpoint_count(),
            "events": self.store.total_event_count(),
            "public_base_url": self.config.as_ref().map(|config| config.public_base_url.clone()),
            "ingress_listener_status": INGRESS_LISTENER_STATUS,
            "ingress_listener_message": INGRESS_LISTENER_MESSAGE,
            "host_forwarded_ingress_status": HOST_FORWARDED_INGRESS_STATUS,
            "host_forwarded_ingress_message": HOST_FORWARDED_INGRESS_MESSAGE,
            "gateway_binding_status": GATEWAY_BINDING_STATUS,
            "gateway_binding_message": GATEWAY_BINDING_MESSAGE,
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured - call configure first".into())
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "store_initialized".into(),
            passed: true,
            message: None,
            critical: true,
        });

        if let Some(config) = &self.config {
            let readiness = config.provisioning_readiness(&self.store);
            checks.push(DoctorCheck {
                name: "public_base_url".into(),
                passed: readiness.public_base_url_accepted,
                message: Some(readiness.public_base_url_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "public_reachability".into(),
                passed: readiness.publicly_routable,
                message: Some(readiness.public_base_url_message.clone()),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "endpoint_profiles".into(),
                passed: readiness.invalid_endpoint_count == 0,
                message: if readiness.invalid_endpoint_count == 0 {
                    Some(format!(
                        "{} endpoint profile(s) validated",
                        readiness.endpoint_count
                    ))
                } else {
                    Some(format!(
                        "{} endpoint profile(s) failed validation",
                        readiness.invalid_endpoint_count
                    ))
                },
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "ingress_listener".into(),
                passed: false,
                message: Some(readiness.ingress_listener_message),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "host_forwarded_ingress".into(),
                passed: true,
                message: Some(readiness.host_forwarded_ingress_message),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "gateway_binding".into(),
                passed: false,
                message: Some(readiness.gateway_binding_message),
                critical: false,
            });
        }

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
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness(&self.store);
        if !readiness.public_base_url_accepted {
            let mut report = SelfCheckReport::failed(
                "public_base_url_invalid",
                readiness.public_base_url_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        if readiness.invalid_endpoint_count > 0 {
            let mut report = SelfCheckReport::failed(
                "endpoint_profiles_invalid",
                format!(
                    "{} endpoint profile(s) failed validation",
                    readiness.invalid_endpoint_count
                ),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        if !readiness.publicly_routable {
            let mut report = SelfCheckReport::degraded(
                "public_base_url_not_public",
                readiness.public_base_url_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::degraded(
            "gateway_ingress_unbound",
            readiness.gateway_binding_message.clone(),
        );
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = operations_info();
        Ok(json!({
            "connector_id": "fcp.webhook-receiver",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
            "ingress_listener": {
                "status": INGRESS_LISTENER_STATUS,
                "message": INGRESS_LISTENER_MESSAGE,
            },
            "host_forwarded_ingress": {
                "status": HOST_FORWARDED_INGRESS_STATUS,
                "operation": WEBHOOK_EVENTS_INGEST_OPERATION,
                "message": HOST_FORWARDED_INGRESS_MESSAGE,
            },
            "gateway_binding": {
                "status": GATEWAY_BINDING_STATUS,
                "message": GATEWAY_BINDING_MESSAGE,
            },
            "event_caps": webhook_event_caps(),
            "ingress_binding": ingress_binding_info(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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

        let result = match operation {
            "webhook.endpoints.create" => self.invoke_endpoints_create(&input),
            "webhook.endpoints.rotate_secret" => self.invoke_endpoints_rotate_secret(&input),
            "webhook.endpoints.delete" => self.invoke_endpoints_delete(&input),
            "webhook.endpoints.list" => self.invoke_endpoints_list(),
            "webhook.events.recent" => self.invoke_events_recent(&input),
            WEBHOOK_EVENTS_INGEST_OPERATION => self.invoke_events_ingest(&input),
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

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

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
        info!("Webhook Receiver connector shutting down");
        self.store.clear();
        self.ingress_state = IngressState::default();
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        self.session_id = None;
        Ok(json!({}))
    }

    // -- Operation implementations --

    fn invoke_endpoints_create(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let path = require_str(input, "path")?.trim();
        if path.is_empty() {
            return Err(WebhookReceiverError::InvalidInput {
                message: "path must not be empty".into(),
            });
        }

        let provider = parse_provider(input)?;
        let provided_credential = optional_str(input, "signing_secret")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let credential_generated = provided_credential.is_none();
        let endpoint_credential =
            provided_credential.unwrap_or_else(|| generate_signing_secret(provider));
        let signature_header = optional_str(input, "signature_header")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(
                || provider.default_signature_header().to_string(),
                str::to_string,
            );

        let signature_algorithm = optional_str(input, "signature_algorithm")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(
                || provider.default_signature_algorithm().to_string(),
                str::to_string,
            );
        let allowed_sources = parse_string_array(input, "allowed_sources")?;

        let endpoint = self.store.create_endpoint_profile(
            path.to_string(),
            endpoint_credential,
            allowed_sources,
            provider,
            signature_header,
            signature_algorithm,
        )?;

        Ok(json!({
            "endpoint_id": endpoint.endpoint_id,
            "url": endpoint.url,
            "provider": endpoint.provider,
            "signature_header": endpoint.signature_header,
            "signature_algorithm": endpoint.signature_algorithm,
            "recommended_events": endpoint.provider.recommended_events(),
            "signing_secret": endpoint.signing_secret,
            "signing_secret_generated": credential_generated,
            "secret_last_rotated_at": endpoint.secret_last_rotated_at.to_rfc3339(),
        }))
    }

    fn invoke_endpoints_rotate_secret(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoint_id = require_str(input, "endpoint_id")?;
        let provider = self.store.get_endpoint(endpoint_id)?.provider;
        let provided_credential = optional_str(input, "signing_secret")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let credential_generated = provided_credential.is_none();
        let endpoint_credential =
            provided_credential.unwrap_or_else(|| generate_signing_secret(provider));
        let endpoint = self
            .store
            .rotate_endpoint_secret(endpoint_id, endpoint_credential)?;

        Ok(json!({
            "endpoint_id": endpoint.endpoint_id,
            "url": endpoint.url,
            "provider": endpoint.provider,
            "signature_header": endpoint.signature_header,
            "signature_algorithm": endpoint.signature_algorithm,
            "recommended_events": endpoint.provider.recommended_events(),
            "signing_secret": endpoint.signing_secret,
            "signing_secret_generated": credential_generated,
            "secret_last_rotated_at": endpoint.secret_last_rotated_at.to_rfc3339(),
        }))
    }

    fn invoke_endpoints_delete(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoint_id = require_str(input, "endpoint_id")?;
        self.store.delete_endpoint(endpoint_id)?;
        Ok(json!({}))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn invoke_endpoints_list(&self) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoints = self.store.list_endpoints();
        let endpoints_json: Vec<serde_json::Value> = endpoints
            .iter()
            .map(|ep| {
                json!({
                    "endpoint_id": ep.endpoint_id,
                    "path": ep.path,
                    "url": ep.url,
                    "provider": ep.provider,
                    "signature_header": ep.signature_header,
                    "signature_algorithm": ep.signature_algorithm,
                    "allowed_sources": ep.allowed_sources,
                    "signing_secret_configured": ep.signing_secret_configured,
                    "secret_last_rotated_at": ep.secret_last_rotated_at.to_rfc3339(),
                    "active": ep.active,
                    "created_at": ep.created_at.to_rfc3339(),
                    "event_count": ep.event_count,
                })
            })
            .collect();

        Ok(json!({ "endpoints": endpoints_json }))
    }

    fn invoke_events_recent(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoint_id = input.get("endpoint_id").and_then(serde_json::Value::as_str);

        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as usize);

        let since_ts = input
            .get("since_ts")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        let events = self.store.get_recent_events(endpoint_id, limit, since_ts)?;

        let events_json: Vec<serde_json::Value> = events
            .iter()
            .map(|evt| {
                json!({
                    "event_id": evt.event_id,
                    "endpoint_id": evt.endpoint_id,
                    "received_at": evt.received_at.to_rfc3339(),
                    "headers": evt.headers,
                    "payload": evt.payload,
                    "signature_valid": evt.signature_valid,
                    "source_ip_hash": evt.source_ip.as_deref().map(redacted_hash),
                })
            })
            .collect();

        Ok(json!({ "events": events_json }))
    }

    fn invoke_events_ingest(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let config = self
            .config
            .clone()
            .ok_or_else(|| WebhookReceiverError::InvalidInput {
                message: "connector must be configured before webhook ingest".into(),
            })?;

        if request_region_bool(input, "deadline_exceeded")
            || request_region_bool(input, "cancelled")
            || request_region_bool(input, "body_timeout")
        {
            return Err(WebhookReceiverError::RequestTimeout {
                message: "webhook request-region deadline was exceeded".into(),
            });
        }

        let method = optional_str(input, "method")?.unwrap_or("POST").trim();
        if !method.eq_ignore_ascii_case("POST") {
            return Err(WebhookReceiverError::MethodNotAllowed {
                method: method.to_string(),
            });
        }

        let path = require_str(input, "path")?.trim();
        if path.is_empty() {
            return Err(WebhookReceiverError::InvalidInput {
                message: "path must not be empty".into(),
            });
        }

        let endpoint = self.store.get_endpoint_by_path(path)?.clone();
        let headers = parse_headers(input)?;
        validate_ingest_content_type(&headers, endpoint.provider)?;
        enforce_source_allowlist(&endpoint, optional_ingest_source_ip(input)?)?;

        let client_key = optional_str(input, "client_id")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| optional_ingest_source_ip(input).ok().flatten())
            .unwrap_or_else(|| "unknown-client".into());
        let rate_key = format!("{path}:{client_key}");
        let now_ms = now_ms();

        let unauthenticated_rate =
            self.ingress_state
                .enforce_rate_limit("unauthenticated", &rate_key, &config, now_ms)?;
        let in_flight_count = self.ingress_state.try_acquire(&rate_key, &config)?;
        let result = self.finish_events_ingest(
            input,
            &config,
            &endpoint,
            &headers,
            &client_key,
            &rate_key,
            &unauthenticated_rate,
            in_flight_count,
            now_ms,
        );
        self.ingress_state.release(&rate_key);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_events_ingest(
        &mut self,
        input: &serde_json::Value,
        config: &WebhookReceiverConfig,
        endpoint: &WebhookEndpoint,
        headers: &BTreeMap<String, String>,
        client_key: &str,
        rate_key: &str,
        unauthenticated_rate: &Value,
        in_flight_count: u64,
        now_ms: u64,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let body = ingest_body(input, config.max_body_bytes)?;
        let signature = verify_endpoint_signature(
            endpoint,
            headers,
            &body,
            input,
            config.signature_tolerance_seconds,
        )?;
        let authenticated_rate =
            self.ingress_state
                .enforce_rate_limit("authenticated", rate_key, config, now_ms)?;

        let event_id =
            event_id_for_ingest(input, headers, &body.payload, endpoint, &body.raw_body)?;
        let received_at = Utc::now();
        let source_ip = optional_ingest_source_ip(input)?;
        let event = WebhookEvent {
            event_id: event_id.clone(),
            endpoint_id: endpoint.endpoint_id.clone(),
            received_at,
            headers: redacted_event_headers(headers, endpoint),
            payload: body.payload.clone(),
            signature_valid: true,
            source_ip: source_ip.clone(),
        };
        self.store.record_event(event)?;

        Ok(json!({
            "accepted": true,
            "status_code": 202,
            "event": {
                "event_id": event_id,
                "endpoint_id": endpoint.endpoint_id,
                "path": endpoint.path,
                "provider": endpoint.provider,
                "received_at": received_at.to_rfc3339(),
                "source_ip_hash": source_ip.as_deref().map(redacted_hash),
            },
            "ingest_log": {
                "decision": "accepted",
                "path": endpoint.path,
                "provider": endpoint.provider.label(),
                "client_hash": redacted_hash(client_key),
                "body_bytes": body.body_bytes,
                "signature": signature,
                "rate_limits": [unauthenticated_rate, authenticated_rate],
                "in_flight": {
                    "key_hash": redacted_hash(rate_key),
                    "count": in_flight_count,
                    "max": config.in_flight_max,
                },
                "body_timeout_ms": config.body_timeout_ms,
                "max_body_bytes": config.max_body_bytes,
            },
            "event_caps": webhook_event_caps(),
            "ingress_binding": ingress_binding_info(),
        }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, WebhookReceiverError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: format!("Missing required field: {field}"),
        })
}

/// Extract an optional string field from input, rejecting non-string values.
fn optional_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<Option<&'a str>, WebhookReceiverError> {
    match input.get(field) {
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| WebhookReceiverError::InvalidInput {
                message: format!("{field} must be a string"),
            }),
        None => Ok(None),
    }
}

/// Parse a string array field, rejecting non-string or blank entries.
fn parse_string_array(
    input: &serde_json::Value,
    field: &str,
) -> Result<Vec<String>, WebhookReceiverError> {
    let Some(value) = input.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: format!("{field} must be an array of strings"),
        })?;

    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let entry = value
                .as_str()
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .ok_or_else(|| WebhookReceiverError::InvalidInput {
                    message: format!("{field}[{index}] must be a non-empty string"),
                })?;
            Ok(entry.to_string())
        })
        .collect()
}

/// Parse a provider preset from create input.
fn parse_provider(input: &serde_json::Value) -> Result<WebhookProvider, WebhookReceiverError> {
    let Some(provider) = optional_str(input, "provider")? else {
        return Ok(WebhookProvider::default());
    };

    WebhookProvider::from_label(provider).ok_or_else(|| WebhookReceiverError::InvalidInput {
        message: format!("Unsupported provider preset: {provider}"),
    })
}

fn optional_usize_param(
    input: &serde_json::Value,
    field: &str,
    default: usize,
    max: usize,
) -> usize {
    input
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .map_or(default, |value| value.min(max))
}

fn optional_u64_param(input: &serde_json::Value, field: &str, default: u64, max: u64) -> u64 {
    input
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0)
        .map_or(default, |value| value.min(max))
}

fn optional_i64_param(input: &serde_json::Value, field: &str, default: i64, max: i64) -> i64 {
    input
        .get(field)
        .and_then(serde_json::Value::as_i64)
        .filter(|value| *value > 0)
        .map_or(default, |value| value.min(max))
}

fn optional_usize_field(
    input: &serde_json::Value,
    field: &str,
) -> Result<Option<usize>, WebhookReceiverError> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let raw = value
        .as_u64()
        .ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: format!("{field} must be an unsigned integer"),
        })?;
    let converted = usize::try_from(raw).map_err(|_| WebhookReceiverError::InvalidInput {
        message: format!("{field} is too large"),
    })?;
    Ok(Some(converted))
}

fn parse_headers(
    input: &serde_json::Value,
) -> Result<BTreeMap<String, String>, WebhookReceiverError> {
    let headers = input
        .get("headers")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: "headers must be an object of HTTP header strings".into(),
        })?;
    let mut parsed = BTreeMap::new();
    for (key, value) in headers {
        let value = value
            .as_str()
            .ok_or_else(|| WebhookReceiverError::InvalidInput {
                message: format!("header `{key}` must be a string"),
            })?
            .trim()
            .to_string();
        parsed.insert(key.to_ascii_lowercase(), value);
    }
    Ok(parsed)
}

fn header_value<'a>(headers: &'a BTreeMap<String, String>, header_name: &str) -> Option<&'a str> {
    headers
        .get(&header_name.to_ascii_lowercase())
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn validate_ingest_content_type(
    headers: &BTreeMap<String, String>,
    provider: WebhookProvider,
) -> Result<(), WebhookReceiverError> {
    let content_type = header_value(headers, "content-type").ok_or_else(|| {
        WebhookReceiverError::InvalidInput {
            message: "Missing required Content-Type header".into(),
        }
    })?;
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    let json_like = media_type == "application/json" || media_type.ends_with("+json");
    let twilio_form =
        provider == WebhookProvider::Twilio && media_type == "application/x-www-form-urlencoded";
    if json_like || twilio_form {
        Ok(())
    } else {
        Err(WebhookReceiverError::UnsupportedMediaType {
            content_type: content_type.to_string(),
        })
    }
}

fn ingest_body(
    input: &serde_json::Value,
    max_bytes: usize,
) -> Result<IngestBody, WebhookReceiverError> {
    if optional_usize_field(input, "body_size_bytes")?.is_some_and(|size| size > max_bytes) {
        return Err(WebhookReceiverError::PayloadTooLarge {
            message: format!("webhook body exceeds maximum size of {max_bytes} bytes"),
        });
    }

    if let Some(value) = input.get("body") {
        let raw_body = value
            .as_str()
            .ok_or_else(|| WebhookReceiverError::InvalidInput {
                message: "body must be a JSON string".into(),
            })?
            .to_string();
        let body_bytes = raw_body.len();
        if body_bytes > max_bytes {
            return Err(WebhookReceiverError::PayloadTooLarge {
                message: format!("webhook body exceeds maximum size of {max_bytes} bytes"),
            });
        }
        let payload = serde_json::from_str(&raw_body).map_err(|error| {
            WebhookReceiverError::InvalidInput {
                message: format!("webhook body is not valid JSON: {error}"),
            }
        })?;
        return Ok(IngestBody {
            payload,
            raw_body,
            body_bytes,
        });
    }

    let payload =
        input
            .get("payload")
            .cloned()
            .ok_or_else(|| WebhookReceiverError::InvalidInput {
                message: "Missing required body or payload field".into(),
            })?;
    let raw_body =
        serde_json::to_string(&payload).map_err(|error| WebhookReceiverError::Internal {
            message: format!("Failed to serialize webhook payload: {error}"),
        })?;
    let body_bytes = raw_body.len();
    if body_bytes > max_bytes {
        return Err(WebhookReceiverError::PayloadTooLarge {
            message: format!("webhook payload exceeds maximum size of {max_bytes} bytes"),
        });
    }
    Ok(IngestBody {
        payload,
        raw_body,
        body_bytes,
    })
}

fn optional_ingest_source_ip(
    input: &serde_json::Value,
) -> Result<Option<String>, WebhookReceiverError> {
    for field in ["source_ip", "remote_addr", "client_ip"] {
        if let Some(value) = optional_str(input, field)?
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

fn enforce_source_allowlist(
    endpoint: &WebhookEndpoint,
    source_ip: Option<String>,
) -> Result<(), WebhookReceiverError> {
    if endpoint.allowed_sources.is_empty() {
        return Ok(());
    }
    let source_ip = source_ip.ok_or_else(|| WebhookReceiverError::Forbidden {
        message: "source_ip is required when allowed_sources is configured".into(),
    })?;
    let ip = source_ip
        .parse::<IpAddr>()
        .map_err(|_| WebhookReceiverError::Forbidden {
            message: "source_ip is not a valid IP address".into(),
        })?;
    for source in &endpoint.allowed_sources {
        if source_pattern_matches_ip(source, ip)? {
            return Ok(());
        }
    }
    Err(WebhookReceiverError::Forbidden {
        message: "source_ip is not in endpoint allowed_sources".into(),
    })
}

fn source_pattern_matches_ip(pattern: &str, ip: IpAddr) -> Result<bool, WebhookReceiverError> {
    let pattern = pattern.trim();
    if let Some((addr, prefix)) = pattern.split_once('/') {
        let base = addr
            .parse::<IpAddr>()
            .map_err(|_| WebhookReceiverError::InvalidInput {
                message: format!("invalid allowed_sources CIDR: {pattern}"),
            })?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| WebhookReceiverError::InvalidInput {
                message: format!("invalid allowed_sources CIDR prefix: {pattern}"),
            })?;
        return ip_in_cidr(ip, base, prefix).ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: format!("allowed_sources CIDR family does not match request IP: {pattern}"),
        });
    }
    let exact = pattern
        .parse::<IpAddr>()
        .map_err(|_| WebhookReceiverError::InvalidInput {
            message: format!("invalid allowed_sources IP address: {pattern}"),
        })?;
    Ok(exact == ip)
}

fn ip_in_cidr(ip: IpAddr, base: IpAddr, prefix: u8) -> Option<bool> {
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) if prefix <= 32 => {
            let mask = ipv4_mask(prefix);
            Some((u32::from(ip) & mask) == (u32::from(base) & mask))
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) if prefix <= 128 => {
            let mask = ipv6_mask(prefix);
            Some((u128::from(ip) & mask) == (u128::from(base) & mask))
        }
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => Some(false),
        _ => None,
    }
}

const fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn verify_endpoint_signature(
    endpoint: &WebhookEndpoint,
    headers: &BTreeMap<String, String>,
    body: &IngestBody,
    input: &serde_json::Value,
    tolerance_seconds: i64,
) -> Result<SignatureProof, WebhookReceiverError> {
    match endpoint.signature_algorithm.to_ascii_lowercase().as_str() {
        "hmac-sha256" => verify_hmac_sha256_signature(endpoint, headers, body),
        "stripe-signature-v1" => {
            verify_stripe_signature(endpoint, headers, body, tolerance_seconds)
        }
        "slack-signature-v0" => verify_slack_signature(endpoint, headers, body, tolerance_seconds),
        "twilio-hmac-sha1" => verify_twilio_signature(endpoint, headers, body, input),
        other => Err(WebhookReceiverError::InvalidInput {
            message: format!("unsupported signature algorithm: {other}"),
        }),
    }
}

fn verify_hmac_sha256_signature(
    endpoint: &WebhookEndpoint,
    headers: &BTreeMap<String, String>,
    body: &IngestBody,
) -> Result<SignatureProof, WebhookReceiverError> {
    let signature = header_value(headers, &endpoint.signature_header).ok_or_else(|| {
        WebhookReceiverError::Unauthorized {
            message: format!("missing signature header {}", endpoint.signature_header),
        }
    })?;
    verify_hmac_sha256_hex(
        &endpoint.signing_secret,
        body.raw_body.as_bytes(),
        signature,
    )?;
    Ok(SignatureProof {
        provider: endpoint.provider.label().to_string(),
        algorithm: endpoint.signature_algorithm.clone(),
        header: endpoint.signature_header.clone(),
        timestamp: None,
    })
}

fn verify_stripe_signature(
    endpoint: &WebhookEndpoint,
    headers: &BTreeMap<String, String>,
    body: &IngestBody,
    tolerance_seconds: i64,
) -> Result<SignatureProof, WebhookReceiverError> {
    let signature = header_value(headers, &endpoint.signature_header).ok_or_else(|| {
        WebhookReceiverError::Unauthorized {
            message: format!("missing signature header {}", endpoint.signature_header),
        }
    })?;
    let parsed = parse_stripe_signature_header(signature)?;
    enforce_signature_timestamp(parsed.timestamp, tolerance_seconds, "Stripe")?;
    let signed_payload = format!("{}.{}", parsed.timestamp, body.raw_body);
    let expected = hmac_sha256(&endpoint.signing_secret, signed_payload.as_bytes())?;
    let verified = parsed.v1_signatures.iter().any(|candidate| {
        hex::decode(candidate)
            .is_ok_and(|decoded| decoded.len() == expected.len() && ct_eq(&decoded, &expected))
    });
    if !verified {
        return Err(WebhookReceiverError::Unauthorized {
            message: "Stripe webhook signature verification failed".into(),
        });
    }
    Ok(SignatureProof {
        provider: endpoint.provider.label().to_string(),
        algorithm: endpoint.signature_algorithm.clone(),
        header: endpoint.signature_header.clone(),
        timestamp: Some(parsed.timestamp),
    })
}

fn verify_slack_signature(
    endpoint: &WebhookEndpoint,
    headers: &BTreeMap<String, String>,
    body: &IngestBody,
    tolerance_seconds: i64,
) -> Result<SignatureProof, WebhookReceiverError> {
    let signature = header_value(headers, &endpoint.signature_header).ok_or_else(|| {
        WebhookReceiverError::Unauthorized {
            message: format!("missing signature header {}", endpoint.signature_header),
        }
    })?;
    let timestamp = header_value(headers, "X-Slack-Request-Timestamp")
        .ok_or_else(|| WebhookReceiverError::Unauthorized {
            message: "missing X-Slack-Request-Timestamp header".into(),
        })?
        .parse::<i64>()
        .map_err(|_| WebhookReceiverError::Unauthorized {
            message: "invalid X-Slack-Request-Timestamp header".into(),
        })?;
    enforce_signature_timestamp(timestamp, tolerance_seconds, "Slack")?;
    let signed_payload = format!("v0:{timestamp}:{}", body.raw_body);
    let expected = hmac_sha256(&endpoint.signing_secret, signed_payload.as_bytes())?;
    let candidate =
        signature
            .strip_prefix("v0=")
            .ok_or_else(|| WebhookReceiverError::Unauthorized {
                message: "Slack signature must use v0= prefix".into(),
            })?;
    let decoded = hex::decode(candidate).map_err(|_| WebhookReceiverError::Unauthorized {
        message: "Slack signature is not valid hex".into(),
    })?;
    if decoded.len() != expected.len() || !ct_eq(&decoded, &expected) {
        return Err(WebhookReceiverError::Unauthorized {
            message: "Slack webhook signature verification failed".into(),
        });
    }
    Ok(SignatureProof {
        provider: endpoint.provider.label().to_string(),
        algorithm: endpoint.signature_algorithm.clone(),
        header: endpoint.signature_header.clone(),
        timestamp: Some(timestamp),
    })
}

fn verify_twilio_signature(
    endpoint: &WebhookEndpoint,
    headers: &BTreeMap<String, String>,
    body: &IngestBody,
    input: &serde_json::Value,
) -> Result<SignatureProof, WebhookReceiverError> {
    let signature = header_value(headers, &endpoint.signature_header).ok_or_else(|| {
        WebhookReceiverError::Unauthorized {
            message: format!("missing signature header {}", endpoint.signature_header),
        }
    })?;
    let provided = STANDARD
        .decode(signature)
        .map_err(|_| WebhookReceiverError::Unauthorized {
            message: "Twilio signature is not valid base64".into(),
        })?;
    let params = input.get("params").unwrap_or(&body.payload);
    let sorted = sorted_twilio_params(params)?;
    let url = optional_str(input, "url")?
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(endpoint.url.as_str());
    validate_twilio_url(url)?;
    let mut data_to_sign = url.to_string();
    for (key, value) in sorted {
        data_to_sign.push_str(&key);
        data_to_sign.push_str(&value);
    }
    let expected = hmac_sha1(&endpoint.signing_secret, data_to_sign.as_bytes())?;
    if provided.len() != expected.len() || !ct_eq(&provided, &expected) {
        return Err(WebhookReceiverError::Unauthorized {
            message: "Twilio webhook signature verification failed".into(),
        });
    }
    Ok(SignatureProof {
        provider: endpoint.provider.label().to_string(),
        algorithm: endpoint.signature_algorithm.clone(),
        header: endpoint.signature_header.clone(),
        timestamp: None,
    })
}

#[derive(Debug)]
struct StripeSignatureParts {
    timestamp: i64,
    v1_signatures: Vec<String>,
}

fn parse_stripe_signature_header(
    header: &str,
) -> Result<StripeSignatureParts, WebhookReceiverError> {
    let mut timestamp = None;
    let mut v1_signatures = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if let Some(raw) = part.strip_prefix("t=") {
            timestamp =
                Some(
                    raw.parse::<i64>()
                        .map_err(|_| WebhookReceiverError::Unauthorized {
                            message: "Stripe signature timestamp is invalid".into(),
                        })?,
                );
        } else if let Some(signature) = part.strip_prefix("v1=") {
            let signature = signature.trim();
            if !signature.is_empty() {
                v1_signatures.push(signature.to_string());
            }
        }
    }
    let timestamp = timestamp.ok_or_else(|| WebhookReceiverError::Unauthorized {
        message: "Stripe signature is missing t= timestamp".into(),
    })?;
    if v1_signatures.is_empty() {
        return Err(WebhookReceiverError::Unauthorized {
            message: "Stripe signature is missing v1= signature".into(),
        });
    }
    Ok(StripeSignatureParts {
        timestamp,
        v1_signatures,
    })
}

fn enforce_signature_timestamp(
    timestamp: i64,
    tolerance_seconds: i64,
    provider: &str,
) -> Result<(), WebhookReceiverError> {
    let now = now_unix_seconds();
    if now.abs_diff(timestamp) > tolerance_seconds as u64 {
        return Err(WebhookReceiverError::Unauthorized {
            message: format!("{provider} webhook signature timestamp is outside allowed tolerance"),
        });
    }
    Ok(())
}

fn verify_hmac_sha256_hex(
    secret: &str,
    data: &[u8],
    signature: &str,
) -> Result<(), WebhookReceiverError> {
    let expected = hmac_sha256(secret, data)?;
    let candidate = signature
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or_else(|| signature.trim());
    let decoded = hex::decode(candidate).map_err(|_| WebhookReceiverError::Unauthorized {
        message: "HMAC-SHA256 signature is not valid hex".into(),
    })?;
    if decoded.len() != expected.len() || !ct_eq(&decoded, &expected) {
        return Err(WebhookReceiverError::Unauthorized {
            message: "HMAC-SHA256 webhook signature verification failed".into(),
        });
    }
    Ok(())
}

fn hmac_sha256(secret: &str, data: &[u8]) -> Result<Vec<u8>, WebhookReceiverError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|error| {
        WebhookReceiverError::Internal {
            message: format!("failed to initialize HMAC-SHA256 verifier: {error}"),
        }
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha1(secret: &str, data: &[u8]) -> Result<Vec<u8>, WebhookReceiverError> {
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).map_err(|error| {
        WebhookReceiverError::Internal {
            message: format!("failed to initialize HMAC-SHA1 verifier: {error}"),
        }
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

fn sorted_twilio_params(
    params: &serde_json::Value,
) -> Result<Vec<(String, String)>, WebhookReceiverError> {
    let params = params
        .as_object()
        .ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: "Twilio payload must be an object of form fields".into(),
        })?;
    let mut sorted = Vec::with_capacity(params.len());
    for (field, value) in params {
        sorted.push((field.clone(), twilio_param_value_to_string(field, value)?));
    }
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(sorted)
}

fn twilio_param_value_to_string(
    field: &str,
    value: &serde_json::Value,
) -> Result<String, WebhookReceiverError> {
    match value {
        serde_json::Value::String(value) => Ok(value.clone()),
        serde_json::Value::Number(value) => Ok(value.to_string()),
        serde_json::Value::Bool(value) => Ok(value.to_string()),
        serde_json::Value::Null => Ok(String::new()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            Err(WebhookReceiverError::InvalidInput {
                message: format!(
                    "Twilio webhook params field `{field}` must be a scalar string, number, boolean, or null"
                ),
            })
        }
    }
}

fn validate_twilio_url(url: &str) -> Result<(), WebhookReceiverError> {
    let parsed = Url::parse(url).map_err(|error| WebhookReceiverError::InvalidInput {
        message: format!("invalid Twilio webhook url: {error}"),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(WebhookReceiverError::InvalidInput {
            message: "Twilio webhook url must use http or https".into(),
        });
    }
    if parsed.host_str().is_none() {
        return Err(WebhookReceiverError::InvalidInput {
            message: "Twilio webhook url must include a host".into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(WebhookReceiverError::InvalidInput {
            message: "Twilio webhook url must not include userinfo".into(),
        });
    }
    if parsed.fragment().is_some() {
        return Err(WebhookReceiverError::InvalidInput {
            message: "Twilio webhook url must not include a fragment".into(),
        });
    }
    Ok(())
}

fn event_id_for_ingest(
    input: &serde_json::Value,
    headers: &BTreeMap<String, String>,
    payload: &serde_json::Value,
    endpoint: &WebhookEndpoint,
    raw_body: &str,
) -> Result<String, WebhookReceiverError> {
    for field in ["delivery_id", "event_id", "request_id"] {
        if let Some(value) = optional_str(input, field)?
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Ok(value.to_string());
        }
    }
    for header in [
        "X-GitHub-Delivery",
        "X-Request-ID",
        "Stripe-Request-Id",
        "X-Slack-Request-Id",
    ] {
        if let Some(value) = header_value(headers, header) {
            return Ok(value.to_string());
        }
    }
    for field in [
        "id",
        "event_id",
        "eventId",
        "delivery_id",
        "MessageSid",
        "SmsSid",
        "CallSid",
    ] {
        if let Some(value) = payload
            .get(field)
            .and_then(value_to_event_id_component)
            .filter(|value| !value.is_empty())
        {
            return Ok(value);
        }
    }
    Ok(format!(
        "evt_{}",
        redacted_hash(&format!("{}:{raw_body}", endpoint.endpoint_id))
    ))
}

fn value_to_event_id_component(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_string())
        }
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn redacted_event_headers(
    headers: &BTreeMap<String, String>,
    endpoint: &WebhookEndpoint,
) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(key, _)| !is_sensitive_header(key, endpoint))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn is_sensitive_header(key: &str, endpoint: &WebhookEndpoint) -> bool {
    let lower = key.to_ascii_lowercase();
    lower == endpoint.signature_header.to_ascii_lowercase()
        || lower.contains("authorization")
        || lower.contains("cookie")
        || lower.contains("signature")
        || lower.contains("secret")
        || lower.contains("token")
}

fn request_region_bool(input: &serde_json::Value, field: &str) -> bool {
    input
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

fn redacted_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

fn webhook_event_caps() -> serde_json::Value {
    json!({
        "streaming": false,
        "replay": true,
        "min_buffer_events": crate::client::MAX_EVENTS_PER_ENDPOINT,
        "host_forwarded_ingress_operation": WEBHOOK_EVENTS_INGEST_OPERATION,
        "native_listener": false,
    })
}

fn ingress_binding_info() -> serde_json::Value {
    json!({
        "native_listener": {
            "status": INGRESS_LISTENER_STATUS,
            "message": INGRESS_LISTENER_MESSAGE,
        },
        "host_forwarded_operation": {
            "status": HOST_FORWARDED_INGRESS_STATUS,
            "operation": WEBHOOK_EVENTS_INGEST_OPERATION,
            "message": HOST_FORWARDED_INGRESS_MESSAGE,
        },
        "gateway_adapter": {
            "status": GATEWAY_BINDING_STATUS,
            "message": GATEWAY_BINDING_MESSAGE,
        },
    })
}

/// Generate a high-entropy signing secret with a provider-specific prefix.
fn generate_signing_secret(provider: WebhookProvider) -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!(
        "{}{}",
        provider.secret_prefix(),
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn public_base_url_policy(public_base_url: &str) -> (bool, bool, String) {
    let parsed = match Url::parse(public_base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (
                false,
                false,
                format!("public_base_url could not be parsed: {error}"),
            );
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, false, "public_base_url must include a host".into());
    };

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return (
            false,
            false,
            format!("public_base_url must use http or https, got: {scheme}"),
        );
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return (
            false,
            false,
            "public_base_url must not include query parameters or fragments".into(),
        );
    }

    let local = is_local_test_host(host);
    if scheme != "https" && !local {
        return (
            false,
            false,
            "public_base_url must use https unless it points to a local test host".into(),
        );
    }

    if local {
        (
            true,
            false,
            format!("Local test base URL accepted but not publicly routable: {public_base_url}"),
        )
    } else {
        (
            true,
            true,
            format!("Public base URL accepted: {public_base_url}"),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

impl WebhookReceiverConnector {
    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "webhook_receiver.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Webhook receiver self-check completed"
        );

        serde_json::to_value(report).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {error}"),
        })
    }
}

/// Build a single [`OperationInfo`].
#[allow(clippy::too_many_arguments)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "webhook.endpoints.create",
            "Register webhook endpoint metadata with provider-aware verification defaults",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "URL path to provision for a host or gateway ingress adapter" },
                    "provider": { "type": "string", "description": "Provider preset: generic, github, stripe, slack, twilio" },
                    "signing_secret": { "type": "string", "description": "Optional signing secret; omitted values are generated in-memory" },
                    "signature_header": { "type": "string", "description": "Override the expected signature header for generic endpoints" },
                    "signature_algorithm": { "type": "string", "description": "Override the verification algorithm for generic endpoints" },
                    "allowed_sources": { "type": "array", "description": "IP CIDR ranges allowed to send webhooks" }
                }
            }),
            json!({
                "type": "object",
                "required": ["endpoint_id", "url", "provider", "signature_header", "signature_algorithm", "signing_secret", "signing_secret_generated", "secret_last_rotated_at"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "url": { "type": "string" },
                    "provider": { "type": "string" },
                    "signature_header": { "type": "string" },
                    "signature_algorithm": { "type": "string" },
                    "recommended_events": { "type": "array" },
                    "signing_secret": { "type": "string" },
                    "signing_secret_generated": { "type": "boolean" },
                    "secret_last_rotated_at": { "type": "string" }
                }
            }),
            "webhook.endpoints.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Register webhook endpoint metadata and auto-populate provider verification settings for a host or gateway ingress adapter.".into(),
                common_mistakes: vec![
                    "Using a provider preset with a mismatched signature header or algorithm.".into(),
                    "Configuring a localhost public_base_url and expecting the endpoint to be reachable from external webhook providers.".into(),
                    "Assuming this connector build opens an HTTP listener; native ingress is explicitly deferred.".into(),
                ],
                examples: vec![
                    r#"{"path": "/hooks/github", "provider": "github"}"#.into(),
                    r#"{"path": "/hooks/custom", "provider": "generic", "signature_header": "X-Signature", "signature_algorithm": "hmac-sha256"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("webhook.endpoints.rotate_secret"),
                    CapabilityId::from_static("webhook.endpoints.list"),
                    CapabilityId::from_static("webhook.endpoints.delete"),
                ],
            },
        ),
        op_info(
            "webhook.endpoints.rotate_secret",
            "Rotate the signing secret for an existing webhook endpoint",
            json!({
                "type": "object",
                "required": ["endpoint_id"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "signing_secret": { "type": "string", "description": "Optional replacement signing secret; omitted values are generated in-memory" }
                }
            }),
            json!({
                "type": "object",
                "required": ["endpoint_id", "signing_secret", "signing_secret_generated", "secret_last_rotated_at"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "url": { "type": "string" },
                    "provider": { "type": "string" },
                    "signature_header": { "type": "string" },
                    "signature_algorithm": { "type": "string" },
                    "recommended_events": { "type": "array" },
                    "signing_secret": { "type": "string" },
                    "signing_secret_generated": { "type": "boolean" },
                    "secret_last_rotated_at": { "type": "string" }
                }
            }),
            "webhook.endpoints.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Rotate a webhook signing secret after suspected exposure or during routine credential hygiene.".into(),
                common_mistakes: vec![
                    "Rotating the local secret without updating the upstream webhook provider configuration.".into(),
                ],
                examples: vec![r#"{"endpoint_id": "ep_abc123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("webhook.endpoints.create"),
                    CapabilityId::from_static("webhook.endpoints.list"),
                ],
            },
        ),
        op_info(
            "webhook.endpoints.delete",
            "Remove a webhook endpoint",
            json!({
                "type": "object",
                "required": ["endpoint_id"],
                "properties": {
                    "endpoint_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "webhook.endpoints.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use:
                    "Remove a webhook endpoint. Incoming webhooks to this path will be rejected."
                        .into(),
                common_mistakes: vec![
                    "Forgetting to unregister the webhook URL at the sending service before deleting the endpoint.".into(),
                    "Using the endpoint path instead of endpoint_id.".into(),
                ],
                examples: vec![r#"{"endpoint_id": "ep_abc123"}"#.into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.list")],
            },
        ),
        op_info(
            "webhook.endpoints.list",
            "List registered webhook endpoints",
            json!({
                "type": "object",
                "required": [],
                "properties": {}
            }),
            json!({
                "type": "object",
                "required": ["endpoints"],
                "properties": {
                    "endpoints": { "type": "array" }
                }
            }),
            "webhook.endpoints.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List configured webhook endpoints.".into(),
                common_mistakes: vec![
                    "Assuming the list reflects live registration status at the sending service — it only shows locally registered endpoints.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.create")],
            },
        ),
        op_info(
            "webhook.events.recent",
            "Get recent webhook events",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "limit": { "type": "integer", "maximum": 100 },
                    "since_ts": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["events"],
                "properties": {
                    "events": { "type": "array" }
                }
            }),
            "webhook.events.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get recent webhook events received on an endpoint.".into(),
                common_mistakes: vec![
                    "Not filtering by endpoint_id and receiving events from all endpoints mixed together.".into(),
                    "Expecting events that failed signature validation to appear in results — they are rejected before storage.".into(),
                ],
                examples: vec![r#"{"endpoint_id": "ep_abc123", "limit": 20}"#.into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.list")],
            },
        ),
        op_info(
            WEBHOOK_EVENTS_INGEST_OPERATION,
            "Process a host-forwarded webhook request through provider-aware ingress guardrails",
            json!({
                "type": "object",
                "required": ["method", "path", "headers"],
                "properties": {
                    "method": { "type": "string", "description": "HTTP method accepted by the host or gateway adapter; POST is required" },
                    "path": { "type": "string", "description": "Webhook request path to route to a registered endpoint" },
                    "url": { "type": "string", "description": "Full public URL used by Twilio signature verification; defaults to endpoint URL" },
                    "headers": { "type": "object", "description": "HTTP headers after host canonicalization" },
                    "body": { "type": "string", "description": "Raw JSON body exactly as signed by the provider" },
                    "payload": { "type": "object", "description": "Already parsed JSON payload when raw body is unavailable" },
                    "params": { "type": "object", "description": "Twilio form params used for X-Twilio-Signature validation" },
                    "source_ip": { "type": "string", "description": "Client IP resolved by the host adapter for allowlist enforcement" },
                    "client_id": { "type": "string", "description": "Rate-limit key component chosen by the host adapter" },
                    "delivery_id": { "type": "string", "description": "Stable provider delivery ID used for replay suppression" },
                    "body_size_bytes": { "type": "integer", "description": "Host-measured body length for pre-parse body cap enforcement" },
                    "deadline_exceeded": { "type": "boolean", "description": "Set true when the host request-region deadline already expired" },
                    "body_timeout": { "type": "boolean", "description": "Set true when bounded body reading timed out in the host adapter" }
                }
            }),
            json!({
                "type": "object",
                "required": ["accepted", "status_code", "event", "ingest_log", "event_caps", "ingress_binding"],
                "properties": {
                    "accepted": { "type": "boolean" },
                    "status_code": { "type": "integer" },
                    "event": { "type": "object" },
                    "ingest_log": { "type": "object" },
                    "event_caps": { "type": "object" },
                    "ingress_binding": { "type": "object" }
                }
            }),
            "webhook.events.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Handle an HTTP webhook request already accepted into an FCP host or gateway request region. The connector verifies route, source, signature, body limits, rate limits, and replay before recording the event.".into(),
                common_mistakes: vec![
                    "Calling this operation with a reserialized body that no longer matches the provider signature.".into(),
                    "Forwarding signature, authorization, or cookie headers into downstream event history.".into(),
                    "Treating this as a native HTTP listener; the connector still opens no network socket.".into(),
                ],
                examples: vec![
                    r#"{"method": "POST", "path": "/hooks/github", "headers": {"Content-Type": "application/json", "X-Hub-Signature-256": "sha256=..."}, "body": "{\"id\":\"evt_1\"}", "source_ip": "203.0.113.10"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("webhook.endpoints.create"),
                    CapabilityId::from_static("webhook.events.recent"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_str_present() {
        let input = json!({"path": "/hooks/github"});
        assert_eq!(require_str(&input, "path").unwrap(), "/hooks/github");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"path": 42});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"path": null});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn operations_info_has_6_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 6);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_ref().is_empty(), "missing id");
            assert!(!op.summary.is_empty(), "missing summary");
            assert!(!op.capability.as_ref().is_empty(), "missing capability");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let ops = operations_info();
        for op in &ops {
            // RiskLevel is a typed enum, always valid by construction
            let _ = op.risk_level;
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            // SafetyTier is a typed enum, always valid by construction
            let _ = op.safety_tier;
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".read") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "read op {} should be safe",
                    op.id.as_ref()
                );
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "read op {} should be low risk",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"webhook.endpoints.create"));
        assert!(ids.contains(&"webhook.endpoints.rotate_secret"));
        assert!(ids.contains(&"webhook.endpoints.delete"));
        assert!(ids.contains(&"webhook.endpoints.list"));
        assert!(ids.contains(&"webhook.events.recent"));
        assert!(ids.contains(&WEBHOOK_EVENTS_INGEST_OPERATION));
    }

    #[test]
    fn manifest_is_honest_about_deferred_ingress_listener() {
        let manifest = include_str!("../manifest.toml");

        assert!(manifest.contains("native HTTP ingress is deferred in this build"));
        assert!(manifest.contains("streaming = false"));
        assert!(!manifest.contains("\"network.listen\""));
        assert!(manifest.contains("host-forwarded webhook ingest"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            // IdempotencyClass is a typed enum, always present by construction
            let _ = op.idempotency;
        }
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = WebhookReceiverConnector::default();
        assert!(c.config.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_state() {
        let c = WebhookReceiverConnector::new();
        assert!(c.config.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.store.endpoint_count(), 0);
        assert_eq!(c.store.total_event_count(), 0);
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"path": true});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"path": ["a", "b"]});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn operations_write_ops_are_not_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".write") {
                assert_ne!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "write op {} should not be safe",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"path": {"nested": "val"}});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"path": ""});
        // Empty string is still a valid string
        assert_eq!(require_str(&input, "path").unwrap(), "");
    }

    #[test]
    fn operations_endpoints_create_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.create")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.write");
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn operations_endpoints_rotate_secret_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.rotate_secret")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.write");
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn operations_endpoints_delete_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.delete")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.write");
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
    }

    #[test]
    fn operations_endpoints_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.list")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.read");
    }

    #[test]
    fn operations_events_recent_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.events.recent")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.events.read");
    }

    #[test]
    fn operations_events_ingest_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == WEBHOOK_EVENTS_INGEST_OPERATION)
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.events.write");
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail a".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail b".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn doctor_check_serializes_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("error detail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "error detail");
    }

    #[test]
    fn doctor_check_skips_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(v.get("message").is_none());
    }

    #[test]
    fn doctor_status_serialize_lowercase() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize_lowercase() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        #[allow(clippy::redundant_clone)]
        let cloned = r.clone();
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("msg".into()),
            critical: true,
        };
        #[allow(clippy::redundant_clone)]
        let cloned = check.clone();
        assert_eq!(cloned.name, "test");
        assert!(!cloned.passed);
        assert_eq!(cloned.message, Some("msg".into()));
        assert!(cloned.critical);
    }

    #[test]
    fn doctor_result_deserialize_roundtrip() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ]);
        let s = serde_json::to_string(&r).unwrap();
        let r2: DoctorResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r2.status, DoctorStatus::Degraded);
        assert_eq!(r2.checks.len(), 2);
    }

    #[test]
    fn parse_provider_defaults_to_generic() {
        let input = json!({});
        assert_eq!(parse_provider(&input).unwrap(), WebhookProvider::Generic);
    }

    #[test]
    fn parse_provider_rejects_unknown_values() {
        let input = json!({"provider": "unknown"});
        assert!(parse_provider(&input).is_err());
    }

    #[test]
    fn parse_string_array_rejects_blank_entries() {
        let input = json!({"allowed_sources": ["10.0.0.0/8", "  "]});
        assert!(parse_string_array(&input, "allowed_sources").is_err());
    }

    #[test]
    fn public_base_url_policy_accepts_https_host() {
        let (accepted, routable, message) = public_base_url_policy("https://hooks.flywheel.test");
        assert!(accepted);
        assert!(routable);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn public_base_url_policy_marks_localhost_degraded() {
        let (accepted, routable, message) = public_base_url_policy("http://localhost:8080");
        assert!(accepted);
        assert!(!routable);
        assert!(message.contains("not publicly routable"));
    }
}
