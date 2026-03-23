//! `Nostr` relay connector.

use std::time::Instant;

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, AuthCaps, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityVerifier, ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::NostrClient;
use crate::types::{
    CAP_EVENTS_READ, CAP_HEALTH_READ, CAP_NOTES_WRITE, CAP_RELAYS_READ, NostrConfig, OP_HEALTH,
    OP_LIST_RELAYS, OP_PUBLISH_NOTE, OP_QUERY_EVENTS, build_filter, note_kind, note_tags,
    required_string,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// ─── Doctor types (V3 requirement) ───────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

// ─── Connector ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct NostrConnector {
    base: BaseConnector,
    client: Option<NostrClient>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

impl NostrConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.nostr")),
            client: None,
            verifier: None,
            started_at: Instant::now(),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "ConnectorRuntime active".into()
            } else {
                "ConnectorRuntime not initialized".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: self.verifier.is_some(),
            message: Some(if self.verifier.is_some() {
                "Handshake completed".into()
            } else {
                "No handshake - run handshake after configure".into()
            }),
            critical: false,
        });

        if let Some(client) = &self.client {
            checks.push(DoctorCheck {
                name: "relays".into(),
                passed: !client.relays.is_empty(),
                message: Some(format!("{} relay(s) configured", client.relay_count())),
                critical: true,
            });

            checks.push(DoctorCheck {
                name: "key_material".into(),
                passed: true,
                message: Some(format!(
                    "Public key: {}...{}",
                    &client.public_key_hex()[..8],
                    &client.public_key_hex()[56..]
                )),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }

    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_PUBLISH_NOTE,
                "Publish a signed public Nostr note",
                "Sign one public kind-1 Nostr note with the configured secp256k1 secret key and publish it to every configured relay. This first slice does not construct encrypted DMs, profile metadata events, or long-lived relay sessions.",
                CAP_NOTES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["content"],
                    "properties": {
                        "content": { "type": "string" },
                        "kind": { "type": "integer", "enum": [1] },
                        "tags": { "type": "array", "items": { "type": "array", "items": { "type": "string" } } }
                    }
                }),
                "Use when you need to publish one public note through the connector's bound keypair to every configured relay.",
                &[
                    "This first slice does not construct or decrypt encrypted DMs (NIP-04/NIP-17).",
                    "`kind` is fixed to `1` for this first-slice note operation.",
                    "`secret_key_hex` is raw hex, not bech32 `nsec` input.",
                    "Publishing fans out to every configured relay; there is no per-request relay override.",
                ],
                &[CAP_HEALTH_READ, CAP_RELAYS_READ, CAP_EVENTS_READ],
            ),
            operation(
                OP_QUERY_EVENTS,
                "Query bounded public Nostr events from configured relays",
                "Run one bounded REQ/EOSE query across configured relays and collect matching public events. The connector does not maintain long-lived subscriptions, replay cursors, or cross-relay dedupe.",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "properties": {
                        "authors": { "type": "array", "items": { "type": "string" } },
                        "kinds": { "type": "array", "items": { "type": "integer" } },
                        "ids": { "type": "array", "items": { "type": "string" } },
                        "since": { "type": "integer" },
                        "until": { "type": "integer" },
                        "limit": { "type": "integer" }
                    }
                }),
                "Use for bounded public-event queries when you already know the relay set and do not need a long-lived subscription.",
                &[
                    "This is a bounded public-event query surface, not DM sync.",
                    "If `limit` is omitted the connector uses `default_query_limit`.",
                    "Results are returned per relay and may contain duplicates across relays.",
                ],
                &[CAP_RELAYS_READ, CAP_HEALTH_READ],
            ),
            operation(
                OP_LIST_RELAYS,
                "List configured relays",
                "Return the configured relay allowlist and the x-only public key derived from the bound secp256k1 secret key. This is local inspection only; it does not discover or mutate relays.",
                CAP_RELAYS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use to inspect which relays and public key this connector instance is bound to.",
                &[
                    "This does not discover relays from NIP metadata or mutate relay policy.",
                    "The relay list is static configuration for this first slice.",
                ],
                &[CAP_HEALTH_READ, CAP_EVENTS_READ],
            ),
            operation(
                OP_HEALTH,
                "Verify relay connectivity and local signing identity",
                "Open and close each configured relay and report reachability alongside the derived public key. This verifies relay reachability and local key derivation, not encrypted DM support or publish success policy.",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use before publishing to confirm the configured relay set is reachable and the bound signing identity is coherent.",
                &[
                    "Health checks websocket reachability only; it does not prove encrypted DM support.",
                    "Health does not score, rank, or deduplicate relays.",
                ],
                &[CAP_RELAYS_READ, CAP_NOTES_WRITE],
            ),
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify(&req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_PUBLISH_NOTE => client.publish_note(&req.input).await?,
            OP_QUERY_EVENTS => client.query_events(&req.input).await?,
            OP_LIST_RELAYS => json!({
                "relays": client.relay_urls(),
                "public_key_hex": client.public_key_hex(),
            }),
            OP_HEALTH => client.health_details().await?,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("unknown operation: {}", req.operation),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for NostrConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for NostrConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config: NostrConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid Nostr configuration: {error}"),
            })?;
        let client = NostrClient::new(&config)?;
        self.client = Some(client);
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(req.capabilities_requested),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: Some(nostr_auth_caps()),
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot {
            status: if self.client.is_some() {
                HealthState::Ready
            } else {
                HealthState::Starting
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: self.client.as_ref().map(|client| {
                json!({
                    "relay_count": client.relay_count(),
                    "public_key_hex": client.public_key_hex(),
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = self.client.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before Nostr self_check",
            ));
        };
        match client.health_details().await {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => Ok(SelfCheckReport::from_error(&error)),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: Some(nostr_auth_caps()),
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        let Some(client) = self.client.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        };
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) = verifier.verify(&req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        if let Err(error) = validate_simulation_input(req.operation.as_str(), &req.input, client) {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_PUBLISH_NOTE => CAP_NOTES_WRITE,
        OP_QUERY_EVENTS => CAP_EVENTS_READ,
        OP_LIST_RELAYS => CAP_RELAYS_READ,
        OP_HEALTH => CAP_HEALTH_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn validate_simulation_input(
    operation: &str,
    input: &Value,
    client: &NostrClient,
) -> FcpResult<()> {
    match operation {
        OP_PUBLISH_NOTE => {
            let _ = required_string(input, "content")?;
            let _ = note_kind(input)?;
            let _ = note_tags(input)?;
            Ok(())
        }
        OP_QUERY_EVENTS => {
            let _ = build_filter(input, client.default_query_limit)?;
            Ok(())
        }
        OP_LIST_RELAYS | OP_HEALTH => Ok(()),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("unknown operation: {operation}"),
        }),
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| {
            matches!(
                capability.as_str(),
                CAP_NOTES_WRITE | CAP_EVENTS_READ | CAP_RELAYS_READ | CAP_HEALTH_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

fn nostr_auth_caps() -> AuthCaps {
    AuthCaps {
        methods: vec!["secp256k1_secret_key_hex".to_string()],
        oauth: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn operation(
    id: &'static str,
    summary: &str,
    description: &str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    when_to_use: &str,
    common_mistakes: &[&str],
    related: &[&'static str],
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(description.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: common_mistakes
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            examples: Vec::new(),
            related: related
                .iter()
                .map(|capability| CapabilityId::from_static(capability))
                .collect(),
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{CapabilityToken, ConnectorId, SelfCheckStatus, ZoneId};
    use fcp_sdk::prelude::FcpConnector;
    use std::sync::atomic::Ordering;

    fn test_config() -> Value {
        json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111"
        })
    }

    fn handshake_request() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [7u8; 32],
            nonce: [9u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    // ── Doctor tests ─────────────────────────────────────────────────

    #[test]
    fn doctor_unconfigured_reports_failure() {
        let connector = NostrConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
        let config_check = result
            .checks
            .iter()
            .find(|c| c.name == "configuration")
            .unwrap();
        assert!(!config_check.passed);
        assert!(
            config_check
                .message
                .as_deref()
                .unwrap()
                .contains("Not configured")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured_reports_success() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector.doctor();
        assert!(result.passed);
        let config_check = result
            .checks
            .iter()
            .find(|c| c.name == "configuration")
            .unwrap();
        assert!(config_check.passed);
        let relays_check = result.checks.iter().find(|c| c.name == "relays").unwrap();
        assert!(relays_check.passed);
        let key_check = result
            .checks
            .iter()
            .find(|c| c.name == "key_material")
            .unwrap();
        assert!(key_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_shows_handshake_not_done() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector.doctor();
        let hs_check = result
            .checks
            .iter()
            .find(|c| c.name == "handshake")
            .unwrap();
        assert!(!hs_check.passed);
        assert!(
            hs_check
                .message
                .as_deref()
                .unwrap()
                .contains("No handshake")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_shows_handshake_done() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(handshake_request()).await.unwrap();
        let result = connector.doctor();
        let hs_check = result
            .checks
            .iter()
            .find(|c| c.name == "handshake")
            .unwrap();
        assert!(hs_check.passed);
    }

    // ── Health tests ─────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn health_starting_when_unconfigured() {
        let connector = NostrConnector::new();
        let snapshot = connector.health().await;
        assert!(matches!(snapshot.status, HealthState::Starting));
        assert!(snapshot.details.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn health_ready_when_configured() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let snapshot = connector.health().await;
        assert!(matches!(snapshot.status, HealthState::Ready));
        let details = snapshot.details.unwrap();
        assert_eq!(details["relay_count"], 1);
        assert!(details["public_key_hex"].is_string());
    }

    // ── Self-check tests ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn self_check_fails_when_unconfigured() {
        let connector = NostrConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
    }

    // ── Introspect tests ─────────────────────────────────────────────

    #[test]
    fn introspection_reports_raw_key_auth_boundary() {
        let intro = NostrConnector::new().introspect();
        let auth = intro.auth_caps.expect("auth caps should be present");
        assert_eq!(auth.methods, vec!["secp256k1_secret_key_hex"]);
        let publish = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_PUBLISH_NOTE)
            .expect("publish operation should exist");
        assert!(
            publish
                .description
                .as_deref()
                .unwrap_or_default()
                .contains("does not construct encrypted DMs")
        );
        let related: Vec<_> = publish
            .ai_hints
            .related
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        assert_eq!(
            related,
            vec![CAP_HEALTH_READ, CAP_RELAYS_READ, CAP_EVENTS_READ]
        );
    }

    #[test]
    fn introspect_has_four_operations() {
        let intro = NostrConnector::new().introspect();
        assert_eq!(intro.operations.len(), 4);
        let ids: Vec<_> = intro.operations.iter().map(|op| op.id.as_str()).collect();
        assert!(ids.contains(&OP_PUBLISH_NOTE));
        assert!(ids.contains(&OP_QUERY_EVENTS));
        assert!(ids.contains(&OP_LIST_RELAYS));
        assert!(ids.contains(&OP_HEALTH));
    }

    #[test]
    fn introspect_event_caps_no_streaming() {
        let intro = NostrConnector::new().introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
    }

    // ── Simulate tests ───────────────────────────────────────────────

    #[test]
    fn simulate_denies_when_not_configured() {
        let connector = NostrConnector::new();
        let response = fcp_async_core::runtime::block_on_sync(async {
            connector
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.nostr"),
                    OperationId::from_static(OP_PUBLISH_NOTE),
                    ZoneId::community(),
                    json!({ "content": "hello" }),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .expect("runtime should complete");
        let response = response.expect("simulate should succeed");
        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-5002"));
        assert_eq!(
            response.failure_reason.as_deref(),
            Some("Connector is not configured")
        );
    }

    // ── Configure / handshake / shutdown lifecycle tests ─────────────

    #[fcp_async_core::runtime::test]
    async fn reconfigure_requires_a_fresh_handshake() {
        let mut connector = NostrConnector::new();
        connector
            .configure(test_config())
            .await
            .expect("configure should succeed");
        connector
            .handshake(handshake_request())
            .await
            .expect("handshake should succeed");
        assert!(connector.base.handshaken.load(Ordering::Relaxed));

        connector
            .configure(test_config())
            .await
            .expect("reconfigure should succeed");

        assert!(!connector.base.handshaken.load(Ordering::Relaxed));
        assert!(connector.verifier.is_none());

        let response = connector
            .simulate(SimulateRequest::new(
                ConnectorId::from_static("fcp.nostr"),
                OperationId::from_static(OP_HEALTH),
                ZoneId::work(),
                json!({}),
                CapabilityToken::test_token(),
            ))
            .await
            .expect("simulate should return");
        assert!(!response.would_succeed);
        let expected = FcpError::NotHandshaken.error_code();
        assert_eq!(response.denial_code.as_deref(), Some(expected.as_str()));
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_base_ready_flags() {
        let mut connector = NostrConnector::new();
        connector
            .configure(test_config())
            .await
            .expect("configure should succeed");
        connector
            .handshake(handshake_request())
            .await
            .expect("handshake should succeed");

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1_000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .expect("shutdown should succeed");

        assert!(!connector.base.configured.load(Ordering::Relaxed));
        assert!(!connector.base.handshaken.load(Ordering::Relaxed));
        assert!(connector.verifier.is_none());
        assert!(connector.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_json() {
        let mut connector = NostrConnector::new();
        let err = connector
            .configure(json!({ "bad": "config" }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_empty_relays() {
        let mut connector = NostrConnector::new();
        let err = connector
            .configure(json!({
                "relay_urls": [],
                "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_grants_requested_capabilities() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let resp = connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: [7u8; 32],
                nonce: [9u8; 32],
                capabilities_requested: vec![
                    CapabilityId::from_static(CAP_HEALTH_READ),
                    CapabilityId::from_static(CAP_NOTES_WRITE),
                    CapabilityId::from_static("unknown.cap"),
                ],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .await
            .unwrap();
        let granted: Vec<_> = resp
            .capabilities_granted
            .iter()
            .map(|g| g.capability.as_str())
            .collect();
        assert!(granted.contains(&CAP_HEALTH_READ));
        assert!(granted.contains(&CAP_NOTES_WRITE));
        assert!(!granted.contains(&"unknown.cap"));
    }

    // ── Connector ID / default tests ─────────────────────────────────

    #[test]
    fn connector_id_is_fcp_nostr() {
        let connector = NostrConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.nostr");
    }

    #[test]
    fn default_creates_new() {
        let connector = NostrConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.nostr");
        assert!(connector.client.is_none());
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let h1 = NostrConnector::manifest_hash();
        let h2 = NostrConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    // ── Required capability tests ────────────────────────────────────

    #[test]
    fn required_capability_publish() {
        let cap = required_capability(OP_PUBLISH_NOTE).unwrap();
        assert_eq!(cap.as_str(), CAP_NOTES_WRITE);
    }

    #[test]
    fn required_capability_query() {
        let cap = required_capability(OP_QUERY_EVENTS).unwrap();
        assert_eq!(cap.as_str(), CAP_EVENTS_READ);
    }

    #[test]
    fn required_capability_unknown() {
        assert!(required_capability("unknown.op").is_err());
    }

    // ── Doctor serialization test ────────────────────────────────────

    #[test]
    fn doctor_result_serializes() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: Some("all good".into()),
            critical: true,
        }]);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["passed"], true);
        assert_eq!(json["checks"][0]["name"], "test");
    }

    #[test]
    fn doctor_result_fails_on_critical_failure() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "pass".into(),
                passed: true,
                message: None,
                critical: false,
            },
            DoctorCheck {
                name: "fail".into(),
                passed: false,
                message: Some("broken".into()),
                critical: true,
            },
        ]);
        assert!(!result.passed);
    }

    #[test]
    fn doctor_result_passes_with_non_critical_failure() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "pass_critical".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "fail_non_critical".into(),
                passed: false,
                message: Some("optional".into()),
                critical: false,
            },
        ]);
        assert!(result.passed);
    }
}
