//! E2E Spotify connector compliance tests.
//!
//! Exercises the Spotify connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features spotify`

#![cfg(feature = "spotify")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus,
    OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
    ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

use fcp_spotify::connector::SpotifyConnector;

// ============================================================================
// Operation -> capability mapping
// ============================================================================

fn required_capability_for_operation(operation: &str) -> &'static str {
    match operation {
        "spotify.search"
        | "spotify.track.get"
        | "spotify.album.get"
        | "spotify.artist.get"
        | "spotify.playlist.get" => "spotify.read",
        "spotify.library.list_saved_tracks" => "spotify.library.read",
        "spotify.library.save_track" | "spotify.library.remove_track" => "spotify.library.write",
        "spotify.playback.get_state" => "spotify.playback.read",
        "spotify.playback.play" | "spotify.playback.pause" => "spotify.playback.write",
        "spotify.player.stream" => "spotify.stream",
        "spotify.media.download_cover" => "spotify.media.read",
        _ => "spotify.read",
    }
}

// ============================================================================
// FcpConnector adapter for SpotifyConnector
// ============================================================================

struct SpotifyConnectorAdapter {
    connector: SpotifyConnector,
    id: ConnectorId,
    verifier: Option<CapabilityVerifier>,
}

impl SpotifyConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: SpotifyConnector::new(),
            id: ConnectorId::from_static("spotify"),
            verifier: None,
        }
    }
}

#[fcp_core::async_trait]
impl FcpConnector for SpotifyConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let nonce = req.nonce;
        let caps = req.capabilities_requested.clone();

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            req.requested_instance_id.clone().unwrap_or_default(),
        ));

        let request = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        // Spotify connector returns simple JSON; build a proper HandshakeResponse.
        let _raw = self.connector.handle_handshake(request).await?;
        let capabilities_granted: Vec<CapabilityGrant> = caps
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: "sha256:spotify-connector-v1".into(),
            nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "not_configured" | "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("spotify_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("spotify.search"),
                summary: "Search tracks, albums, artists, playlists, and podcast episodes"
                    .to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": { "type": "string" },
                        "type": { "type": "string" },
                        "limit": { "type": "integer" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "tracks": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("spotify.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Find Spotify entities by text query.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![
                        r#"{"query": "kind of blue", "type": "album", "limit": 10}"#.to_string(),
                    ],
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        // Verify capability token before delegating to the connector.
        let cap_id: CapabilityId = required_capability_for_operation(req.operation.as_str())
            .parse()
            .map_err(|_| FcpError::Internal {
                message: "invalid capability id".into(),
            })?;
        if let Some(verifier) = &self.verifier {
            verifier.verify(&req.capability_token, &cap_id, &req.operation, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        let request_id = req.id;
        let params = json!({
            "operation_id": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        let value = self.connector.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.handle_simulate(request).await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize simulate response: {err}"),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn reference_manifest_with_hash() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
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
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(cose)
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("spotify-e2e"),
        connector_id: ConnectorId::from_static("spotify"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn spotify_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/spotify/manifest.toml"))
        .expect("spotify manifest toml")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .and_then(|constraints| constraints.get("host_allow"))
        .and_then(toml::Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .expect("operation host_allow")
}

fn host_allowed(host: &str, host_allow: &[String]) -> bool {
    host_allow.iter().any(|pattern| {
        pattern == host
            || pattern
                .strip_prefix("*.")
                .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
    })
}

/// Spotify search API success response.
fn spotify_search_response() -> serde_json::Value {
    json!({
        "tracks": {
            "items": [
                {
                    "id": "1",
                    "name": "Test Track",
                    "artists": [{"name": "Test"}]
                }
            ],
            "total": 1
        }
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "spotify.playback" but invoke targets "spotify.search"
/// (which requires "spotify.read").
#[fcp_async_core::runtime::test]
async fn default_deny_compliance_suite_passes() {
    let mut connector = SpotifyConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["spotify.playback"],
    );
    // Token grants "spotify.playback" but invoke targets "spotify.search" -> denial
    let token = build_token(&signing_key, "spotify.playback", &["spotify.playback"]);
    let invoke = invoke_request("spotify.search", json!({ "query": "kind of blue" }), token);

    let dynamic = DynamicSuite {
        config: json!({
            "access_token": "BQtest_token_000",
            "base_url": "http://localhost:9999"
        }),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "spotify_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-spotify");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock REST API.
#[fcp_async_core::runtime::test]
async fn allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /search?... (base_url already includes path prefix)
    Mock::given(method("GET"))
        .and(path_regex(r"^/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(spotify_search_response()))
        .mount(mock.inner())
        .await;

    let mut connector = SpotifyConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["spotify.read"]);
    let token = build_token(&signing_key, "spotify.read", &["spotify.search"]);
    let invoke = invoke_request("spotify.search", json!({ "query": "kind of blue" }), token);
    let suite = ConnectorSuite {
        test_name: "spotify_allow_valid_token".to_string(),
        config: json!({
            "access_token": "BQtest_token_000",
            "base_url": mock.base_url(),
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-spotify");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let invoke_entry = report
        .logs
        .iter()
        .find(|entry| entry.context.get("operation") == Some(&json!("invoke")))
        .expect("invoke entry");
    assert_eq!(invoke_entry.result, "pass");
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Spotify manifest restricts operations to `api.spotify.com`.
/// Verify that matching hosts pass and non-matching hosts are denied.
#[test]
fn manifest_network_guard_allows_and_denies() {
    let manifest = spotify_manifest_toml();

    let operations = [
        "spotify.search",
        "spotify.track.get",
        "spotify.album.get",
        "spotify.playlist.get",
        "spotify.library.list_saved_tracks",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);

        // All operations should allow api.spotify.com
        assert!(
            host_allowed("api.spotify.com", &host_allow),
            "api.spotify.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("evil.com", &host_allow),
            "evil.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("notspotify.com", &host_allow),
            "notspotify.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.spotify.evil.com", &host_allow),
            "api.spotify.evil.com should be denied for {operation_name}"
        );
    }
}
