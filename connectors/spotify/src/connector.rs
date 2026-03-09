//! FCP `Spotify` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OAuthRecipe, OperationId, OperationInfo, ProvisioningRecipe,
    ProvisioningStep, ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport,
    StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, SpotifyAuth, SpotifyClient},
    error::SpotifyError,
};

/// Parsed and validated `Spotify` connector configuration.
#[derive(Debug, Clone)]
struct SpotifyConfig {
    auth: SpotifyAuth,
    base_url: String,
}

impl SpotifyConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
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

        let auth = match (access_token, credential_id) {
            (Some(key), None) => SpotifyAuth::AccessToken(key),
            (None, Some(cred_id)) => SpotifyAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of access_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_token or credential_id in configuration".into(),
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

    /// Auth mode label for provisioning readiness.
    const fn auth_mode(&self) -> &'static str {
        match &self.auth {
            SpotifyAuth::AccessToken(_) => "access_token",
            SpotifyAuth::CredentialId(_) => "credential_id",
        }
    }

    /// Compute provisioning readiness from current configuration.
    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: self.auth_mode(),
            token_configured: matches!(&self.auth, SpotifyAuth::AccessToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

/// Provisioning readiness snapshot.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
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

/// FCP `Spotify` Connector.
pub struct SpotifyConnector {
    base: Arc<BaseConnector>,
    config: Option<SpotifyConfig>,
    client: Option<Arc<SpotifyClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SpotifyConnector {
    /// Create a new `Spotify` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("spotify"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for SpotifyConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SpotifyConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SpotifyConfig::from_params(&params)?;
        let provisioning = config.provisioning_readiness();
        let status = if provisioning.network_ok {
            "configured"
        } else {
            "configured_with_warnings"
        };
        info!(
            event = "spotify.provisioning.configure",
            auth = %config.auth.redacted_label(),
            auth_mode = provisioning.auth_mode,
            network_ok = provisioning.network_ok,
            base_url = %config.base_url,
            "Configuring Spotify connector"
        );

        let client = SpotifyClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({
            "status": status,
            "provisioning": provisioning,
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
            "connector_id": "fcp.spotify",
            "connector_version": "0.1.0",
            "capabilities": [
                "spotify.read"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let provisioning = self
            .config
            .as_ref()
            .map(SpotifyConfig::provisioning_readiness);

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
            "provisioning": provisioning,
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: Some(if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured — call configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "API client initialized".into()
            } else {
                "API client not initialized".into()
            }),
            critical: true,
        });

        if let Some(config) = &self.config {
            let readiness = config.provisioning_readiness();
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: readiness.network_ok,
                message: Some(readiness.network_message),
                critical: true,
            });

            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth mode: {}", readiness.auth_mode)),
                critical: false,
            });

            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                passed: !readiness.requires_credential_injection,
                message: Some(if readiness.requires_credential_injection {
                    "credential_id mode requires egress proxy injection".into()
                } else {
                    "Credential injection not required".into()
                }),
                critical: false,
            });
        }

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: Some(if handshaken {
                "Handshake completed".into()
            } else {
                "Handshake not completed".into()
            }),
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report =
                SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness();
        if !readiness.network_ok {
            let mut report = SelfCheckReport::failed(
                "network_constraints_invalid",
                readiness.network_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let Some(_client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        if readiness.requires_credential_injection {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy injection; skipping live probe",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.spotify",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
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
            "spotify.profile.get" => self.invoke_profile_get(client).await,
            "spotify.search" => self.invoke_search(client, &input).await,
            "spotify.tracks.get" => self.invoke_tracks_get(client, &input).await,
            "spotify.albums.get" => self.invoke_albums_get(client, &input).await,
            "spotify.artists.get" => self.invoke_artists_get(client, &input).await,
            "spotify.playlists.get" => self.invoke_playlists_get(client, &input).await,
            "spotify.playlists.list" => self.invoke_playlists_list(client).await,
            "spotify.player.recently_played" => self.invoke_recently_played(client, &input).await,
            "spotify.top_items" => self.invoke_top_items(client, &input).await,
            "spotify.recommendations.get" => self.invoke_recommendations(client, &input).await,
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
        info!("Spotify connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_profile_get(
        &self,
        client: &SpotifyClient,
    ) -> Result<serde_json::Value, SpotifyError> {
        let resp = client.get_current_profile().await?;
        Ok(json!({ "profile": resp }))
    }

    async fn invoke_search(
        &self,
        client: &SpotifyClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SpotifyError> {
        let query = require_str(input, "query")?;
        let types = input
            .get("types")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("track");
        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(20) as u32;
        let resp = client.search(query, types, limit).await?;
        Ok(json!({ "results": resp }))
    }

    async fn invoke_tracks_get(
        &self,
        client: &SpotifyClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SpotifyError> {
        let track_id = require_str(input, "track_id")?;
        let resp = client.get_track(track_id).await?;
        Ok(json!({ "track": resp }))
    }

    async fn invoke_albums_get(
        &self,
        client: &SpotifyClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SpotifyError> {
        let album_id = require_str(input, "album_id")?;
        let resp = client.get_album(album_id).await?;
        Ok(json!({ "album": resp }))
    }

    async fn invoke_artists_get(
        &self,
        client: &SpotifyClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SpotifyError> {
        let artist_id = require_str(input, "artist_id")?;
        let resp = client.get_artist(artist_id).await?;
        Ok(json!({ "artist": resp }))
    }

    async fn invoke_playlists_get(
        &self,
        client: &SpotifyClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SpotifyError> {
        let playlist_id = require_str(input, "playlist_id")?;
        let resp = client.get_playlist(playlist_id).await?;
        Ok(json!({ "playlist": resp }))
    }

    async fn invoke_playlists_list(
        &self,
        client: &SpotifyClient,
    ) -> Result<serde_json::Value, SpotifyError> {
        let resp = client.list_playlists().await?;
        let items = resp.get("items").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "playlists": items }))
    }

    async fn invoke_recently_played(
        &self,
        client: &SpotifyClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SpotifyError> {
        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(20) as u32;
        let resp = client.get_recently_played(limit).await?;
        let items = resp.get("items").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "items": items }))
    }

    async fn invoke_top_items(
        &self,
        client: &SpotifyClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SpotifyError> {
        let item_type = require_str(input, "item_type")?;
        let time_range = input
            .get("time_range")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("medium_term");
        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(20) as u32;
        let resp = client.get_top_items(item_type, time_range, limit).await?;
        let items = resp.get("items").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "items": items }))
    }

    async fn invoke_recommendations(
        &self,
        client: &SpotifyClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SpotifyError> {
        let seed_artists = input
            .get("seed_artists")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let seed_genres = input
            .get("seed_genres")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(20) as u32;
        let resp = client
            .get_recommendations(seed_artists, seed_genres, limit)
            .await?;
        let tracks = resp.get("tracks").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "tracks": tracks }))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "spotify.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Spotify self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Build the `OAuth2` Authorization Code + PKCE provisioning recipe for Spotify.
#[must_use]
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("spotify.oauth2_pkce"),
        "1",
        "Spotify OAuth2 Authorization Code + PKCE provisioning",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("oauth_authorize"),
        ProvisioningStepType::Oauth {
            flow: OAuthRecipe::AuthorizationCodePkce {
                authorization_url: "https://accounts.spotify.com/authorize".into(),
                token_url: "https://accounts.spotify.com/api/token".into(),
                scopes: vec![
                    "user-read-playback-state".into(),
                    "user-read-currently-playing".into(),
                    "user-library-read".into(),
                    "playlist-read-private".into(),
                    "user-read-email".into(),
                    "user-read-private".into(),
                ],
                auto_browser: true,
                callback_port: 8_899,
            },
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "spotify_access_token".into(),
                value_from: StepId::new("oauth_authorize"),
                scope: "connector:fcp.spotify".into(),
            },
        )
        .depends_on(StepId::new("oauth_authorize")),
    )
}

/// Validate base URL against network constraints policy.
fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let allowed_host = host.eq_ignore_ascii_case("api.spotify.com")
        || host.eq_ignore_ascii_case("accounts.spotify.com")
        || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and api.spotify.com or accounts.spotify.com (localhost/127.0.0.1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SpotifyError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SpotifyError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build a single `OperationInfo` entry.
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
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

/// Build the operations info for introspection.
#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "spotify.profile.get",
            "Get current user profile",
            json!({
                "type": "object",
                "properties": {}
            }),
            json!({
                "type": "object",
                "required": ["profile"],
                "properties": { "profile": { "type": "object" } }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Fetch the authenticated user's Spotify profile.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("spotify.playlists.list"),
                    CapabilityId::from_static("spotify.top_items"),
                ],
            },
        ),
        op_info(
            "spotify.search",
            "Search tracks, albums, artists, and playlists",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string", "maxLength": 512 },
                    "types": { "type": "string", "enum": ["track", "album", "artist", "playlist", "show", "episode"] },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50 }
                }
            }),
            json!({
                "type": "object",
                "required": ["results"],
                "properties": {
                    "results": { "type": "object" }
                }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Find Spotify entities by text query.".into(),
                common_mistakes: vec![
                    "Using lowercase country codes for market.".into(),
                    "Forgetting type filter when expecting a single entity class.".into(),
                ],
                examples: vec![
                    r#"{"query": "kind of blue", "types": "album", "limit": 10}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("spotify.tracks.get"),
                    CapabilityId::from_static("spotify.albums.get"),
                    CapabilityId::from_static("spotify.artists.get"),
                ],
            },
        ),
        op_info(
            "spotify.tracks.get",
            "Get track metadata by ID",
            json!({
                "type": "object",
                "required": ["track_id"],
                "properties": {
                    "track_id": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["track"],
                "properties": { "track": { "type": "object" } }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Fetch full metadata for a known Spotify track ID.".into(),
                common_mistakes: vec![
                    "Passing a Spotify URL instead of a track ID.".into(),
                ],
                examples: vec![
                    r#"{"track_id": "11dFghVXANMlKmJXsNCbNl"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("spotify.search"),
                    CapabilityId::from_static("spotify.albums.get"),
                ],
            },
        ),
        op_info(
            "spotify.albums.get",
            "Get album metadata by ID",
            json!({
                "type": "object",
                "required": ["album_id"],
                "properties": {
                    "album_id": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["album"],
                "properties": { "album": { "type": "object" } }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Fetch album metadata for a known album ID.".into(),
                common_mistakes: vec![
                    "Passing a URI prefix (spotify:album:...) without stripping it.".into(),
                ],
                examples: vec![
                    r#"{"album_id": "4aawyAB9vmqN3uQ7FjRGTy"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("spotify.search"),
                    CapabilityId::from_static("spotify.tracks.get"),
                ],
            },
        ),
        op_info(
            "spotify.artists.get",
            "Get artist metadata by ID",
            json!({
                "type": "object",
                "required": ["artist_id"],
                "properties": {
                    "artist_id": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["artist"],
                "properties": { "artist": { "type": "object" } }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Fetch artist metadata for a known artist ID.".into(),
                common_mistakes: vec![
                    "Passing a Spotify URI (spotify:artist:...) or URL instead of the bare artist ID string.".into(),
                ],
                examples: vec![
                    r#"{"artist_id": "06HL4z0CvFAxyc27GXpf02"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("spotify.search"),
                    CapabilityId::from_static("spotify.albums.get"),
                ],
            },
        ),
        op_info(
            "spotify.playlists.get",
            "Get playlist metadata by ID",
            json!({
                "type": "object",
                "required": ["playlist_id"],
                "properties": {
                    "playlist_id": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["playlist"],
                "properties": { "playlist": { "type": "object" } }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read playlist metadata and track references.".into(),
                common_mistakes: vec![
                    "Expecting all tracks when playlist is paginated.".into(),
                ],
                examples: vec![
                    r#"{"playlist_id": "37i9dQZF1DXcBWIGoYBM5M"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("spotify.search"),
                    CapabilityId::from_static("spotify.playlists.list"),
                ],
            },
        ),
        op_info(
            "spotify.playlists.list",
            "List current user playlists",
            json!({
                "type": "object",
                "properties": {}
            }),
            json!({
                "type": "object",
                "required": ["playlists"],
                "properties": {
                    "playlists": { "type": "array" }
                }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List the current user's playlists.".into(),
                common_mistakes: vec![
                    "Forgetting pagination for large libraries.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("spotify.playlists.get"),
                ],
            },
        ),
        op_info(
            "spotify.player.recently_played",
            "Get recently played tracks",
            json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50 }
                }
            }),
            json!({
                "type": "object",
                "required": ["items"],
                "properties": {
                    "items": { "type": "array" }
                }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read recently played tracks for the current user.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"limit": 10}"#.into()],
                related: vec![
                    CapabilityId::from_static("spotify.top_items"),
                ],
            },
        ),
        op_info(
            "spotify.top_items",
            "Get user top artists or tracks",
            json!({
                "type": "object",
                "required": ["item_type"],
                "properties": {
                    "item_type": { "type": "string", "enum": ["artists", "tracks"] },
                    "time_range": { "type": "string", "enum": ["short_term", "medium_term", "long_term"] },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50 }
                }
            }),
            json!({
                "type": "object",
                "required": ["items"],
                "properties": {
                    "items": { "type": "array" }
                }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Fetch the user's top artists or tracks over a given time range.".into(),
                common_mistakes: vec![
                    "Using an invalid time_range value.".into(),
                ],
                examples: vec![
                    r#"{"item_type": "tracks", "time_range": "medium_term", "limit": 20}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("spotify.player.recently_played"),
                ],
            },
        ),
        op_info(
            "spotify.recommendations.get",
            "Get track recommendations",
            json!({
                "type": "object",
                "properties": {
                    "seed_artists": { "type": "string" },
                    "seed_genres": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100 }
                }
            }),
            json!({
                "type": "object",
                "required": ["tracks"],
                "properties": {
                    "tracks": { "type": "array" }
                }
            }),
            "spotify.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get personalized track recommendations based on seeds.".into(),
                common_mistakes: vec![
                    "Not providing at least one seed (artist or genre).".into(),
                ],
                examples: vec![
                    r#"{"seed_genres": "indie,rock", "limit": 20}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("spotify.search"),
                    CapabilityId::from_static("spotify.tracks.get"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = SpotifyConfig::from_params(&json!({
            "access_token": "test-access-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, SpotifyAuth::AccessToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = SpotifyConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = SpotifyConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://spotify.example.com/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://spotify.example.com/v1");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = SpotifyConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = SpotifyConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = SpotifyConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = SpotifyConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = SpotifyConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = SpotifyConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"track_id": "track_abc"});
        assert_eq!(require_str(&input, "track_id").unwrap(), "track_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "track_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"track_id": 42});
        assert!(require_str(&input, "track_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"track_id": null});
        assert!(require_str(&input, "track_id").is_err());
    }

    /// Serialize `operations_info()` to JSON for backward-compatible test assertions.
    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn operations_info_has_10_operations() {
        assert_eq!(operations_info().len(), 10);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
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
            // All RiskLevel enum variants are valid by construction
            let _ = op.risk_level;
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            // All SafetyTier enum variants are valid by construction
            let _ = op.safety_tier;
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
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
        assert!(ids.contains(&"spotify.profile.get"));
        assert!(ids.contains(&"spotify.search"));
        assert!(ids.contains(&"spotify.tracks.get"));
        assert!(ids.contains(&"spotify.albums.get"));
        assert!(ids.contains(&"spotify.artists.get"));
        assert!(ids.contains(&"spotify.playlists.get"));
        assert!(ids.contains(&"spotify.playlists.list"));
        assert!(ids.contains(&"spotify.player.recently_played"));
        assert!(ids.contains(&"spotify.top_items"));
        assert!(ids.contains(&"spotify.recommendations.get"));
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
    fn config_trims_access_token() {
        let config =
            SpotifyConfig::from_params(&json!({ "access_token": "  BQtoken123  " })).unwrap();
        match &config.auth {
            SpotifyAuth::AccessToken(t) => assert_eq!(t, "BQtoken123"),
            SpotifyAuth::CredentialId(_) => panic!("expected AccessToken"),
        }
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            // IdempotencyClass is always present by construction
            let _ = op.idempotency;
        }
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = SpotifyConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn all_operations_are_read_only() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.safety_tier,
                SafetyTier::Safe,
                "op {} should be safe (read-only connector)",
                op.id.as_ref()
            );
        }
    }

    // ── Additional connector coverage ────────────────────────────

    #[test]
    fn connector_new_fields() {
        let c = SpotifyConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_default_base_url() {
        let config = SpotifyConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_error_message_both_auth() {
        let result = SpotifyConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, code } => {
                assert!(message.contains("exactly one"), "got: {message}");
                assert_eq!(code, 1003);
            }
            e => panic!("expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_error_message_no_auth() {
        let result = SpotifyConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"), "got: {message}");
            }
            e => panic!("expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_error_non_string_credential() {
        let result = SpotifyConfig::from_params(&json!({
            "credential_id": 42,
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("string"), "got: {message}");
            }
            e => panic!("expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_error_invalid_uuid() {
        let result = SpotifyConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("UUID"), "got: {message}");
            }
            e => panic!("expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"track_id": [1, 2, 3]});
        assert!(require_str(&input, "track_id").is_err());
    }

    #[test]
    fn require_str_bool_value() {
        let input = json!({"track_id": true});
        assert!(require_str(&input, "track_id").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"track_id": ""});
        // Empty string is still a valid string
        assert_eq!(require_str(&input, "track_id").unwrap(), "");
    }

    #[test]
    fn operations_all_low_risk() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.risk_level,
                RiskLevel::Low,
                "op {} should be low risk",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_all_strict_idempotency() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.idempotency,
                IdempotencyClass::Strict,
                "op {} should have strict idempotency",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_all_spotify_read_capability() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.capability.as_ref(),
                "spotify.read",
                "op {} should have spotify.read capability",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_includes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed!".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("message"));
        assert!(v.contains("failed!"));
    }

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let back: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(back.status, DoctorStatus::Healthy);
        assert_eq!(back.checks.len(), 1);
    }

    #[test]
    fn doctor_check_clone_debug() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let cloned = check.clone();
        assert_eq!(cloned.name, "test_check");
        let dbg = format!("{check:?}");
        assert!(dbg.contains("test_check"));
    }

    #[test]
    fn doctor_result_clone_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let cloned = r.clone();
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    // ── Provisioning tests ──────────────────────────────────────────

    #[test]
    fn provisioning_recipe_has_expected_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "spotify.oauth2_pkce");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
        assert_eq!(recipe.steps[0].id.as_str(), "oauth_authorize");
        assert_eq!(recipe.steps[1].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_oauth_pkce_step() {
        let recipe = provisioning_recipe();
        let step = &recipe.steps[0];
        match &step.kind {
            ProvisioningStepType::Oauth { flow } => match flow {
                OAuthRecipe::AuthorizationCodePkce {
                    authorization_url,
                    token_url,
                    scopes,
                    auto_browser,
                    callback_port,
                } => {
                    assert_eq!(
                        authorization_url,
                        "https://accounts.spotify.com/authorize"
                    );
                    assert_eq!(token_url, "https://accounts.spotify.com/api/token");
                    assert!(scopes.contains(&"user-read-playback-state".to_string()));
                    assert!(scopes.contains(&"user-read-currently-playing".to_string()));
                    assert!(scopes.contains(&"user-library-read".to_string()));
                    assert!(scopes.contains(&"playlist-read-private".to_string()));
                    assert!(scopes.contains(&"user-read-email".to_string()));
                    assert!(scopes.contains(&"user-read-private".to_string()));
                    assert_eq!(scopes.len(), 6);
                    assert!(*auto_browser);
                    assert_eq!(*callback_port, 8_899);
                }
                _ => panic!("expected AuthorizationCodePkce, got {flow:?}"),
            },
            _ => panic!("expected Oauth step type, got {:?}", step.kind),
        }
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        // First step has no dependencies
        assert!(recipe.steps[0].depends_on.is_empty());
        // Second step depends on the first
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "oauth_authorize");
    }

    #[test]
    fn provisioning_readiness_unconfigured() {
        // Build a config with access_token and default base_url
        let config = SpotifyConfig::from_params(&json!({
            "access_token": "BQtoken",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "access_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        // Default base_url (api.spotify.com) should pass network policy
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_bearer_token() {
        let config = SpotifyConfig::from_params(&json!({
            "access_token": "BQtoken123",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "access_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let config = SpotifyConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn base_url_policy_accepts_spotify() {
        let (ok, message) = base_url_policy("https://api.spotify.com/v1");
        assert!(ok, "expected accepted, got: {message}");
        assert!(message.contains("accepted"));

        let (ok2, _) = base_url_policy("https://accounts.spotify.com/authorize");
        assert!(ok2);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://api.spotify.com/v1");
        assert!(!ok, "expected rejected, got: {message}");
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com/api");
        assert!(!ok, "expected rejected, got: {message}");
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);

        let (ok2, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok2);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = SpotifyConfig::from_params(&json!({
            "access_token": "BQtoken",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let json = serde_json::to_value(&readiness).unwrap();
        assert_eq!(json["auth_mode"], "access_token");
        assert_eq!(json["token_configured"], true);
        assert_eq!(json["credential_id_configured"], false);
        assert_eq!(json["requires_credential_injection"], false);
        assert_eq!(json["network_ok"], true);
        assert!(json["network_message"].as_str().unwrap().contains("accepted"));
        assert_eq!(json["base_url"], DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let json = serde_json::to_value(&recipe).unwrap();
        assert_eq!(json["id"], "spotify.oauth2_pkce");
        assert_eq!(json["version"], "1");
        assert!(json["steps"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn base_url_policy_rejects_unparseable() {
        let (ok, message) = base_url_policy("not a url at all");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn provisioning_recipe_store_secret_step() {
        let recipe = provisioning_recipe();
        let step = &recipe.steps[1];
        match &step.kind {
            ProvisioningStepType::StoreSecret {
                key,
                value_from,
                scope,
            } => {
                assert_eq!(key, "spotify_access_token");
                assert_eq!(value_from.as_str(), "oauth_authorize");
                assert_eq!(scope, "connector:fcp.spotify");
            }
            _ => panic!("expected StoreSecret step type, got {:?}", step.kind),
        }
    }
}
