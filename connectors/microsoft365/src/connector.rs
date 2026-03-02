//! FCP Microsoft 365 Connector implementation.

use std::sync::Arc;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL},
};
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::Deserialize;
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_API_URL, M365Auth, M365Client},
    error::M365Error,
};

const DEFAULT_AUTH_URL: &str = "https://login.microsoftonline.com";
const DEFAULT_CLIENT_CREDENTIAL_SCOPE: &str = "https://graph.microsoft.com/.default";

#[derive(Debug, Clone)]
struct M365Config {
    auth_mode: M365AuthMode,
    api_url: String,
    required_permissions: Vec<String>,
    token_permissions: Option<TokenPermissions>,
}

#[derive(Debug, Clone)]
enum M365AuthMode {
    AccessToken,
    ClientCredentials {
        tenant_id: String,
        client_id: String,
        scope: String,
    },
    CredentialId(CredentialId),
}

impl M365AuthMode {
    fn label(&self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::ClientCredentials { .. } => "client_credentials",
            Self::CredentialId(_) => "credential_id",
        }
    }

    fn summary(&self) -> serde_json::Value {
        match self {
            Self::AccessToken => json!({ "mode": "access_token" }),
            Self::ClientCredentials {
                tenant_id,
                client_id,
                scope,
            } => {
                let prefix = client_id.chars().take(8).collect::<String>();
                json!({
                    "mode": "client_credentials",
                    "tenant_id": tenant_id,
                    "client_id_prefix": prefix,
                    "scope": scope,
                })
            }
            Self::CredentialId(credential_id) => json!({
                "mode": "credential_id",
                "credential_id": credential_id,
            }),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct TokenPermissions {
    scopes: Vec<String>,
    roles: Vec<String>,
}

impl TokenPermissions {
    fn parse(token: &str) -> FcpResult<Self> {
        let mut parts = token.split('.');
        let _header = parts.next().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "access_token is not a JWT (missing header)".into(),
        })?;
        let payload_b64 = parts.next().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "access_token is not a JWT (missing payload)".into(),
        })?;

        let payload_bytes = BASE64_URL
            .decode(payload_b64)
            .or_else(|_| BASE64.decode(payload_b64))
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "access_token payload is not valid base64".into(),
            })?;

        let payload_json: serde_json::Value =
            serde_json::from_slice(&payload_bytes).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "access_token payload is not valid JSON".into(),
            })?;

        let scopes = payload_json
            .get("scp")
            .and_then(|v| v.as_str())
            .map(|raw| {
                raw.split_whitespace()
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let roles = payload_json
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if scopes.is_empty() && roles.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "access_token is missing both scp and roles claims".into(),
            });
        }

        Ok(Self { scopes, roles })
    }

    fn all(&self) -> Vec<String> {
        let mut perms = self.scopes.clone();
        perms.extend(self.roles.iter().cloned());
        perms
    }

    fn missing_required(&self, required_permissions: &[String]) -> Vec<String> {
        let available = self.all();
        required_permissions
            .iter()
            .filter(|required| !available.iter().any(|present| present == *required))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppCredentialsConfig {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    #[serde(default = "default_client_credential_scope")]
    scope: String,
}

fn default_client_credential_scope() -> String {
    DEFAULT_CLIENT_CREDENTIAL_SCOPE.to_string()
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
}

/// FCP Microsoft 365 Connector.
pub struct M365Connector {
    base: Arc<BaseConnector>,
    config: Option<M365Config>,
    client: Option<M365Client>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl M365Connector {
    /// Create a new Microsoft 365 connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "fcp.microsoft365",
            ))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let allow_test_endpoints = params
            .get("allow_test_api_url")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_URL);
        let api_url = validate_endpoint(
            api_url,
            &["graph.microsoft.com"],
            allow_test_endpoints,
            "api_url",
        )?;

        let auth_url = params
            .get("auth_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_AUTH_URL);
        let auth_url = validate_endpoint(
            auth_url,
            &["login.microsoftonline.com"],
            allow_test_endpoints,
            "auth_url",
        )?;

        let required_permissions = parse_required_permissions(&params)?;

        let access_token = parse_access_token(&params);
        let credential_id = parse_credential_id(&params)?;
        let app_credentials = parse_app_credentials(&params)?;

        let selected = [access_token.is_some(), credential_id.is_some(), app_credentials.is_some()]
            .into_iter()
            .filter(|selected_mode| *selected_mode)
            .count();

        if selected != 1 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide exactly one auth source: access_token, credential_id, or app_credentials".into(),
            });
        }

        let (auth_mode, auth, token_permissions) = if let Some(token) = access_token {
            let permissions = TokenPermissions::parse(&token)?;
            ensure_required_permissions(&permissions, &required_permissions)?;
            (
                M365AuthMode::AccessToken,
                M365Auth::AccessToken(token),
                Some(permissions),
            )
        } else if let Some(credential_id) = credential_id {
            (
                M365AuthMode::CredentialId(credential_id.clone()),
                M365Auth::CredentialId(credential_id),
                None,
            )
        } else if let Some(app_cfg) = app_credentials {
            let token = exchange_client_credentials(&auth_url, &app_cfg).await?;
            let permissions = TokenPermissions::parse(&token)?;
            ensure_required_permissions(&permissions, &required_permissions)?;
            (
                M365AuthMode::ClientCredentials {
                    tenant_id: app_cfg.tenant_id,
                    client_id: app_cfg.client_id,
                    scope: app_cfg.scope,
                },
                M365Auth::AccessToken(token),
                Some(permissions),
            )
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "No supported auth mode selected".into(),
            });
        };

        let auth_label = auth.redacted_label();
        let mut client = M365Client::new_with_auth(auth).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;
        client = client.with_api_url(&api_url);

        self.config = Some(M365Config {
            auth_mode,
            api_url: api_url.clone(),
            required_permissions,
            token_permissions,
        });
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth_label, api_url = %api_url, "Microsoft 365 connector configured");

        Ok(json!({
            "status": "configured",
            "auth": auth_label,
            "api_url": api_url
        }))
    }

    /// Handle handshake method.
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
            manifest_hash: "sha256:microsoft365-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let auth_mode = self
            .config
            .as_ref()
            .map(|c| c.auth_mode.label())
            .unwrap_or("unconfigured");
        let permissions = self
            .config
            .as_ref()
            .and_then(|c| c.token_permissions.as_ref().map(TokenPermissions::all))
            .unwrap_or_default();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "auth_mode": auth_mode,
            "api_url": self.config.as_ref().map(|c| c.api_url.clone()),
            "permissions": permissions,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: build_operations(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle connector self-check for host doctor/readiness.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let Some(client) = &self.client else {
            let report = SelfCheckReport::failed(
                "client_not_initialized",
                "Connector is configured but HTTP client is unavailable",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if matches!(config.auth_mode, M365AuthMode::CredentialId(_)) {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; readiness depends on egress proxy credential injection",
            );
            report.details = Some(json!({
                "auth_mode": config.auth_mode.summary(),
                "required_permissions": config.required_permissions,
            }));
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let mut report = match client.health_check().await {
            Ok(_) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };
        report.details = Some(json!({
            "auth_mode": config.auth_mode.summary(),
            "required_permissions": config.required_permissions,
            "permissions": config.token_permissions.as_ref().map(TokenPermissions::all).unwrap_or_default(),
        }));

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            // ── Mail ─────────────────────────────────────────
            "m365.mail.list_messages" => self.invoke_list_messages(input).await,
            "m365.mail.get_message" => self.invoke_get_message(input).await,
            "m365.mail.send_message" => self.invoke_send_message(input).await,
            "m365.mail.create_draft" => self.invoke_create_draft(input).await,
            // ── Files ────────────────────────────────────────
            "m365.files.list_items" => self.invoke_list_items(input).await,
            "m365.files.download_file" => self.invoke_download_file(input).await,
            "m365.files.upload_file" => self.invoke_upload_file(input).await,
            "m365.files.delete_item" => self.invoke_delete_item(input).await,
            // ── Calendar ─────────────────────────────────────
            "m365.calendar.list_events" => self.invoke_list_events(input).await,
            "m365.calendar.create_event" => self.invoke_create_event(input).await,
            "m365.calendar.delete_event" => self.invoke_delete_event(input).await,
            "m365.calendar.get_freebusy" => self.invoke_get_freebusy(input).await,
            // ── Tasks ────────────────────────────────────────
            "m365.tasks.list_task_lists" => self.invoke_list_task_lists(input).await,
            "m365.tasks.list_tasks" => self.invoke_list_tasks(input).await,
            "m365.tasks.create_task" => self.invoke_create_task(input).await,
            // ── Subscriptions ────────────────────────────────
            "m365.subscriptions.create" => self.invoke_create_subscription(input).await,
            "m365.subscriptions.renew" => self.invoke_renew_subscription(input).await,
            "m365.subscriptions.delete" => self.invoke_delete_subscription(input).await,
            // ── Delta ────────────────────────────────────────
            "m365.delta.sync" => self.invoke_delta_sync(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Mail operation implementations ───────────────────────────

    async fn invoke_list_messages(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let folder_id = input.get("folder_id").and_then(|v| v.as_str());
        let top = input.get("top").and_then(|v| v.as_u64()).map(|v| v as u32);
        let skip = input.get("skip").and_then(|v| v.as_u64()).map(|v| v as u32);
        let filter = input.get("filter").and_then(|v| v.as_str());
        let result = client
            .list_messages(user_id, folder_id, top, skip, filter)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "messages": result.value }))
    }

    async fn invoke_get_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message_id = require_str(&input, "message_id")?;
        let message = client
            .get_message(user_id, message_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "message": message }))
    }

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message = input.get("message").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: message".into(),
        })?;
        client
            .send_message(user_id, message)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "sent" }))
    }

    async fn invoke_create_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message = input.get("message").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: message".into(),
        })?;
        let draft = client
            .create_draft(user_id, message)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "message": draft }))
    }

    // ── Files operation implementations ──────────────────────────

    async fn invoke_list_items(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let path = input.get("path").and_then(|v| v.as_str());
        let result = client
            .list_items(user_id, path)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "items": result.value }))
    }

    async fn invoke_download_file(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let item_id = require_str(&input, "item_id")?;
        let (content, metadata) = client
            .download_file(user_id, item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({
            "content": content,
            "name": metadata.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            "size": metadata.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
        }))
    }

    async fn invoke_upload_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let path = require_str(&input, "path")?;
        let content_b64 = require_str(&input, "content")?;
        let content = BASE64.decode(content_b64).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid base64 content: {e}"),
        })?;
        let item = client
            .upload_file(user_id, path, &content)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "item": item }))
    }

    async fn invoke_delete_item(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let item_id = require_str(&input, "item_id")?;
        client
            .delete_item(user_id, item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "deleted" }))
    }

    // ── Calendar operation implementations ───────────────────────

    async fn invoke_list_events(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let start = input.get("start_datetime").and_then(|v| v.as_str());
        let end = input.get("end_datetime").and_then(|v| v.as_str());
        let result = client
            .list_events(user_id, start, end)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "events": result.value }))
    }

    async fn invoke_create_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let subject = require_str(&input, "subject")?;
        let start = input.get("start").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: start".into(),
        })?;
        let end = input.get("end").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: end".into(),
        })?;
        let mut event = json!({
            "subject": subject,
            "start": start,
            "end": end,
        });
        if let Some(body) = input.get("body") {
            event["body"] = body.clone();
        }
        if let Some(location) = input.get("location") {
            event["location"] = location.clone();
        }
        if let Some(attendees) = input.get("attendees") {
            event["attendees"] = attendees.clone();
        }
        let created = client
            .create_event(user_id, &event)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "event": created }))
    }

    async fn invoke_delete_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let event_id = require_str(&input, "event_id")?;
        client
            .delete_event(user_id, event_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "deleted" }))
    }

    async fn invoke_get_freebusy(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let schedules_val = input.get("schedules").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: schedules".into(),
        })?;
        let schedules: Vec<String> = schedules_val
            .as_array()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "schedules must be an array".into(),
            })?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        let start_time = input.get("start_time").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: start_time".into(),
        })?;
        let end_time = input.get("end_time").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: end_time".into(),
        })?;
        let result = client
            .get_freebusy(&schedules, start_time, end_time)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "schedules": result.get("value").cloned().unwrap_or(json!([])) }))
    }

    // ── Tasks operation implementations ──────────────────────────

    async fn invoke_list_task_lists(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let result = client
            .list_task_lists(user_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "task_lists": result.value }))
    }

    async fn invoke_list_tasks(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let task_list_id = require_str(&input, "task_list_id")?;
        let result = client
            .list_tasks(user_id, task_list_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "tasks": result.value }))
    }

    async fn invoke_create_task(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let task_list_id = require_str(&input, "task_list_id")?;
        let title = require_str(&input, "title")?;
        let mut task = json!({ "title": title });
        if let Some(body) = input.get("body") {
            task["body"] = body.clone();
        }
        if let Some(due) = input.get("due_datetime").and_then(|v| v.as_str()) {
            task["dueDateTime"] = json!({
                "dateTime": due,
                "timeZone": "UTC",
            });
        }
        let created = client
            .create_task(user_id, task_list_id, &task)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "task": created }))
    }

    // ── Subscription operation implementations ───────────────────

    async fn invoke_create_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let change_type = require_str(&input, "change_type")?;
        let notification_url = require_str(&input, "notification_url")?;
        let resource = require_str(&input, "resource")?;
        let expiration = require_str(&input, "expiration_datetime")?;
        let sub = json!({
            "changeType": change_type,
            "notificationUrl": notification_url,
            "resource": resource,
            "expirationDateTime": expiration,
        });
        let created = client
            .create_subscription(&sub)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "subscription": created }))
    }

    async fn invoke_renew_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let subscription_id = require_str(&input, "subscription_id")?;
        let expiration = require_str(&input, "expiration_datetime")?;
        let renewed = client
            .renew_subscription(subscription_id, expiration)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "subscription": renewed }))
    }

    async fn invoke_delete_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let subscription_id = require_str(&input, "subscription_id")?;
        client
            .delete_subscription(subscription_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "deleted" }))
    }

    // ── Delta operation implementations ──────────────────────────

    async fn invoke_delta_sync(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resource = require_str(&input, "resource")?;
        let delta_token = input.get("delta_token").and_then(|v| v.as_str());
        let result = client
            .delta_sync(resource, delta_token)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;

        // Extract delta token from deltaLink if present
        let token = result
            .delta_link
            .as_deref()
            .and_then(|link| {
                link.split("$deltatoken=")
                    .nth(1)
                    .map(std::string::ToString::to_string)
            })
            .unwrap_or_default();

        Ok(json!({
            "changes": result.value,
            "delta_token": token,
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(&self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
        info!("Microsoft 365 connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

fn parse_access_token(params: &serde_json::Value) -> Option<String> {
    let top_level = params
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);

    top_level.or_else(|| {
        params
            .get("oauth")
            .and_then(|oauth| oauth.get("access_token"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

fn parse_credential_id(params: &serde_json::Value) -> FcpResult<Option<CredentialId>> {
    let Some(raw) = params.get("credential_id") else {
        return Ok(None);
    };
    let raw = raw.as_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "credential_id must be a string".into(),
    })?;
    let parsed = CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: "credential_id must be a valid UUID".into(),
    })?;
    Ok(Some(parsed))
}

fn parse_app_credentials(params: &serde_json::Value) -> FcpResult<Option<AppCredentialsConfig>> {
    let Some(raw) = params.get("app_credentials") else {
        return Ok(None);
    };
    let config: AppCredentialsConfig =
        serde_json::from_value(raw.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid app_credentials object: {e}"),
        })?;

    if config.tenant_id.trim().is_empty()
        || config.client_id.trim().is_empty()
        || config.client_secret.trim().is_empty()
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "app_credentials tenant_id, client_id, and client_secret are required".into(),
        });
    }

    Ok(Some(config))
}

fn parse_required_permissions(params: &serde_json::Value) -> FcpResult<Vec<String>> {
    let Some(raw) = params.get("required_permissions") else {
        return Ok(Vec::new());
    };
    let values = raw.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "required_permissions must be an array of strings".into(),
    })?;

    let mut required = Vec::new();
    for value in values {
        let permission = value.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "required_permissions entries must be strings".into(),
        })?;
        let permission = permission.trim();
        if permission.is_empty() {
            continue;
        }
        if !required.iter().any(|existing| existing == permission) {
            required.push(permission.to_string());
        }
    }
    Ok(required)
}

fn ensure_required_permissions(
    token_permissions: &TokenPermissions,
    required_permissions: &[String],
) -> FcpResult<()> {
    if required_permissions.is_empty() {
        return Ok(());
    }
    let missing = token_permissions.missing_required(required_permissions);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Token is missing required permissions: {}",
                missing.join(", ")
            ),
        })
    }
}

fn validate_endpoint(
    raw_url: &str,
    allowed_hosts: &[&str],
    allow_test_endpoints: bool,
    field_name: &str,
) -> FcpResult<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field_name} cannot be empty"),
        });
    }

    let parsed = reqwest::Url::parse(trimmed).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid {field_name}: {e}"),
    })?;

    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field_name} must include a host"),
    })?;

    if !allow_test_endpoints && parsed.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field_name} must use https in production mode"),
        });
    }

    if parsed.host().is_some_and(|value| value.is_ipv4() || value.is_ipv6()) && !allow_test_endpoints {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field_name} must not use an IP literal"),
        });
    }

    let host_lower = host.to_ascii_lowercase();
    let allowed = allowed_hosts.iter().any(|allowed_host| host_lower == *allowed_host);
    if !allowed && !(allow_test_endpoints && is_local_test_host(&host_lower)) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "{field_name} host '{host}' is not allowed by connector NetworkConstraints"
            ),
        });
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

async fn exchange_client_credentials(
    auth_url: &str,
    config: &AppCredentialsConfig,
) -> FcpResult<String> {
    let token_endpoint = format!(
        "{}/{}/oauth2/v2.0/token",
        auth_url.trim_end_matches('/'),
        config.tenant_id
    );

    let response = reqwest::Client::builder()
        .build()
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to build OAuth HTTP client: {e}"),
        })?
        .post(&token_endpoint)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("scope", config.scope.as_str()),
        ])
        .send()
        .await
        .map_err(|e| FcpError::External {
            service: "microsoft365_oauth".into(),
            message: e.to_string(),
            status_code: e.status().map(|status| status.as_u16()),
            retryable: e.is_timeout() || e.is_connect(),
            retry_after: None,
        })?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no-body>".to_string());
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: format!(
                "Client credentials token exchange failed: HTTP {} ({})",
                status.as_u16(),
                body.chars().take(256).collect::<String>()
            ),
        });
    }

    let payload: OAuthTokenResponse =
        response
            .json()
            .await
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("OAuth token response was invalid JSON: {e}"),
            })?;
    if payload.access_token.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "OAuth token response did not include access_token".into(),
        });
    }

    Ok(payload.access_token)
}

impl Default for M365Connector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
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

fn build_operations() -> Vec<OperationInfo> {
    vec![
        // ── Mail operations ──────────────────────────────────────
        op_info(
            "m365.mail.list_messages",
            "List messages in a mailbox folder with optional filtering",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "folder_id": { "type": "string" },
                    "top": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "skip": { "type": "integer" },
                    "filter": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "messages": { "type": "array" } } }),
            "m365.mail.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List email messages in a user's mailbox. Supports OData filters for search.".into(),
                common_mistakes: vec![
                    "Not using $filter for targeted queries, resulting in large responses.".into(),
                    "Forgetting to handle @odata.nextLink for pagination.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "folder_id": "inbox", "top": 25}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.mail.get_message"),
                    CapabilityId::from_static("m365.mail.send_message"),
                ],
            },
        ),
        op_info(
            "m365.mail.get_message",
            "Get a specific email message with headers and body",
            json!({
                "type": "object",
                "required": ["user_id", "message_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
            "m365.mail.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read a specific email message by ID.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"user_id": "me", "message_id": "AAMkAG..."}"#.into()],
                related: vec![CapabilityId::from_static("m365.mail.list_messages")],
            },
        ),
        op_info(
            "m365.mail.send_message",
            "Send an email message",
            json!({
                "type": "object",
                "required": ["user_id", "message"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message": { "type": "object" }
                }
            }),
            json!({ "type": "object" }),
            "m365.mail.send",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Send an email via Outlook/Microsoft 365. Triggers real email delivery.".into(),
                common_mistakes: vec![
                    "Sending without confirming recipients with the user first.".into(),
                    "Not setting saveToSentItems to true (default is true, but be explicit).".into(),
                ],
                examples: vec![
                    r#"{"user_id": "me", "message": {"subject": "Hello", "body": {"contentType": "Text", "content": "Hi there"}, "toRecipients": [{"emailAddress": {"address": "bob@contoso.com"}}]}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("m365.mail.create_draft"),
                    CapabilityId::from_static("m365.mail.list_messages"),
                ],
            },
        ),
        op_info(
            "m365.mail.create_draft",
            "Create a draft email message",
            json!({
                "type": "object",
                "required": ["user_id", "message"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message": { "type": "object" }
                }
            }),
            json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
            "m365.mail.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a draft email without sending it. Safer for review workflows.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"user_id": "me", "message": {"subject": "Draft", "body": {"contentType": "Text", "content": "Review before sending"}}}"#.into()],
                related: vec![CapabilityId::from_static("m365.mail.send_message")],
            },
        ),
        // ── Files operations ─────────────────────────────────────
        op_info(
            "m365.files.list_items",
            "List files and folders in a OneDrive path or drive root",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "path": { "type": "string" },
                    "drive_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "items": { "type": "array" } } }),
            "m365.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Browse files and folders in OneDrive or SharePoint document libraries.".into(),
                common_mistakes: vec!["Not handling pagination for large directories.".into()],
                examples: vec![r#"{"user_id": "me", "path": "/Documents"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.download_file"),
                    CapabilityId::from_static("m365.files.upload_file"),
                ],
            },
        ),
        op_info(
            "m365.files.download_file",
            "Download a file from OneDrive",
            json!({
                "type": "object",
                "required": ["user_id", "item_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "item_id": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["content"],
                "properties": {
                    "content": { "type": "string" },
                    "name": { "type": "string" },
                    "size": { "type": "integer" }
                }
            }),
            "m365.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Download a file from OneDrive by item ID.".into(),
                common_mistakes: vec!["Downloading very large files without checking size first.".into()],
                examples: vec![r#"{"user_id": "me", "item_id": "01ABCDEF..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.list_items"),
                    CapabilityId::from_static("m365.files.upload_file"),
                ],
            },
        ),
        op_info(
            "m365.files.upload_file",
            "Upload a file to OneDrive (simple upload for files up to 4 MB)",
            json!({
                "type": "object",
                "required": ["user_id", "path", "content"],
                "properties": {
                    "user_id": { "type": "string" },
                    "path": { "type": "string" },
                    "content": { "type": "string" },
                    "conflict_behavior": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "item": { "type": "object" } } }),
            "m365.files.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Upload a file to OneDrive. For files >4 MB, use a resumable upload session.".into(),
                common_mistakes: vec![
                    "Uploading files >4 MB via simple upload (use upload session instead).".into(),
                    "Not specifying conflict_behavior, which defaults to fail on existing files.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "path": "/Documents/notes.txt", "content": "SGVsbG8gV29ybGQ="}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.download_file"),
                    CapabilityId::from_static("m365.files.list_items"),
                ],
            },
        ),
        op_info(
            "m365.files.delete_item",
            "Delete a file or folder from OneDrive",
            json!({
                "type": "object",
                "required": ["user_id", "item_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "item_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "m365.files.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Permanently delete a file or folder. Items go to the recycle bin first.".into(),
                common_mistakes: vec!["Deleting folders with contents without user confirmation.".into()],
                examples: vec![r#"{"user_id": "me", "item_id": "01ABCDEF..."}"#.into()],
                related: vec![CapabilityId::from_static("m365.files.list_items")],
            },
        ),
        // ── Calendar operations ──────────────────────────────────
        op_info(
            "m365.calendar.list_events",
            "List calendar events within a time range",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "start_datetime": { "type": "string" },
                    "end_datetime": { "type": "string" },
                    "calendar_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "events": { "type": "array" } } }),
            "m365.calendar.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List calendar events. Use calendarView for expanded recurring events.".into(),
                common_mistakes: vec![
                    "Not using calendarView endpoint for recurring events (list only returns master events).".into(),
                    "Querying unbounded time ranges.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "start_datetime": "2026-03-01T00:00:00Z", "end_datetime": "2026-03-08T00:00:00Z"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.create_event"),
                    CapabilityId::from_static("m365.calendar.get_freebusy"),
                ],
            },
        ),
        op_info(
            "m365.calendar.create_event",
            "Create a calendar event with optional attendees",
            json!({
                "type": "object",
                "required": ["user_id", "subject", "start", "end"],
                "properties": {
                    "user_id": { "type": "string" },
                    "subject": { "type": "string" },
                    "start": { "type": "object" },
                    "end": { "type": "object" },
                    "body": { "type": "object" },
                    "location": { "type": "object" },
                    "attendees": { "type": "array" }
                }
            }),
            json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
            "m365.calendar.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a calendar event. Adding attendees sends meeting invitations.".into(),
                common_mistakes: vec![
                    "Adding attendees without user confirmation (sends real meeting invites).".into(),
                    "Not specifying timeZone in start/end objects.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "subject": "Team Standup", "start": {"dateTime": "2026-03-03T09:00:00", "timeZone": "America/Chicago"}, "end": {"dateTime": "2026-03-03T09:30:00", "timeZone": "America/Chicago"}}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.list_events"),
                    CapabilityId::from_static("m365.calendar.delete_event"),
                ],
            },
        ),
        op_info(
            "m365.calendar.delete_event",
            "Delete a calendar event",
            json!({
                "type": "object",
                "required": ["user_id", "event_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "event_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "m365.calendar.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Delete a calendar event. Sends cancellation notices to attendees.".into(),
                common_mistakes: vec!["Deleting recurring event master instead of a single instance.".into()],
                examples: vec![r#"{"user_id": "me", "event_id": "AAMkAG..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.list_events"),
                    CapabilityId::from_static("m365.calendar.create_event"),
                ],
            },
        ),
        op_info(
            "m365.calendar.get_freebusy",
            "Check free/busy availability for one or more users",
            json!({
                "type": "object",
                "required": ["schedules", "start_time", "end_time"],
                "properties": {
                    "schedules": { "type": "array" },
                    "start_time": { "type": "object" },
                    "end_time": { "type": "object" }
                }
            }),
            json!({ "type": "object", "properties": { "schedules": { "type": "array" } } }),
            "m365.calendar.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Check when users are free or busy to schedule meetings.".into(),
                common_mistakes: vec!["Querying too many schedules at once (max 20 per request).".into()],
                examples: vec![r#"{"schedules": ["alice@contoso.com"], "start_time": {"dateTime": "2026-03-03T08:00:00", "timeZone": "UTC"}, "end_time": {"dateTime": "2026-03-03T18:00:00", "timeZone": "UTC"}}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.create_event"),
                    CapabilityId::from_static("m365.calendar.list_events"),
                ],
            },
        ),
        // ── Tasks operations ─────────────────────────────────────
        op_info(
            "m365.tasks.list_task_lists",
            "List all To Do task lists",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "task_lists": { "type": "array" } } }),
            "m365.tasks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all To Do task lists for a user.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"user_id": "me"}"#.into()],
                related: vec![CapabilityId::from_static("m365.tasks.list_tasks")],
            },
        ),
        op_info(
            "m365.tasks.list_tasks",
            "List tasks in a To Do task list",
            json!({
                "type": "object",
                "required": ["user_id", "task_list_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "task_list_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "tasks": { "type": "array" } } }),
            "m365.tasks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List tasks from a Microsoft To Do list.".into(),
                common_mistakes: vec!["Not listing task lists first to get the correct task_list_id.".into()],
                examples: vec![r#"{"user_id": "me", "task_list_id": "AAMkAG..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.tasks.create_task"),
                    CapabilityId::from_static("m365.tasks.list_task_lists"),
                ],
            },
        ),
        op_info(
            "m365.tasks.create_task",
            "Create a new task in a To Do list",
            json!({
                "type": "object",
                "required": ["user_id", "task_list_id", "title"],
                "properties": {
                    "user_id": { "type": "string" },
                    "task_list_id": { "type": "string" },
                    "title": { "type": "string" },
                    "body": { "type": "object" },
                    "due_datetime": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "task": { "type": "object" } } }),
            "m365.tasks.write",
            RiskLevel::Low,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a task in Microsoft To Do.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"user_id": "me", "task_list_id": "AAMkAG...", "title": "Review PR #42", "due_datetime": "2026-03-05T17:00:00Z"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.tasks.list_tasks"),
                    CapabilityId::from_static("m365.tasks.list_task_lists"),
                ],
            },
        ),
        // ── Subscription operations ──────────────────────────────
        op_info(
            "m365.subscriptions.create",
            "Create a Graph API webhook subscription for change notifications",
            json!({
                "type": "object",
                "required": ["change_type", "notification_url", "resource", "expiration_datetime"],
                "properties": {
                    "change_type": { "type": "string" },
                    "notification_url": { "type": "string" },
                    "resource": { "type": "string" },
                    "expiration_datetime": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "subscription": { "type": "object" } } }),
            "m365.subscriptions.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Subscribe to change notifications for mail, calendar, files, etc.".into(),
                common_mistakes: vec![
                    "Not implementing the validation endpoint that Graph calls during creation.".into(),
                    "Setting expirationDateTime beyond the resource's max (e.g., 4230 min for messages).".into(),
                ],
                examples: vec![r#"{"change_type": "created,updated", "notification_url": "https://webhook.example.com/m365", "resource": "/me/messages", "expiration_datetime": "2026-03-04T00:00:00Z"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.subscriptions.renew"),
                    CapabilityId::from_static("m365.subscriptions.delete"),
                ],
            },
        ),
        op_info(
            "m365.subscriptions.renew",
            "Renew (extend) a Graph API webhook subscription before it expires",
            json!({
                "type": "object",
                "required": ["subscription_id", "expiration_datetime"],
                "properties": {
                    "subscription_id": { "type": "string" },
                    "expiration_datetime": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "subscription": { "type": "object" } } }),
            "m365.subscriptions.write",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Renew a webhook subscription before it expires to maintain continuous notifications.".into(),
                common_mistakes: vec!["Letting subscriptions expire; implement proactive renewal timers.".into()],
                examples: vec![r#"{"subscription_id": "sub-123", "expiration_datetime": "2026-03-07T00:00:00Z"}"#.into()],
                related: vec![CapabilityId::from_static("m365.subscriptions.create")],
            },
        ),
        op_info(
            "m365.subscriptions.delete",
            "Delete a Graph API webhook subscription",
            json!({
                "type": "object",
                "required": ["subscription_id"],
                "properties": {
                    "subscription_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "m365.subscriptions.write",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Remove a webhook subscription when no longer needed.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"subscription_id": "sub-123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.subscriptions.create"),
                    CapabilityId::from_static("m365.subscriptions.renew"),
                ],
            },
        ),
        // ── Delta operations ─────────────────────────────────────
        op_info(
            "m365.delta.sync",
            "Perform incremental delta query to get changes since last sync",
            json!({
                "type": "object",
                "required": ["resource"],
                "properties": {
                    "resource": { "type": "string" },
                    "delta_token": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["changes", "delta_token"],
                "properties": {
                    "changes": { "type": "array" },
                    "delta_token": { "type": "string" }
                }
            }),
            "m365.delta.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Incrementally sync changes for mail, calendar, or files since last sync.".into(),
                common_mistakes: vec![
                    "Not persisting delta_token between syncs (forces full re-sync).".into(),
                    "Not handling @removed items in the delta response.".into(),
                ],
                examples: vec![
                    r#"{"resource": "/me/messages"}"#.into(),
                    r#"{"resource": "/me/events", "delta_token": "opaquetoken123"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("m365.subscriptions.create")],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    fn make_access_token(scopes: &[&str], roles: &[&str]) -> String {
        let header = BASE64_URL.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = serde_json::json!({
            "scp": scopes.join(" "),
            "roles": roles,
        });
        let payload = BASE64_URL.encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{payload}.signature")
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = M365Connector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.mail.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = M365Connector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_access_token_permissions() {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read", "Calendars.Read"], &[]);
        let result = connector
            .handle_configure(json!({
                "access_token": token,
                "required_permissions": ["Mail.Read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["auth_mode"], "access_token");
        assert_eq!(health["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_required_permissions() {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["User.Read"], &[]);
        let result = connector
            .handle_configure(json!({
                "access_token": token,
                "required_permissions": ["Mail.Read"]
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("missing required permissions"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_app_credentials_exchanges_token() {
        let token_server = MockServer::start().await;
        let token = make_access_token(&[], &["Mail.Read.All"]);

        Mock::given(method("POST"))
            .and(path("/tenant-id/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&token_server)
            .await;

        let mut connector = M365Connector::new();
        let result = connector
            .handle_configure(json!({
                "allow_test_api_url": true,
                "auth_url": token_server.uri(),
                "app_credentials": {
                    "tenant_id": "tenant-id",
                    "client_id": "11111111-2222-3333-4444-555555555555",
                    "client_secret": "secret-value"
                },
                "required_permissions": ["Mail.Read.All"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["auth_mode"], "client_credentials");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_degraded_for_credential_id_mode() {
        let mut connector = M365Connector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(
            result["reason_code"],
            "credential_injection_required"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = M365Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.mail.get_message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "m365.mail.get_message");
        let result = connector
            .handle_invoke(json!({
                "operation": "m365.mail.get_message",
                "input": { "user_id": "me", "message_id": "msg_123" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = M365Connector::new();
        connector.client = Some(
            M365Client::new("test_token")
                .unwrap()
                .with_api_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.calendar.create_event"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "m365.calendar.create_event");
        let result = connector
            .handle_invoke(json!({
                "operation": "m365.calendar.create_event",
                "input": { "user_id": "me", "subject": "Test" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("start")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = M365Connector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        // Mail (4)
        assert!(op_ids.contains(&"m365.mail.list_messages"));
        assert!(op_ids.contains(&"m365.mail.get_message"));
        assert!(op_ids.contains(&"m365.mail.send_message"));
        assert!(op_ids.contains(&"m365.mail.create_draft"));
        // Files (4)
        assert!(op_ids.contains(&"m365.files.list_items"));
        assert!(op_ids.contains(&"m365.files.download_file"));
        assert!(op_ids.contains(&"m365.files.upload_file"));
        assert!(op_ids.contains(&"m365.files.delete_item"));
        // Calendar (4)
        assert!(op_ids.contains(&"m365.calendar.list_events"));
        assert!(op_ids.contains(&"m365.calendar.create_event"));
        assert!(op_ids.contains(&"m365.calendar.delete_event"));
        assert!(op_ids.contains(&"m365.calendar.get_freebusy"));
        // Tasks (3)
        assert!(op_ids.contains(&"m365.tasks.list_task_lists"));
        assert!(op_ids.contains(&"m365.tasks.list_tasks"));
        assert!(op_ids.contains(&"m365.tasks.create_task"));
        // Subscriptions (3)
        assert!(op_ids.contains(&"m365.subscriptions.create"));
        assert!(op_ids.contains(&"m365.subscriptions.renew"));
        assert!(op_ids.contains(&"m365.subscriptions.delete"));
        // Delta (1)
        assert!(op_ids.contains(&"m365.delta.sync"));

        assert_eq!(ops.len(), 19);
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest.compute_interface_hash().expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2.compute_interface_hash().expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
