//! FCP Google Workspace Events Connector implementation.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use fcp_google_discovery::{
    auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth},
    provisioning::load_default_google_provisioning_bundle,
};
use serde_json::json;
use tracing::info;

use crate::client::{DEFAULT_EVENTS_BASE_URL, DEFAULT_PUBSUB_BASE_URL, WorkspaceEventsClient};

/// Validated connector configuration.
struct WorkspaceEventsConfig {
    auth: GoogleMaterializedAuth,
    events_base_url: String,
    pubsub_base_url: String,
    required_scopes: Vec<String>,
}

impl WorkspaceEventsConfig {
    async fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let required_scopes = resolve_workspace_events_required_scopes(params)?;
        let mut auth_params = params.clone();
        let auth_object = auth_params
            .as_object_mut()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "configure params must be a JSON object".into(),
            })?;
        auth_object.insert(
            "required_scopes".to_string(),
            serde_json::json!(required_scopes.clone()),
        );

        let selection =
            GoogleAuthSelection::from_connector_config(&auth_params).map_err(map_auth_error)?;
        let auth = selection
            .materialize()
            .await
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Failed to materialize Google auth source: {error}"),
            })?;

        Ok(Self {
            auth,
            events_base_url: params
                .get("events_base_url")
                .and_then(|value| value.as_str())
                .unwrap_or(DEFAULT_EVENTS_BASE_URL)
                .to_string(),
            pubsub_base_url: params
                .get("pubsub_base_url")
                .and_then(|value| value.as_str())
                .unwrap_or(DEFAULT_PUBSUB_BASE_URL)
                .to_string(),
            required_scopes,
        })
    }
}

fn parse_string_array_field(
    params: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };
    let values = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("`{field}` must be an array of strings"),
    })?;
    if values.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must not be empty"),
        });
    }

    let mut deduped = BTreeSet::new();
    for value in values {
        let item = value.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must contain only strings"),
        })?;
        let item = item.trim();
        if item.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("`{field}` entries must not be empty"),
            });
        }
        deduped.insert(item.to_string());
    }

    Ok(Some(deduped.into_iter().collect()))
}

fn resolve_workspace_events_required_scopes(params: &serde_json::Value) -> FcpResult<Vec<String>> {
    let explicit_scopes = parse_string_array_field(params, "required_scopes")?;
    let scope_triggers = parse_string_array_field(params, "scope_triggers")?.unwrap_or_default();
    if explicit_scopes.is_some() && !scope_triggers.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide either `required_scopes` or `scope_triggers`, not both".into(),
        });
    }
    if let Some(scopes) = explicit_scopes {
        return Ok(scopes);
    }

    let bundle = load_default_google_provisioning_bundle("workspace_events").map_err(|error| {
        FcpError::Internal {
            message: format!(
                "Failed to load embedded Workspace Events provisioning bundle: {error}"
            ),
        }
    })?;
    bundle
        .scopes_for_triggers(scope_triggers)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Workspace Events scope trigger selection: {error}"),
        })
}

#[allow(clippy::needless_pass_by_value)]
fn map_auth_error(error: GoogleAuthError) -> FcpError {
    match &error {
        GoogleAuthError::ExactlyOneSourceRequired { count: 0 } => FcpError::InvalidRequest {
            code: 1003,
            message: "Missing authentication: supply one Google auth source".into(),
        },
        GoogleAuthError::ExactlyOneSourceRequired { .. } => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Provide exactly one Google auth source: {error}"),
        },
        _ => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Google auth configuration: {error}"),
        },
    }
}

/// FCP Google Workspace Events connector.
pub struct WorkspaceEventsConnector {
    base: Arc<BaseConnector>,
    client: Option<WorkspaceEventsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
    required_scopes: Vec<String>,
}

impl WorkspaceEventsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-workspace-events",
            ))),
            client: None,
            verifier: None,
            session_id: None,
            required_scopes: Vec::new(),
        }
    }

    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = WorkspaceEventsConfig::from_params(&params).await?;
        let status = match &config.auth {
            GoogleMaterializedAuth::CredentialReference { .. } => {
                "configured_pending_token_materialization"
            }
            GoogleMaterializedAuth::BearerToken { .. } => "configured",
        };
        let client = WorkspaceEventsClient::new_with_auth(config.auth.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create Workspace Events client: {e}"),
            })?
            .with_base_urls(config.events_base_url, config.pubsub_base_url);

        let auth_label = client.auth_redacted_label();
        self.required_scopes.clone_from(&config.required_scopes);
        self.client = Some(client);
        self.base
            .configured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!(
            auth = %auth_label,
            status,
            required_scopes = ?self.required_scopes,
            "Google Workspace Events connector configured"
        );

        Ok(json!({
            "status": status,
            "required_scopes": self.required_scopes,
            "provisioning_surface": "workspace_events"
        }))
    }

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

        let session_id = fcp_core::SessionId::new();
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
            manifest_hash: "sha256:google-workspace-events-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 50,
                requires_ack: true,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let status = if self.client.is_some() {
            "healthy"
        } else {
            "not_configured"
        };
        let metrics = self.base.metrics();
        Ok(json!({
            "status": status,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 50,
                requires_ack: true,
            }),
            operations: vec![
                op_info(
                    "workspace_events.describe_provisioning",
                    "Describe the embedded provisioning recipe and effective scope set",
                    json!({
                        "type": "object",
                        "properties": {
                            "scope_triggers": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional provisioning escalation triggers to resolve into an effective scope set"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "bundle": { "type": "object" },
                            "effective_scopes": { "type": "array", "items": { "type": "string" } }
                        }
                    }),
                    "workspace_events.provisioning.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect the embedded Workspace Events + Pub/Sub setup contract before provisioning or widening consent.".into(),
                        common_mistakes: vec![
                            "Assuming Workspace Events has a broad standalone OAuth scope instead of product-specific event scopes".into(),
                        ],
                        examples: vec![r#"{"scope_triggers":["User selects Chat space metadata events."]}"#.into()],
                        related: vec![CapabilityId::from_static("workspace_events.create_subscription")],
                    },
                ),
                op_info(
                    "workspace_events.list_subscriptions",
                    "List Workspace Events subscriptions",
                    json!({
                        "type": "object",
                        "properties": {
                            "page_size": { "type": "integer", "description": "Maximum subscriptions to return" },
                            "page_token": { "type": "string", "description": "Pagination token from a prior response" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "subscriptions": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    "workspace_events.subscriptions.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect the current Workspace Events control-plane state before creating, reactivating, or deleting subscriptions.".into(),
                        common_mistakes: vec![
                            "Assuming subscription expiration/reactivation state is implicit instead of reading the current control-plane resource".into(),
                        ],
                        examples: vec![r#"{"page_size": 25}"#.into()],
                        related: vec![CapabilityId::from_static("workspace_events.get_subscription")],
                    },
                ),
                op_info(
                    "workspace_events.get_subscription",
                    "Get a single Workspace Events subscription",
                    json!({
                        "type": "object",
                        "required": ["subscription_name"],
                        "properties": {
                            "subscription_name": { "type": "string", "description": "Resource name like subscriptions/AAAA" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "subscription": { "type": "object" }
                        }
                    }),
                    "workspace_events.subscriptions.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read exact state for one Workspace Events subscription, including TTL, state, target resource, and delivery configuration.".into(),
                        common_mistakes: vec![
                            "Passing a Pub/Sub subscription name instead of the Workspace Events subscription resource".into(),
                        ],
                        examples: vec![r#"{"subscription_name":"subscriptions/AAAAA"}"#.into()],
                        related: vec![CapabilityId::from_static("workspace_events.list_subscriptions")],
                    },
                ),
                op_info(
                    "workspace_events.create_subscription",
                    "Create a Workspace Events subscription backed by a Pub/Sub topic",
                    json!({
                        "type": "object",
                        "required": ["target_resource", "event_types", "pubsub_topic"],
                        "properties": {
                            "target_resource": { "type": "string", "description": "Resource to watch, for example a Chat space resource URI" },
                            "event_types": { "type": "array", "items": { "type": "string" }, "description": "Explicit event type identifiers to subscribe to" },
                            "pubsub_topic": { "type": "string", "description": "Fully-qualified Pub/Sub topic used for delivery" },
                            "ttl": { "type": "string", "description": "Optional TTL duration string accepted by Workspace Events" },
                            "include_resource": { "type": "boolean", "description": "Whether payloads should embed the changed resource when supported" },
                            "field_mask": { "type": "string", "description": "Optional resource field mask for payload shaping" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "operation": { "type": "object" }
                        }
                    }),
                    "workspace_events.subscriptions.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new Workspace Events subscription after Pub/Sub topic and IAM bootstrap are complete.".into(),
                        common_mistakes: vec![
                            "Creating the upstream subscription before the Pub/Sub topic and publisher IAM are ready".into(),
                            "Using a broad event scope set when a narrower event-type selection would suffice".into(),
                        ],
                        examples: vec![r#"{"target_resource":"//chat.googleapis.com/spaces/AAAA","event_types":["google.workspace.chat.message.v1.created"],"pubsub_topic":"projects/demo/topics/workspace-events"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("workspace_events.describe_provisioning"),
                            CapabilityId::from_static("workspace_events.reactivate_subscription"),
                        ],
                    },
                ),
                op_info(
                    "workspace_events.reactivate_subscription",
                    "Reactivate a suspended Workspace Events subscription",
                    json!({
                        "type": "object",
                        "required": ["subscription_name"],
                        "properties": {
                            "subscription_name": { "type": "string", "description": "Subscription resource to reactivate" },
                            "ttl": { "type": "string", "description": "Optional replacement TTL for the reactivated subscription" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "operation": { "type": "object" }
                        }
                    }),
                    "workspace_events.subscriptions.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Recover a suspended subscription after fixing delivery or authorization preconditions.".into(),
                        common_mistakes: vec![
                            "Reactivating before the underlying Pub/Sub or IAM problem is fixed".into(),
                        ],
                        examples: vec![r#"{"subscription_name":"subscriptions/AAAAA","ttl":"86400s"}"#.into()],
                        related: vec![CapabilityId::from_static("workspace_events.get_subscription")],
                    },
                ),
                op_info(
                    "workspace_events.delete_subscription",
                    "Delete a Workspace Events subscription",
                    json!({
                        "type": "object",
                        "required": ["subscription_name"],
                        "properties": {
                            "subscription_name": { "type": "string", "description": "Subscription resource to delete" },
                            "validate_only": { "type": "boolean", "description": "If true, validate the delete without executing it" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "operation": { "type": "object" }
                        }
                    }),
                    "workspace_events.subscriptions.write",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Remove an obsolete Workspace Events subscription when you intentionally want delivery to stop.".into(),
                        common_mistakes: vec![
                            "Deleting the Workspace Events subscription and assuming the Pub/Sub subscription is also cleaned up automatically".into(),
                        ],
                        examples: vec![r#"{"subscription_name":"subscriptions/AAAAA","validate_only":true}"#.into()],
                        related: vec![CapabilityId::from_static("workspace_events.reactivate_subscription")],
                    },
                ),
                op_info(
                    "workspace_events.pull_events",
                    "Pull Pub/Sub messages for a Workspace Events delivery subscription",
                    json!({
                        "type": "object",
                        "required": ["pubsub_subscription"],
                        "properties": {
                            "pubsub_subscription": { "type": "string", "description": "Fully-qualified Pub/Sub subscription name" },
                            "max_messages": { "type": "integer", "description": "Maximum messages to pull in one request" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "received_messages": { "type": "array", "items": { "type": "object" } },
                            "decoded_events": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    "workspace_events.delivery.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Consume the next batch of Pub/Sub-delivered Workspace Events messages after control-plane setup is complete.".into(),
                        common_mistakes: vec![
                            "Using the Workspace Events subscription name instead of the Pub/Sub delivery subscription".into(),
                            "Forgetting to ack after successful processing when the delivery path requires ack".into(),
                        ],
                        examples: vec![r#"{"pubsub_subscription":"projects/demo/subscriptions/workspace-events","max_messages":10}"#.into()],
                        related: vec![CapabilityId::from_static("workspace_events.ack_events")],
                    },
                ),
                op_info(
                    "workspace_events.ack_events",
                    "Acknowledge Pub/Sub messages after successful processing",
                    json!({
                        "type": "object",
                        "required": ["pubsub_subscription", "ack_ids"],
                        "properties": {
                            "pubsub_subscription": { "type": "string", "description": "Fully-qualified Pub/Sub subscription name" },
                            "ack_ids": { "type": "array", "items": { "type": "string" }, "description": "Ack IDs returned by pull_events" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "status": { "type": "string" },
                            "acked_count": { "type": "integer" }
                        }
                    }),
                    "workspace_events.delivery.ack",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Acknowledge Pub/Sub messages only after downstream handling has succeeded and you want delivery retries to stop.".into(),
                        common_mistakes: vec![
                            "Acking messages before processing completes, which can lose events on downstream failure".into(),
                        ],
                        examples: vec![r#"{"pubsub_subscription":"projects/demo/subscriptions/workspace-events","ack_ids":["ACK-1","ACK-2"]}"#.into()],
                        related: vec![CapabilityId::from_static("workspace_events.pull_events")],
                    },
                ),
            ],
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    #[allow(clippy::single_match_else)]
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: "Missing 'operation' field".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));
        self.base.record_request(true);

        match operation {
            "workspace_events.describe_provisioning" => {
                let scope_triggers =
                    parse_string_array_field(&input, "scope_triggers")?.unwrap_or_default();
                let bundle = load_default_google_provisioning_bundle("workspace_events").map_err(
                    |error| FcpError::Internal {
                        message: format!(
                            "Failed to load embedded Workspace Events provisioning bundle: {error}"
                        ),
                    },
                )?;
                let effective_scopes =
                    bundle
                        .scopes_for_triggers(scope_triggers)
                        .map_err(|error| FcpError::InvalidRequest {
                            code: 1003,
                            message: format!(
                                "Invalid Workspace Events scope trigger selection: {error}"
                            ),
                        })?;
                Ok(json!({
                    "bundle": bundle,
                    "effective_scopes": effective_scopes,
                }))
            }
            _ => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                match operation {
                    "workspace_events.list_subscriptions" => {
                        let page_size = optional_u32(&input, "page_size")?;
                        let page_token = optional_str(&input, "page_token");
                        let response = client
                            .list_subscriptions(page_size, page_token)
                            .await
                            .map_err(|e| {
                                self.base.record_request(false);
                                e.to_fcp_error()
                            })?;
                        Ok(json!({
                            "subscriptions": response.subscriptions,
                            "next_page_token": response.next_page_token,
                        }))
                    }
                    "workspace_events.get_subscription" => {
                        let subscription_name = require_str(&input, "subscription_name")?;
                        let subscription = client
                            .get_subscription(subscription_name)
                            .await
                            .map_err(|e| {
                                self.base.record_request(false);
                                e.to_fcp_error()
                            })?;
                        Ok(json!({ "subscription": subscription }))
                    }
                    "workspace_events.create_subscription" => {
                        let target_resource = require_str(&input, "target_resource")?;
                        let event_types = require_string_vec(&input, "event_types")?;
                        let pubsub_topic = require_str(&input, "pubsub_topic")?;
                        let ttl = optional_str(&input, "ttl");
                        let include_resource =
                            optional_bool(&input, "include_resource")?.unwrap_or(false);
                        let field_mask = optional_str(&input, "field_mask");
                        let operation = client
                            .create_subscription(
                                target_resource,
                                &event_types,
                                pubsub_topic,
                                ttl,
                                include_resource,
                                field_mask,
                            )
                            .await
                            .map_err(|e| {
                                self.base.record_request(false);
                                e.to_fcp_error()
                            })?;
                        Ok(json!({ "operation": operation }))
                    }
                    "workspace_events.reactivate_subscription" => {
                        let subscription_name = require_str(&input, "subscription_name")?;
                        let ttl = optional_str(&input, "ttl");
                        let operation = client
                            .reactivate_subscription(subscription_name, ttl)
                            .await
                            .map_err(|e| {
                                self.base.record_request(false);
                                e.to_fcp_error()
                            })?;
                        Ok(json!({ "operation": operation }))
                    }
                    "workspace_events.delete_subscription" => {
                        let subscription_name = require_str(&input, "subscription_name")?;
                        let validate_only =
                            optional_bool(&input, "validate_only")?.unwrap_or(false);
                        let operation = client
                            .delete_subscription(subscription_name, validate_only)
                            .await
                            .map_err(|e| {
                                self.base.record_request(false);
                                e.to_fcp_error()
                            })?;
                        Ok(json!({ "operation": operation }))
                    }
                    "workspace_events.pull_events" => {
                        let pubsub_subscription = require_str(&input, "pubsub_subscription")?;
                        let max_messages = optional_u32(&input, "max_messages")?.unwrap_or(10);
                        let response = client
                            .pull_events(pubsub_subscription, max_messages)
                            .await
                            .map_err(|e| {
                                self.base.record_request(false);
                                e.to_fcp_error()
                            })?;
                        let decoded_events = decode_received_messages(&response.received_messages);
                        Ok(json!({
                            "received_messages": response.received_messages,
                            "decoded_events": decoded_events,
                        }))
                    }
                    "workspace_events.ack_events" => {
                        let pubsub_subscription = require_str(&input, "pubsub_subscription")?;
                        let ack_ids = require_string_vec(&input, "ack_ids")?;
                        let _ = client
                            .ack_events(pubsub_subscription, &ack_ids)
                            .await
                            .map_err(|e| {
                                self.base.record_request(false);
                                e.to_fcp_error()
                            })?;
                        Ok(json!({
                            "status": "acked",
                            "acked_count": ack_ids.len(),
                        }))
                    }
                    _ => Err(FcpError::InvalidRequest {
                        code: 1002,
                        message: format!("Unknown operation: {operation}"),
                    }),
                }
            }
        }
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        Ok(json!({
            "operation": operation,
            "would_execute": true,
            "dry_run": true,
            "streaming": operation == "workspace_events.pull_events" || operation == "workspace_events.ack_events"
        }))
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.client = None;
        info!("Google Workspace Events connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for WorkspaceEventsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Missing '{field}'"),
        })
}

fn optional_str<'a>(input: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    input.get(field).and_then(|v| v.as_str())
}

fn optional_bool(input: &serde_json::Value, field: &str) -> FcpResult<Option<bool>> {
    match input.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Field '{field}' must be a boolean"),
            }),
    }
}

fn optional_u32(input: &serde_json::Value, field: &str) -> FcpResult<Option<u32>> {
    match input.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Field '{field}' must be a non-negative 32-bit integer"),
            }),
    }
}

fn require_string_vec(input: &serde_json::Value, field: &str) -> FcpResult<Vec<String>> {
    let values =
        input
            .get(field)
            .and_then(|v| v.as_array())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Missing '{field}'"),
            })?;
    if values.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("Field '{field}' must not be empty"),
        });
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1001,
                    message: format!("Field '{field}' must contain only strings"),
                })
        })
        .collect()
}

fn decode_received_messages(messages: &[crate::types::ReceivedMessage]) -> Vec<serde_json::Value> {
    messages
        .iter()
        .map(|received| {
            let (decoded_json, decoded_text) = received
                .message
                .as_ref()
                .map_or((None, String::new()), |message| {
                    STANDARD
                        .decode(message.data.as_bytes())
                        .ok()
                        .map_or((None, String::new()), |bytes| {
                            let text = String::from_utf8_lossy(&bytes).to_string();
                            let decoded_json = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
                            (decoded_json, text)
                        })
                });

            json!({
                "ack_id": received.ack_id,
                "delivery_attempt": received.delivery_attempt,
                "message_id": received.message.as_ref().map(|message| message.message_id.clone()),
                "publish_time": received.message.as_ref().map(|message| message.publish_time.clone()),
                "attributes": received.message.as_ref().map(|message| message.attributes.clone()).unwrap_or_default(),
                "decoded_json": decoded_json,
                "decoded_text": if decoded_text.is_empty() { None::<String> } else { Some(decoded_text) },
            })
        })
        .collect()
}

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
        summary: summary.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn health_unconfigured() {
        let connector = WorkspaceEventsConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(connector.handle_health()).unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[test]
    fn configure_uses_default_scope_bundle() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut connector = WorkspaceEventsConnector::new();
            let result = connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured");
            assert_eq!(
                result["required_scopes"][0],
                "https://www.googleapis.com/auth/chat.messages.readonly"
            );
        });
    }

    #[test]
    fn describe_provisioning_returns_workspace_events_bundle() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut connector = WorkspaceEventsConnector::new();
            let result = connector
                .handle_invoke(json!({
                    "operation": "workspace_events.describe_provisioning",
                    "input": {
                        "scope_triggers": ["User selects Chat space metadata events."]
                    }
                }))
                .await
                .unwrap();
            assert_eq!(
                result["bundle"]["surface"]["surface_id"],
                "workspace_events"
            );
            assert!(
                result["effective_scopes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|scope| scope == "https://www.googleapis.com/auth/chat.spaces.readonly")
            );
        });
    }

    #[test]
    fn decode_received_messages_parses_json_payloads() {
        let decoded = decode_received_messages(&[crate::types::ReceivedMessage {
            ack_id: "ack-1".into(),
            message: Some(crate::types::PubsubMessage {
                data: STANDARD.encode(br#"{"event":"created"}"#),
                message_id: "msg-1".into(),
                publish_time: "2026-03-14T18:00:00Z".into(),
                ordering_key: String::new(),
                attributes: std::collections::BTreeMap::new(),
            }),
            delivery_attempt: 1,
        }]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0]["decoded_json"]["event"], "created");
    }

    #[test]
    fn list_subscriptions_uses_workspace_events_endpoint() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v1/subscriptions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "subscriptions": [
                        { "name": "subscriptions/abc", "state": "ACTIVE" }
                    ],
                    "nextPageToken": ""
                })))
                .mount(&server)
                .await;

            let mut connector = WorkspaceEventsConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "events_base_url": format!("{}/v1", server.uri()),
                    "pubsub_base_url": format!("{}/v1", server.uri()),
                }))
                .await
                .unwrap();

            let result = connector
                .handle_invoke(json!({
                    "operation": "workspace_events.list_subscriptions",
                    "input": {}
                }))
                .await
                .unwrap();
            assert_eq!(result["subscriptions"][0]["name"], "subscriptions/abc");
        });
    }

    #[test]
    fn create_subscription_posts_expected_shape() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/subscriptions"))
                .and(body_string_contains("pubsubTopic"))
                .and(body_string_contains(
                    "google.workspace.chat.message.v1.created",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "operations/create-subscription-1",
                    "done": false
                })))
                .mount(&server)
                .await;

            let mut connector = WorkspaceEventsConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "events_base_url": format!("{}/v1", server.uri()),
                    "pubsub_base_url": format!("{}/v1", server.uri()),
                }))
                .await
                .unwrap();

            let result = connector
                .handle_invoke(json!({
                    "operation": "workspace_events.create_subscription",
                    "input": {
                        "target_resource": "//chat.googleapis.com/spaces/AAAA",
                        "event_types": ["google.workspace.chat.message.v1.created"],
                        "pubsub_topic": "projects/demo/topics/workspace-events"
                    }
                }))
                .await
                .unwrap();
            assert_eq!(
                result["operation"]["name"],
                "operations/create-subscription-1"
            );
        });
    }

    #[test]
    fn pull_events_reads_pubsub_delivery_path() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/projects/.+/subscriptions/.+:pull"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "receivedMessages": [
                        {
                            "ackId": "ack-1",
                            "deliveryAttempt": 1,
                            "message": {
                                "data": STANDARD.encode(br#"{"event":"created"}"#),
                                "messageId": "msg-1",
                                "publishTime": "2026-03-14T18:00:00Z"
                            }
                        }
                    ]
                })))
                .mount(&server)
                .await;

            let mut connector = WorkspaceEventsConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "events_base_url": format!("{}/v1", server.uri()),
                    "pubsub_base_url": format!("{}/v1", server.uri()),
                }))
                .await
                .unwrap();

            let result = connector
                .handle_invoke(json!({
                    "operation": "workspace_events.pull_events",
                    "input": {
                        "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                        "max_messages": 5
                    }
                }))
                .await
                .unwrap();
            assert_eq!(result["received_messages"][0]["ackId"], "ack-1");
            assert_eq!(
                result["decoded_events"][0]["decoded_json"]["event"],
                "created"
            );
        });
    }
}
