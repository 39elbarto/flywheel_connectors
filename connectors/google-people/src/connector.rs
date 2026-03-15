//! FCP Google People Connector implementation.

use std::collections::BTreeSet;
use std::sync::Arc;

use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use fcp_google_discovery::{
    ServiceAliasRegistry,
    auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth},
    policy::{GooglePolicyCatalog, PolicyApprovalMode, PolicyRiskLevel, PolicySafetyTier},
    provisioning::load_default_google_provisioning_bundle,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, instrument};

use crate::{
    client::{
        DEFAULT_BASE_URL, GooglePeopleClient, google_auth_is_secretless, google_auth_redacted_label,
    },
    error::GooglePeopleError,
};

const DEFAULT_CONTACT_FIELDS: &[&str] =
    &["names", "emailAddresses", "phoneNumbers", "organizations"];
const DEFAULT_DIRECTORY_FIELDS: &[&str] = &["names", "emailAddresses", "organizations"];
const DEFAULT_GROUP_FIELDS: &[&str] = &["name", "formattedName", "groupType", "memberCount"];

/// Validated configuration for the Google People connector.
struct GooglePeopleConfig {
    auth: GoogleMaterializedAuth,
    base_url: String,
    service_identity: String,
    required_scopes: Vec<String>,
}

impl GooglePeopleConfig {
    async fn from_params(params: &Value) -> FcpResult<Self> {
        let service_selector = params
            .get("service_selector")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("people");
        let service = ServiceAliasRegistry::default()
            .resolve(service_selector)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid service_selector: {error}"),
            })?;
        if service.api_name != "people" || service.api_version != "v1" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "service_selector must resolve to people:v1 (got {})",
                    service.identity()
                ),
            });
        }

        let required_scopes = resolve_people_required_scopes(params)?;
        let mut auth_params = params.clone();
        let auth_object = auth_params
            .as_object_mut()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "configure params must be a JSON object".into(),
            })?;
        auth_object.insert(
            "required_scopes".to_string(),
            json!(required_scopes.clone()),
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

        let base_url = params
            .get("base_url")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self {
            auth,
            base_url,
            service_identity: service.identity(),
            required_scopes,
        })
    }
}

fn parse_string_array_field(params: &Value, field: &str) -> FcpResult<Option<Vec<String>>> {
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

fn parse_string_list_or_csv(input: &Value, field: &str) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    match value {
        Value::String(raw) => {
            let values = raw
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("`{field}` must not be empty"),
                });
            }
            Ok(Some(values))
        }
        Value::Array(_) => parse_string_array_field(input, field),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must be a string or array of strings"),
        }),
    }
}

fn resolve_people_required_scopes(params: &Value) -> FcpResult<Vec<String>> {
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

    let bundle =
        load_default_google_provisioning_bundle("people").map_err(|error| FcpError::Internal {
            message: format!("Failed to load embedded Google People provisioning bundle: {error}"),
        })?;
    bundle
        .scopes_for_triggers(scope_triggers)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid people scope trigger selection: {error}"),
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

fn self_check_report_from_result(result: Result<(), GooglePeopleError>) -> SelfCheckReport {
    match result {
        Ok(()) => SelfCheckReport::ok(),
        Err(error) => {
            if error.is_retryable() {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            } else {
                SelfCheckReport::failed("self_check_failed", error.to_string())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// FCP Google People Connector.
pub struct GooglePeopleConnector {
    base: Arc<BaseConnector>,
    config: Option<GooglePeopleConfig>,
    client: Option<GooglePeopleClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GooglePeopleConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-people",
            ))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = GooglePeopleConfig::from_params(&params).await?;

        let client = GooglePeopleClient::new_with_auth(config.auth.clone())
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to create HTTP client: {error}"),
            })?
            .with_base_url(&config.base_url);

        info!(
            auth = %google_auth_redacted_label(&config.auth),
            service = %config.service_identity,
            "Google People connector configured"
        );

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        let config = self.config.as_ref().expect("config stored after configure");
        Ok(json!({
            "status": "configured",
            "details": {
                "service_identity": config.service_identity,
                "required_scopes": config.required_scopes,
                "auth_mode": google_auth_redacted_label(&config.auth),
                "base_url": config.base_url,
            }
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {error}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:google-people-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize response: {error}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(google_auth_redacted_label(&config.auth));
            health["base_url"] = json!(config.base_url);
            health["service_identity"] = json!(config.service_identity);
            health["required_scopes"] = json!(config.required_scopes);
        }
        Ok(health)
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let mut checks = Vec::new();

        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured – call `configure` first".into(),
            }
        });

        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "HTTP client is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "HTTP client is not initialized".into(),
            }
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Base URL: {}", config.base_url),
            });
            checks.push(DoctorCheck {
                name: "service_identity".into(),
                status: DoctorStatus::Healthy,
                message: format!("Discovery service: {}", config.service_identity),
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", google_auth_redacted_label(&config.auth)),
            });
            checks.push(DoctorCheck {
                name: "required_scopes".into(),
                status: DoctorStatus::Healthy,
                message: format!("Required scopes: {}", config.required_scopes.join(", ")),
            });
        } else {
            for name in [
                "base_url",
                "service_identity",
                "auth_mode",
                "required_scopes",
            ] {
                checks.push(DoctorCheck {
                    name: name.to_string(),
                    status: DoctorStatus::Unhealthy,
                    message: format!("{name} not set (not configured)"),
                });
            }
        }

        let egress_target = self
            .config
            .as_ref()
            .map_or("people.googleapis.com", |config| {
                config
                    .base_url
                    .strip_prefix("https://")
                    .or_else(|| config.base_url.strip_prefix("http://"))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("people.googleapis.com")
            });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: format!("Egress target: {egress_target}"),
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Healthy,
                message: if google_auth_is_secretless(&config.auth) {
                    "Secretless mode – egress proxy will inject credentials".into()
                } else {
                    "Direct token mode – no proxy injection needed".into()
                },
            });
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        let overall = if checks
            .iter()
            .any(|check| check.status == DoctorStatus::Unhealthy)
        {
            DoctorStatus::Unhealthy
        } else if checks
            .iter()
            .any(|check| check.status == DoctorStatus::Degraded)
        {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        serde_json::to_value(DoctorResult {
            status: overall,
            checks,
        })
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {error}"),
        })
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {error}"),
            });
        };

        if let Some(config) = &self.config
            && google_auth_is_secretless(&config.auth)
        {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; egress proxy injection required for checks",
            );
            return serde_json::to_value(report).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {error}"),
            });
        }

        let report = self_check_report_from_result(client.health_check().await);
        serde_json::to_value(report).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {error}"),
        })
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        let policy = load_people_policy_catalog()?;
        let introspection = Introspection {
            operations: vec![
                policy_backed_operation_info(
                    &policy,
                    "people.list_connections",
                    "people.connections.list",
                    "List the authenticated user's contacts",
                    json!({
                        "type": "object",
                        "properties": {
                            "person_fields": { "type": "array", "items": { "type": "string" }, "description": "Explicit People field mask entries to return." },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" },
                            "sort_order": { "type": "string", "description": "People API sort order such as LAST_MODIFIED_ASCENDING." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "connections": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": "string" },
                            "next_sync_token": { "type": "string" }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Enumerate the authenticated user's contact corpus with an explicit field mask.".into(),
                        common_mistakes: vec![
                            "Broad field masks widen privacy exposure; request only the fields you need.".into(),
                        ],
                        examples: vec![
                            r#"{"person_fields":["names","emailAddresses"],"page_size":50}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.profile.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.get_person",
                    "people.get",
                    "Get a single contact or directory person by resource name",
                    json!({
                        "type": "object",
                        "required": ["resource_name"],
                        "properties": {
                            "resource_name": { "type": "string", "description": "Google People resource name such as people/c123. `people/me` is intentionally rejected by this connector." },
                            "person_fields": { "type": "array", "items": { "type": "string" } },
                            "sources": { "type": "array", "items": { "type": "string" }, "description": "Optional People source filters." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "person": { "type": "object" } }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Fetch one People resource when you already have its resource name.".into(),
                        common_mistakes: vec![
                            "This connector intentionally does not expose `people/me` because self-profile reads can require broader personal-profile scopes.".into(),
                        ],
                        examples: vec![
                            r#"{"resource_name":"people/c123","person_fields":["names","emailAddresses"]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.contacts.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.search_contacts",
                    "people.searchContacts",
                    "Search the authenticated user's contacts",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "person_fields": { "type": "array", "items": { "type": "string" } },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "results": { "type": "array", "items": { "type": "object" } } }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Find matching contacts by name, email, or phone fragments.".into(),
                        common_mistakes: vec![
                            "Remember that `person_fields` controls the returned fields, not the search query.".into(),
                        ],
                        examples: vec![
                            r#"{"query":"alice","person_fields":["names","emailAddresses"]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.contacts.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.list_other_contacts",
                    "otherContacts.list",
                    "List Google-suggested other contacts",
                    json!({
                        "type": "object",
                        "properties": {
                            "person_fields": { "type": "array", "items": { "type": "string" } },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "other_contacts": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read the separate Google-suggested Other Contacts corpus after explicitly opting into that data surface.".into(),
                        common_mistakes: vec![
                            "Other Contacts requires its own scope trigger above ordinary contacts.readonly.".into(),
                        ],
                        examples: vec![
                            r#"{"person_fields":["names","emailAddresses"],"page_size":25}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.other_contacts.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.search_directory_people",
                    "people.searchDirectoryPeople",
                    "Search Google Workspace directory people",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "person_fields": { "type": "array", "items": { "type": "string" } },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 500 },
                            "sources": { "type": "array", "items": { "type": "string" }, "description": "Optional directory source filters. Defaults to DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "results": { "type": "array", "items": { "type": "object" } } }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search org-wide directory profiles after explicitly opting into directory.readonly.".into(),
                        common_mistakes: vec![
                            "Directory results are not the same as the user's personal contacts corpus.".into(),
                        ],
                        examples: vec![
                            r#"{"query":"alice","person_fields":["names","emailAddresses","organizations"]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.directory.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.list_contact_groups",
                    "contactGroups.list",
                    "List contact groups",
                    json!({
                        "type": "object",
                        "properties": {
                            "group_fields": { "type": "array", "items": { "type": "string" } },
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "contact_groups": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect contact-group metadata without mutating memberships.".into(),
                        common_mistakes: vec![
                            "Group membership mutation is intentionally out of scope for this first slice.".into(),
                        ],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("people.contact_groups.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.create_contact",
                    "people.createContact",
                    "Create a new contact",
                    json!({
                        "type": "object",
                        "required": ["person"],
                        "properties": {
                            "person": { "type": "object", "description": "Raw People person payload containing the contact fields to create." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "person": { "type": "object" } }
                    }),
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a durable contact entry after explicitly opting into contacts write scope.".into(),
                        common_mistakes: vec![
                            "Do not rely on hidden defaults; provide the actual People fields you intend to write.".into(),
                        ],
                        examples: vec![
                            r#"{"person":{"names":[{"givenName":"Alice","familyName":"Ng"}],"emailAddresses":[{"value":"alice@example.com"}]}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.contacts.write")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.update_contact",
                    "people.updateContact",
                    "Update an existing contact with explicit field-mask semantics",
                    json!({
                        "type": "object",
                        "required": ["resource_name", "person"],
                        "properties": {
                            "resource_name": { "type": "string" },
                            "person": { "type": "object", "description": "Raw People person payload. Must include `etag`." },
                            "update_person_fields": { "type": "array", "items": { "type": "string" }, "description": "Optional explicit update field mask. If omitted, the connector derives it from non-empty top-level keys in `person`." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "person": { "type": "object" } }
                    }),
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Patch a contact while keeping the updated field mask explicit.".into(),
                        common_mistakes: vec![
                            "People updateContact expects an `etag`; omitting it turns a safe concurrency check into a confusing API failure.".into(),
                        ],
                        examples: vec![
                            r#"{"resource_name":"people/c123","person":{"etag":"%EgUBAQMEBQY=","emailAddresses":[{"value":"alice@example.com"}]}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("people.contacts.write")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "people.delete_contact",
                    "people.deleteContact",
                    "Delete an existing contact",
                    json!({
                        "type": "object",
                        "required": ["resource_name"],
                        "properties": {
                            "resource_name": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "deleted": { "type": "boolean" } }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete a contact after explicit interactive approval.".into(),
                        common_mistakes: vec![
                            "Deletion is irreversible; confirm you are targeting the correct People resource name before calling.".into(),
                        ],
                        examples: vec![r#"{"resource_name":"people/c123"}"#.into()],
                        related: vec![CapabilityId::from_static("people.contacts.delete")],
                    },
                )?,
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize introspection: {error}"),
        })
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {error}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize response: {error}"),
        })
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(&self, params: Value) -> FcpResult<Value> {
        let operation =
            params
                .get("operation")
                .and_then(Value::as_str)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;
        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|error| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid capability_token format: {error}"),
                }
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let introspection = self.handle_introspect().await?;
        let cap_str = introspection
            .get("operations")
            .and_then(Value::as_array)
            .and_then(|ops| {
                ops.iter()
                    .find(|op| op.get("id").and_then(Value::as_str) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;
        let cap_id =
            CapabilityId::new(cap_str.to_string()).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid capability ID format".into(),
            })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "people.list_connections" => self.invoke_list_connections(input).await,
            "people.get_person" => self.invoke_get_person(input).await,
            "people.search_contacts" => self.invoke_search_contacts(input).await,
            "people.list_other_contacts" => self.invoke_list_other_contacts(input).await,
            "people.search_directory_people" => self.invoke_search_directory_people(input).await,
            "people.list_contact_groups" => self.invoke_list_contact_groups(input).await,
            "people.create_contact" => self.invoke_create_contact(input).await,
            "people.update_contact" => self.invoke_update_contact(input).await,
            "people.delete_contact" => self.invoke_delete_contact(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_list_connections(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_CONTACT_FIELDS)?;
        let page_size = parse_u32_field(&input, "page_size")?;
        let page_token = input.get("page_token").and_then(Value::as_str);
        let sort_order = input.get("sort_order").and_then(Value::as_str);

        let response = client
            .list_connections(&person_fields, page_size, page_token, sort_order)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!(response))
    }

    async fn invoke_get_person(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resource_name = require_str(&input, "resource_name")?;
        if resource_name == "people/me" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "`people/me` is intentionally not exposed by this connector; request a concrete contact or directory resource instead".into(),
            });
        }

        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_CONTACT_FIELDS)?;
        let sources = parse_string_list_or_csv(&input, "sources")?.unwrap_or_default();
        let person = client
            .get_person(resource_name, &person_fields, &sources)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "person": person }))
    }

    async fn invoke_search_contacts(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_CONTACT_FIELDS)?;
        let page_size = parse_u32_field(&input, "page_size")?;

        let response = client
            .search_contacts(query, &person_fields, page_size)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!(response))
    }

    async fn invoke_list_other_contacts(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_CONTACT_FIELDS)?;
        let page_size = parse_u32_field(&input, "page_size")?;
        let page_token = input.get("page_token").and_then(Value::as_str);

        let response = client
            .list_other_contacts(&person_fields, page_size, page_token)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!(response))
    }

    async fn invoke_search_directory_people(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let person_fields =
            field_list_with_default(&input, "person_fields", DEFAULT_DIRECTORY_FIELDS)?;
        let page_size = parse_u32_field(&input, "page_size")?;
        let sources = parse_string_list_or_csv(&input, "sources")?
            .unwrap_or_else(|| vec!["DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE".to_string()]);

        let response = client
            .search_directory_people(query, &person_fields, page_size, &sources)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!(response))
    }

    async fn invoke_list_contact_groups(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let group_fields = field_list_with_default(&input, "group_fields", DEFAULT_GROUP_FIELDS)?;
        let page_size = parse_u32_field(&input, "page_size")?;
        let page_token = input.get("page_token").and_then(Value::as_str);

        let response = client
            .list_contact_groups(&group_fields, page_size, page_token)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!(response))
    }

    async fn invoke_create_contact(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let person = input.get("person").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: person".into(),
        })?;
        if !person.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "`person` must be a JSON object".into(),
            });
        }

        let created = client
            .create_contact(person)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "person": created }))
    }

    async fn invoke_update_contact(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resource_name = require_str(&input, "resource_name")?;
        let mut person = input
            .get("person")
            .cloned()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: person".into(),
            })?;
        let person_object = person.as_object_mut().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "`person` must be a JSON object".into(),
        })?;

        if let Some(existing) = person_object.get("resourceName").and_then(Value::as_str)
            && existing != resource_name
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "`resource_name` must match `person.resourceName` when both are supplied"
                    .into(),
            });
        }
        person_object.insert("resourceName".to_string(), json!(resource_name));

        if person_object.get("etag").and_then(Value::as_str).is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "`person.etag` is required for update_contact to keep People API concurrency semantics explicit".into(),
            });
        }

        let update_person_fields = parse_string_list_or_csv(&input, "update_person_fields")?
            .unwrap_or_else(|| derive_update_person_fields(&person).unwrap_or_default());
        if update_person_fields.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "update_contact requires at least one non-empty mutable field or an explicit `update_person_fields` list".into(),
            });
        }

        let updated = client
            .update_contact(resource_name, &update_person_fields, &person)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "person": updated }))
    }

    async fn invoke_delete_contact(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resource_name = require_str(&input, "resource_name")?;
        client
            .delete_contact(resource_name)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "deleted": true }))
    }

    pub async fn handle_shutdown(&self, _params: Value) -> FcpResult<Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Google People connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GooglePeopleConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn load_people_policy_catalog() -> FcpResult<GooglePolicyCatalog> {
    GooglePolicyCatalog::load_default().map_err(|error| FcpError::Internal {
        message: format!("Failed to load embedded Google policy catalog: {error}"),
    })
}

fn policy_backed_operation_info(
    policy: &GooglePolicyCatalog,
    operation_id: &'static str,
    discovery_method_key: &'static str,
    summary: &str,
    input_schema: Value,
    output_schema: Value,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> FcpResult<OperationInfo> {
    let resolved = policy
        .classify_operation("people", discovery_method_key)
        .ok_or(FcpError::Internal {
            message: format!("Missing People policy mapping for `{discovery_method_key}`"),
        })?;
    let capability = CapabilityId::new(resolved.rule.capability.clone()).map_err(|error| {
        FcpError::Internal {
            message: format!(
                "Invalid capability `{}` in Google People policy catalog: {error}",
                resolved.rule.capability
            ),
        }
    })?;

    Ok(OperationInfo {
        id: OperationId::from_static(operation_id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability,
        risk_level: map_policy_risk_level(resolved.rule.risk_level),
        description: None,
        rate_limit: None,
        requires_approval: map_policy_approval_mode(resolved.rule.approval_mode),
        safety_tier: map_policy_safety_tier(resolved.rule.safety_tier),
        idempotency,
        ai_hints,
    })
}

const fn map_policy_risk_level(level: PolicyRiskLevel) -> RiskLevel {
    match level {
        PolicyRiskLevel::Low => RiskLevel::Low,
        PolicyRiskLevel::Medium => RiskLevel::Medium,
        PolicyRiskLevel::High => RiskLevel::High,
        PolicyRiskLevel::Critical => RiskLevel::Critical,
    }
}

const fn map_policy_safety_tier(tier: PolicySafetyTier) -> SafetyTier {
    match tier {
        PolicySafetyTier::Safe => SafetyTier::Safe,
        PolicySafetyTier::Risky => SafetyTier::Risky,
        PolicySafetyTier::Dangerous => SafetyTier::Dangerous,
        PolicySafetyTier::Critical => SafetyTier::Critical,
        PolicySafetyTier::Forbidden => SafetyTier::Forbidden,
    }
}

const fn map_policy_approval_mode(mode: PolicyApprovalMode) -> Option<ApprovalMode> {
    match mode {
        PolicyApprovalMode::None => None,
        PolicyApprovalMode::Policy => Some(ApprovalMode::Policy),
        PolicyApprovalMode::Interactive => Some(ApprovalMode::Interactive),
        PolicyApprovalMode::ElevationToken => Some(ApprovalMode::ElevationToken),
    }
}

fn require_str<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn parse_u32_field(input: &Value, field: &str) -> FcpResult<Option<u32>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let raw = value.as_u64().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("`{field}` must be a positive integer"),
    })?;
    u32::try_from(raw)
        .map(Some)
        .map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` is out of range for Google People API"),
        })
}

fn field_list_with_default(
    input: &Value,
    field: &str,
    default_fields: &[&str],
) -> FcpResult<Vec<String>> {
    Ok(parse_string_list_or_csv(input, field)?.unwrap_or_else(|| {
        default_fields
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    }))
}

fn derive_update_person_fields(person: &Value) -> FcpResult<Vec<String>> {
    let person_object = person.as_object().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "`person` must be a JSON object".into(),
    })?;
    let candidates = [
        "addresses",
        "biographies",
        "emailAddresses",
        "memberships",
        "names",
        "organizations",
        "phoneNumbers",
    ];
    let mut fields = Vec::new();
    for key in candidates {
        if person_object
            .get(key)
            .is_some_and(value_has_meaningful_content)
        {
            fields.push(key.to_string());
        }
    }
    Ok(fields)
}

fn value_has_meaningful_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(raw) => !raw.trim().is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => !object.is_empty(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_google_discovery::{
        DiscoveryEndpointKind, DiscoveryServiceId, generator::generate_google_service_artifacts,
        normalize_snapshot_bytes,
    };

    #[test]
    fn resolve_people_required_scopes_defaults_to_contacts_readonly() {
        let scopes = resolve_people_required_scopes(&json!({})).unwrap();
        assert_eq!(
            scopes,
            vec!["https://www.googleapis.com/auth/contacts.readonly".to_string()]
        );
    }

    #[test]
    fn resolve_people_required_scopes_applies_scope_triggers() {
        let scopes = resolve_people_required_scopes(&json!({
            "scope_triggers": [
                "User enables contact create, update, photo update, or group-membership mutation workflows.",
                "User enables Google Workspace directory search or lookup workflows."
            ]
        }))
        .unwrap();
        assert!(scopes.contains(&"https://www.googleapis.com/auth/contacts.readonly".to_string()));
        assert!(scopes.contains(&"https://www.googleapis.com/auth/contacts".to_string()));
        assert!(scopes.contains(&"https://www.googleapis.com/auth/directory.readonly".to_string()));
    }

    #[test]
    fn resolve_people_required_scopes_rejects_mixed_inputs() {
        let error = resolve_people_required_scopes(&json!({
            "required_scopes": ["https://www.googleapis.com/auth/contacts.readonly"],
            "scope_triggers": ["User enables reads from Google-suggested other contacts."]
        }))
        .unwrap_err();
        match error {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Provide either `required_scopes` or `scope_triggers`"));
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_service_selector_alias_contacts() {
        let mut connector = GooglePeopleConnector::new();
        let response = connector
            .handle_configure(json!({
                "access_token": "ya29.test-token",
                "service_selector": "contacts"
            }))
            .await
            .unwrap();
        assert_eq!(response["details"]["service_identity"], json!("people:v1"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_service_selector() {
        let mut connector = GooglePeopleConnector::new();
        let error = connector
            .handle_configure(json!({
                "access_token": "ya29.test-token",
                "service_selector": "gmail"
            }))
            .await
            .unwrap_err();
        match error {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("service_selector"));
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_exposes_policy_backed_approval_modes() {
        let connector = GooglePeopleConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let operations = result["operations"].as_array().unwrap();

        let list_connections = operations
            .iter()
            .find(|op| op["id"] == "people.list_connections")
            .unwrap();
        let delete_contact = operations
            .iter()
            .find(|op| op["id"] == "people.delete_contact")
            .unwrap();

        assert_eq!(list_connections["capability"], "people.contacts.read");
        assert_eq!(list_connections["requires_approval"], "policy");
        assert_eq!(delete_contact["capability"], "people.contacts.delete");
        assert_eq!(delete_contact["requires_approval"], "interactive");
    }

    #[test]
    fn derive_update_person_fields_requires_mutated_keys() {
        let fields = derive_update_person_fields(&json!({
            "etag": "%EgUBAQMEBQY=",
            "names": [{"givenName": "Alice"}],
            "emailAddresses": [{"value": "alice@example.com"}]
        }))
        .unwrap();
        assert_eq!(
            fields,
            vec!["emailAddresses".to_string(), "names".to_string()]
        );
    }

    #[test]
    fn people_generated_operations_cover_core_connector_surface() {
        let service = DiscoveryServiceId::new("people", "v1").unwrap();
        let discovery_json = json!({
            "name": "people",
            "version": "v1",
            "rootUrl": "https://people.googleapis.com/",
            "servicePath": "",
            "auth": {
                "oauth2": {
                    "scopes": {
                        "https://www.googleapis.com/auth/contacts": { "description": "contacts" },
                        "https://www.googleapis.com/auth/contacts.readonly": { "description": "contacts readonly" },
                        "https://www.googleapis.com/auth/contacts.other.readonly": { "description": "other contacts readonly" },
                        "https://www.googleapis.com/auth/directory.readonly": { "description": "directory readonly" }
                    }
                }
            },
            "resources": {
                "people": {
                    "methods": {
                        "get": { "path": "v1/{+resourceName}", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.readonly"] },
                        "searchContacts": { "path": "v1/people:searchContacts", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.readonly"] },
                        "searchDirectoryPeople": { "path": "v1/people:searchDirectoryPeople", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/directory.readonly"] },
                        "createContact": { "path": "v1/people:createContact", "httpMethod": "POST", "scopes": ["https://www.googleapis.com/auth/contacts"] },
                        "updateContact": { "path": "v1/{+resourceName}:updateContact", "httpMethod": "PATCH", "scopes": ["https://www.googleapis.com/auth/contacts"] },
                        "deleteContact": { "path": "v1/{+resourceName}:deleteContact", "httpMethod": "DELETE", "scopes": ["https://www.googleapis.com/auth/contacts"] }
                    },
                    "resources": {
                        "connections": {
                            "methods": {
                                "list": { "path": "v1/people/me/connections", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.readonly"] }
                            }
                        }
                    }
                },
                "otherContacts": {
                    "methods": {
                        "list": { "path": "v1/otherContacts", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.other.readonly"] }
                    }
                },
                "contactGroups": {
                    "methods": {
                        "list": { "path": "v1/contactGroups", "httpMethod": "GET", "scopes": ["https://www.googleapis.com/auth/contacts.readonly"] }
                    }
                }
            }
        });

        let snapshot = normalize_snapshot_bytes(
            &service,
            serde_json::to_vec(&discovery_json).unwrap().as_slice(),
            DiscoveryEndpointKind::Alternate,
            "https://example.test/people",
        )
        .unwrap()
        .snapshot;
        let policy = GooglePolicyCatalog::load_default().unwrap();
        let generated = generate_google_service_artifacts(&snapshot, &policy).unwrap();

        let connections = generated
            .manifest_fragment
            .operations
            .iter()
            .find(|op| op.operation_id == "people.people.connections.list")
            .unwrap();
        let delete_contact = generated
            .manifest_fragment
            .operations
            .iter()
            .find(|op| op.operation_id == "people.people.delete_contact")
            .unwrap();
        let groups = generated
            .manifest_fragment
            .operations
            .iter()
            .find(|op| op.operation_id == "people.contact_groups.list")
            .unwrap();

        assert_eq!(connections.capability, "people.contacts.read");
        assert_eq!(delete_contact.capability, "people.contacts.delete");
        assert_eq!(
            delete_contact.approval_mode,
            Some(ApprovalMode::Interactive)
        );
        assert_eq!(groups.capability, "people.contact_groups.read");
    }
}
