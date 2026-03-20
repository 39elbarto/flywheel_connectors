//! FCP `Firebase` connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
};
use fcp_google_discovery::auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, instrument};

use crate::{
    client::{
        DEFAULT_FIRESTORE_BASE_URL, FirebaseClient, firebase_auth_is_secretless,
        firebase_auth_redacted_label,
    },
    error::FirebaseError,
    types::{
        FirestoreBatchWriteRequest, FirestoreCreateRequest, FirestoreDeleteRequest,
        FirestoreGetRequest, FirestoreListRequest, FirestoreQueryRequest, FirestoreUpdateRequest,
        RealtimeDeleteRequest, RealtimeGetRequest, RealtimeSetRequest,
    },
};

const FIRESTORE_GET_OP: &str = "firebase.firestore.get";
const FIRESTORE_LIST_OP: &str = "firebase.firestore.list";
const FIRESTORE_CREATE_OP: &str = "firebase.firestore.create";
const FIRESTORE_UPDATE_OP: &str = "firebase.firestore.update";
const FIRESTORE_DELETE_OP: &str = "firebase.firestore.delete";
const FIRESTORE_QUERY_OP: &str = "firebase.firestore.query";
const FIRESTORE_BATCH_WRITE_OP: &str = "firebase.firestore.batch_write";
const RTDB_GET_OP: &str = "firebase.rtdb.get";
const RTDB_SET_OP: &str = "firebase.rtdb.set";
const RTDB_DELETE_OP: &str = "firebase.rtdb.delete";
const HEALTH_OP: &str = "firebase.health";

const FIREBASE_READ_CAPABILITY: &str = "firebase.read";
const FIREBASE_WRITE_CAPABILITY: &str = "firebase.write";

/// Validated Firebase connector configuration.
#[derive(Debug, Clone)]
struct FirebaseConfig {
    auth: GoogleMaterializedAuth,
    project_id: String,
    database_id: String,
    firestore_base_url: String,
    realtime_database_url: String,
    request_timeout_ms: u64,
    required_scopes: Vec<String>,
}

impl FirebaseConfig {
    async fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let project_id = required_string_field(params, "project_id")?;
        let database_id = optional_string_field(params, "database_id")
            .unwrap_or("(default)")
            .to_string();
        let firestore_base_url = optional_string_field(params, "firestore_base_url")
            .unwrap_or(DEFAULT_FIRESTORE_BASE_URL)
            .to_string();
        let realtime_database_url = optional_string_field(params, "realtime_database_url")
            .map_or_else(|| default_realtime_database_url(project_id), str::to_string);
        let request_timeout_ms = params
            .get("request_timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(30_000);
        if request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }

        let required_scopes = parse_string_array_field(params, "required_scopes")?
            .unwrap_or_else(default_required_scopes);
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

        Ok(Self {
            auth,
            project_id: project_id.to_string(),
            database_id,
            firestore_base_url,
            realtime_database_url,
            request_timeout_ms,
            required_scopes,
        })
    }
}

/// Doctor result returned by the `doctor` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Connector readiness state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Single doctor check entry.
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
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP `Firebase` connector.
pub struct FirebaseConnector {
    base: Arc<BaseConnector>,
    config: Option<FirebaseConfig>,
    client: Option<Arc<FirebaseClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl FirebaseConnector {
    /// Create a new Firebase connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.firebase"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for FirebaseConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl FirebaseConnector {
    /// Handle the `configure` method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = FirebaseConfig::from_params(&params).await?;
        info!(
            auth = %firebase_auth_redacted_label(&config.auth),
            project_id = %config.project_id,
            database_id = %config.database_id,
            firestore_base_url = %config.firestore_base_url,
            realtime_database_url = %config.realtime_database_url,
            "Configuring Firebase connector"
        );

        let client = FirebaseClient::new(
            config.auth.clone(),
            &config.project_id,
            &config.database_id,
            &config.firestore_base_url,
            &config.realtime_database_url,
            config.request_timeout_ms,
        )
        .map_err(|error| error.to_fcp_error())?;

        let status = if firebase_auth_is_secretless(&config.auth) {
            "pending_credentials"
        } else {
            "configured"
        };
        let result = json!({
            "status": status,
            "details": {
                "project_id": config.project_id,
                "database_id": config.database_id,
                "auth_mode": firebase_auth_redacted_label(&config.auth),
                "required_scopes": config.required_scopes,
                "firestore_base_url": config.firestore_base_url,
                "realtime_database_url": config.realtime_database_url,
            }
        });

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);

        Ok(result)
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

        self.session_id = params
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.firebase",
            "connector_version": "0.1.0",
            "capabilities": [
                FIREBASE_READ_CAPABILITY,
                FIREBASE_WRITE_CAPABILITY,
            ]
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
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: self
                .config
                .as_ref()
                .map(|config| format!("Configured for Firebase project {}", config.project_id))
                .or_else(|| Some("Not configured — call configure first".into())),
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                None
            } else {
                Some("Firebase client not initialized".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: self.session_id.is_some(),
            message: if self.session_id.is_some() {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "firestore_host_policy".into(),
                passed: host_is_allowed(&config.firestore_base_url, &["firestore.googleapis.com"]),
                message: Some(format!("Firestore base URL: {}", config.firestore_base_url)),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "realtime_database_host_policy".into(),
                passed: host_is_allowed_suffix(
                    &config.realtime_database_url,
                    &["firebaseio.com", "firebasedatabase.app"],
                ),
                message: Some(format!(
                    "Realtime Database URL: {}",
                    config.realtime_database_url
                )),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                passed: !firebase_auth_is_secretless(&config.auth),
                message: Some(if firebase_auth_is_secretless(&config.auth) {
                    "Configured with credential_id; egress proxy injection required".into()
                } else {
                    format!(
                        "Using Google auth mode {}",
                        firebase_auth_redacted_label(&config.auth)
                    )
                }),
                critical: false,
            });
        }

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({ "status": "error" })))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let report = match (&self.config, &self.client) {
            (None, _) | (_, None) => {
                SelfCheckReport::failed("not_configured", "Connector is not configured yet")
            }
            (Some(config), Some(_)) if firebase_auth_is_secretless(&config.auth) => {
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; live checks require egress proxy token materialization",
                )
            }
            (_, Some(client)) => match client.health().await {
                Ok(_) => SelfCheckReport::ok(),
                Err(error) => {
                    if error.is_retryable() {
                        SelfCheckReport::degraded("self_check_retryable", error.to_string())
                    } else {
                        SelfCheckReport::failed("self_check_failed", error.to_string())
                    }
                }
            },
        };

        serde_json::to_value(report).map_err(|error| FcpError::Internal {
            message: error.to_string(),
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let operations = typed_operations_info();
        Ok(json!({
            "connector_id": "fcp.firebase",
            "version": "0.1.0",
            "operations": serde_json::to_value(&operations).unwrap_or_default(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(Value::as_str)
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
            FIRESTORE_GET_OP => self.invoke_firestore_get(client, &input).await,
            FIRESTORE_LIST_OP => self.invoke_firestore_list(client, &input).await,
            FIRESTORE_CREATE_OP => self.invoke_firestore_create(client, &input).await,
            FIRESTORE_UPDATE_OP => self.invoke_firestore_update(client, &input).await,
            FIRESTORE_DELETE_OP => self.invoke_firestore_delete(client, &input).await,
            FIRESTORE_QUERY_OP => self.invoke_firestore_query(client, &input).await,
            FIRESTORE_BATCH_WRITE_OP => self.invoke_firestore_batch_write(client, &input).await,
            RTDB_GET_OP => self.invoke_rtdb_get(client, &input).await,
            RTDB_SET_OP => self.invoke_rtdb_set(client, &input).await,
            RTDB_DELETE_OP => self.invoke_rtdb_delete(client, &input).await,
            HEALTH_OP => self.invoke_health(client).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|error| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            error.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or("");

        let allowed = typed_operations_info()
            .iter()
            .any(|entry| entry.id.as_str() == operation);

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
        info!("Firebase connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    async fn invoke_firestore_get(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: FirestoreGetRequest = serde_json::from_value(input.clone())?;
        let result = client.firestore_get(&request).await?;
        serde_json::to_value(result).map_err(FirebaseError::Json)
    }

    async fn invoke_firestore_list(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: FirestoreListRequest = serde_json::from_value(input.clone())?;
        let result = client.firestore_list(&request).await?;
        serde_json::to_value(result).map_err(FirebaseError::Json)
    }

    async fn invoke_firestore_create(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: FirestoreCreateRequest = serde_json::from_value(input.clone())?;
        let result = client.firestore_create(&request).await?;
        serde_json::to_value(result).map_err(FirebaseError::Json)
    }

    async fn invoke_firestore_update(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: FirestoreUpdateRequest = serde_json::from_value(input.clone())?;
        let result = client.firestore_update(&request).await?;
        serde_json::to_value(result).map_err(FirebaseError::Json)
    }

    async fn invoke_firestore_delete(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: FirestoreDeleteRequest = serde_json::from_value(input.clone())?;
        client.firestore_delete(&request).await
    }

    async fn invoke_firestore_query(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: FirestoreQueryRequest = serde_json::from_value(input.clone())?;
        let result = client.firestore_query(&request).await?;
        serde_json::to_value(result).map_err(FirebaseError::Json)
    }

    async fn invoke_firestore_batch_write(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: FirestoreBatchWriteRequest = serde_json::from_value(input.clone())?;
        client.firestore_batch_write(&request).await
    }

    async fn invoke_rtdb_get(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: RealtimeGetRequest = serde_json::from_value(input.clone())?;
        let result = client.rtdb_get(&request).await?;
        Ok(json!({ "data": result }))
    }

    async fn invoke_rtdb_set(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: RealtimeSetRequest = serde_json::from_value(input.clone())?;
        let result = client.rtdb_set(&request).await?;
        Ok(json!({ "data": result }))
    }

    async fn invoke_rtdb_delete(
        &self,
        client: &FirebaseClient,
        input: &Value,
    ) -> Result<Value, FirebaseError> {
        let request: RealtimeDeleteRequest = serde_json::from_value(input.clone())?;
        let result = client.rtdb_delete(&request).await?;
        Ok(json!({ "data": result }))
    }

    async fn invoke_health(&self, client: &FirebaseClient) -> Result<Value, FirebaseError> {
        let result = client.health().await?;
        Ok(json!({ "health": result }))
    }
}

fn required_string_field<'a>(params: &'a Value, field: &str) -> FcpResult<&'a str> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing {field} in configuration"),
        })
}

fn optional_string_field<'a>(params: &'a Value, field: &str) -> Option<&'a str> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_string_array_field(params: &Value, field: &str) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };
    let values = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an array of strings"),
    })?;

    let mut parsed = Vec::new();
    for value in values {
        let item = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must contain only strings"),
        })?;
        let item = item.trim();
        if item.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} entries must not be empty"),
            });
        }
        parsed.push(item.to_string());
    }

    Ok(Some(parsed))
}

fn default_required_scopes() -> Vec<String> {
    vec![
        "https://www.googleapis.com/auth/datastore".into(),
        "https://www.googleapis.com/auth/firebase.database".into(),
    ]
}

fn default_realtime_database_url(project_id: &str) -> String {
    format!("https://{project_id}.firebaseio.com")
}

fn host_is_allowed(url: &str, hosts: &[&str]) -> bool {
    reqwest::Url::parse(url).ok().is_some_and(|parsed| {
        parsed.scheme() == "https" && parsed.host_str().is_some_and(|host| hosts.contains(&host))
    })
}

fn host_is_allowed_suffix(url: &str, suffixes: &[&str]) -> bool {
    reqwest::Url::parse(url).ok().is_some_and(|parsed| {
        parsed.scheme() == "https"
            && parsed.host_str().is_some_and(|host| {
                suffixes
                    .iter()
                    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
            })
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

#[allow(clippy::too_many_lines)]
fn typed_operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(FIRESTORE_GET_OP),
            summary: "Get a Firestore document".into(),
            description: Some("Reads one document from the configured Firestore database.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["document_path"],
                "properties": {
                    "document_path": { "type": "string" },
                    "mask": { "type": "array", "items": { "type": "string" } }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_READ_CAPABILITY),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Read one Firestore document by relative path.".into(),
                common_mistakes: vec!["Using a collection path instead of a document path.".into()],
                examples: vec![r#"{"document_path":"users/alice"}"#.into()],
                related: vec![CapabilityId::from_static(FIRESTORE_LIST_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(FIRESTORE_LIST_OP),
            summary: "List Firestore documents in a collection".into(),
            description: Some("Enumerates documents under a relative collection path.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection_path"],
                "properties": {
                    "collection_path": { "type": "string" },
                    "page_size": { "type": "integer" },
                    "page_token": { "type": "string" },
                    "order_by": { "type": "string" },
                    "show_missing": { "type": "boolean" },
                    "mask": { "type": "array", "items": { "type": "string" } }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_READ_CAPABILITY),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Browse Firestore documents under a collection path.".into(),
                common_mistakes: vec!["Passing a document path instead of a collection path.".into()],
                examples: vec![r#"{"collection_path":"rooms/alpha/messages","page_size":25}"#.into()],
                related: vec![CapabilityId::from_static(FIRESTORE_GET_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(FIRESTORE_CREATE_OP),
            summary: "Create a Firestore document".into(),
            description: Some("Creates a document under a Firestore collection.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection_path", "document"],
                "properties": {
                    "collection_path": { "type": "string" },
                    "document_id": { "type": "string" },
                    "document": { "type": "object" },
                    "mask": { "type": "array", "items": { "type": "string" } }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_WRITE_CAPABILITY),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Create a new Firestore document under a collection.".into(),
                common_mistakes: vec!["Sending a non-object Firestore document payload.".into()],
                examples: vec![r#"{"collection_path":"users","document_id":"alice","document":{"displayName":"Alice"}}"#.into()],
                related: vec![CapabilityId::from_static(FIRESTORE_UPDATE_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(FIRESTORE_UPDATE_OP),
            summary: "Update a Firestore document".into(),
            description: Some("Patches a Firestore document with an update mask.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["document_path", "document"],
                "properties": {
                    "document_path": { "type": "string" },
                    "document": { "type": "object" },
                    "update_mask": { "type": "array", "items": { "type": "string" } },
                    "mask": { "type": "array", "items": { "type": "string" } },
                    "current_exists": { "type": "boolean" },
                    "current_update_time": { "type": "string" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_WRITE_CAPABILITY),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Patch a Firestore document with explicit field paths.".into(),
                common_mistakes: vec!["Using a collection path instead of a document path.".into()],
                examples: vec![r#"{"document_path":"users/alice","document":{"displayName":"Alice A."},"update_mask":["displayName"]}"#.into()],
                related: vec![CapabilityId::from_static(FIRESTORE_CREATE_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(FIRESTORE_DELETE_OP),
            summary: "Delete a Firestore document".into(),
            description: Some("Permanently deletes one Firestore document.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["document_path"],
                "properties": {
                    "document_path": { "type": "string" },
                    "current_exists": { "type": "boolean" },
                    "current_update_time": { "type": "string" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_WRITE_CAPABILITY),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use only for intentional Firestore document deletion.".into(),
                common_mistakes: vec!["Passing a collection path, which Firestore will reject.".into()],
                examples: vec![r#"{"document_path":"users/alice"}"#.into()],
                related: vec![CapabilityId::from_static(FIRESTORE_GET_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(FIRESTORE_QUERY_OP),
            summary: "Run a Firestore structured query".into(),
            description: Some("Executes a Firestore `structuredQuery` payload.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["structured_query"],
                "properties": {
                    "parent_path": { "type": "string" },
                    "structured_query": { "type": "object" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_READ_CAPABILITY),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use for Firestore server-side filtering and ordering beyond collection listing.".into(),
                common_mistakes: vec!["Supplying query JSON under the wrong top-level key; pass only structured_query.".into()],
                examples: vec![r#"{"structured_query":{"from":[{"collectionId":"users"}]}}"#.into()],
                related: vec![CapabilityId::from_static(FIRESTORE_LIST_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(FIRESTORE_BATCH_WRITE_OP),
            summary: "Execute a Firestore batch write".into(),
            description: Some("Sends raw Firestore write operations to `documents:batchWrite`.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["writes"],
                "properties": {
                    "writes": { "type": "array" },
                    "labels": { "type": "object" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_WRITE_CAPABILITY),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Apply multiple Firestore writes when per-write status visibility matters.".into(),
                common_mistakes: vec!["Including more than one write for the same document in a batch.".into()],
                examples: vec![r#"{"writes":[{"delete":"projects/demo/databases/(default)/documents/users/alice"}]}"#.into()],
                related: vec![CapabilityId::from_static(FIRESTORE_UPDATE_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(RTDB_GET_OP),
            summary: "Read from Realtime Database".into(),
            description: Some("Fetches JSON from the configured Realtime Database instance.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "order_by": { "type": "string" },
                    "start_at": {},
                    "end_at": {},
                    "equal_to": {},
                    "limit_to_first": { "type": "integer" },
                    "limit_to_last": { "type": "integer" },
                    "shallow": { "type": "boolean" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_READ_CAPABILITY),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Read JSON data from Realtime Database, optionally with server-side query params.".into(),
                common_mistakes: vec!["Forgetting that order_by must target an indexed child or special key.".into()],
                examples: vec![r#"{"path":"presence/alice"}"#.into()],
                related: vec![CapabilityId::from_static(RTDB_SET_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(RTDB_SET_OP),
            summary: "Write a value into Realtime Database".into(),
            description: Some("Replaces the JSON value at a Realtime Database path.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["path", "value"],
                "properties": {
                    "path": { "type": "string" },
                    "value": {},
                    "silent": { "type": "boolean" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_WRITE_CAPABILITY),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Replace a JSON subtree in Realtime Database.".into(),
                common_mistakes: vec!["Overwriting a whole subtree when a narrower path was intended.".into()],
                examples: vec![r#"{"path":"presence/alice","value":{"online":true}}"#.into()],
                related: vec![CapabilityId::from_static(RTDB_GET_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(RTDB_DELETE_OP),
            summary: "Delete a value from Realtime Database".into(),
            description: Some("Removes the JSON value at a Realtime Database path.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" },
                    "silent": { "type": "boolean" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_WRITE_CAPABILITY),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Delete a JSON subtree from Realtime Database.".into(),
                common_mistakes: vec!["Deleting a parent path that contains more data than intended.".into()],
                examples: vec![r#"{"path":"presence/alice"}"#.into()],
                related: vec![CapabilityId::from_static(RTDB_GET_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(HEALTH_OP),
            summary: "Fetch Firebase database metadata".into(),
            description: Some("Checks Firestore reachability by reading database metadata.".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(FIREBASE_READ_CAPABILITY),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Verify that the configured Firebase project and Firestore database are reachable.".into(),
                common_mistakes: vec!["Assuming a successful health check proves every Firestore collection or RTDB rule is accessible.".into()],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(FIRESTORE_GET_OP)],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

fn operations_info() -> serde_json::Value {
    serde_json::to_value(typed_operations_info()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_access_token() {
        let mut connector = FirebaseConnector::new();
        let result = connector
            .handle_configure(json!({
                "project_id": "demo-project",
                "access_token": "ya29.test"
            }))
            .await
            .unwrap();

        assert_eq!(result["details"]["project_id"], "demo-project");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_credential_id() {
        let mut connector = FirebaseConnector::new();
        let result = connector
            .handle_configure(json!({
                "project_id": "demo-project",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "pending_credentials");
    }

    #[test]
    fn default_realtime_database_url_uses_project_id() {
        assert_eq!(
            default_realtime_database_url("demo-project"),
            "https://demo-project.firebaseio.com"
        );
    }

    #[test]
    fn connector_id_matches_reported_namespace() {
        let connector = FirebaseConnector::new();
        assert_eq!(connector.base.id.as_str(), "fcp.firebase");
    }

    #[test]
    fn host_policy_requires_https_and_firebase_hosts() {
        assert!(host_is_allowed(
            "https://firestore.googleapis.com/v1/projects/demo-project",
            &["firestore.googleapis.com"]
        ));
        assert!(!host_is_allowed(
            "http://firestore.googleapis.com/v1/projects/demo-project",
            &["firestore.googleapis.com"]
        ));
        assert!(!host_is_allowed(
            "https://localhost:8787/v1/projects/demo-project",
            &["firestore.googleapis.com"]
        ));

        assert!(host_is_allowed_suffix(
            "https://demo-project.firebaseio.com",
            &["firebaseio.com", "firebasedatabase.app"]
        ));
        assert!(!host_is_allowed_suffix(
            "http://demo-project.firebaseio.com",
            &["firebaseio.com", "firebasedatabase.app"]
        ));
        assert!(!host_is_allowed_suffix(
            "https://localhost",
            &["firebaseio.com", "firebasedatabase.app"]
        ));
    }

    #[test]
    fn typed_operations_include_firestore_and_rtdb() {
        let operations = typed_operations_info();
        assert_eq!(operations.len(), 11);
        assert!(
            operations
                .iter()
                .any(|op| op.id.as_str() == FIRESTORE_GET_OP)
        );
        assert!(operations.iter().any(|op| op.id.as_str() == RTDB_SET_OP));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_reports_unconfigured_connector() {
        let connector = FirebaseConnector::new();
        let doctor = connector.handle_doctor().await.unwrap();
        assert_eq!(doctor["status"], "unhealthy");
    }
}
