//! FCP `Firebase` connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_google_discovery::auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
};
use reqwest::Url;
use serde::Serialize;
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

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
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
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/firebase_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/firebase_connector/<timestamp>";
const FIRESTORE_ALLOWED_HOSTS: &[&str] = &["firestore.googleapis.com"];
const REALTIME_DATABASE_ALLOWED_SUFFIXES: &[&str] = &["firebaseio.com", "firebasedatabase.app"];
const GOOGLE_SCOPE_DATASTORE: &str = "https://www.googleapis.com/auth/datastore";
const GOOGLE_SCOPE_REALTIME_DATABASE: &str = "https://www.googleapis.com/auth/firebase.database";
const GOOGLE_SCOPE_CLOUD_PLATFORM: &str = "https://www.googleapis.com/auth/cloud-platform";

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

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (firestore_host_ok, firestore_host_message) =
            firestore_endpoint_policy(&self.firestore_base_url);
        let (realtime_database_host_ok, realtime_database_host_message) =
            realtime_database_endpoint_policy(&self.realtime_database_url);
        let firestore_scope_configured = scope_covers_firestore(&self.required_scopes);
        let realtime_database_scope_configured =
            scope_covers_realtime_database(&self.required_scopes);
        let network_ok = firestore_host_ok && realtime_database_host_ok;

        ProvisioningReadiness {
            auth_mode: firebase_auth_redacted_label(&self.auth),
            secret_material_configured: !firebase_auth_is_secretless(&self.auth),
            requires_credential_injection: firebase_auth_is_secretless(&self.auth),
            project_id: self.project_id.clone(),
            database_id: self.database_id.clone(),
            firestore: EndpointReadiness {
                url: self.firestore_base_url.clone(),
                host_ok: firestore_host_ok,
                message: firestore_host_message.clone(),
            },
            realtime_database: EndpointReadiness {
                url: self.realtime_database_url.clone(),
                host_ok: realtime_database_host_ok,
                message: realtime_database_host_message.clone(),
            },
            network_ok,
            network_message: format!("{firestore_host_message}; {realtime_database_host_message}"),
            request_timeout_ms: self.request_timeout_ms,
            required_scopes: self.required_scopes.clone(),
            scope_coverage: ScopeCoverage {
                firestore: firestore_scope_configured,
                realtime_database: realtime_database_scope_configured,
                guidance: firebase_permissions_guidance(
                    firestore_scope_configured,
                    realtime_database_scope_configured,
                    firebase_auth_is_secretless(&self.auth),
                ),
            },
            host_policy_guidance: "Production verification must target https://firestore.googleapis.com/v1 plus a Firebase-hosted Realtime Database endpoint under *.firebaseio.com or *.firebasedatabase.app. Deterministic verification may use localhost override endpoints for both surfaces.",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    auth_mode: String,
    secret_material_configured: bool,
    requires_credential_injection: bool,
    project_id: String,
    database_id: String,
    firestore: EndpointReadiness,
    realtime_database: EndpointReadiness,
    network_ok: bool,
    network_message: String,
    request_timeout_ms: u64,
    required_scopes: Vec<String>,
    scope_coverage: ScopeCoverage,
    host_policy_guidance: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct EndpointReadiness {
    url: String,
    host_ok: bool,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct ScopeCoverage {
    firestore: bool,
    realtime_database: bool,
    guidance: String,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

/// Doctor result returned by the `doctor` method.
#[derive(Debug, Clone, Serialize)]
struct DoctorResult {
    ready: bool,
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
}

/// Connector readiness state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Single doctor check entry.
#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let ready = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self {
            ready,
            status,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }

    const fn status_label(&self) -> &'static str {
        match self.status {
            DoctorStatus::Healthy => "healthy",
            DoctorStatus::Degraded => "degraded",
            DoctorStatus::Unhealthy => "unhealthy",
        }
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Firebase project plus a non-production Firestore database and Realtime Database namespace.",
            "Provision a Google credential that can read Firestore database metadata and, if you will test writes, mutate only synthetic staging fixtures.",
            "Seed deterministic Firestore documents and Realtime Database paths before running destructive verification flows.",
            "Use localhost override endpoints when you need deterministic wiremock-style verification without touching live Firebase infrastructure.",
        ],
        dedicated_environment: "Run verification only against staging Firebase data or localhost verification stubs. Firestore delete and Realtime Database delete operations are destructive and should never target production documents or JSON subtrees.",
        redaction_rules: vec![
            "Never print raw bearer tokens, injected credentials, or Authorization headers.",
            "Treat project_id, database_id, and Firebase hostnames as environment metadata; share them only when the environment is disposable or already public.",
            "Do not paste private Firestore document bodies or Realtime Database payloads into shared logs unless they are synthetic fixtures.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "firestore_host_invalid",
                symptom: "doctor/self_check reports an invalid Firestore base URL",
                action: "Set firestore_base_url to https://firestore.googleapis.com/v1 unless you are deliberately fronting Google APIs through a compliant proxy.",
            },
            RemediationHint {
                code: "realtime_database_host_invalid",
                symptom: "doctor/self_check reports an invalid Realtime Database endpoint",
                action: "Set realtime_database_url to the Firebase-hosted database root such as https://<project>.firebaseio.com or the regional *.firebasedatabase.app endpoint for the target database.",
            },
            RemediationHint {
                code: "credential_injection_required",
                symptom: "configure succeeds with credential_id but self_check cannot prove live access",
                action: "Ensure the host or egress proxy injects a concrete Google credential at runtime, then rerun self_check before invoking write or delete operations.",
            },
            RemediationHint {
                code: "google_scopes_incomplete",
                symptom: "doctor warns that required_scopes do not cover both Firestore and Realtime Database surfaces",
                action: "Add datastore and firebase.database scopes, or use cloud-platform when the deployment policy allows a broader Google credential.",
            },
            RemediationHint {
                code: "permissions_insufficient",
                symptom: "self_check or invoke returns 401/403 from Firebase",
                action: "Verify the bound Google principal has Firebase Rules and IAM coverage for the specific Firestore database and Realtime Database paths under test.",
            },
        ],
        rerun_commands: vec![
            "scripts/e2e/firebase_connector_verification.sh",
            "fwc manifest fix connectors/firebase/manifest.toml --check --json",
            "rch exec -- cargo test -p fcp-firebase --test integration -- --nocapture",
            "rch exec -- cargo clippy -p fcp-firebase --all-targets -- -D warnings",
        ],
        artifact_root_hint: ARTIFACT_ROOT_HINT,
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

    fn doctor(&self) -> DoctorResult {
        let provisioning = self
            .config
            .as_ref()
            .map(FirebaseConfig::provisioning_readiness);
        let handshaken = self.session_id.is_some();
        let mut checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                message: self
                    .config
                    .as_ref()
                    .map(|config| format!("Configured for Firebase project {}", config.project_id))
                    .or_else(|| {
                        Some("Not configured; call configure before handshake or invoke".into())
                    }),
                critical: true,
            },
            DoctorCheck {
                name: "client_initialized".into(),
                passed: self.client.is_some(),
                message: if self.client.is_some() {
                    None
                } else {
                    Some("Firebase client not initialized; re-run configure".into())
                },
                critical: true,
            },
            DoctorCheck {
                name: "handshake".into(),
                passed: handshaken,
                message: if handshaken {
                    None
                } else {
                    Some("Handshake not completed".into())
                },
                critical: false,
            },
        ];

        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "firestore_host_policy".into(),
                passed: readiness.firestore.host_ok,
                message: Some(readiness.firestore.message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "realtime_database_host_policy".into(),
                passed: readiness.realtime_database.host_ok,
                message: Some(readiness.realtime_database.message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth mode: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "secret_material".into(),
                passed: readiness.secret_material_configured,
                message: Some(if readiness.secret_material_configured {
                    "Concrete Google credential configured directly".into()
                } else {
                    "Secretless mode requires host-side credential injection before live verification"
                        .into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "scope_coverage".into(),
                passed: readiness.scope_coverage.firestore
                    && readiness.scope_coverage.realtime_database,
                message: Some(readiness.scope_coverage.guidance.clone()),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }

    fn attach_self_check_details(
        mut report: SelfCheckReport,
        provisioning: Option<&ProvisioningReadiness>,
        live_probe: Option<&Value>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "provisioning": provisioning,
            "live_probe": live_probe,
            "operator_guidance": operator_guidance(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
        }));
        report
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
        let client_initialized = self.client.is_some();
        let handshaken = self.session_id.is_some();
        let provisioning = self
            .config
            .as_ref()
            .map(FirebaseConfig::provisioning_readiness);
        let ready = configured
            && client_initialized
            && handshaken
            && provisioning
                .as_ref()
                .is_none_or(|readiness| readiness.network_ok);
        let status = if ready {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "client_initialized": client_initialized,
            "handshaken": handshaken,
            "ready": ready,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "details": {
                "provisioning": provisioning,
                "operator_guidance": operator_guidance(),
                "verification_script": VERIFICATION_SCRIPT_PATH,
                "artifact_root_hint": ARTIFACT_ROOT_HINT,
            }
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.doctor();
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "firebase.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Firebase doctor checks completed"
        );
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({ "status": "error" })))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let provisioning = self
            .config
            .as_ref()
            .map(FirebaseConfig::provisioning_readiness);
        let report = match (&self.config, &self.client, provisioning.as_ref()) {
            (None, _, _) | (_, None, _) => Self::attach_self_check_details(
                SelfCheckReport::failed("not_configured", "Connector is not configured yet"),
                provisioning.as_ref(),
                None,
            ),
            (Some(_), Some(_), Some(readiness)) if !readiness.network_ok => {
                Self::attach_self_check_details(
                    SelfCheckReport::failed(
                        "network_constraints_invalid",
                        readiness.network_message.clone(),
                    ),
                    provisioning.as_ref(),
                    None,
                )
            }
            (Some(config), Some(_), Some(_)) if firebase_auth_is_secretless(&config.auth) => {
                Self::attach_self_check_details(
                    SelfCheckReport::degraded(
                        "credential_injection_required",
                        "Configured with credential_id; live checks require host-side Google credential materialization",
                    ),
                    provisioning.as_ref(),
                    None,
                )
            }
            (Some(config), Some(client), Some(readiness)) => match client.health().await {
                Ok(health) => {
                    let live_probe = json!({
                        "probe": "firestore.database.get",
                        "database_resource": format!(
                            "projects/{}/databases/{}",
                            config.project_id, config.database_id
                        ),
                        "response": health,
                        "network_ok": readiness.network_ok,
                    });
                    Self::attach_self_check_details(
                        SelfCheckReport::ok(),
                        provisioning.as_ref(),
                        Some(&live_probe),
                    )
                }
                Err(FirebaseError::Unauthorized { message }) => Self::attach_self_check_details(
                    SelfCheckReport::failed("auth_invalid", message),
                    provisioning.as_ref(),
                    None,
                ),
                Err(error) if error.is_retryable() => Self::attach_self_check_details(
                    SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                    provisioning.as_ref(),
                    None,
                ),
                Err(error) => Self::attach_self_check_details(
                    SelfCheckReport::failed("self_check_failed", error.to_string()),
                    provisioning.as_ref(),
                    None,
                ),
            },
            (Some(_), Some(_), None) => Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "self_check_failed",
                    "Provisioning state could not be derived from the current configuration",
                ),
                None,
                None,
            ),
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
        GOOGLE_SCOPE_DATASTORE.into(),
        GOOGLE_SCOPE_REALTIME_DATABASE.into(),
    ]
}

fn default_realtime_database_url(project_id: &str) -> String {
    format!("https://{project_id}.firebaseio.com")
}

fn host_is_local_verification_stub(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".localhost")
}

fn host_is_allowed(url: &str, hosts: &[&str]) -> bool {
    Url::parse(url).ok().is_some_and(|parsed| {
        parsed.scheme() == "https" && parsed.host_str().is_some_and(|host| hosts.contains(&host))
    })
}

fn host_is_allowed_suffix(url: &str, suffixes: &[&str]) -> bool {
    Url::parse(url).ok().is_some_and(|parsed| {
        parsed.scheme() == "https"
            && parsed.host_str().is_some_and(|host| {
                suffixes
                    .iter()
                    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
            })
    })
}

fn firestore_endpoint_policy(url: &str) -> (bool, String) {
    match Url::parse(url) {
        Ok(parsed) => {
            let Some(host) = parsed.host_str() else {
                return (false, "Firestore base URL must include a host".into());
            };
            if host_is_local_verification_stub(host) {
                return match parsed.scheme() {
                    "http" | "https" => (
                        true,
                        format!("Firestore localhost verification endpoint accepted: {url}"),
                    ),
                    scheme => (
                        false,
                        format!(
                            "Firestore localhost verification endpoint must use http or https, got {scheme}"
                        ),
                    ),
                };
            }
            if parsed.scheme() != "https" {
                return (
                    false,
                    format!("Firestore base URL must use https, got {}", parsed.scheme()),
                );
            }
            if FIRESTORE_ALLOWED_HOSTS.contains(&host) {
                (true, format!("Firestore endpoint accepted: {url}"))
            } else {
                (
                    false,
                    format!(
                        "Firestore host must be one of {FIRESTORE_ALLOWED_HOSTS:?} or a localhost verification stub, got {host}"
                    ),
                )
            }
        }
        Err(error) => (false, format!("invalid firestore_base_url: {error}")),
    }
}

fn realtime_database_endpoint_policy(url: &str) -> (bool, String) {
    match Url::parse(url) {
        Ok(parsed) => {
            let Some(host) = parsed.host_str() else {
                return (false, "Realtime Database URL must include a host".into());
            };
            if host_is_local_verification_stub(host) {
                return match parsed.scheme() {
                    "http" | "https" => (
                        true,
                        format!(
                            "Realtime Database localhost verification endpoint accepted: {url}"
                        ),
                    ),
                    scheme => (
                        false,
                        format!(
                            "Realtime Database localhost verification endpoint must use http or https, got {scheme}"
                        ),
                    ),
                };
            }
            if parsed.scheme() != "https" {
                return (
                    false,
                    format!(
                        "Realtime Database URL must use https, got {}",
                        parsed.scheme()
                    ),
                );
            }
            if REALTIME_DATABASE_ALLOWED_SUFFIXES
                .iter()
                .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
            {
                (true, format!("Realtime Database endpoint accepted: {url}"))
            } else {
                (
                    false,
                    format!(
                        "Realtime Database host must end with one of {REALTIME_DATABASE_ALLOWED_SUFFIXES:?} or be a localhost verification stub, got {host}"
                    ),
                )
            }
        }
        Err(error) => (false, format!("invalid realtime_database_url: {error}")),
    }
}

fn scope_covers_firestore(scopes: &[String]) -> bool {
    scopes.iter().any(|scope| {
        matches!(
            scope.as_str(),
            GOOGLE_SCOPE_DATASTORE | GOOGLE_SCOPE_CLOUD_PLATFORM
        )
    })
}

fn scope_covers_realtime_database(scopes: &[String]) -> bool {
    scopes.iter().any(|scope| {
        matches!(
            scope.as_str(),
            GOOGLE_SCOPE_REALTIME_DATABASE | GOOGLE_SCOPE_CLOUD_PLATFORM
        )
    })
}

fn firebase_permissions_guidance(
    firestore_scope_configured: bool,
    realtime_database_scope_configured: bool,
    secretless: bool,
) -> String {
    match (
        firestore_scope_configured,
        realtime_database_scope_configured,
        secretless,
    ) {
        (true, true, true) => "Secretless mode is configured. The injected Google credential must still carry Firestore and Realtime Database access for the target Firebase project.".into(),
        (true, true, false) => "Configured scopes cover both Firestore and Realtime Database. Live permissions still depend on the Google principal bound to the access token.".into(),
        (false, true, _) => "Configured required_scopes omit Firestore access. Add https://www.googleapis.com/auth/datastore or cloud-platform before relying on Firestore reads or writes.".into(),
        (true, false, _) => "Configured required_scopes omit Realtime Database access. Add https://www.googleapis.com/auth/firebase.database or cloud-platform before relying on RTDB reads or writes.".into(),
        (false, false, _) => "Configured required_scopes omit both Firestore and Realtime Database access. Add datastore plus firebase.database scopes, or use cloud-platform when the deployment policy permits broader Google access.".into(),
    }
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
            requires_approval: Some(ApprovalMode::Policy),
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
            requires_approval: Some(ApprovalMode::Policy),
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
            requires_approval: Some(ApprovalMode::Interactive),
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
            requires_approval: Some(ApprovalMode::Policy),
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
            requires_approval: Some(ApprovalMode::Policy),
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
            requires_approval: Some(ApprovalMode::Interactive),
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
    fn host_policy_accepts_official_hosts_and_local_verification_overrides() {
        assert!(host_is_allowed(
            "https://firestore.googleapis.com/v1/projects/demo-project",
            &["firestore.googleapis.com"]
        ));
        assert!(!host_is_allowed(
            "http://firestore.googleapis.com/v1/projects/demo-project",
            &["firestore.googleapis.com"]
        ));
        let (firestore_local_ok, firestore_local_message) =
            firestore_endpoint_policy("http://localhost:8787/v1/projects/demo-project");
        assert!(firestore_local_ok);
        assert!(firestore_local_message.contains("localhost"));

        assert!(host_is_allowed_suffix(
            "https://demo-project.firebaseio.com",
            &["firebaseio.com", "firebasedatabase.app"]
        ));
        assert!(!host_is_allowed_suffix(
            "http://demo-project.firebaseio.com",
            &["firebaseio.com", "firebasedatabase.app"]
        ));
        let (realtime_local_ok, realtime_local_message) =
            realtime_database_endpoint_policy("http://localhost:9000");
        assert!(realtime_local_ok);
        assert!(realtime_local_message.contains("localhost"));
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

    #[test]
    fn manifest_declares_agent_actionable_ai_hints() {
        for operation in typed_operations_info() {
            let operation_id = operation.id.as_str();
            let marker = format!("[provides.operations.\"{operation_id}\".ai_hints]");
            let maybe_block = MANIFEST_TOML.split_once(&marker).map(|(_, remainder)| {
                remainder
                    .split_once("\n[provides.operations.")
                    .map_or(remainder, |(block, _)| block)
            });
            assert!(
                maybe_block.is_some(),
                "{operation_id} missing manifest ai_hints block"
            );
            let block = maybe_block.unwrap_or_default();

            assert!(
                block.contains("when_to_use = "),
                "{operation_id} missing when_to_use"
            );
            assert!(
                !block.contains("when_to_use = \"\""),
                "{operation_id} has empty when_to_use"
            );
            assert!(
                block.contains("common_mistakes = ["),
                "{operation_id} missing common_mistakes"
            );
            assert!(
                !block.contains("common_mistakes = []"),
                "{operation_id} has empty common_mistakes"
            );
            assert!(
                block.contains("examples = ["),
                "{operation_id} missing examples"
            );
            assert!(
                !block.contains("examples = []"),
                "{operation_id} has empty examples"
            );
            assert!(
                !block.contains("related = []"),
                "{operation_id} has empty related hints"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_reports_unconfigured_connector() {
        let connector = FirebaseConnector::new();
        let doctor = connector.handle_doctor().await.unwrap();
        assert_eq!(doctor["status"], "unhealthy");
        assert_eq!(doctor["ready"], false);
        assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
        assert_eq!(
            doctor["operator_guidance"]["artifact_root_hint"],
            ARTIFACT_ROOT_HINT
        );
    }

    #[test]
    fn mutation_operations_require_approval_metadata() {
        let operations = typed_operations_info();
        let find = |id: &str| operations.iter().find(|op| op.id.as_str() == id).unwrap();

        assert_eq!(
            find(FIRESTORE_CREATE_OP).requires_approval,
            Some(ApprovalMode::Policy)
        );
        assert_eq!(
            find(FIRESTORE_UPDATE_OP).requires_approval,
            Some(ApprovalMode::Policy)
        );
        assert_eq!(
            find(FIRESTORE_BATCH_WRITE_OP).requires_approval,
            Some(ApprovalMode::Policy)
        );
        assert_eq!(
            find(RTDB_SET_OP).requires_approval,
            Some(ApprovalMode::Policy)
        );
        assert_eq!(
            find(FIRESTORE_DELETE_OP).requires_approval,
            Some(ApprovalMode::Interactive)
        );
        assert_eq!(
            find(RTDB_DELETE_OP).requires_approval,
            Some(ApprovalMode::Interactive)
        );
    }
}
