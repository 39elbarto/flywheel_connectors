//! Azure connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    client::AzureClient,
    types::{AzureAuth, SetSecretAttributes, SetSecretRequest},
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_LIST_SUBSCRIPTIONS: &str = "azure.management.list_subscriptions";
const OP_LIST_RESOURCE_GROUPS: &str = "azure.management.list_resource_groups";
const OP_LIST_RESOURCES: &str = "azure.management.list_resources";
const OP_BLOB_LIST_CONTAINERS: &str = "azure.storage.blob_list_containers";
const OP_BLOB_LIST_BLOBS: &str = "azure.storage.blob_list_blobs";
const OP_BLOB_GET: &str = "azure.storage.blob_get";
const OP_BLOB_PUT: &str = "azure.storage.blob_put";
const OP_KEYVAULT_LIST_SECRETS: &str = "azure.keyvault.list_secrets";
const OP_KEYVAULT_GET_SECRET: &str = "azure.keyvault.get_secret";
const OP_KEYVAULT_SET_SECRET: &str = "azure.keyvault.set_secret";

// Capability IDs
const CAP_MANAGEMENT_READ: &str = "azure.management.read";
const CAP_STORAGE_READ: &str = "azure.storage.read";
const CAP_STORAGE_WRITE: &str = "azure.storage.write";
const CAP_KEYVAULT_READ: &str = "azure.keyvault.read";
const CAP_KEYVAULT_WRITE: &str = "azure.keyvault.write";

#[derive(Clone, Deserialize)]
pub struct AzureConfig {
    #[serde(default = "default_management_url")]
    pub management_url: String,
    #[serde(flatten)]
    pub auth: AzureAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_management_url() -> String {
    "https://management.azure.com".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for AzureConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureConfig")
            .field("management_url", &self.management_url)
            .field("auth", &self.auth)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl AzureConfig {
    fn validate(&self) -> Result<(), String> {
        validate_management_url(&self.management_url)?;

        if matches!(
            &self.auth,
            AzureAuth::BearerToken { bearer_token } if bearer_token.trim().is_empty()
        ) {
            return Err("bearer_token is required".into());
        }

        Ok(())
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {error}"),
            })?;

        config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message,
            })?;

        Ok(config)
    }
}

fn validate_https_url(url: &str, label: &str) -> Result<Url, String> {
    let parsed =
        Url::parse(url).map_err(|error| format!("{label} must be a valid URL: {error}"))?;
    if parsed.scheme() != "https" {
        return Err(format!("{label} must use https"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{label} must not include embedded credentials"));
    }
    if parsed.port_or_known_default() != Some(443) {
        return Err(format!("{label} must resolve to port 443"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "{label} must not include a query string or fragment"
        ));
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(format!("{label} must not include a path"));
    }
    Ok(parsed)
}

fn validate_allowed_host_url<F>(
    url: &str,
    label: &str,
    expected_host_description: &str,
    host_allowed: F,
) -> Result<(), String>
where
    F: FnOnce(&str) -> bool,
{
    let parsed = validate_https_url(url, label)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("{label} must include a host"))?;
    if !host_allowed(host) {
        return Err(format!(
            "{label} host must match {expected_host_description}"
        ));
    }
    Ok(())
}

fn validate_management_url(url: &str) -> Result<(), String> {
    if url.trim().is_empty() {
        return Err("management_url cannot be empty".into());
    }
    validate_allowed_host_url(url, "management_url", "management.azure.com", |host| {
        host.eq_ignore_ascii_case("management.azure.com")
    })
}

fn validate_blob_base_url(url: &str) -> Result<(), String> {
    validate_allowed_host_url(url, "blob_base_url", "*.blob.core.windows.net", |host| {
        host.ends_with(".blob.core.windows.net")
    })
}

fn validate_vault_base_url(url: &str) -> Result<(), String> {
    validate_allowed_host_url(url, "vault_base_url", "*.vault.azure.net", |host| {
        host.ends_with(".vault.azure.net")
    })
}

fn validate_optional_override(
    url: Option<&str>,
    label: &str,
    validator: fn(&str) -> Result<(), String>,
) -> FcpResult<()> {
    if let Some(url) = url {
        validator(url).map_err(|message| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label}: {message}"),
        })?;
    }
    Ok(())
}

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
        let passed = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
pub struct AzureConnector {
    base: BaseConnector,
    config: Option<AzureConfig>,
    client: Option<AzureClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl AzureConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.azure")),
            config: None,
            client: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut digest = Sha256::new();
        digest.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(digest.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: self
                .config
                .as_ref()
                .map(|_| "Configuration loaded".into())
                .or_else(|| Some("Not configured".into())),
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: self
                .client
                .as_ref()
                .map(|_| "Client initialized".into())
                .or_else(|| Some("Client not initialized".into())),
            critical: true,
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "management_url".into(),
                passed: validate_management_url(&config.management_url).is_ok(),
                message: Some(format!("Management URL: {}", config.management_url)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth: {}", config.auth.redacted_label())),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }

    fn capability_for_operation(operation: &str) -> Option<CapabilityId> {
        let capability = match operation {
            OP_LIST_SUBSCRIPTIONS | OP_LIST_RESOURCE_GROUPS | OP_LIST_RESOURCES => {
                CAP_MANAGEMENT_READ
            }
            OP_BLOB_LIST_CONTAINERS | OP_BLOB_LIST_BLOBS | OP_BLOB_GET => CAP_STORAGE_READ,
            OP_BLOB_PUT => CAP_STORAGE_WRITE,
            OP_KEYVAULT_LIST_SECRETS | OP_KEYVAULT_GET_SECRET => CAP_KEYVAULT_READ,
            OP_KEYVAULT_SET_SECRET => CAP_KEYVAULT_WRITE,
            _ => return None,
        };
        Some(CapabilityId::from_static(capability))
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing string field: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }
}

impl Default for AzureConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn schema(required: &[&str]) -> serde_json::Value {
    if required.is_empty() {
        json!({ "type": "object" })
    } else {
        json!({ "type": "object", "required": required })
    }
}

#[allow(clippy::too_many_arguments)]
fn op(
    id: &'static str,
    summary: &'static str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    when_to_use: &'static str,
    requires_approval: Option<ApprovalMode>,
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
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: Vec::new(),
            examples: Vec::new(),
            related: Vec::new(),
        },
        rate_limit: None,
        requires_approval,
    }
}

fn operations_info() -> Vec<OperationInfo> {
    vec![
        op(
            OP_LIST_SUBSCRIPTIONS,
            "List Azure subscriptions",
            CAP_MANAGEMENT_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            schema(&[]),
            schema(&[]),
            "Enumerate Azure subscriptions available to the configured credentials",
            None,
        ),
        op(
            OP_LIST_RESOURCE_GROUPS,
            "List resource groups in a subscription",
            CAP_MANAGEMENT_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            schema(&["subscription_id"]),
            schema(&[]),
            "List resource groups within a specific Azure subscription",
            None,
        ),
        op(
            OP_LIST_RESOURCES,
            "List resources in a resource group",
            CAP_MANAGEMENT_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            schema(&["subscription_id", "resource_group"]),
            schema(&[]),
            "Enumerate resources within a specific Azure resource group",
            None,
        ),
        op(
            OP_BLOB_LIST_CONTAINERS,
            "List blob storage containers",
            CAP_STORAGE_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            schema(&["storage_account"]),
            schema(&[]),
            "List blob containers in an Azure storage account",
            None,
        ),
        op(
            OP_BLOB_LIST_BLOBS,
            "List blobs in a container",
            CAP_STORAGE_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            schema(&["storage_account", "container"]),
            schema(&[]),
            "List blobs within a specific Azure storage container",
            None,
        ),
        op(
            OP_BLOB_GET,
            "Download a blob",
            CAP_STORAGE_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            schema(&["storage_account", "container", "blob_name"]),
            schema(&[]),
            "Download or read the contents of a specific blob",
            None,
        ),
        op(
            OP_BLOB_PUT,
            "Upload a blob",
            CAP_STORAGE_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            schema(&[
                "storage_account",
                "container",
                "blob_name",
                "content_base64",
            ]),
            schema(&[]),
            "Upload or overwrite a blob in an Azure storage container",
            None,
        ),
        op(
            OP_KEYVAULT_LIST_SECRETS,
            "List Key Vault secrets",
            CAP_KEYVAULT_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            schema(&["vault_name"]),
            schema(&[]),
            "List secret names stored in an Azure Key Vault",
            None,
        ),
        op(
            OP_KEYVAULT_GET_SECRET,
            "Get a Key Vault secret value",
            CAP_KEYVAULT_READ,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            schema(&["vault_name", "secret_name"]),
            schema(&[]),
            "Retrieve the actual value of a specific secret from Azure Key Vault",
            None,
        ),
        op(
            OP_KEYVAULT_SET_SECRET,
            "Set a Key Vault secret",
            CAP_KEYVAULT_WRITE,
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            schema(&["vault_name", "secret_name", "value"]),
            schema(&[]),
            "Create or update a secret in Azure Key Vault",
            Some(ApprovalMode::Interactive),
        ),
    ]
}

impl AzureConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        let Some(verifier) = &self.verifier else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        };
        let Some(capability) = Self::capability_for_operation(operation) else {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        };
        verifier.verify(&req.capability_token, &capability, &req.operation, &[])?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Azure client".into(),
        })?;

        let output = match operation {
            OP_LIST_SUBSCRIPTIONS => serde_json::to_value(
                client
                    .list_subscriptions()
                    .await
                    .map_err(|e| e.to_fcp_error())?,
            )
            .map_err(|e| FcpError::Internal {
                message: e.to_string(),
            })?,

            OP_LIST_RESOURCE_GROUPS => {
                let subscription_id = Self::require_str(&req.input, "subscription_id")?;
                serde_json::to_value(
                    client
                        .list_resource_groups(subscription_id)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_LIST_RESOURCES => {
                let subscription_id = Self::require_str(&req.input, "subscription_id")?;
                let resource_group = Self::require_str(&req.input, "resource_group")?;
                serde_json::to_value(
                    client
                        .list_resources(subscription_id, resource_group)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_LIST_CONTAINERS => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_list_containers(storage_account, blob_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_LIST_BLOBS => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_list_blobs(storage_account, container, blob_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_GET => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob_name = Self::require_str(&req.input, "blob_name")?;
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_get(storage_account, container, blob_name, blob_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_BLOB_PUT => {
                let storage_account = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob_name = Self::require_str(&req.input, "blob_name")?;
                let content_base64 = Self::require_str(&req.input, "content_base64")?;
                let content_type = req.input.get("content_type").and_then(|v| v.as_str());
                let blob_base_url = req.input.get("blob_base_url").and_then(|v| v.as_str());
                validate_optional_override(blob_base_url, "blob_base_url", validate_blob_base_url)?;
                serde_json::to_value(
                    client
                        .blob_put(
                            storage_account,
                            container,
                            blob_name,
                            content_base64,
                            content_type,
                            blob_base_url,
                        )
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_KEYVAULT_LIST_SECRETS => {
                let vault_name = Self::require_str(&req.input, "vault_name")?;
                let vault_base_url = req.input.get("vault_base_url").and_then(|v| v.as_str());
                validate_optional_override(
                    vault_base_url,
                    "vault_base_url",
                    validate_vault_base_url,
                )?;
                serde_json::to_value(
                    client
                        .keyvault_list_secrets(vault_name, vault_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_KEYVAULT_GET_SECRET => {
                let vault_name = Self::require_str(&req.input, "vault_name")?;
                let secret_name = Self::require_str(&req.input, "secret_name")?;
                let vault_base_url = req.input.get("vault_base_url").and_then(|v| v.as_str());
                validate_optional_override(
                    vault_base_url,
                    "vault_base_url",
                    validate_vault_base_url,
                )?;
                serde_json::to_value(
                    client
                        .keyvault_get_secret(vault_name, secret_name, vault_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            OP_KEYVAULT_SET_SECRET => {
                let vault_name = Self::require_str(&req.input, "vault_name")?;
                let secret_name = Self::require_str(&req.input, "secret_name")?;
                let value = Self::require_str(&req.input, "value")?;
                let vault_base_url = req.input.get("vault_base_url").and_then(|v| v.as_str());
                validate_optional_override(
                    vault_base_url,
                    "vault_base_url",
                    validate_vault_base_url,
                )?;
                let tags = req.input.get("tags").cloned();
                let content_type = req
                    .input
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let enabled = req.input.get("enabled").and_then(|v| v.as_bool());

                let set_req = SetSecretRequest {
                    value: value.into(),
                    tags,
                    content_type,
                    attributes: enabled.map(|e| SetSecretAttributes { enabled: Some(e) }),
                };
                serde_json::to_value(
                    client
                        .keyvault_set_secret(vault_name, secret_name, &set_req, vault_base_url)
                        .await
                        .map_err(|e| e.to_fcp_error())?,
                )
                .map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }

            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[async_trait]
impl FcpConnector for AzureConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let azure = AzureConfig::from_value(config)?;
        let client = AzureClient::new(
            azure.auth.clone(),
            azure.retry.clone(),
            Duration::from_millis(azure.request_timeout_ms),
        )
        .map_err(|error| FcpError::Internal {
            message: format!("Client init: {error}"),
        })?
        .with_management_url(&azure.management_url);

        self.client = Some(client);
        self.config = Some(azure);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.config.is_some() && self.client.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        if client.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; egress proxy injection is required for health checks",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(error) if error.is_retryable() => Ok(SelfCheckReport::degraded(
                "self_check_retryable",
                error.to_string(),
            )),
            Err(error) => Ok(SelfCheckReport::failed(
                "self_check_failed",
                error.to_string(),
            )),
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
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
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
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{CapabilityToken, RequestId, ZoneId};

    fn valid_config() -> serde_json::Value {
        json!({
            "mode": "bearer_token",
            "bearer_token": "test-token"
        })
    }

    #[test]
    fn new_connector_starts_unconfigured() {
        assert!(AzureConnector::new().config.is_none());
    }

    #[test]
    fn manifest_hash_is_stable() {
        assert_eq!(
            AzureConnector::manifest_hash(),
            AzureConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_accepts_bearer_token() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            assert!(connector.client.is_some());
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_empty_token() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "bearer_token",
                    "bearer_token": ""
                }))
                .await
                .unwrap_err();
            match err {
                FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1001),
                other => panic!("expected invalid request, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_empty_management_url() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "bearer_token",
                    "bearer_token": "tok",
                    "management_url": ""
                }))
                .await
                .unwrap_err();
            match err {
                FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1001),
                other => panic!("expected invalid request, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn management_url_requires_https_and_azure_host() {
        assert!(validate_management_url("https://management.azure.com").is_ok());
        assert!(validate_management_url("http://management.azure.com").is_err());
        assert!(validate_management_url("https://example.com").is_err());
        assert!(validate_management_url("https://user:pass@management.azure.com").is_err());
        assert!(validate_management_url("https://management.azure.com/subscriptions").is_err());
    }

    #[test]
    fn override_urls_require_https_and_expected_hosts() {
        assert!(validate_blob_base_url("https://acct.blob.core.windows.net").is_ok());
        assert!(validate_blob_base_url("http://acct.blob.core.windows.net").is_err());
        assert!(validate_blob_base_url("https://example.com").is_err());
        assert!(validate_blob_base_url("https://user:pass@acct.blob.core.windows.net").is_err());

        assert!(validate_vault_base_url("https://vault-one.vault.azure.net").is_ok());
        assert!(validate_vault_base_url("http://vault-one.vault.azure.net").is_err());
        assert!(validate_vault_base_url("https://example.com").is_err());
        assert!(validate_vault_base_url("https://user:pass@vault-one.vault.azure.net").is_err());
    }

    #[test]
    fn doctor_reports_not_configured() {
        let doctor = AzureConnector::new().doctor();
        assert!(!doctor.passed);
        assert_eq!(doctor.checks[0].name, "configuration");
    }

    #[test]
    fn doctor_reports_configured() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let doctor = connector.doctor();
            assert!(doctor.passed);
        })
        .unwrap();
    }

    #[test]
    fn simulate_allows_requests() {
        fcp_async_core::runtime::block_on_sync(async {
            let response = AzureConnector::new()
                .simulate(SimulateRequest {
                    r#type: "simulate".into(),
                    id: RequestId::new("sim-1"),
                    connector_id: ConnectorId::from_static("fcp.azure"),
                    operation: OperationId::from_static(OP_LIST_SUBSCRIPTIONS),
                    zone_id: ZoneId::work(),
                    input: json!({}),
                    capability_token: CapabilityToken::test_token(),
                    estimate_cost: false,
                    check_availability: false,
                    context: None,
                    correlation_id: None,
                })
                .await
                .unwrap();
            assert!(response.would_succeed);
        })
        .unwrap();
    }

    #[test]
    fn subscribe_returns_streaming_not_supported() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = AzureConnector::new();
            let err = connector
                .subscribe(SubscribeRequest {
                    r#type: "subscribe".into(),
                    id: RequestId::new("sub-1"),
                    topics: vec!["test".into()],
                    since: None,
                    max_events_per_sec: None,
                    batch_ms: None,
                    window_size: None,
                    capability_token: Some(CapabilityToken::test_token()),
                })
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::StreamingNotSupported));
        })
        .unwrap();
    }

    #[test]
    fn unsubscribe_returns_streaming_not_supported() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = AzureConnector::new();
            let err = connector
                .unsubscribe(UnsubscribeRequest {
                    r#type: "unsubscribe".into(),
                    id: RequestId::new("unsub-1"),
                    topics: vec!["test".into()],
                    capability_token: Some(CapabilityToken::test_token()),
                })
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::StreamingNotSupported));
        })
        .unwrap();
    }

    #[test]
    fn health_degraded_when_not_configured() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = AzureConnector::new();
            let snapshot = connector.health().await;
            assert!(!snapshot.is_ready());
        })
        .unwrap();
    }

    #[test]
    fn health_ready_when_configured() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let snapshot = connector.health().await;
            assert!(snapshot.is_ready());
        })
        .unwrap();
    }

    #[test]
    fn self_check_returns_degraded_when_not_configured() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = AzureConnector::new();
            let report = connector.self_check().await.unwrap();
            assert!(matches!(report.status, fcp_core::SelfCheckStatus::Degraded));
        })
        .unwrap();
    }

    #[test]
    fn shutdown_clears_state() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = AzureConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            connector
                .shutdown(ShutdownRequest {
                    r#type: "shutdown".into(),
                    deadline_ms: 5_000,
                    drain: false,
                    reason: None,
                })
                .await
                .unwrap();
            assert!(connector.config.is_none());
            assert!(connector.client.is_none());
        })
        .unwrap();
    }

    #[test]
    fn introspect_returns_all_operations() {
        let connector = AzureConnector::new();
        let introspection = connector.introspect();
        assert_eq!(introspection.operations.len(), 10);

        let op_ids: Vec<&str> = introspection
            .operations
            .iter()
            .map(|o| o.id.as_str())
            .collect();
        assert!(op_ids.contains(&OP_LIST_SUBSCRIPTIONS));
        assert!(op_ids.contains(&OP_LIST_RESOURCE_GROUPS));
        assert!(op_ids.contains(&OP_LIST_RESOURCES));
        assert!(op_ids.contains(&OP_BLOB_LIST_CONTAINERS));
        assert!(op_ids.contains(&OP_BLOB_LIST_BLOBS));
        assert!(op_ids.contains(&OP_BLOB_GET));
        assert!(op_ids.contains(&OP_BLOB_PUT));
        assert!(op_ids.contains(&OP_KEYVAULT_LIST_SECRETS));
        assert!(op_ids.contains(&OP_KEYVAULT_GET_SECRET));
        assert!(op_ids.contains(&OP_KEYVAULT_SET_SECRET));
    }

    #[test]
    fn keyvault_set_secret_requires_approval() {
        let connector = AzureConnector::new();
        let introspection = connector.introspect();
        let set_secret_op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == OP_KEYVAULT_SET_SECRET)
            .expect("keyvault_set_secret operation should exist");
        assert_eq!(
            set_secret_op.requires_approval,
            Some(ApprovalMode::Interactive)
        );
    }

    #[test]
    fn read_only_ops_do_not_require_approval() {
        let connector = AzureConnector::new();
        let introspection = connector.introspect();
        let read_ops = [
            OP_LIST_SUBSCRIPTIONS,
            OP_LIST_RESOURCE_GROUPS,
            OP_LIST_RESOURCES,
            OP_BLOB_LIST_CONTAINERS,
            OP_BLOB_LIST_BLOBS,
            OP_BLOB_GET,
            OP_KEYVAULT_LIST_SECRETS,
            OP_KEYVAULT_GET_SECRET,
        ];
        for op_id in read_ops {
            let operation = introspection
                .operations
                .iter()
                .find(|o| o.id.as_str() == op_id)
                .unwrap_or_else(|| panic!("{op_id} should exist"));
            assert_eq!(
                operation.requires_approval, None,
                "{op_id} should not require approval"
            );
        }
    }

    #[test]
    fn capability_mapping_is_complete() {
        let ops = [
            OP_LIST_SUBSCRIPTIONS,
            OP_LIST_RESOURCE_GROUPS,
            OP_LIST_RESOURCES,
            OP_BLOB_LIST_CONTAINERS,
            OP_BLOB_LIST_BLOBS,
            OP_BLOB_GET,
            OP_BLOB_PUT,
            OP_KEYVAULT_LIST_SECRETS,
            OP_KEYVAULT_GET_SECRET,
            OP_KEYVAULT_SET_SECRET,
        ];
        for op_id in ops {
            assert!(
                AzureConnector::capability_for_operation(op_id).is_some(),
                "no capability mapping for {op_id}"
            );
        }
    }

    #[test]
    fn unknown_operation_has_no_capability() {
        assert!(AzureConnector::capability_for_operation("azure.unknown").is_none());
    }

    #[test]
    fn connector_id_is_fcp_azure() {
        let connector = AzureConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.azure");
    }

    #[test]
    fn default_impl_works() {
        let connector = AzureConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.azure");
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            AzureConnector::require_str(&json!({"k": "v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(AzureConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(AzureConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(AzureConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }
}
