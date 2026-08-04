//! FCP lifecycle and bounded operation dispatch for Google Apps Script.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{
    client::{AppsScriptClient, source_inventory},
    types::{DeploymentConfig, ProcessFilter, ScriptFile, SourceReplacement},
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

pub struct AppsScriptConnector {
    base: Arc<BaseConnector>,
    client: Option<AppsScriptClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
}

#[allow(clippy::unused_async)]
impl AppsScriptConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-apps-script",
            ))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }
    fn manifest_hash() -> String {
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(MANIFEST_TOML.as_bytes()))
        )
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let selection =
            GoogleAuthSelection::from_connector_config(params.get("auth").unwrap_or(&params))
                .map_err(|e| invalid(format!("invalid Google auth config: {e}")))?;
        let materialized = selection
            .materialize()
            .await
            .map_err(|e| invalid(format!("failed to materialize Google auth: {e}")))?;
        let status = if matches!(
            materialized,
            GoogleMaterializedAuth::CredentialReference { .. }
        ) {
            "configured_pending_token_materialization"
        } else {
            "configured"
        };
        let mut client =
            AppsScriptClient::new_with_auth(materialized).map_err(|e| FcpError::Internal {
                message: format!("failed to create Apps Script client: {e}"),
            })?;
        if let Some(raw) = params.get("base_url") {
            client = client.with_base_url(validate_base_url(
                raw.as_str()
                    .ok_or_else(|| invalid("base_url must be a string"))?,
            )?);
        }
        let auth = client.auth_redacted_label();
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth, status, "Google Apps Script connector configured");
        Ok(json!({"status": status}))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        let req: HandshakeRequest = serde_json::from_value(params)
            .map_err(|e| invalid(format!("invalid handshake request: {e}")))?;
        if let Some(id) = req.requested_instance_id {
            Arc::get_mut(&mut self.base)
                .ok_or_else(|| FcpError::Internal {
                    message: "cannot assign instance ID after sharing state".into(),
                })?
                .instance_id = id;
        }
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let session_id = fcp_core::SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);
        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req
                .capabilities_requested
                .into_iter()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
            session_id,
            manifest_hash: Self::manifest_hash(),
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
        serde_json::to_value(response).map_err(internal_json)
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let metrics = self.base.metrics();
        Ok(
            json!({"status": if self.client.is_some() {"healthy"} else {"not_configured"}, "metrics": {"requests_total": metrics.requests_total, "requests_error": metrics.requests_error}}),
        )
    }
    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let ready = self.client.is_some();
        Ok(
            json!({"status": if ready {"healthy"} else {"unhealthy"}, "checks": [{"name":"configuration","passed":ready,"critical":true}]}),
        )
    }
    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        Ok(
            json!({"status": if self.client.is_some() {"pass"} else {"fail"}, "check": if self.client.is_some() {"configured"} else {"not_configured"}}),
        )
    }
    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        serde_json::to_value(Introspection {
            operations: operation_specs()
                .into_iter()
                .map(OperationSpec::info)
                .collect(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        })
        .map_err(internal_json)
    }

    pub async fn handle_invoke(&mut self, params: Value) -> FcpResult<Value> {
        let result = self.invoke(params).await;
        self.base.record_request(result.is_ok());
        result
    }
    async fn invoke(&self, params: Value) -> FcpResult<Value> {
        let operation = require_str(&params, "operation")?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let spec = operation_specs()
            .into_iter()
            .find(|spec| spec.id == operation)
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;
        let op_id: OperationId = operation
            .parse()
            .map_err(|_| invalid("invalid operation ID"))?;
        let token: CapabilityToken = serde_json::from_value(
            params
                .get("capability_token")
                .cloned()
                .ok_or_else(|| invalid("missing capability_token"))?,
        )
        .map_err(|e| invalid(format!("invalid capability_token: {e}")))?;
        let resources = resources(operation, &input)?;
        self.verifier
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .verify_bound(
                token,
                &CapabilityId::from_static(spec.capability),
                &op_id,
                &resources,
            )?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        dispatch(client, operation, &input).await
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let req: SimulateRequest = serde_json::from_value(params)
            .map_err(|e| invalid(format!("invalid simulate request: {e}")))?;
        let operation = req.operation.as_str();
        let Some(spec) = operation_specs()
            .into_iter()
            .find(|spec| spec.id == operation)
        else {
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                "operation is not exposed",
                FcpError::OperationNotGranted {
                    operation: operation.into(),
                }
                .error_code(),
            ))
            .map_err(internal_json);
        };
        let response = if self.client.is_none() {
            SimulateResponse::denied(
                req.id,
                "connector not configured",
                FcpError::NotConfigured.error_code(),
            )
        } else if let Some(verifier) = &self.verifier {
            match resources(operation, &req.input).and_then(|uris| {
                verifier
                    .verify_bound(
                        req.capability_token,
                        &CapabilityId::from_static(spec.capability),
                        &req.operation,
                        &uris,
                    )
                    .map(|_| ())
            }) {
                Ok(()) => SimulateResponse::allowed(req.id),
                Err(e) => SimulateResponse::denied(req.id, e.to_string(), e.error_code())
                    .with_missing_capabilities(vec![spec.capability.into()]),
            }
        } else {
            SimulateResponse::denied(
                req.id,
                "connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            )
        };
        serde_json::to_value(response).map_err(internal_json)
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({"status":"shutdown"}))
    }
}

impl Default for AppsScriptConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
async fn dispatch(client: &AppsScriptClient, operation: &str, input: &Value) -> FcpResult<Value> {
    bounded(dispatch_inner(client, operation, input).await?)
}

#[allow(clippy::too_many_lines)]
async fn dispatch_inner(
    client: &AppsScriptClient,
    operation: &str,
    input: &Value,
) -> FcpResult<Value> {
    match operation {
        "script.projects.get" => Ok(
            json!({"project": client.get_project(require_str(input, "script_id")?).await.map_err(|e| e.to_fcp_error())?}),
        ),
        "script.projects.get_content" => {
            let script_id = require_str(input, "script_id")?;
            let version = optional_i32(input, "version_number")?;
            let content = client
                .get_content(script_id, version)
                .await
                .map_err(|e| e.to_fcp_error())?;
            let (inventory, inventory_sha256) =
                source_inventory(&content.files).map_err(|e| e.to_fcp_error())?;
            let file = match optional_str(input, "file_name")? {
                Some(name) => {
                    let file = content
                        .files
                        .into_iter()
                        .find(|file| file.name == name)
                        .ok_or_else(|| FcpError::ResourceNotFound {
                            resource: "script source file".into(),
                        })?;
                    Some(source_chunk(
                        &file,
                        optional_usize(input, "source_offset")?.unwrap_or(0),
                        optional_usize(input, "source_limit")?.unwrap_or(48_000),
                    )?)
                }
                None => None,
            };
            bounded(
                json!({"script_id": content.script_id, "inventory": inventory, "inventory_sha256": inventory_sha256, "file": file}),
            )
        }
        "script.projects.create" => {
            let created = client
                .create_project(
                    require_str(input, "title")?,
                    optional_str(input, "parent_id")?,
                )
                .await
                .map_err(|e| e.to_fcp_error())?;
            let readback = client
                .get_project(&created.script_id)
                .await
                .map_err(|e| e.to_fcp_error())?;
            bounded(json!({"project": created, "readback": readback}))
        }
        "script.projects.update_content" => update_content(client, input).await,
        "script.projects.get_metrics" => Ok(
            json!({"metrics": client.get_metrics(require_str(input, "script_id")?, require_str(input, "granularity")?, optional_str(input, "deployment_id")?).await.map_err(|e| e.to_fcp_error())?}),
        ),
        "script.versions.create" => {
            let script_id = require_str(input, "script_id")?;
            let created = client
                .create_version(script_id, optional_str(input, "description")?)
                .await
                .map_err(|e| e.to_fcp_error())?;
            let readback = client
                .get_version(script_id, created.version_number)
                .await
                .map_err(|e| e.to_fcp_error())?;
            bounded(json!({"version": created, "readback": readback}))
        }
        "script.versions.get" => Ok(
            json!({"version": client.get_version(require_str(input, "script_id")?, require_i32(input, "version_number")?).await.map_err(|e| e.to_fcp_error())?}),
        ),
        "script.versions.list" => Ok(
            json!({"page": client.list_versions(require_str(input, "script_id")?, page_size(input)?, optional_str(input, "page_token")?).await.map_err(|e| e.to_fcp_error())?}),
        ),
        "script.deployments.get" => Ok(
            json!({"deployment": client.get_deployment(require_str(input, "script_id")?, require_str(input, "deployment_id")?).await.map_err(|e| e.to_fcp_error())?}),
        ),
        "script.deployments.list" => Ok(
            json!({"page": client.list_deployments(require_str(input, "script_id")?, page_size(input)?, optional_str(input, "page_token")?).await.map_err(|e| e.to_fcp_error())?}),
        ),
        "script.deployments.create" => {
            require_true(input, "confirm_deployment_change")?;
            let config: DeploymentConfig = value_as(input, "deployment_config")?;
            require_matching_script_id(require_str(input, "script_id")?, &config)?;
            let deployment = client
                .create_deployment(require_str(input, "script_id")?, &config)
                .await
                .map_err(|e| e.to_fcp_error())?;
            let readback = client
                .get_deployment(require_str(input, "script_id")?, &deployment.deployment_id)
                .await
                .map_err(|e| e.to_fcp_error())?;
            bounded(json!({"deployment": deployment, "readback": readback}))
        }
        "script.deployments.update" => {
            require_true(input, "confirm_deployment_change")?;
            let script_id = require_str(input, "script_id")?;
            let deployment_id = require_str(input, "deployment_id")?;
            let config: DeploymentConfig = value_as(input, "deployment_config")?;
            require_matching_script_id(script_id, &config)?;
            let preflight = client
                .get_deployment(script_id, deployment_id)
                .await
                .map_err(|e| e.to_fcp_error())?;
            let updated = client
                .update_deployment(script_id, deployment_id, &config)
                .await
                .map_err(|e| e.to_fcp_error())?;
            let readback = client
                .get_deployment(script_id, deployment_id)
                .await
                .map_err(|e| e.to_fcp_error())?;
            bounded(
                json!({"preflight": deployment_receipt(&preflight), "updated": deployment_receipt(&updated), "readback": deployment_receipt(&readback)}),
            )
        }
        "script.processes.list" => Ok(
            json!({"page": client.list_processes(None, &process_filter(input)?, page_size(input)?, optional_str(input, "page_token")?).await.map_err(|e| e.to_fcp_error())?}),
        ),
        "script.processes.list_for_project" => Ok(
            json!({"page": client.list_processes(Some(require_str(input, "script_id")?), &process_filter(input)?, page_size(input)?, optional_str(input, "page_token")?).await.map_err(|e| e.to_fcp_error())?}),
        ),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

async fn update_content(client: &AppsScriptClient, input: &Value) -> FcpResult<Value> {
    let replacement: SourceReplacement = serde_json::from_value(input.clone())
        .map_err(|e| invalid(format!("invalid source replacement: {e}")))?;
    if !replacement.confirm_replace_all_files {
        return Err(invalid(
            "confirm_replace_all_files must be true after reviewing the inventory diff",
        ));
    }
    let current = client
        .get_content(&replacement.script_id, None)
        .await
        .map_err(|e| e.to_fcp_error())?;
    let (before, before_digest) = source_inventory(&current.files).map_err(|e| e.to_fcp_error())?;
    // ubs:ignore -- inventory digests are public concurrency state, not secrets.
    if before_digest != replacement.expected_current_inventory_sha256 {
        return Err(invalid(
            "current source inventory changed; repeat preflight",
        ));
    }
    let (after_expected, after_digest) =
        source_inventory(&replacement.files).map_err(|e| e.to_fcp_error())?;
    let before_names = before
        .iter()
        .map(|v| v.name.clone())
        .collect::<BTreeSet<_>>();
    let after_names = after_expected
        .iter()
        .map(|v| v.name.clone())
        .collect::<BTreeSet<_>>();
    let removed = before_names
        .difference(&after_names)
        .cloned()
        .collect::<Vec<_>>();
    let mut expected_removed = replacement.expected_removed_files.clone();
    expected_removed.sort();
    if removed != expected_removed {
        return Err(invalid(
            "removed file list does not match expected_removed_files",
        ));
    }
    let version = client
        .create_version(&replacement.script_id, Some("FCP pre-update snapshot"))
        .await
        .map_err(|e| e.to_fcp_error())?;
    client
        .update_content(&replacement.script_id, &replacement.files)
        .await
        .map_err(|e| e.to_fcp_error())?;
    let readback = client
        .get_content(&replacement.script_id, None)
        .await
        .map_err(|e| e.to_fcp_error())?;
    let (after, readback_digest) =
        source_inventory(&readback.files).map_err(|e| e.to_fcp_error())?;
    // ubs:ignore -- inventory digests are public reconciliation state, not secrets.
    if readback_digest != after_digest {
        return Err(FcpError::External { service: "google_apps_script".into(), message: "source write reached provider but inventory readback did not match; outcome requires reconciliation".into(), status_code: None, retryable: false, retry_after: None });
    }
    let before_by_name = before
        .iter()
        .map(|v| (&v.name, &v.sha256))
        .collect::<BTreeMap<_, _>>();
    let after_by_name = after
        .iter()
        .map(|v| (&v.name, &v.sha256))
        .collect::<BTreeMap<_, _>>();
    let added = after_names
        .difference(&before_names)
        .cloned()
        .collect::<Vec<_>>();
    let changed = after_names
        .intersection(&before_names)
        .filter(|name| before_by_name.get(name) != after_by_name.get(name))
        .cloned()
        .collect::<Vec<_>>();
    bounded(
        json!({"snapshot_version": version.version_number, "before_inventory_sha256": before_digest, "after_inventory_sha256": readback_digest, "added_files": added, "changed_files": changed, "removed_files": removed, "readback": after}),
    )
}

#[derive(Clone, Copy)]
struct OperationSpec {
    id: &'static str,
    summary: &'static str,
    capability: &'static str,
    risk: RiskLevel,
    safety: SafetyTier,
    idempotency: IdempotencyClass,
}
impl OperationSpec {
    fn info(self) -> OperationInfo {
        OperationInfo {
            id: OperationId::from_static(self.id),
            summary: self.summary.into(),
            description: None,
            input_schema: input_schema(self.id),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(self.capability),
            risk_level: self.risk,
            safety_tier: self.safety,
            idempotency: self.idempotency,
            ai_hints: AgentHint {
                when_to_use: self.summary.into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: (!matches!(self.safety, SafetyTier::Safe))
                .then_some(ApprovalMode::Policy),
        }
    }
}
fn input_schema(operation: &str) -> Value {
    let string = || json!({"type":"string","minLength":1,"maxLength":512});
    let page = || {
        json!({
            "page_size":{"type":"integer","minimum":1,"maximum":50},
            "page_token":{"type":"string","minLength":1,"maxLength":4096}
        })
    };
    match operation {
        "script.projects.get" => {
            json!({"type":"object","required":["script_id"],"properties":{"script_id":string()},"additionalProperties":false})
        }
        "script.projects.get_content" => {
            json!({"type":"object","required":["script_id"],"properties":{"script_id":string(),"version_number":{"type":"integer","minimum":1},"file_name":{"type":"string","minLength":1,"maxLength":512},"source_offset":{"type":"integer","minimum":0},"source_limit":{"type":"integer","minimum":1,"maximum":48000}},"additionalProperties":false})
        }
        "script.projects.create" => {
            json!({"type":"object","required":["title"],"properties":{"title":{"type":"string","minLength":1,"maxLength":256},"parent_id":string()},"additionalProperties":false})
        }
        "script.projects.update_content" => {
            json!({"type":"object","required":["script_id","files","expected_current_inventory_sha256","expected_removed_files","confirm_replace_all_files"],"properties":{"script_id":string(),"files":{"type":"array","minItems":1,"maxItems":200,"items":{"type":"object","required":["name","type","source"],"properties":{"name":{"type":"string","minLength":1,"maxLength":128},"type":{"type":"string","enum":["SERVER_JS","HTML","JSON"]},"source":{"type":"string"}},"additionalProperties":false}},"expected_current_inventory_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"expected_removed_files":{"type":"array","items":{"type":"string","minLength":1,"maxLength":128},"uniqueItems":true},"confirm_replace_all_files":{"const":true}},"additionalProperties":false})
        }
        "script.projects.get_metrics" => {
            json!({"type":"object","required":["script_id","granularity"],"properties":{"script_id":string(),"granularity":{"type":"string","enum":["DAILY","WEEKLY"]},"deployment_id":string()},"additionalProperties":false})
        }
        "script.versions.create" => {
            json!({"type":"object","required":["script_id"],"properties":{"script_id":string(),"description":{"type":"string","maxLength":512}},"additionalProperties":false})
        }
        "script.versions.get" => {
            json!({"type":"object","required":["script_id","version_number"],"properties":{"script_id":string(),"version_number":{"type":"integer","minimum":1}},"additionalProperties":false})
        }
        "script.versions.list" | "script.deployments.list" => {
            let mut properties = page().as_object().cloned().unwrap_or_default();
            properties.insert("script_id".into(), string());
            json!({"type":"object","required":["script_id"],"properties":properties,"additionalProperties":false})
        }
        "script.deployments.get" => {
            json!({"type":"object","required":["script_id","deployment_id"],"properties":{"script_id":string(),"deployment_id":string()},"additionalProperties":false})
        }
        "script.deployments.create" => {
            json!({"type":"object","required":["script_id","deployment_config","confirm_deployment_change"],"properties":{"script_id":string(),"deployment_config":deployment_config_schema(),"confirm_deployment_change":{"const":true}},"additionalProperties":false})
        }
        "script.deployments.update" => {
            json!({"type":"object","required":["script_id","deployment_id","deployment_config","confirm_deployment_change"],"properties":{"script_id":string(),"deployment_id":string(),"deployment_config":deployment_config_schema(),"confirm_deployment_change":{"const":true}},"additionalProperties":false})
        }
        "script.processes.list" => {
            json!({"type":"object","properties":process_filter_schema(false),"additionalProperties":false})
        }
        "script.processes.list_for_project" => {
            json!({"type":"object","required":["script_id"],"properties":process_filter_schema(true),"additionalProperties":false})
        }
        _ => json!({"type":"object","additionalProperties":false}),
    }
}
fn deployment_config_schema() -> Value {
    json!({"type":"object","required":["script_id","version_number","manifest_file_name"],"properties":{"script_id":{"type":"string","minLength":1,"maxLength":512},"version_number":{"type":"integer","minimum":1},"manifest_file_name":{"type":"string","minLength":1,"maxLength":128},"description":{"type":"string","maxLength":512}},"additionalProperties":false})
}
fn process_filter_schema(include_script_id: bool) -> Value {
    let mut properties = serde_json::Map::new();
    if include_script_id {
        properties.insert(
            "script_id".into(),
            json!({"type":"string","minLength":1,"maxLength":512}),
        );
    }
    properties.insert(
        "page_size".into(),
        json!({"type":"integer","minimum":1,"maximum":50}),
    );
    properties.insert(
        "page_token".into(),
        json!({"type":"string","minLength":1,"maxLength":4096}),
    );
    for name in ["function_name", "deployment_id"] {
        properties.insert(
            name.into(),
            json!({"type":"string","minLength":1,"maxLength":512}),
        );
    }
    for name in ["start_time", "end_time"] {
        properties.insert(name.into(), json!({"type":"string","format":"date-time"}));
    }
    properties.insert(
        "types".into(),
        enum_array_schema(&[
            "ADD_ON",
            "EXECUTION_API",
            "TIME_DRIVEN",
            "TRIGGER",
            "WEBAPP",
            "EDITOR",
            "SIMPLE_TRIGGER",
            "MENU",
            "BATCH_TASK",
        ]),
    );
    properties.insert(
        "statuses".into(),
        enum_array_schema(&[
            "RUNNING",
            "PAUSED",
            "COMPLETED",
            "CANCELED",
            "FAILED",
            "TIMED_OUT",
            "UNKNOWN",
            "DELAYED",
            "EXECUTION_DISABLED",
        ]),
    );
    properties.insert(
        "user_access_levels".into(),
        enum_array_schema(&["NONE", "READ", "WRITE", "OWNER"]),
    );
    Value::Object(properties)
}
fn enum_array_schema(values: &[&str]) -> Value {
    json!({"type":"array","maxItems":10,"uniqueItems":true,"items":{"type":"string","enum":values}})
}
#[allow(clippy::too_many_lines)]
fn operation_specs() -> Vec<OperationSpec> {
    use IdempotencyClass::{None as No, Strict};
    use RiskLevel::{High, Low, Medium};
    use SafetyTier::{Dangerous, Risky, Safe};
    vec![
        OperationSpec {
            id: "script.projects.get",
            summary: "Get Apps Script project metadata",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
        OperationSpec {
            id: "script.projects.get_content",
            summary: "Get bounded source inventory or one source file",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
        OperationSpec {
            id: "script.projects.create",
            summary: "Create an Apps Script project",
            capability: "script.source.write",
            risk: Medium,
            safety: Risky,
            idempotency: No,
        },
        OperationSpec {
            id: "script.projects.update_content",
            summary: "Replace complete Apps Script project source",
            capability: "script.source.write",
            risk: High,
            safety: Dangerous,
            idempotency: No,
        },
        OperationSpec {
            id: "script.projects.get_metrics",
            summary: "Read Apps Script project metrics",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
        OperationSpec {
            id: "script.versions.create",
            summary: "Create a restorable Apps Script version",
            capability: "script.source.write",
            risk: Medium,
            safety: Risky,
            idempotency: No,
        },
        OperationSpec {
            id: "script.versions.get",
            summary: "Get an Apps Script version",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
        OperationSpec {
            id: "script.versions.list",
            summary: "List Apps Script versions",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
        OperationSpec {
            id: "script.deployments.get",
            summary: "Get an Apps Script deployment",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
        OperationSpec {
            id: "script.deployments.list",
            summary: "List Apps Script deployments",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
        OperationSpec {
            id: "script.deployments.create",
            summary: "Create an Apps Script deployment",
            capability: "script.deployment.write",
            risk: High,
            safety: Dangerous,
            idempotency: No,
        },
        OperationSpec {
            id: "script.deployments.update",
            summary: "Update an Apps Script deployment",
            capability: "script.deployment.write",
            risk: High,
            safety: Dangerous,
            idempotency: No,
        },
        OperationSpec {
            id: "script.processes.list",
            summary: "List Apps Script process history",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
        OperationSpec {
            id: "script.processes.list_for_project",
            summary: "List process history for one Apps Script project",
            capability: "script.read",
            risk: Low,
            safety: Safe,
            idempotency: Strict,
        },
    ]
}

fn resources(operation: &str, input: &Value) -> FcpResult<Vec<String>> {
    let root = if operation == "script.projects.create" {
        "google-apps-script:projects".into()
    } else if let Ok(id) = require_str(input, "script_id") {
        format!("google-apps-script:project:{id}")
    } else if operation == "script.processes.list" {
        "google-apps-script:processes".into()
    } else {
        return Err(invalid("missing script_id"));
    };
    let mut resources = vec![root];
    if matches!(
        operation,
        "script.deployments.get" | "script.deployments.update"
    ) {
        resources.push(format!(
            "google-apps-script:deployment:{}",
            require_str(input, "deployment_id")?
        ));
    }
    Ok(resources)
}
fn validate_base_url(raw: &str) -> FcpResult<String> {
    let url = Url::parse(raw.trim()).map_err(|e| invalid(format!("invalid base_url: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid("base_url requires host"))?;
    let local = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if (!local && (url.scheme() != "https" || host != "script.googleapis.com"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "base_url must be exact https://script.googleapis.com/v1 (loopback allowed for tests)",
        ));
    }
    Ok(raw.trim().trim_end_matches('/').into())
}
fn require_str<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing '{field}'")))
}
fn optional_str<'a>(value: &'a Value, field: &str) -> FcpResult<Option<&'a str>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .map(Some)
            .ok_or_else(|| invalid(format!("'{field}' must be a string"))),
    }
}
fn require_i32(value: &Value, field: &str) -> FcpResult<i32> {
    optional_i32(value, field)?.ok_or_else(|| invalid(format!("missing '{field}'")))
}
fn optional_i32(value: &Value, field: &str) -> FcpResult<Option<i32>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| invalid(format!("'{field}' must be a 32-bit integer"))),
    }
}
fn optional_usize(value: &Value, field: &str) -> FcpResult<Option<usize>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| invalid(format!("'{field}' must be a non-negative integer"))),
    }
}
fn page_size(value: &Value) -> FcpResult<u16> {
    value.get("page_size").map_or(Ok(50), |v| {
        v.as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| (1..=50).contains(n))
            .ok_or_else(|| invalid("page_size must be 1..=50"))
    })
}
fn require_true(value: &Value, field: &str) -> FcpResult<()> {
    if value.get(field).and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(invalid(format!(
            "'{field}' must be true after preflight review"
        )))
    }
}
fn value_as<T: DeserializeOwned>(value: &Value, field: &str) -> FcpResult<T> {
    serde_json::from_value(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| invalid(format!("missing '{field}'")))?,
    )
    .map_err(|e| invalid(format!("invalid '{field}': {e}")))
}
fn process_filter(input: &Value) -> FcpResult<ProcessFilter> {
    serde_json::from_value(json!({
        "function_name": input.get("function_name"),
        "deployment_id": input.get("deployment_id"),
        "start_time": input.get("start_time"),
        "end_time": input.get("end_time"),
        "types": input.get("types").cloned().unwrap_or_else(|| json!([])),
        "statuses": input.get("statuses").cloned().unwrap_or_else(|| json!([])),
        "user_access_levels": input.get("user_access_levels").cloned().unwrap_or_else(|| json!([]))
    }))
    .map_err(|e| invalid(format!("invalid process filter: {e}")))
}
fn require_matching_script_id(script_id: &str, config: &DeploymentConfig) -> FcpResult<()> {
    if config.script_id == script_id {
        Ok(())
    } else {
        Err(invalid(
            "deployment_config.script_id must match the target script_id",
        ))
    }
}
fn source_chunk(file: &ScriptFile, offset: usize, limit: usize) -> FcpResult<Value> {
    if limit == 0 || limit > 48_000 {
        return Err(invalid("source_limit must be 1..=48000 bytes"));
    }
    if offset > file.source.len() || !file.source.is_char_boundary(offset) {
        return Err(invalid(
            "source_offset must be a UTF-8 byte boundary within the file",
        ));
    }
    let mut end = offset.saturating_add(limit).min(file.source.len());
    while end > offset && !file.source.is_char_boundary(end) {
        end -= 1;
    }
    let next_source_offset = (end < file.source.len()).then_some(end);
    Ok(json!({
        "name": file.name,
        "type": file.file_type,
        "source": &file.source[offset..end],
        "source_offset": offset,
        "next_source_offset": next_source_offset,
        "total_source_bytes": file.source.len()
    }))
}
fn deployment_receipt(value: &crate::types::Deployment) -> Value {
    json!({"deployment_id": value.deployment_id, "version_number": value.deployment_config.version_number, "entry_point_count": value.entry_points.len(), "update_time_present": value.update_time.is_some()})
}
fn bounded(value: Value) -> FcpResult<Value> {
    let bytes = serde_json::to_vec(&value).map_err(internal_json)?;
    if bytes.len() > 60_000 {
        Err(invalid(
            "result exceeds 60000-byte connector budget; narrow the request",
        ))
    } else {
        Ok(value)
    }
}
fn invalid(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}
#[allow(clippy::needless_pass_by_value)]
fn internal_json(error: serde_json::Error) -> FcpError {
    FcpError::Internal {
        message: format!("JSON serialization failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{client::AppsScriptClient, types::FileType};
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
    use fcp_prelude::CapabilityConstraints;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn auth() -> GoogleMaterializedAuth {
        GoogleMaterializedAuth::BearerToken {
            access_token: ["test", "token", "never", "log"].join("-"),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: vec![],
            quota_project_id: None,
        }
    }

    fn files() -> Vec<ScriptFile> {
        vec![
            ScriptFile {
                name: "appsscript".into(),
                file_type: FileType::Json,
                source: r#"{"timeZone":"Etc/UTC"}"#.into(),
            },
            ScriptFile {
                name: "Code".into(),
                file_type: FileType::ServerJs,
                source: "function fixture() { return true; }".into(),
            },
        ]
    }

    #[test]
    fn source_chunks_are_utf8_safe_and_bounded() {
        let file = ScriptFile {
            name: "Code".into(),
            file_type: FileType::ServerJs,
            source: "абвгд".into(),
        };
        let first = source_chunk(&file, 0, 5).expect("first chunk");
        assert_eq!(first["source"], "аб");
        assert_eq!(first["next_source_offset"], 4);
        let second = source_chunk(&file, 4, 48_000).expect("second chunk");
        assert_eq!(second["source"], "вгд");
        assert!(second["next_source_offset"].is_null());
        assert!(source_chunk(&file, 1, 10).is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn replacement_creates_snapshot_writes_and_reads_back() {
        let server = MockServer::start().await;
        let files = files();
        Mock::given(method("GET"))
            .and(path("/v1/projects/script_123/content"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "scriptId": "script_123",
                "files": files
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/projects/script_123/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "scriptId": "script_123",
                "versionNumber": 7
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/v1/projects/script_123/content"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "scriptId": "script_123",
                "files": files
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = AppsScriptClient::new_with_auth(auth())
            .expect("client")
            .with_base_url(format!("{}/v1", server.uri()));
        let (_, digest) = source_inventory(&files).expect("inventory");
        let result = update_content(
            &client,
            &json!({
                "script_id": "script_123",
                "files": files,
                "expected_current_inventory_sha256": digest,
                "expected_removed_files": [],
                "confirm_replace_all_files": true
            }),
        )
        .await
        .expect("safe replacement");
        assert_eq!(result["snapshot_version"], 7);
        assert_eq!(result["added_files"], json!([]));
        assert_eq!(result["removed_files"], json!([]));
    }

    #[fcp_async_core::runtime::test]
    async fn omitted_existing_file_is_rejected_before_provider_write() {
        let server = MockServer::start().await;
        let current = files();
        Mock::given(method("GET"))
            .and(path("/v1/projects/script_123/content"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "scriptId": "script_123",
                "files": current
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let client = AppsScriptClient::new_with_auth(auth())
            .expect("client")
            .with_base_url(format!("{}/v1", server.uri()));
        let (_, digest) = source_inventory(&current).expect("inventory");
        let replacement = vec![current[0].clone()];
        let error = update_content(
            &client,
            &json!({
                "script_id": "script_123",
                "files": replacement,
                "expected_current_inventory_sha256": digest,
                "expected_removed_files": [],
                "confirm_replace_all_files": true
            }),
        )
        .await
        .expect_err("omitted file must require exact removal acknowledgement");
        assert!(error.to_string().contains("expected_removed_files"));
    }

    #[fcp_async_core::runtime::test]
    async fn wrong_capability_is_denied_before_provider_io() {
        let server = MockServer::start().await;
        let signing_key = Ed25519SigningKey::generate();
        let instance_id = fcp_core::InstanceId::new();
        let mut connector = AppsScriptConnector::new();
        connector
            .handle_configure(json!({
                "access_token": (["test", "token"].join("-")),
                "base_url": format!("{}/v1", server.uri())
            }))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:private",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0_u8; 32],
                "capabilities_requested": ["script.read", "script.source.write"],
                "requested_instance_id": instance_id
            }))
            .await
            .expect("handshake");
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..CapabilityConstraints::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
        let now = Utc::now();
        let token = CapabilityTokenBuilder::new()
            .capability_id("script.source.write")
            .zone_id("z:private")
            .principal("user:test")
            .operations(&["script.projects.get"])
            .issuer("node:test")
            .audience("*")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("attach constraints")
            .target_instance(instance_id.as_str())
            .sign(&signing_key)
            .expect("sign capability token");
        let error = connector
            .handle_invoke(json!({
                "operation": "script.projects.get",
                "input": {"script_id": "script_123"},
                "capability_token": CapabilityToken::from_raw(token)
            }))
            .await
            .expect_err("wrong capability must be denied");
        assert!(
            matches!(
                error,
                FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
            ),
            "unexpected error: {error:?}"
        );
        assert!(
            server
                .received_requests()
                .await
                .expect("received requests")
                .is_empty()
        );
    }
}
