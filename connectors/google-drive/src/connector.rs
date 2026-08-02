//! FCP Google Drive Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;

use chrono::Utc;
use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, Introspection, OperationId, OperationInfo, SelfCheckReport, SessionId,
    SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_drive_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("www.googleapis.com")
}

/// Validate a google-drive `base_url` override.
///
/// Pins the host to Drive's API host (localhost permitted for tests),
/// requires https on any non-local host, and rejects userinfo / query /
/// fragment components because DriveClient concatenates the returned
/// string into downstream request URLs via `format!("{base_url}/...", ...)`.
fn validate_drive_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }
    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    if !local && !host_is_drive_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target www.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn drive_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        "drive.list_files"
        | "drive.parse_url"
        | "drive.list_shared_with_me"
        | "drive.list_drives"
        | "drive.get_file"
        | "drive.list_permissions"
        | "drive.list_revisions"
        | "drive.list_comments"
        | "drive.about"
        | "drive.download_file"
        | "drive.export_file" => Ok(CapabilityId::from_static("drive.read")),
        "drive.add_permission" | "drive.update_permission" | "drive.revoke_permission" => {
            Ok(CapabilityId::from_static("drive.share.write"))
        }
        "drive.mark_for_deletion_review"
        | "drive.restore_from_deletion_review"
        | "drive.restore_file" => Ok(CapabilityId::from_static("drive.quarantine.write")),
        "drive.list_deletion_review" => Ok(CapabilityId::from_static("drive.read")),
        "drive.upload_file" | "drive.copy_file" => {
            Ok(CapabilityId::from_static("drive.content.write"))
        }
        "drive.create_folder"
        | "drive.update_metadata"
        | "drive.move_file"
        | "drive.create_shortcut"
        | "drive.create_comment"
        | "drive.create_reply" => Ok(CapabilityId::from_static("drive.metadata.write")),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn validate_drive_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    reject_forbidden_drive_input(input)?;
    match operation {
        "drive.list_files" | "drive.list_shared_with_me" | "drive.list_drives" | "drive.about" => {}
        "drive.parse_url" => {
            require_str(input, "url")?;
        }
        "drive.get_file"
        | "drive.download_file"
        | "drive.list_permissions"
        | "drive.list_revisions"
        | "drive.list_comments"
        | "drive.restore_file"
        | "drive.mark_for_deletion_review" => {
            require_str(input, "file_id")?;
            if operation == "drive.mark_for_deletion_review" {
                if let Some(mode) = optional_str(input, "mode") {
                    if !matches!(mode, "default" | "move_shared_drive_original") {
                        return Err(FcpError::InvalidRequest {
                            code: 1003,
                            message: "mode must be default or move_shared_drive_original".into(),
                        });
                    }
                }
            }
        }
        "drive.list_deletion_review" => {}
        "drive.restore_from_deletion_review" => {
            let receipt = input
                .get("receipt")
                .and_then(serde_json::Value::as_object)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required object: receipt".into(),
                })?;
            for field in ["file_id", "original_name", "review_folder_id", "mode"] {
                if !receipt.get(field).is_some_and(serde_json::Value::is_string) {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("receipt is missing string field: {field}"),
                    });
                }
            }
            if !matches!(
                receipt.get("mode").and_then(serde_json::Value::as_str),
                Some("owned_move" | "shared_drive_move" | "shortcut")
            ) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "receipt mode is not recognized".into(),
                });
            }
        }
        "drive.export_file" => {
            require_str(input, "file_id")?;
            require_str(input, "mime_type")?;
        }
        "drive.create_folder" => {
            require_str(input, "name")?;
        }
        "drive.upload_file" => {
            require_str(input, "name")?;
            require_str(input, "mime_type")?;
            require_str(input, "content_base64")?;
        }
        "drive.update_metadata" => {
            require_str(input, "file_id")?;
            let patch = input
                .get("patch")
                .and_then(serde_json::Value::as_object)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required object: patch".into(),
                })?;
            if patch.is_empty()
                || patch
                    .keys()
                    .any(|key| !SAFE_METADATA_FIELDS.contains(&key.as_str()))
            {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "patch contains unsupported metadata field".into(),
                });
            }
        }
        "drive.move_file" => {
            require_str(input, "file_id")?;
            require_str(input, "add_parent")?;
        }
        "drive.copy_file" => {
            require_str(input, "file_id")?;
        }
        "drive.create_shortcut" => {
            require_str(input, "name")?;
            require_str(input, "target_id")?;
        }
        "drive.create_comment" => {
            require_str(input, "file_id")?;
            require_str(input, "content")?;
        }
        "drive.create_reply" => {
            require_str(input, "file_id")?;
            require_str(input, "comment_id")?;
            require_str(input, "content")?;
        }
        "drive.add_permission" => {
            require_str(input, "file_id")?;
            let permission_type = require_str(input, "permission_type")?;
            if !matches!(permission_type, "user" | "group" | "domain" | "anyone") {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid permission_type".into(),
                });
            }
            let role = require_str(input, "role")?;
            if !matches!(role, "reader" | "commenter" | "writer" | "organizer") {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid role; expected reader, commenter, writer, or organizer"
                        .into(),
                });
            }
            if matches!(permission_type, "user" | "group") {
                require_str(input, "email")?;
            }
            if permission_type == "domain" {
                require_str(input, "domain")?;
            }
        }
        "drive.update_permission" => {
            require_str(input, "file_id")?;
            require_str(input, "permission_id")?;
            require_str(input, "role")?;
        }
        "drive.revoke_permission" => {
            require_str(input, "file_id")?;
            require_str(input, "permission_id")?;
        }
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    }
    Ok(())
}

fn drive_resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    match operation {
        "drive.list_files" | "drive.list_shared_with_me" | "drive.parse_url" => {
            Ok(vec!["drive://files".into()])
        }
        "drive.list_drives" => Ok(vec!["drive://shared-drives".into()]),
        "drive.get_file"
        | "drive.download_file"
        | "drive.export_file"
        | "drive.list_permissions"
        | "drive.list_revisions"
        | "drive.list_comments"
        | "drive.update_metadata"
        | "drive.move_file"
        | "drive.copy_file"
        | "drive.create_comment"
        | "drive.restore_file"
        | "drive.mark_for_deletion_review" => {
            let file_id = require_str(input, "file_id")?;
            Ok(vec![format!("drive://files/{file_id}")])
        }
        "drive.list_deletion_review" => Ok(vec!["drive://deletion-review".into()]),
        "drive.restore_from_deletion_review" => {
            let receipt = input.get("receipt").expect("validated receipt");
            let file_id = require_str(receipt, "file_id")?;
            Ok(vec![format!("drive://files/{file_id}")])
        }
        "drive.create_reply" => {
            let file_id = require_str(input, "file_id")?;
            let comment_id = require_str(input, "comment_id")?;
            Ok(vec![format!(
                "drive://files/{file_id}/comments/{comment_id}"
            )])
        }
        "drive.add_permission" | "drive.update_permission" | "drive.revoke_permission" => {
            let file_id = require_str(input, "file_id")?;
            Ok(vec![format!("drive://files/{file_id}/permissions")])
        }
        "drive.create_folder" | "drive.upload_file" => {
            let parent_id = input
                .get("parent_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("root");
            Ok(vec![format!("drive://folders/{parent_id}/children")])
        }
        "drive.create_shortcut" => {
            let parent_id = input
                .get("parent_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("root");
            Ok(vec![format!("drive://folders/{parent_id}/children")])
        }
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

use crate::{
    client::{DEFAULT_BASE_URL, DriveClient},
    error::DriveError,
    types::{DoctorCheck, DoctorReport},
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: &[&str] = &[
    "drive.parse_url",
    "drive.list_files",
    "drive.list_shared_with_me",
    "drive.list_drives",
    "drive.get_file",
    "drive.list_permissions",
    "drive.list_revisions",
    "drive.list_comments",
    "drive.about",
    "drive.download_file",
    "drive.export_file",
    "drive.create_folder",
    "drive.upload_file",
    "drive.update_metadata",
    "drive.move_file",
    "drive.copy_file",
    "drive.create_shortcut",
    "drive.create_comment",
    "drive.create_reply",
    "drive.add_permission",
    "drive.update_permission",
    "drive.revoke_permission",
    "drive.mark_for_deletion_review",
    "drive.list_deletion_review",
    "drive.restore_from_deletion_review",
    "drive.restore_file",
];
const REVIEW_FOLDER_NAME: &str = "_FCP_DELETE_REVIEW";
const REVIEW_PREFIX: &str = "[FCP-DELETE-REVIEW ";
const SAFE_METADATA_FIELDS: &[&str] = &[
    "name",
    "description",
    "starred",
    "viewedByMeTime",
    "modifiedTime",
];

/// FCP Google Drive Connector.
pub struct DriveConnector {
    base: Arc<BaseConnector>,
    client: Option<DriveClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl DriveConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("google-drive"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let selection = GoogleAuthSelection::from_connector_config(&params).map_err(|error| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Google auth configuration: {error}"),
            }
        })?;

        let materialized =
            selection
                .materialize()
                .await
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Failed to materialize Google auth: {error}"),
                })?;

        let status = match &materialized {
            GoogleMaterializedAuth::CredentialReference { .. } => {
                "configured_pending_token_materialization"
            }
            GoogleMaterializedAuth::BearerToken { .. } => "configured",
        };

        let base_url = match params.get("base_url") {
            Some(value) => {
                validate_drive_base_url(value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "`base_url` must be a string".into(),
                })?)?
            }
            None => DEFAULT_BASE_URL.to_string(),
        };

        let client = DriveClient::new_with_auth(materialized)
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?
            .with_base_url(&base_url);

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth_label, status, "Drive connector configured");

        Ok(json!({ "status": status }))
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

        let verifier_instance_id = req
            .requested_instance_id
            .clone()
            .unwrap_or_else(|| self.base.instance_id.clone());

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            verifier_instance_id,
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

    /// Handle doctor diagnostics.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Client configured
        let client_present = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_configured".into(),
            passed: client_present,
            message: if client_present {
                "Google Drive client is configured".into()
            } else {
                "No client configured — call configure with valid Google credentials".into()
            },
        });

        if !client_present {
            let report = DoctorReport {
                ready: false,
                checks,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize doctor report: {e}"),
            });
        }

        let client = self.client.as_ref().expect("checked above");

        // Check 2: API reachability via about endpoint
        match client.about().await {
            Ok(about) => {
                checks.push(DoctorCheck {
                    name: "api_reachable".into(),
                    passed: true,
                    message: format!(
                        "Drive API reachable — user: {}",
                        about
                            .user
                            .as_ref()
                            .and_then(|u| u.display_name.as_deref())
                            .unwrap_or("unknown")
                    ),
                });

                // Check 3: Storage quota
                if let Some(quota) = &about.storage_quota {
                    let has_limit = quota.limit.is_some();
                    checks.push(DoctorCheck {
                        name: "storage_quota".into(),
                        passed: true,
                        message: if has_limit {
                            let usage = quota.usage.as_deref().unwrap_or("0");
                            let limit = quota.limit.as_deref().unwrap_or("0");
                            format!("Storage quota: {usage} / {limit} bytes")
                        } else {
                            "Storage quota: unlimited".into()
                        },
                    });
                }
            }
            Err(e) => {
                checks.push(DoctorCheck {
                    name: "api_reachable".into(),
                    passed: false,
                    message: format!("Drive API unreachable: {e}"),
                });
            }
        }

        let ready = checks.iter().all(|c| c.passed);
        let report = DoctorReport { ready, checks };
        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor report: {e}"),
        })
    }

    /// Handle connector self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match client.health_check().await {
            Ok(()) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "api_reachable": true,
                    "base_url": DEFAULT_BASE_URL,
                }));
                report
            }
            Err(e) => {
                if e.is_retryable() {
                    SelfCheckReport::degraded("api_transient_error", e.to_string())
                } else {
                    SelfCheckReport::failed("api_unreachable", e.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: operations_info(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;
        let operation = req.operation.as_str();
        let response = match drive_capability_for_operation(operation) {
            Ok(capability) => {
                if let Err(error) = validate_drive_input(operation, &req.input) {
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code())
                } else if self.client.is_none() {
                    SimulateResponse::denied(
                        req.id,
                        "Connector is not configured",
                        FcpError::NotConfigured.error_code(),
                    )
                } else if let Some(verifier) = &self.verifier {
                    let resource_uris = drive_resource_uris_for_operation(operation, &req.input)?;
                    match verifier.verify_bound(
                        req.capability_token,
                        &capability,
                        &req.operation,
                        &resource_uris,
                    ) {
                        Ok(_) => SimulateResponse::allowed(req.id),
                        Err(error) => {
                            let is_grant_mismatch = matches!(
                                error,
                                FcpError::CapabilityDenied { .. }
                                    | FcpError::OperationNotGranted { .. }
                            );
                            let mut response = SimulateResponse::denied(
                                req.id,
                                error.to_string(),
                                error.error_code(),
                            );
                            if is_grant_mismatch {
                                response = response
                                    .with_missing_capabilities(vec![capability.to_string()]);
                            }
                            response
                        }
                    }
                } else {
                    SimulateResponse::denied(
                        req.id,
                        "Connector handshake not completed",
                        FcpError::NotHandshaken.error_code(),
                    )
                }
            }
            Err(error) => SimulateResponse::denied(req.id, error.to_string(), error.error_code()),
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

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
        let capability =
            serde_json::from_value::<CapabilityToken>(token_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid capability_token format: {e}"),
                }
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id = drive_capability_for_operation(operation)?;
        validate_drive_input(operation, &input)?;
        let resource_uris = drive_resource_uris_for_operation(operation, &input)?;

        if let Some(verifier) = &self.verifier {
            verifier.verify_bound(capability, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "drive.parse_url" => Self::invoke_parse_url(&input),
            "drive.list_files" => self.invoke_list_files(input).await,
            "drive.list_shared_with_me" => self.invoke_list_shared_with_me(input).await,
            "drive.list_drives" => self.invoke_list_drives(input).await,
            "drive.get_file" => self.invoke_get_file(input).await,
            "drive.list_permissions" => self.invoke_file_collection(input, "permissions").await,
            "drive.list_revisions" => self.invoke_file_collection(input, "revisions").await,
            "drive.list_comments" => self.invoke_file_collection(input, "comments").await,
            "drive.about" => self.invoke_about().await,
            "drive.download_file" => self.invoke_download_file(input).await,
            "drive.export_file" => self.invoke_export_file(input).await,
            "drive.create_folder" => self.invoke_create_folder(input).await,
            "drive.upload_file" => self.invoke_upload_file(input).await,
            "drive.update_metadata" => self.invoke_update_metadata(input).await,
            "drive.move_file" => self.invoke_move_file(input).await,
            "drive.copy_file" => self.invoke_copy_file(input).await,
            "drive.create_shortcut" => self.invoke_create_shortcut(input).await,
            "drive.create_comment" => self.invoke_create_comment(input).await,
            "drive.create_reply" => self.invoke_create_reply(input).await,
            "drive.add_permission" => self.invoke_add_permission(input).await,
            "drive.update_permission" => self.invoke_update_permission(input).await,
            "drive.revoke_permission" => self.invoke_revoke_permission(input).await,
            "drive.mark_for_deletion_review" => self.invoke_mark_for_deletion_review(input).await,
            "drive.list_deletion_review" => self.invoke_list_deletion_review(input).await,
            "drive.restore_from_deletion_review" => {
                self.invoke_restore_from_deletion_review(input).await
            }
            "drive.restore_file" => self.invoke_restore_file(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_list_files(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = input.get("query").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_cursor = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_files(
                query,
                max_results,
                page_cursor,
                input.get("corpora").and_then(|v| v.as_str()),
                input.get("drive_id").and_then(|v| v.as_str()),
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({
            "files": result.files,
            "next_page_token": result.next_page_token
        }))
    }

    fn invoke_parse_url(input: &serde_json::Value) -> FcpResult<serde_json::Value> {
        let raw = require_str(input, "url")?;
        let parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid Drive URL: {error}"),
        })?;
        if parsed.scheme() != "https"
            || !matches!(
                parsed.host_str(),
                Some("drive.google.com" | "docs.google.com")
            )
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Drive URL must use https on drive.google.com or docs.google.com".into(),
            });
        }
        let segments = parsed
            .path_segments()
            .map(|parts| parts.collect::<Vec<_>>())
            .unwrap_or_default();
        let file_id = parsed
            .query_pairs()
            .find(|(key, _)| key == "id")
            .map(|(_, value)| value.into_owned())
            .or_else(|| {
                segments.windows(2).find_map(|window| {
                    matches!(window[0], "d" | "folders").then(|| window[1].to_string())
                })
            })
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Drive URL does not contain a file or folder ID".into(),
            })?;
        if file_id.trim().is_empty() || file_id.contains('/') || file_id.contains('\\') {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Drive URL contains an invalid file ID".into(),
            });
        }
        let resource_key = parsed
            .query_pairs()
            .find(|(key, _)| key.eq_ignore_ascii_case("resourcekey"))
            .map(|(_, value)| value.into_owned());
        Ok(json!({"file_id": file_id, "resource_key": resource_key}))
    }

    async fn invoke_list_shared_with_me(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let result = client
            .list_shared_with_me(
                input.get("query").and_then(|v| v.as_str()),
                optional_u32(&input, "page_size")?,
                input.get("page_token").and_then(|v| v.as_str()),
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"files": result.files, "next_page_token": result.next_page_token}))
    }

    async fn invoke_list_drives(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        client
            .list_drives(
                optional_u32(&input, "page_size")?,
                input.get("page_token").and_then(|v| v.as_str()),
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())
    }

    async fn invoke_get_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;

        let file = client
            .get_file(file_id, optional_str(&input, "resource_key"))
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({ "file": file }))
    }

    async fn invoke_about(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let about = client
            .about()
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"about": about}))
    }

    async fn invoke_download_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;

        let content = client
            .download_file(file_id, optional_str(&input, "resource_key"))
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({
            "file_id": file_id,
            "content_base64": content
        }))
    }

    async fn invoke_export_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;
        let mime_type = require_str(&input, "mime_type")?;
        let content = client
            .export_file(file_id, mime_type, optional_str(&input, "resource_key"))
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"file_id": file_id, "mime_type": mime_type, "content_base64": content}))
    }

    async fn invoke_file_collection(
        &self,
        input: serde_json::Value,
        collection: &str,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;
        let key = optional_str(&input, "resource_key");
        match collection {
            "permissions" => client.list_permissions(file_id, key).await,
            "revisions" => client.list_revisions(file_id, key).await,
            "comments" => client.list_comments(file_id, key).await,
            _ => unreachable!("bounded collection selector"),
        }
        .map_err(|e: DriveError| e.to_fcp_error())
    }

    async fn invoke_create_folder(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let name = require_str(&input, "name")?;
        let parent_id = input.get("parent_id").and_then(|v| v.as_str());

        let folder = client
            .create_folder(name, parent_id)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({ "folder": folder }))
    }

    async fn invoke_upload_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let name = require_str(&input, "name")?;
        let mime_type = require_str(&input, "mime_type")?;
        let content = require_str(&input, "content_base64")?;
        let parent_id = input.get("parent_id").and_then(|v| v.as_str());

        let file = client
            .upload_file(name, mime_type, parent_id, content)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({ "file": file }))
    }

    async fn invoke_update_metadata(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;
        let patch = input.get("patch").expect("validated patch");
        let file = client
            .update_metadata(file_id, patch)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({ "file": file }))
    }

    async fn invoke_move_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let remove_parents: Vec<String> = input
            .get("remove_parents")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();
        let file = client
            .move_file(
                require_str(&input, "file_id")?,
                require_str(&input, "add_parent")?,
                &remove_parents,
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"file": file}))
    }

    async fn invoke_copy_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file = client
            .copy_file(
                require_str(&input, "file_id")?,
                optional_str(&input, "name"),
                optional_str(&input, "parent_id"),
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"file": file}))
    }

    async fn invoke_create_shortcut(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file = client
            .create_shortcut(
                require_str(&input, "name")?,
                require_str(&input, "target_id")?,
                optional_str(&input, "parent_id"),
                optional_str(&input, "target_resource_key"),
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"shortcut": file}))
    }

    async fn invoke_create_comment(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        client
            .create_comment(
                require_str(&input, "file_id")?,
                require_str(&input, "content")?,
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())
    }

    async fn invoke_create_reply(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        client
            .create_reply(
                require_str(&input, "file_id")?,
                require_str(&input, "comment_id")?,
                require_str(&input, "content")?,
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())
    }

    async fn invoke_add_permission(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;
        let role = require_str(&input, "role")?;
        let permission = client
            .add_permission(
                file_id,
                require_str(&input, "permission_type")?,
                role,
                optional_str(&input, "email"),
                optional_str(&input, "domain"),
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({ "permission": permission }))
    }

    async fn invoke_update_permission(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let permission = client
            .update_permission(
                require_str(&input, "file_id")?,
                require_str(&input, "permission_id")?,
                require_str(&input, "role")?,
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"permission": permission}))
    }

    async fn invoke_revoke_permission(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        client
            .revoke_permission(
                require_str(&input, "file_id")?,
                require_str(&input, "permission_id")?,
            )
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"revoked": true}))
    }

    async fn invoke_restore_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file = client
            .restore_file(require_str(&input, "file_id")?)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;
        Ok(json!({"file": file}))
    }

    async fn invoke_mark_for_deletion_review(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;
        let resource_key = optional_str(&input, "resource_key");
        let file = client
            .get_file(file_id, resource_key)
            .await
            .map_err(|error| error.to_fcp_error())?;

        if file.trashed == Some(true) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "A trashed file cannot enter deletion review; restore it first".into(),
            });
        }
        if file.name.starts_with(REVIEW_PREFIX) {
            return Ok(json!({"already_marked": true, "file": file}));
        }

        let original_name = file.name.clone();
        let original_parents = file.parents.clone().unwrap_or_default();
        let original_permissions = file.permissions.clone().unwrap_or_default();
        let original_checksum = file.md5_checksum.clone();
        let owner_summary = file
            .owners
            .as_ref()
            .into_iter()
            .flatten()
            .filter_map(|owner| owner.email_address.as_deref())
            .collect::<Vec<_>>()
            .join(",");
        let review_name = format!(
            "[FCP-DELETE-REVIEW {}] {}",
            Utc::now().format("%Y-%m-%d"),
            original_name
        );
        let about = client.about().await.map_err(|error| error.to_fcp_error())?;
        let current_email = about.user.and_then(|user| user.email_address);
        let personally_owned = file.drive_id.is_none()
            && current_email.as_deref().is_some_and(|email| {
                file.owners.as_ref().is_some_and(|owners| {
                    owners
                        .iter()
                        .any(|owner| owner.email_address.as_deref() == Some(email))
                })
            });
        let requested_shared_move =
            optional_str(&input, "mode") == Some("move_shared_drive_original");

        let (mode, review_folder, marked_file, shortcut_id) = if personally_owned
            || requested_shared_move
        {
            if requested_shared_move {
                if input
                    .get("confirm_shared_drive_move")
                    .and_then(serde_json::Value::as_bool)
                    != Some(true)
                {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message:
                            "move_shared_drive_original requires confirm_shared_drive_move=true"
                                .into(),
                    });
                }
                if file.drive_id.is_none()
                    || file
                        .capabilities
                        .as_ref()
                        .and_then(|capabilities| capabilities.can_move_item_within_drive)
                        != Some(true)
                {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "Shared Drive item cannot be moved within its Drive".into(),
                    });
                }
            }
            let review_folder = self
                .find_or_create_review_folder(file.drive_id.as_deref())
                .await?;
            client
                .update_metadata(file_id, &json!({"name": review_name}))
                .await
                .map_err(|error| error.to_fcp_error())?;
            let moved = match client
                .move_file(file_id, &review_folder.id, &original_parents)
                .await
            {
                Ok(moved) => moved,
                Err(error) => {
                    if let Err(rollback_error) = client
                        .update_metadata(file_id, &json!({"name": original_name}))
                        .await
                    {
                        return Err(FcpError::External {
                            service: "google-drive".into(),
                            message: format!(
                                "Deletion-review move failed ({error}); rename rollback also failed ({rollback_error})"
                            ),
                            status_code: None,
                            retryable: false,
                            retry_after: None,
                        });
                    }
                    return Err(error.to_fcp_error());
                }
            };
            (
                if personally_owned {
                    "owned_move"
                } else {
                    "shared_drive_move"
                },
                review_folder,
                moved,
                None,
            )
        } else {
            let review_folder = self.find_or_create_review_folder(None).await?;
            let shortcut_name = if owner_summary.is_empty() {
                review_name.clone()
            } else {
                format!("{review_name} [owner: {owner_summary}]")
            };
            let shortcut = client
                .create_shortcut(
                    &shortcut_name,
                    file_id,
                    Some(&review_folder.id),
                    resource_key,
                )
                .await
                .map_err(|error| error.to_fcp_error())?;
            let unchanged = client
                .get_file(file_id, resource_key)
                .await
                .map_err(|error| error.to_fcp_error())?;
            ("shortcut", review_folder, unchanged, Some(shortcut.id))
        };

        if marked_file.id != file.id
            || marked_file.trashed == Some(true)
            || marked_file.md5_checksum != original_checksum
            || marked_file.permissions.clone().unwrap_or_default() != original_permissions
            || (mode == "shortcut"
                && (marked_file.name != original_name
                    || marked_file.parents.clone().unwrap_or_default() != original_parents))
            || (mode != "shortcut"
                && (marked_file.name != review_name
                    || !marked_file.parents.as_ref().is_some_and(|parents| {
                        parents.iter().any(|parent| parent == &review_folder.id)
                    })))
        {
            return Err(FcpError::External {
                service: "google-drive".into(),
                message: "Deletion-review verification detected changed identity, content, trash state, or permissions".into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            });
        }

        let receipt = json!({
            "version": 1,
            "mode": mode,
            "file_id": file.id,
            "original_name": original_name,
            "original_parents": original_parents,
            "review_name": review_name,
            "review_folder_id": review_folder.id,
            "drive_id": file.drive_id,
            "md5_checksum": original_checksum,
            "permission_ids": original_permissions.iter().map(|permission| permission.id.as_str()).collect::<Vec<_>>(),
            "permissions": original_permissions,
            "shortcut_id": shortcut_id,
            "resource_key": resource_key,
        });
        Ok(json!({"file": marked_file, "receipt": receipt}))
    }

    async fn invoke_list_deletion_review(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let drive_id = optional_str(&input, "drive_id");
        let Some(folder) = self.find_review_folder(drive_id).await? else {
            return Ok(json!({"files": [], "review_folder": null}));
        };
        let query = format!("'{}' in parents", folder.id.replace('\'', "\\'"));
        let files = client
            .list_files(
                Some(&query),
                optional_u32(&input, "page_size")?,
                optional_str(&input, "page_token"),
                Some(if drive_id.is_some() { "drive" } else { "user" }),
                drive_id,
            )
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(
            json!({"review_folder": folder, "files": files.files, "next_page_token": files.next_page_token}),
        )
    }

    async fn invoke_restore_from_deletion_review(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let receipt = input.get("receipt").expect("validated receipt");
        let mode = require_str(receipt, "mode")?;
        let file_id = require_str(receipt, "file_id")?;
        if mode == "shortcut" {
            let file = client
                .get_file(file_id, optional_str(receipt, "resource_key"))
                .await
                .map_err(|error| error.to_fcp_error())?;
            let shortcut_id = require_str(receipt, "shortcut_id")?;
            let review_folder_id = require_str(receipt, "review_folder_id")?;
            let shortcut = client
                .get_file(shortcut_id, None)
                .await
                .map_err(|error| error.to_fcp_error())?;
            if !shortcut
                .parents
                .as_ref()
                .is_some_and(|parents| parents.iter().any(|parent| parent == review_folder_id))
            {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Review shortcut no longer matches the receipt".into(),
                });
            }
            client
                .move_file(shortcut_id, "root", &[review_folder_id.to_owned()])
                .await
                .map_err(|error| error.to_fcp_error())?;
            let cancelled_shortcut = client
                .update_metadata(
                    shortcut_id,
                    &json!({"name": format!(
                        "[FCP-REVIEW-CANCELLED] {}",
                        require_str(receipt, "original_name")?
                    )}),
                )
                .await
                .map_err(|error| error.to_fcp_error())?;
            return Ok(json!({
                "restored": true,
                "original_unchanged": true,
                "file": file,
                "cancelled_shortcut": cancelled_shortcut
            }));
        }

        let original_parents = receipt
            .get("original_parents")
            .and_then(serde_json::Value::as_array)
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "receipt is missing original_parents".into(),
            })?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "receipt original_parents must contain strings".into(),
                    })
            })
            .collect::<FcpResult<Vec<_>>>()?;
        if original_parents.len() > 1 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "receipt contains multiple original parents; refusing to guess restoration placement".into(),
            });
        }
        let current = client
            .get_file(file_id, optional_str(receipt, "resource_key"))
            .await
            .map_err(|error| error.to_fcp_error())?;
        let review_folder_id = require_str(receipt, "review_folder_id")?;
        if !current.name.starts_with(REVIEW_PREFIX)
            || !current
                .parents
                .as_ref()
                .is_some_and(|parents| parents.iter().any(|parent| parent == review_folder_id))
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Current file state does not match the deletion-review receipt".into(),
            });
        }
        let destination = original_parents.first().map_or("root", String::as_str);
        let moved = client
            .move_file(file_id, destination, &[review_folder_id.to_owned()])
            .await
            .map_err(|error| error.to_fcp_error())?;
        let restored = match client
            .update_metadata(
                file_id,
                &json!({"name": require_str(receipt, "original_name")?}),
            )
            .await
        {
            Ok(restored) => restored,
            Err(error) => {
                if let Err(rollback_error) = client
                    .move_file(file_id, review_folder_id, &[destination.to_owned()])
                    .await
                {
                    return Err(FcpError::External {
                        service: "google-drive".into(),
                        message: format!(
                            "Restoration rename failed ({error}); folder rollback also failed ({rollback_error})"
                        ),
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    });
                }
                return Err(error.to_fcp_error());
            }
        };
        if restored.id != moved.id
            || restored.trashed == Some(true)
            || restored.parents.as_deref() != Some(&[destination.to_owned()])
            || receipt.get("md5_checksum").is_some_and(|checksum| {
                !checksum.is_null() && checksum.as_str() != restored.md5_checksum.as_deref()
            })
            || receipt.get("permissions").is_some_and(|permissions| {
                !permissions.is_null()
                    && serde_json::to_value(restored.permissions.clone().unwrap_or_default())
                        .ok()
                        .as_ref()
                        != Some(permissions)
            })
        {
            return Err(FcpError::External {
                service: "google-drive".into(),
                message: "Restoration readback did not match the receipt".into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            });
        }
        Ok(json!({"restored": true, "file": restored}))
    }

    async fn find_review_folder(
        &self,
        drive_id: Option<&str>,
    ) -> FcpResult<Option<crate::types::DriveFile>> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let root_id = drive_id.unwrap_or("root");
        let query = format!(
            "name = '{REVIEW_FOLDER_NAME}' and mimeType = 'application/vnd.google-apps.folder' and '{root_id}' in parents"
        );
        let response = client
            .list_files(
                Some(&query),
                Some(2),
                None,
                Some(if drive_id.is_some() { "drive" } else { "user" }),
                drive_id,
            )
            .await
            .map_err(|error| error.to_fcp_error())?;
        if response.files.len() > 1 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Multiple deletion-review folders found; refusing to choose one".into(),
            });
        }
        Ok(response.files.into_iter().next())
    }

    async fn find_or_create_review_folder(
        &self,
        drive_id: Option<&str>,
    ) -> FcpResult<crate::types::DriveFile> {
        if let Some(folder) = self.find_review_folder(drive_id).await? {
            return Ok(folder);
        }
        self.client
            .as_ref()
            .ok_or(FcpError::NotConfigured)?
            .create_folder(REVIEW_FOLDER_NAME, Some(drive_id.unwrap_or("root")))
            .await
            .map_err(|error| error.to_fcp_error())
    }

    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Drive connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for DriveConnector {
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

fn optional_str<'a>(input: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    input.get(field).and_then(serde_json::Value::as_str)
}

fn optional_u32(input: &serde_json::Value, field: &str) -> FcpResult<Option<u32>> {
    match input.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .map(Some)
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be an unsigned 32-bit integer"),
            }),
    }
}

/// Reject every file deletion/trash/raw escape before capability verification or provider I/O.
fn reject_forbidden_drive_input(value: &serde_json::Value) -> FcpResult<()> {
    fn compact(value: &str) -> String {
        value
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace() && !matches!(ch, '_' | '-' | '.'))
            .flat_map(char::to_lowercase)
            .collect()
    }

    fn percent_decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut output = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    output.push(byte);
                    index += 3;
                    continue;
                }
            }
            output.push(bytes[index]);
            index += 1;
        }
        String::from_utf8_lossy(&output).into_owned()
    }

    fn walk(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => map.iter().any(|(key, child)| {
                let normalized = compact(key);
                (normalized == "trashed" && child.as_bool() == Some(true))
                    || matches!(
                        normalized.as_str(),
                        "delete"
                            | "harddelete"
                            | "emptytrash"
                            | "raw"
                            | "rawrequest"
                            | "httpmethod"
                            | "requestpath"
                    )
                    || walk(child)
            }),
            serde_json::Value::Array(items) => items.iter().any(walk),
            serde_json::Value::String(text) => {
                let decoded_once = percent_decode(text);
                let decoded_twice = percent_decode(&decoded_once);
                let normalized = compact(&decoded_twice);
                normalized.contains("trashed=true")
                    || normalized.contains("\"trashed\":true")
                    || normalized.contains("filesdelete")
                    || normalized.contains("emptytrash")
                    || normalized.contains("drivetrashfile")
                    || normalized.contains("googleraw")
            }
            _ => false,
        }
    }

    if walk(value) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Drive file deletion, trashing, or raw request bypass is forbidden".into(),
        });
    }
    Ok(())
}

fn operations_info() -> Vec<OperationInfo> {
    static OPERATIONS: OnceLock<Vec<OperationInfo>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            ordered_manifest_operations()
                .into_iter()
                .map(|(id, operation)| operation_info_from_manifest(id, &operation))
                .collect()
        })
        .clone()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded Drive manifest should parse");
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|known_id| *known_id == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

fn operation_info_from_manifest(id: String, operation: &OperationSection) -> OperationInfo {
    let description = operation.description.clone();
    OperationInfo {
        id: OperationId::new(id).expect("manifest operation id should be canonical"),
        summary: description.clone(),
        description: Some(description),
        input_schema: operation.input_schema.clone(),
        output_schema: operation.output_schema.clone(),
        capability: operation.capability.clone(),
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints.clone(),
        rate_limit: operation
            .rate_limit
            .as_ref()
            .map(|rate_limit| rate_limit.0.clone()),
        requires_approval: approval_mode_from_manifest(operation.requires_approval),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CapabilityConstraints;

    fn bearer_config(value: &str) -> serde_json::Value {
        let mut params = serde_json::Map::new();
        params.insert(["access", "token"].join("_"), json!(value));
        serde_json::Value::Object(params)
    }

    fn bearer_config_with_base_url(
        value: &str,
        base_url: impl Into<serde_json::Value>,
    ) -> serde_json::Value {
        let mut params = serde_json::Map::new();
        params.insert(["access", "token"].join("_"), json!(value));
        params.insert("base_url".to_string(), base_url.into());
        serde_json::Value::Object(params)
    }

    fn build_capability(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        operation: &'static str,
    ) -> CapabilityToken {
        let capability = match operation {
            "drive.list_files"
            | "drive.parse_url"
            | "drive.list_shared_with_me"
            | "drive.list_drives"
            | "drive.get_file"
            | "drive.list_permissions"
            | "drive.list_revisions"
            | "drive.list_comments"
            | "drive.about"
            | "drive.list_deletion_review"
            | "drive.download_file"
            | "drive.export_file" => "drive.read",
            "drive.add_permission" | "drive.update_permission" | "drive.revoke_permission" => {
                "drive.share.write"
            }
            "drive.mark_for_deletion_review"
            | "drive.restore_from_deletion_review"
            | "drive.restore_file" => "drive.quarantine.write",
            "drive.upload_file" | "drive.copy_file" => "drive.content.write",
            "drive.create_folder"
            | "drive.update_metadata"
            | "drive.move_file"
            | "drive.create_shortcut"
            | "drive.create_comment"
            | "drive.create_reply" => "drive.metadata.write",
            _ => "drive.read",
        };
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor)
            .expect("serialize capability constraints");
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id)
            .audience("*")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("attach capability constraints")
            .sign(signing_key)
            .expect("sign capability");
        CapabilityToken::from_raw(cose)
    }

    fn simulate_request(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        operation: &'static str,
        input: serde_json::Value,
    ) -> serde_json::Value {
        let capability = build_capability(signing_key, instance_id, operation);
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("google-drive"),
            OperationId::from_static(operation),
            fcp_core::ZoneId::work(),
            input,
            capability,
        ))
        .expect("serialize simulate request")
    }

    fn parse_simulate_response(value: serde_json::Value) -> SimulateResponse {
        serde_json::from_value(value).expect("simulate response")
    }

    async fn configure_and_handshake(
        connector: &mut DriveConnector,
        signing_key: &Ed25519SigningKey,
    ) {
        let nonce = vec![7_u8; 32];
        connector
            .handle_configure(bearer_config("test"))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "capabilities_requested": ["drive.read", "drive.write"],
                "nonce": nonce
            }))
            .await
            .unwrap();
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(DriveConnector::manifest_hash(), expected);
        assert_ne!(
            DriveConnector::manifest_hash(),
            "sha256:google-drive-connector-v1"
        );
    }

    #[test]
    fn validate_drive_base_url_accepts_googleapis() {
        let out = validate_drive_base_url("https://www.googleapis.com/drive/v3").unwrap();
        assert_eq!(out, "https://www.googleapis.com/drive/v3");
    }

    #[test]
    fn validate_drive_base_url_allows_localhost_http() {
        validate_drive_base_url("http://localhost:9999").unwrap();
        validate_drive_base_url("http://127.0.0.1/drive").unwrap();
        validate_drive_base_url("http://[::1]:9999/drive").unwrap();
    }

    #[test]
    fn validate_drive_base_url_rejects_foreign_host() {
        let err = validate_drive_base_url("https://evil.example.com/drive/v3").unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { ref message, .. } if message.contains("www.googleapis.com")),
            "expected InvalidRequest mentioning www.googleapis.com, got {err:?}"
        );
    }

    #[test]
    fn validate_drive_base_url_rejects_substring_smuggle() {
        let err = validate_drive_base_url("https://evil.com/drive.googleapis.com/v3").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_drive_base_url_rejects_query_fragment_userinfo() {
        assert!(matches!(
            validate_drive_base_url("https://www.googleapis.com/drive/v3?leak=x").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_drive_base_url("https://www.googleapis.com/drive/v3#frag").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err =
            validate_drive_base_url("https://attacker:pw@www.googleapis.com/drive/v3").unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { ref message, .. } if message.contains("userinfo")),
            "expected InvalidRequest mentioning userinfo, got {err:?}"
        );
    }

    #[test]
    fn validate_drive_base_url_rejects_plain_http_on_public_host() {
        let err = validate_drive_base_url("http://www.googleapis.com/drive/v3").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn host_is_drive_googleapis_rejects_wrong_hosts_and_lookalikes() {
        assert!(host_is_drive_googleapis("www.googleapis.com"));
        assert!(!host_is_drive_googleapis("googleapis.com"));
        assert!(!host_is_drive_googleapis("drive.googleapis.com"));
        assert!(!host_is_drive_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_drive_googleapis("evil-googleapis.com"));
    }

    #[test]
    fn forbidden_surface_is_absent_from_operation_catalog() {
        let ids = operations_info()
            .into_iter()
            .map(|operation| operation.id.to_string())
            .collect::<Vec<_>>();
        for forbidden in [
            "drive.trash_file",
            "drive.delete_file",
            "drive.empty_trash",
            "drive.delete_revision",
            "drive.raw",
            "google.execute",
        ] {
            assert!(
                !ids.iter().any(|id| id == forbidden),
                "{forbidden} leaked into introspection"
            );
        }
    }

    #[test]
    fn rejects_nested_and_encoded_trash_or_raw_bypasses() {
        for input in [
            json!({"patch": {"trashed": true}}),
            json!({"batch": [{"metadata": {"Trashed": true}}]}),
            json!({"payload": "%7B%22trashed%22%3Atrue%7D"}),
            json!({"payload": "%257B%2522trashed%2522%253Atrue%257D"}),
            json!({"method": "files.delete"}),
            json!({"operation": "drive.trash_file"}),
            json!({"raw_request": {"http_method": "DELETE", "request_path": "/drive/v3/files/x"}}),
        ] {
            assert!(
                reject_forbidden_drive_input(&input).is_err(),
                "accepted forbidden input: {input}"
            );
        }
        assert!(reject_forbidden_drive_input(&json!({"patch": {"trashed": false}})).is_ok());
        assert!(reject_forbidden_drive_input(&json!({"patch": {"name": "safe"}})).is_ok());
    }

    #[test]
    fn deletion_review_inputs_fail_closed() {
        assert!(
            validate_drive_input(
                "drive.mark_for_deletion_review",
                &json!({"file_id": "file_1", "mode": "delete_now"}),
            )
            .is_err()
        );
        assert!(validate_drive_input("drive.restore_from_deletion_review", &json!({})).is_err());
        assert!(
            validate_drive_input(
                "drive.restore_from_deletion_review",
                &json!({"receipt": {
                    "file_id": "file_1",
                    "original_name": "report.txt",
                    "review_folder_id": "folder_review",
                    "mode": "owned_move"
                }}),
            )
            .is_ok()
        );
    }

    #[test]
    fn parses_drive_urls_without_following_external_content() {
        let parsed = DriveConnector::invoke_parse_url(&json!({
            "url": "https://drive.google.com/file/d/file_123/view?resourcekey=rk_456"
        }))
        .unwrap();
        assert_eq!(parsed["file_id"], "file_123");
        assert_eq!(parsed["resource_key"], "rk_456");

        let folder = DriveConnector::invoke_parse_url(&json!({
            "url": "https://drive.google.com/drive/folders/folder_123"
        }))
        .unwrap();
        assert_eq!(folder["file_id"], "folder_123");

        assert!(
            DriveConnector::invoke_parse_url(&json!({"url": "https://evil.example/file/d/x"}))
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_has_all_operations() {
        let connector = DriveConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert_eq!(op_ids, OPERATION_ORDER);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("Drive manifest should parse");
        let operations = operations_info();

        assert_eq!(operations.len(), manifest.provides.operations.len());
        for operation in operations {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_str())
                .expect("runtime operation should be declared in manifest");
            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
            assert_eq!(operation.capability, manifest_operation.capability);
            assert_eq!(operation.risk_level, manifest_operation.risk_level);
            assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
            assert_eq!(operation.idempotency, manifest_operation.idempotency);
            assert_eq!(
                operation.requires_approval,
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).expect("operation hints serialize"),
                serde_json::to_value(&manifest_operation.ai_hints)
                    .expect("manifest operation hints serialize")
            );
            assert_eq!(
                serde_json::to_value(operation.rate_limit.as_ref())
                    .expect("operation rate limit serializes"),
                serde_json::to_value(manifest_operation.rate_limit.as_ref())
                    .expect("manifest operation rate limit serializes")
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_bearer_auth() {
        let mut connector = DriveConnector::new();
        let result = connector
            .handle_configure(bearer_config("ya29.test"))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_credential_id() {
        let mut connector = DriveConnector::new();
        let cred_id = fcp_core::CredentialId::new();
        let result = connector
            .handle_configure(json!({ "credential_id": cred_id.to_string() }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured_pending_token_materialization");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_no_auth_fails() {
        let mut connector = DriveConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_base_url_override() {
        let mut connector = DriveConnector::new();
        let err = connector
            .handle_configure(bearer_config_with_base_url("ya29.test", json!(123)))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
            "expected base_url validation error, got {err:?}"
        );

        let mut connector = DriveConnector::new();
        let err = connector
            .handle_configure(bearer_config_with_base_url("ya29.test", json!("")))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("empty")),
            "expected empty base_url validation error, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let connector = DriveConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn health_configured() {
        let mut connector = DriveConnector::new();
        connector
            .handle_configure(bearer_config("ya29.test"))
            .await
            .unwrap();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_succeeds() {
        let connector = DriveConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    #[test]
    fn default_impl() {
        let _connector = DriveConnector::default();
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_before_configure() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = DriveConnector::new();
        let result = connector
            .handle_simulate(simulate_request(
                &signing_key,
                connector.instance_id(),
                "drive.get_file",
                json!({ "file_id": "file_123" }),
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_missing_required_input() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = DriveConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;
        let result = connector
            .handle_simulate(simulate_request(
                &signing_key,
                connector.instance_id(),
                "drive.get_file",
                json!({}),
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::InvalidRequest {
                    code: 1003,
                    message: String::new()
                }
                .error_code()
            )
        );
        assert!(
            response
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("file_id"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_allows_valid_authorized_request() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = DriveConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;
        let result = connector
            .handle_simulate(simulate_request(
                &signing_key,
                connector.instance_id(),
                "drive.get_file",
                json!({ "file_id": "file_123" }),
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(response.would_succeed);
        assert!(response.denial_code.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation_is_denied() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = DriveConnector::new();
        let result = connector
            .handle_simulate(simulate_request(
                &signing_key,
                connector.instance_id(),
                "drive.nope",
                json!({}),
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::OperationNotGranted {
                    operation: String::new()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unconfigured() {
        let connector = DriveConnector::new();
        let value = connector.handle_doctor().await.unwrap();
        assert_eq!(value["ready"], false);
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks[0]["name"], "client_configured");
        assert_eq!(checks[0]["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = DriveConnector::new();
        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured() {
        let mut connector = DriveConnector::new();
        connector
            .handle_configure(bearer_config("ya29.test"))
            .await
            .unwrap();
        let value = connector.handle_doctor().await.unwrap();
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks[0]["name"], "client_configured");
        assert_eq!(checks[0]["passed"], true);
        // API reachability will fail without a mock server, but the check still runs
        assert!(checks.len() >= 2);
    }
}
