//! Typed owner-confirmation seam for n8n workflow writes.
//!
//! This module deliberately does not own durable provider state, mint tokens,
//! read KeePass, or perform provider I/O. The production run-once path in
//! `fcp-host` remains the only authority for cryptographic verification,
//! request binding, replay protection, provider-attempt receipts, and
//! `unknown` recovery. This module only represents the exact plan that an
//! eventual trusted owner adapter may confirm and turn into the existing FCP
//! `ApprovalToken` format.

#![allow(dead_code)]

use std::{env, fmt, fs, str};

use blake3::Hasher;
use fcp_crypto::{canonicalize::to_deterministic_cbor, ed25519::Ed25519VerifyingKey};
use fcp_prelude::{ApprovalScope, ApprovalToken, ExecutionScope, InputConstraint, Uuid, ZoneId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

const PLAN_DOMAIN: &[u8] = b"fwc-n8n.owner-approval-plan.v1";
const INPUT_DOMAIN: &[u8] = b"fwc-n8n.owner-approval-input.v1";
const PRECONDITION_DOMAIN: &[u8] = b"fwc-n8n.owner-approval-precondition.v1";
const CREATION_RECEIPT_DOMAIN: &[u8] = b"fwc-n8n.owner-approval-creation-receipt.v1";
const OFFICIAL_MCP_PAYLOAD_DOMAIN: &str = "sha256:";
const OFFICIAL_MCP_WRAPPER_OPERATION: &str = "n8n.mcp.call";
const APPROVAL_REQUEST_SCHEMA: &str = "fwc.n8n.owner-approval-request.v1";
const APPROVAL_ISSUER: &str = "owner:n8n-approval-issuer";
const MAX_APPROVAL_TTL_MS: u64 = 60_000;
const APPROVAL_PUBLIC_KEY_ENV: &str = "FCP_HOST_APPROVAL_PUBLIC_KEY";
const APPROVAL_PUBLIC_KEY_FILE_ENV: &str = "FCP_HOST_APPROVAL_PUBLIC_KEY_FILE";

/// The typed n8n operations covered by this seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum N8nLifecycleOperation {
    Publish,
    Unpublish,
    Archive,
    CreateDraft,
    DeleteDisposable,
}

impl N8nLifecycleOperation {
    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::Publish | Self::Unpublish => "n8n.workflows.lifecycle",
            Self::Archive => "n8n.workflows.archive",
            Self::CreateDraft => "n8n.workflows.create_draft",
            Self::DeleteDisposable => "n8n.workflows.delete_disposable",
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Unpublish => "unpublish",
            Self::Archive => "archive",
            Self::CreateDraft => "create_draft",
            Self::DeleteDisposable => "delete_disposable",
        }
    }
}

/// An explicit provider target. Legacy LeviLaser is intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum N8nApprovalServer {
    Eec,
    Hetzner,
}

impl N8nApprovalServer {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Eec => "eec",
            Self::Hetzner => "hetzner",
        }
    }
}

/// Non-secret, exact owner request consumed by the isolated issuer.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct N8nApprovalIssueRequest {
    pub schema: String,
    pub server: N8nApprovalServer,
    pub workflow_id: String,
    pub operation: N8nLifecycleOperation,
    pub input: Value,
    pub official_mcp_tool: String,
    pub official_mcp_resource_uri: String,
    pub official_mcp_payload_digest: String,
    pub parent_binding_sha256: String,
    pub expires_at_ms: u64,
}

impl fmt::Debug for N8nApprovalIssueRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("N8nApprovalIssueRequest")
            .field("schema", &self.schema)
            .field("server", &self.server)
            .field("workflow_id", &"[REDACTED]")
            .field("operation", &self.operation)
            .field("input", &"[REDACTED]")
            .field("official_mcp_tool", &self.official_mcp_tool)
            .field("official_mcp_resource_uri", &self.official_mcp_resource_uri)
            .field(
                "official_mcp_payload_digest",
                &self.official_mcp_payload_digest,
            )
            .field("parent_binding_sha256", &self.parent_binding_sha256)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Redaction-safe owner-confirmation plan.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct N8nApprovalPlan {
    pub(crate) server: N8nApprovalServer,
    pub(crate) resource_uri: String,
    pub(crate) workflow_id: String,
    pub(crate) operation: N8nLifecycleOperation,
    pub(crate) canonical_input_digest: String,
    pub(crate) creation_receipt_digest: Option<String>,
    pub(crate) parent_binding_sha256: String,
    pub(crate) precondition_digest: String,
    pub(crate) idempotency_key: String,
    pub(crate) expires_at_ms: u64,
    pub(crate) official_mcp_tool: String,
    pub(crate) official_mcp_payload_digest: String,
    pub(crate) plan_digest: String,
}

impl fmt::Debug for N8nApprovalPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("N8nApprovalPlan")
            .field("server", &self.server)
            .field("resource_uri", &"[REDACTED]")
            .field("workflow_id", &"[REDACTED]")
            .field("operation", &self.operation)
            .field("canonical_input_digest", &self.canonical_input_digest)
            .field("creation_receipt_digest", &self.creation_receipt_digest)
            .field("parent_binding_sha256", &self.parent_binding_sha256)
            .field("precondition_digest", &self.precondition_digest)
            .field("idempotency_key", &"[REDACTED]")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("official_mcp_tool", &self.official_mcp_tool)
            .field(
                "official_mcp_payload_digest",
                &self.official_mcp_payload_digest,
            )
            .field("plan_digest", &self.plan_digest)
            .finish()
    }
}

impl N8nApprovalPlan {
    /// Build a plan from exact typed input and current-state precondition.
    pub(crate) fn new(
        server: N8nApprovalServer,
        workflow_id: impl Into<String>,
        operation: N8nLifecycleOperation,
        input: &Value,
        precondition: &Value,
        idempotency_key: impl Into<String>,
        expires_at_ms: u64,
    ) -> Result<Self, N8nApprovalError> {
        let workflow_id = workflow_id.into();
        let valid_workflow_id = !workflow_id.is_empty()
            && workflow_id.len() <= 128
            && workflow_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~')
            });
        if (operation == N8nLifecycleOperation::CreateDraft && !workflow_id.is_empty())
            || (operation != N8nLifecycleOperation::CreateDraft && !valid_workflow_id)
        {
            return Err(N8nApprovalError::InvalidPlan(
                "workflow id is not a safe exact identifier",
            ));
        }
        let idempotency_key = idempotency_key.into();
        Uuid::parse_str(&idempotency_key)
            .map_err(|_| N8nApprovalError::InvalidPlan("idempotency key must be a UUID"))?;
        if expires_at_ms == 0 {
            return Err(N8nApprovalError::InvalidPlan("expiry must be non-zero"));
        }
        let resource_uri = if operation == N8nLifecycleOperation::CreateDraft {
            let project_uri = input
                .get("project_id")
                .and_then(Value::as_str)
                .map(|project_id| {
                    format!(
                        "fwc-n8n://{}/projects/{}",
                        server.as_str(),
                        encode_resource_segment(project_id)
                    )
                });
            project_uri.unwrap_or_else(|| format!("fwc-n8n://{}", server.as_str()))
        } else {
            format!(
                "fwc-n8n://{}/workflows/{}",
                server.as_str(),
                encode_resource_segment(&workflow_id)
            )
        };
        let canonical_input_digest = digest(INPUT_DOMAIN, input);
        let creation_receipt_digest = if operation == N8nLifecycleOperation::DeleteDisposable {
            let receipt = input
                .get("creationReceipt")
                .and_then(Value::as_str)
                .filter(|value| is_blake3_digest(value))
                .ok_or(N8nApprovalError::InvalidPlan(
                    "disposable creation receipt is invalid",
                ))?;
            Some(digest(
                CREATION_RECEIPT_DOMAIN,
                &Value::String(receipt.to_owned()),
            ))
        } else {
            None
        };
        let parent_binding_sha256 =
            n8n_parent_binding_digest(server, &resource_uri, operation.operation_id(), input)?;
        let precondition_digest = digest(PRECONDITION_DOMAIN, precondition);
        let mut plan = Self {
            server,
            resource_uri,
            workflow_id,
            operation,
            canonical_input_digest,
            creation_receipt_digest,
            parent_binding_sha256,
            precondition_digest,
            idempotency_key,
            expires_at_ms,
            official_mcp_tool: String::new(),
            official_mcp_payload_digest: String::new(),
            plan_digest: String::new(),
        };
        plan.refresh_digest();
        Ok(plan)
    }

    fn from_official_mcp(
        server: N8nApprovalServer,
        workflow_id: &str,
        operation: N8nLifecycleOperation,
        official_mcp_tool: &str,
        official_mcp_resource_uri: &str,
        official_mcp_payload_digest: &str,
        input: &Value,
        precondition: &Value,
        idempotency_key: &str,
        expires_at_ms: u64,
    ) -> Result<Self, N8nApprovalError> {
        let expected_tool = match operation {
            N8nLifecycleOperation::Publish => "publish_workflow",
            N8nLifecycleOperation::Unpublish => "unpublish_workflow",
            N8nLifecycleOperation::Archive => "archive_workflow",
            N8nLifecycleOperation::CreateDraft | N8nLifecycleOperation::DeleteDisposable => "",
        };
        let direct_rest = matches!(
            operation,
            N8nLifecycleOperation::CreateDraft | N8nLifecycleOperation::DeleteDisposable
        );
        if direct_rest {
            if !official_mcp_tool.is_empty()
                || !official_mcp_resource_uri.is_empty()
                || !official_mcp_payload_digest.is_empty()
            {
                return Err(N8nApprovalError::InvalidPlan(
                    "direct REST approval cannot carry official MCP binding",
                ));
            }
        } else if official_mcp_tool != expected_tool
            || !is_sha256_digest(official_mcp_payload_digest)
        {
            return Err(N8nApprovalError::InvalidPlan(
                "official MCP tool or payload digest is not exact",
            ));
        }
        let mut plan = Self::new(
            server,
            workflow_id,
            operation,
            input,
            precondition,
            idempotency_key,
            expires_at_ms,
        )?;
        official_mcp_tool.clone_into(&mut plan.official_mcp_tool);
        official_mcp_payload_digest.clone_into(&mut plan.official_mcp_payload_digest);
        plan.refresh_digest();
        Ok(plan)
    }

    fn refresh_digest(&mut self) {
        self.plan_digest = digest(
            PLAN_DOMAIN,
            &json!({
                "server": self.server.as_str(),
                "resource_uri": self.resource_uri,
                "workflow_id": self.workflow_id,
                "operation": self.operation.as_str(),
                "wrapper_operation": OFFICIAL_MCP_WRAPPER_OPERATION,
                "canonical_input_digest": self.canonical_input_digest,
                "creation_receipt_digest": self.creation_receipt_digest,
                "parent_binding_sha256": self.parent_binding_sha256,
                "precondition_digest": self.precondition_digest,
                "idempotency_key": self.idempotency_key,
                "expires_at_ms": self.expires_at_ms,
                "official_mcp_tool": self.official_mcp_tool,
                "official_mcp_payload_digest": self.official_mcp_payload_digest,
            }),
        );
    }

    /// Confirm exactly this plan through a trusted future issuer.
    pub(crate) fn confirm<I: N8nApprovalIssuer>(
        &self,
        confirmation: &N8nOwnerConfirmation,
        issuer: &I,
        now_ms: u64,
    ) -> Result<ApprovalToken, N8nApprovalError> {
        if now_ms >= self.expires_at_ms {
            return Err(N8nApprovalError::StalePlan);
        }
        if confirmation.plan_digest != self.plan_digest {
            return Err(N8nApprovalError::ConfirmationMismatch);
        }
        if confirmation.confirmed_at_ms > now_ms
            || confirmation.confirmed_at_ms >= self.expires_at_ms
        {
            return Err(N8nApprovalError::StalePlan);
        }
        let token = issuer.issue(self, confirmation)?;
        validate_issued_token_shape(&token, self, now_ms)?;
        Ok(token)
    }
}

/// Exact owner confirmation; it contains no token or workflow payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct N8nOwnerConfirmation {
    pub(crate) plan_digest: String,
    pub(crate) confirmed_at_ms: u64,
}

/// Future trusted owner adapter. It must return the existing FCP token type.
pub(crate) trait N8nApprovalIssuer {
    fn issue(
        &self,
        plan: &N8nApprovalPlan,
        confirmation: &N8nOwnerConfirmation,
    ) -> Result<ApprovalToken, N8nApprovalError>;
}

/// Built-in issuer until a separately reviewed host/KeePass adapter exists.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FailClosedN8nApprovalIssuer;

impl N8nApprovalIssuer for FailClosedN8nApprovalIssuer {
    fn issue(
        &self,
        _plan: &N8nApprovalPlan,
        _confirmation: &N8nOwnerConfirmation,
    ) -> Result<ApprovalToken, N8nApprovalError> {
        Err(N8nApprovalError::IssuerUnavailable)
    }
}

/// Canonicalize the existing FCP approval token for host verification.
///
/// The signature is deliberately removed before serialization, preserving the
/// existing host preimage contract. Cryptographic verification and complete
/// request binding remain in the host run-once verifier.
pub fn canonical_approval_token_bytes(
    token: &ApprovalToken,
) -> Result<Vec<u8>, fcp_cbor::SerializationError> {
    let mut unsigned = token.clone();
    unsigned.signature = None;
    fcp_cbor::to_canonical_cbor(&unsigned)
}

fn validate_issued_token_shape(
    token: &ApprovalToken,
    plan: &N8nApprovalPlan,
    now_ms: u64,
) -> Result<(), N8nApprovalError> {
    if token.token_id.is_empty()
        || token.signature.as_ref().is_none_or(Vec::is_empty)
        || token.zone_id != ZoneId::work()
        || !token.is_valid(now_ms)
        || token.expires_at_ms > plan.expires_at_ms
    {
        return Err(N8nApprovalError::InvalidIssuedToken);
    }
    let ApprovalScope::Execution(scope) = &token.scope else {
        return Err(N8nApprovalError::InvalidIssuedToken);
    };
    let direct_rest = matches!(
        plan.operation,
        N8nLifecycleOperation::CreateDraft | N8nLifecycleOperation::DeleteDisposable
    );
    let expected_connector = if direct_rest {
        "fcp.n8n"
    } else {
        "fcp.mcp-bridge"
    };
    let expected_method = if direct_rest {
        plan.operation.operation_id()
    } else {
        OFFICIAL_MCP_WRAPPER_OPERATION
    };
    if scope.connector_id != expected_connector || scope.method_pattern != expected_method {
        return Err(N8nApprovalError::InvalidIssuedToken);
    }
    if scope.request_object_id.is_some() {
        return Err(N8nApprovalError::InvalidIssuedToken);
    }
    if direct_rest {
        let mut expected_input_hash = [0_u8; 32];
        hex::decode_to_slice(&plan.parent_binding_sha256, &mut expected_input_hash)
            .map_err(|_| N8nApprovalError::InvalidIssuedToken)?;
        if scope.input_hash != Some(expected_input_hash) || !scope.input_constraints.is_empty() {
            return Err(N8nApprovalError::InvalidIssuedToken);
        }
    }
    Ok(())
}

/// Build the exact typed owner-plan digest consumed by the host run-once
/// verifier. The issuer remains private and fail-closed; this helper only
/// reconstructs public/redacted binding material and returns `None` on any
/// mismatch or stale plan.
pub fn n8n_typed_approval_plan_digest(
    server: &str,
    workflow_id: &str,
    operation: &str,
    official_mcp_tool: &str,
    official_mcp_payload_digest: &str,
    input: &Value,
    precondition: &Value,
    idempotency_key: &str,
    expires_at_ms: u64,
    now_ms: u64,
) -> Option<String> {
    let server = match server {
        "eec" => N8nApprovalServer::Eec,
        "hetzner" => N8nApprovalServer::Hetzner,
        _ => return None,
    };
    let operation = match operation {
        "publish" => N8nLifecycleOperation::Publish,
        "unpublish" => N8nLifecycleOperation::Unpublish,
        "archive" => N8nLifecycleOperation::Archive,
        "create_draft" => N8nLifecycleOperation::CreateDraft,
        "delete_disposable" => N8nLifecycleOperation::DeleteDisposable,
        _ => return None,
    };
    if now_ms >= expires_at_ms {
        return None;
    }
    N8nApprovalPlan::from_official_mcp(
        server,
        workflow_id,
        operation,
        official_mcp_tool,
        "",
        official_mcp_payload_digest,
        input,
        precondition,
        idempotency_key,
        expires_at_ms,
    )
    .ok()
    .map(|plan| plan.plan_digest)
}

/// Build the exact official-MCP constraints checked by the host for a typed
/// lifecycle/archive approval. Direct REST approvals use their exact request
/// binding as the token input hash and carry no MCP constraints.
pub fn n8n_official_mcp_approval_constraints(
    server: N8nApprovalServer,
    official_mcp_tool: &str,
    official_mcp_resource_uri: &str,
    official_mcp_payload_digest: &str,
    parent_binding_sha256: &str,
    typed_plan_digest: &str,
) -> Result<Vec<InputConstraint>, N8nApprovalError> {
    if typed_plan_digest.is_empty()
        || !is_sha256_digest(official_mcp_payload_digest)
        || !is_raw_sha256_digest(parent_binding_sha256)
    {
        return Err(N8nApprovalError::InvalidPlan(
            "official MCP approval binding is invalid",
        ));
    }
    let expected_tool = match official_mcp_tool {
        "publish_workflow" | "unpublish_workflow" | "archive_workflow" => official_mcp_tool,
        _ => {
            return Err(N8nApprovalError::InvalidPlan(
                "official MCP tool is not lifecycle/archive",
            ));
        }
    };
    let payload_sha256 = official_mcp_payload_digest
        .strip_prefix(OFFICIAL_MCP_PAYLOAD_DOMAIN)
        .ok_or(N8nApprovalError::InvalidPlan(
            "official MCP payload digest is invalid",
        ))?;
    if !is_raw_sha256_digest(payload_sha256) {
        return Err(N8nApprovalError::InvalidPlan(
            "official MCP payload digest is invalid",
        ));
    }
    let server_root = format!("fwc-mcp-bridge://{}", server.as_str());
    if official_mcp_resource_uri != server_root {
        return Err(N8nApprovalError::InvalidPlan(
            "official MCP resource binding is invalid",
        ));
    }
    Ok([
        (
            "operation",
            Value::String(OFFICIAL_MCP_WRAPPER_OPERATION.to_owned()),
        ),
        (
            "parent_binding_sha256",
            Value::String(parent_binding_sha256.to_owned()),
        ),
        ("payload_sha256", Value::String(payload_sha256.to_owned())),
        ("provider", Value::String("mcp".to_owned())),
        (
            "resource_uri",
            Value::String(official_mcp_resource_uri.to_owned()),
        ),
        ("server_id", Value::String(server.as_str().to_owned())),
        ("tool_name", Value::String(expected_tool.to_owned())),
        (
            "typed_plan_sha256",
            Value::String(typed_plan_digest.to_owned()),
        ),
    ]
    .into_iter()
    .map(|(field, expected)| InputConstraint {
        pointer: format!("/{field}"),
        expected,
    })
    .collect())
}

/// Load the same runtime trust-root source used by the host's typed n8n path.
/// The issuer deliberately does not embed a separate build-time key.
pub fn n8n_runtime_approval_verifying_key() -> Result<Ed25519VerifyingKey, N8nApprovalError> {
    let inline = env::var(APPROVAL_PUBLIC_KEY_ENV).ok();
    let file = env::var(APPROVAL_PUBLIC_KEY_FILE_ENV).ok();
    if inline.is_some() && file.is_some() {
        return Err(N8nApprovalError::IssuerUnavailable);
    }
    let bytes = if let Some(raw) = inline {
        decode_public_key_text(&raw)?
    } else if let Some(path) = file {
        let raw = fs::read(path).map_err(|_| N8nApprovalError::IssuerUnavailable)?;
        if raw.len() == 32 {
            raw
        } else {
            let text = str::from_utf8(&raw).map_err(|_| N8nApprovalError::IssuerUnavailable)?;
            decode_public_key_text(text)?
        }
    } else {
        return Err(N8nApprovalError::IssuerUnavailable);
    };
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| N8nApprovalError::IssuerUnavailable)?;
    Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| N8nApprovalError::IssuerUnavailable)
}

fn decode_public_key_text(raw: &str) -> Result<Vec<u8>, N8nApprovalError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(N8nApprovalError::IssuerUnavailable);
    }
    hex::decode(trimmed)
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed))
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, trimmed))
        .map_err(|_| N8nApprovalError::IssuerUnavailable)
}

fn n8n_parent_binding_digest(
    server: N8nApprovalServer,
    resource_uri: &str,
    operation: &str,
    input: &Value,
) -> Result<String, N8nApprovalError> {
    let canonical = to_deterministic_cbor(&json!({
        "server_id": server.as_str(),
        "resource_uri": resource_uri,
        "operation": operation,
        "input": input,
    }))
    .map_err(|_| N8nApprovalError::InvalidPlan("high-level binding cannot be canonicalized"))?;
    Ok(hex::encode(blake3::hash(&canonical).as_bytes()))
}

/// Construct the unsigned existing FCP `ApprovalToken` shape. The isolated
/// binary owns private-key handling and signs the canonical bytes separately.
pub fn build_unsigned_n8n_approval_token(
    request: &N8nApprovalIssueRequest,
    now_ms: u64,
) -> Result<ApprovalToken, N8nApprovalError> {
    validate_issue_request(request, now_ms)?;
    let object = request
        .input
        .as_object()
        .ok_or(N8nApprovalError::InvalidPlan(
            "high-level input must be an object",
        ))?;
    let guard = object
        .get("guard")
        .and_then(Value::as_object)
        .ok_or(N8nApprovalError::InvalidPlan("guard is missing"))?;
    let approval_ref = guard
        .get("approvalRef")
        .and_then(Value::as_str)
        .ok_or(N8nApprovalError::InvalidPlan("approvalRef is missing"))?;
    let idempotency_key = guard
        .get("idempotencyKey")
        .and_then(Value::as_str)
        .ok_or(N8nApprovalError::InvalidPlan("idempotency key is missing"))?;
    let precondition = guard
        .get("precondition")
        .ok_or(N8nApprovalError::InvalidPlan("precondition is missing"))?;
    let plan = N8nApprovalPlan::from_official_mcp(
        request.server,
        &request.workflow_id,
        request.operation,
        &request.official_mcp_tool,
        &request.official_mcp_resource_uri,
        &request.official_mcp_payload_digest,
        &request.input,
        precondition,
        idempotency_key,
        request.expires_at_ms,
    )?;
    let expected_parent_binding = n8n_parent_binding_digest(
        request.server,
        &plan.resource_uri,
        request.operation.operation_id(),
        &request.input,
    )?;
    if expected_parent_binding != request.parent_binding_sha256 {
        return Err(N8nApprovalError::InvalidPlan(
            "parent binding does not match the exact high-level request",
        ));
    }
    let direct_rest = matches!(
        request.operation,
        N8nLifecycleOperation::CreateDraft | N8nLifecycleOperation::DeleteDisposable
    );
    let (connector_id, method_pattern, input_hash, constraints) = if direct_rest {
        let mut input_hash = [0_u8; 32];
        hex::decode_to_slice(&request.parent_binding_sha256, &mut input_hash).map_err(|_| {
            N8nApprovalError::InvalidPlan("parent binding is not a raw SHA-256 value")
        })?;
        (
            "fcp.n8n",
            request.operation.operation_id(),
            Some(input_hash),
            Vec::new(),
        )
    } else {
        let constraints = n8n_official_mcp_approval_constraints(
            request.server,
            &request.official_mcp_tool,
            &request.official_mcp_resource_uri,
            &request.official_mcp_payload_digest,
            &request.parent_binding_sha256,
            &plan.plan_digest,
        )?;
        let payload_hex = request
            .official_mcp_payload_digest
            .strip_prefix(OFFICIAL_MCP_PAYLOAD_DOMAIN)
            .ok_or(N8nApprovalError::InvalidPlan(
                "official MCP payload digest is invalid",
            ))?;
        let mut input_hash = [0_u8; 32];
        hex::decode_to_slice(payload_hex, &mut input_hash)
            .map_err(|_| N8nApprovalError::InvalidPlan("official MCP payload digest is invalid"))?;
        (
            "fcp.mcp-bridge",
            OFFICIAL_MCP_WRAPPER_OPERATION,
            Some(input_hash),
            constraints,
        )
    };
    Ok(ApprovalToken::approved(
        approval_ref,
        now_ms,
        request.expires_at_ms,
        APPROVAL_ISSUER,
        ApprovalScope::Execution(ExecutionScope {
            connector_id: connector_id.to_owned(),
            method_pattern: method_pattern.to_owned(),
            request_object_id: None,
            input_hash,
            input_constraints: constraints,
        }),
        ZoneId::work(),
        None,
    ))
}

fn validate_issue_request(
    request: &N8nApprovalIssueRequest,
    now_ms: u64,
) -> Result<(), N8nApprovalError> {
    if request.schema != APPROVAL_REQUEST_SCHEMA
        || request.expires_at_ms <= now_ms
        || request.expires_at_ms > now_ms.saturating_add(MAX_APPROVAL_TTL_MS)
    {
        return Err(N8nApprovalError::InvalidPlan(
            "request schema or short expiry is invalid",
        ));
    }
    let object = request
        .input
        .as_object()
        .ok_or(N8nApprovalError::InvalidPlan(
            "high-level input must be an object",
        ))?;
    let allowed_top_level: &[&str] = match request.operation {
        N8nLifecycleOperation::Publish => &["id", "action", "versionId", "guard"],
        N8nLifecycleOperation::Unpublish => &["id", "action", "guard"],
        N8nLifecycleOperation::Archive => &["id", "guard"],
        N8nLifecycleOperation::CreateDraft => {
            &["name", "project_id", "parent_folder_id", "graph", "guard"]
        }
        N8nLifecycleOperation::DeleteDisposable => &["id", "creationReceipt", "guard"],
    };
    if object
        .keys()
        .any(|key| !allowed_top_level.contains(&key.as_str()))
        || (request.operation != N8nLifecycleOperation::CreateDraft
            && object.get("id").and_then(Value::as_str) != Some(request.workflow_id.as_str()))
        || (request.operation == N8nLifecycleOperation::CreateDraft
            && !request.workflow_id.is_empty())
    {
        return Err(N8nApprovalError::InvalidPlan(
            "workflow target or high-level input is not exact",
        ));
    }
    match request.operation {
        N8nLifecycleOperation::Publish => {
            if object.get("action").and_then(Value::as_str) != Some("publish") {
                return Err(N8nApprovalError::InvalidPlan("publish action is not exact"));
            }
            if let Some(version) = object.get("versionId") {
                validate_identifier(version, "publish version is invalid")?;
            }
        }
        N8nLifecycleOperation::Unpublish => {
            if object.get("action").and_then(Value::as_str) != Some("unpublish") {
                return Err(N8nApprovalError::InvalidPlan(
                    "unpublish action is not exact",
                ));
            }
        }
        N8nLifecycleOperation::Archive => {}
        N8nLifecycleOperation::CreateDraft => {
            if object
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty() || value.len() > 256)
            {
                return Err(N8nApprovalError::InvalidPlan(
                    "create_draft name is invalid",
                ));
            }
            for field in ["project_id", "parent_folder_id"] {
                if let Some(value) = object.get(field) {
                    validate_identifier(value, "create_draft target is invalid")?;
                }
            }
            let graph = object.get("graph").and_then(Value::as_object).ok_or(
                N8nApprovalError::InvalidPlan("create_draft graph is invalid"),
            )?;
            if graph.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "nodes" | "connections" | "settings" | "staticData" | "pinData"
                )
            }) || graph
                .get("nodes")
                .and_then(Value::as_array)
                .is_none_or(|nodes| {
                    nodes.len() > 10_000 || nodes.iter().any(|node| !node.is_object())
                })
                || graph
                    .get("connections")
                    .and_then(Value::as_object)
                    .is_none()
            {
                return Err(N8nApprovalError::InvalidPlan(
                    "create_draft graph is invalid",
                ));
            }
            if let Some(settings) = graph.get("settings")
                && !settings.is_null()
            {
                let settings = settings.as_object().ok_or(N8nApprovalError::InvalidPlan(
                    "create_draft graph settings are invalid",
                ))?;
                if settings
                    .get("availableInMCP")
                    .is_some_and(|value| value != &Value::Bool(false))
                {
                    return Err(N8nApprovalError::InvalidPlan(
                        "create_draft cannot enable MCP access",
                    ));
                }
            }
        }
        N8nLifecycleOperation::DeleteDisposable => {
            let receipt = object
                .get("creationReceipt")
                .and_then(Value::as_str)
                .filter(|value| is_blake3_digest(value))
                .ok_or(N8nApprovalError::InvalidPlan(
                    "disposable creation receipt is invalid",
                ))?;
            if receipt["blake3-256:".len()..]
                .bytes()
                .any(|byte| byte.is_ascii_uppercase())
            {
                return Err(N8nApprovalError::InvalidPlan(
                    "disposable creation receipt is invalid",
                ));
            }
        }
    }
    if request.operation != N8nLifecycleOperation::CreateDraft {
        validate_identifier(
            object.get("id").unwrap_or(&Value::Null),
            "workflow id is invalid",
        )?;
    }
    let guard = object
        .get("guard")
        .and_then(Value::as_object)
        .ok_or(N8nApprovalError::InvalidPlan("guard is missing"))?;
    if guard.len() != 3
        || !guard.contains_key("approvalRef")
        || !guard.contains_key("idempotencyKey")
        || !guard.contains_key("precondition")
    {
        return Err(N8nApprovalError::InvalidPlan("guard is not exact"));
    }
    guard
        .get("approvalRef")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .ok_or(N8nApprovalError::InvalidPlan("approvalRef is invalid"))?;
    let idempotency_key = guard
        .get("idempotencyKey")
        .and_then(Value::as_str)
        .ok_or(N8nApprovalError::InvalidPlan("idempotency key is missing"))?;
    Uuid::parse_str(idempotency_key)
        .map_err(|_| N8nApprovalError::InvalidPlan("idempotency key must be a UUID"))?;
    let precondition = guard
        .get("precondition")
        .and_then(Value::as_object)
        .ok_or(N8nApprovalError::InvalidPlan("precondition is missing"))?;
    if request.operation == N8nLifecycleOperation::CreateDraft {
        if !precondition.is_empty() {
            return Err(N8nApprovalError::InvalidPlan(
                "create_draft precondition must be empty",
            ));
        }
        return Ok(());
    }
    const REQUIRED: [&str; 5] = [
        "versionId",
        "activeVersionId",
        "active",
        "isArchived",
        "stateDigest",
    ];
    if precondition.len() != REQUIRED.len()
        || REQUIRED
            .iter()
            .any(|field| !precondition.contains_key(*field))
    {
        return Err(N8nApprovalError::InvalidPlan("precondition is not exact"));
    }
    validate_identifier(
        precondition.get("versionId").unwrap_or(&Value::Null),
        "precondition version is invalid",
    )?;
    let active_version = precondition
        .get("activeVersionId")
        .ok_or(N8nApprovalError::InvalidPlan("activeVersionId is missing"))?;
    if !active_version.is_null() {
        validate_identifier(active_version, "activeVersionId is invalid")?;
    }
    if precondition
        .get("active")
        .and_then(Value::as_bool)
        .is_none()
        || precondition
            .get("isArchived")
            .and_then(Value::as_bool)
            .is_none()
        || precondition
            .get("stateDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| !is_blake3_digest(value))
    {
        return Err(N8nApprovalError::InvalidPlan(
            "precondition value is invalid",
        ));
    }
    if matches!(
        request.operation,
        N8nLifecycleOperation::Archive | N8nLifecycleOperation::DeleteDisposable
    ) && (precondition.get("active") != Some(&Value::Bool(false))
        || precondition.get("isArchived") != Some(&Value::Bool(false))
        || !active_version.is_null())
    {
        return Err(N8nApprovalError::InvalidPlan(
            "archive precondition is not inactive and unarchived",
        ));
    }
    Ok(())
}

fn validate_identifier(value: &Value, message: &'static str) -> Result<(), N8nApprovalError> {
    value
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 256 && value.trim() == *value)
        .ok_or(N8nApprovalError::InvalidPlan(message))?;
    Ok(())
}

fn is_blake3_digest(value: &str) -> bool {
    value.strip_prefix("blake3-256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn is_raw_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum N8nApprovalError {
    #[error("invalid n8n approval plan: {0}")]
    InvalidPlan(&'static str),
    #[error("owner confirmation does not match the exact n8n plan")]
    ConfirmationMismatch,
    #[error("n8n approval plan is stale or expired")]
    StalePlan,
    #[error("n8n owner approval issuer is unavailable")]
    IssuerUnavailable,
    #[error("trusted n8n approval token is invalid")]
    InvalidIssuedToken,
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            let mut canonical = serde_json::Map::new();
            for (key, child) in entries {
                canonical.insert(key.clone(), canonical_json(child));
            }
            Value::Object(canonical)
        }
        Value::Array(array) => Value::Array(array.iter().map(canonical_json).collect()),
        scalar => scalar.clone(),
    }
}

fn digest(domain: &[u8], value: &Value) -> String {
    let canonical = canonical_json(value);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&bytes);
    format!("blake3-256:{}", hasher.finalize().to_hex())
}

fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix(OFFICIAL_MCP_PAYLOAD_DOMAIN)
        .is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn encode_resource_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;
    const EXPIRY: u64 = 10_000;

    fn plan() -> N8nApprovalPlan {
        N8nApprovalPlan::new(
            N8nApprovalServer::Eec,
            "workflow-test-id",
            N8nLifecycleOperation::Publish,
            &json!({"id":"workflow-test-id","action":"publish","versionId":"v2"}),
            &json!({"versionId":"v1","active":false,"isArchived":false,"stateDigest":"digest"}),
            "00000000-0000-4000-8000-000000000001",
            EXPIRY,
        )
        .expect("plan")
    }

    fn token(_plan: &N8nApprovalPlan) -> ApprovalToken {
        ApprovalToken::approved(
            "token-test",
            NOW,
            EXPIRY,
            "owner",
            ApprovalScope::Execution(fcp_prelude::ExecutionScope {
                connector_id: "fcp.mcp-bridge".to_owned(),
                method_pattern: OFFICIAL_MCP_WRAPPER_OPERATION.to_owned(),
                request_object_id: None,
                input_hash: None,
                input_constraints: Vec::new(),
            }),
            ZoneId::work(),
            Some(vec![7; 64]),
        )
    }

    struct TestIssuer;
    impl N8nApprovalIssuer for TestIssuer {
        fn issue(
            &self,
            plan: &N8nApprovalPlan,
            _confirmation: &N8nOwnerConfirmation,
        ) -> Result<ApprovalToken, N8nApprovalError> {
            Ok(token(plan))
        }
    }

    #[test]
    fn plan_digest_binds_target_and_all_approval_fields() {
        let first = plan();
        let second = N8nApprovalPlan::new(
            N8nApprovalServer::Hetzner,
            "workflow-test-id",
            N8nLifecycleOperation::Publish,
            &json!({"action":"publish","id":"workflow-test-id","versionId":"v3"}),
            &json!({"isArchived":false,"active":false,"versionId":"v1","stateDigest":"digest"}),
            "00000000-0000-4000-8000-000000000001",
            EXPIRY,
        )
        .expect("plan");
        assert_ne!(first.plan_digest, second.plan_digest);
        assert_ne!(first.canonical_input_digest, second.canonical_input_digest);
        assert_ne!(first.resource_uri, second.resource_uri);
    }

    #[test]
    fn confirmation_is_exact_and_default_issuer_fails_closed() {
        let plan = plan();
        let mismatch = N8nOwnerConfirmation {
            plan_digest: "wrong".into(),
            confirmed_at_ms: NOW,
        };
        assert!(matches!(
            plan.confirm(&mismatch, &TestIssuer, NOW),
            Err(N8nApprovalError::ConfirmationMismatch)
        ));
        let confirmation = N8nOwnerConfirmation {
            plan_digest: plan.plan_digest.clone(),
            confirmed_at_ms: NOW,
        };
        assert!(matches!(
            plan.confirm(&confirmation, &FailClosedN8nApprovalIssuer, NOW),
            Err(N8nApprovalError::IssuerUnavailable)
        ));
        assert!(plan.confirm(&confirmation, &TestIssuer, NOW).is_ok());
    }

    #[test]
    fn expiry_and_token_shape_are_fail_closed() {
        let plan = plan();
        let confirmation = N8nOwnerConfirmation {
            plan_digest: plan.plan_digest.clone(),
            confirmed_at_ms: NOW,
        };
        assert!(matches!(
            plan.confirm(&confirmation, &TestIssuer, EXPIRY),
            Err(N8nApprovalError::StalePlan)
        ));
        let mut bad = token(&plan);
        bad.scope = ApprovalScope::Execution(fcp_prelude::ExecutionScope {
            connector_id: "fcp.mcp-bridge".to_owned(),
            method_pattern: "n8n.workflows.archive".to_owned(),
            request_object_id: None,
            input_hash: None,
            input_constraints: Vec::new(),
        });
        assert!(matches!(
            validate_issued_token_shape(&bad, &plan, NOW),
            Err(N8nApprovalError::InvalidIssuedToken)
        ));
    }

    #[test]
    fn debug_and_serialized_plan_redact_workflow_and_idempotency_material() {
        let plan = plan();
        let debug = format!("{plan:?}");
        assert!(!debug.contains("workflow-test-id"));
        assert!(!debug.contains("00000000-0000-4000-8000-000000000001"));
        let serialized = serde_json::to_string(&plan).expect("serialize");
        assert!(serialized.contains("plan_digest"));
    }

    #[test]
    fn canonical_token_bytes_omit_signature() {
        let mut token = token(&plan());
        let unsigned = canonical_approval_token_bytes(&token).expect("canonical");
        token.signature = Some(vec![9; 64]);
        let signed = canonical_approval_token_bytes(&token).expect("canonical");
        assert_eq!(unsigned, signed);
    }

    #[test]
    fn official_mcp_plan_digest_binds_every_host_admission_field() {
        let input = json!({
            "id": "workflow-1",
            "action": "publish",
            "versionId": "version-2",
            "guard": {
                "approvalRef": "owner-confirmation",
                "idempotencyKey": "00000000-0000-4000-8000-000000000001",
                "precondition": {
                    "versionId": "version-1",
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }
        });
        let precondition = input.pointer("/guard/precondition").expect("precondition");
        let payload = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let exact = n8n_typed_approval_plan_digest(
            "eec",
            "workflow-1",
            "publish",
            "publish_workflow",
            payload,
            &input,
            precondition,
            "00000000-0000-4000-8000-000000000001",
            EXPIRY,
            NOW,
        )
        .expect("exact plan digest");

        let changed_payload =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let cases = [
            n8n_typed_approval_plan_digest(
                "hetzner",
                "workflow-1",
                "publish",
                "publish_workflow",
                payload,
                &input,
                precondition,
                "00000000-0000-4000-8000-000000000001",
                EXPIRY,
                NOW,
            ),
            n8n_typed_approval_plan_digest(
                "eec",
                "workflow-2",
                "publish",
                "publish_workflow",
                payload,
                &input,
                precondition,
                "00000000-0000-4000-8000-000000000001",
                EXPIRY,
                NOW,
            ),
            n8n_typed_approval_plan_digest(
                "eec",
                "workflow-1",
                "publish",
                "publish_workflow",
                changed_payload,
                &input,
                precondition,
                "00000000-0000-4000-8000-000000000001",
                EXPIRY,
                NOW,
            ),
            n8n_typed_approval_plan_digest(
                "eec",
                "workflow-1",
                "publish",
                "publish_workflow",
                payload,
                &input,
                &json!({"stateDigest": "changed"}),
                "00000000-0000-4000-8000-000000000001",
                EXPIRY,
                NOW,
            ),
            n8n_typed_approval_plan_digest(
                "eec",
                "workflow-1",
                "publish",
                "publish_workflow",
                payload,
                &input,
                precondition,
                "00000000-0000-4000-8000-000000000002",
                EXPIRY,
                NOW,
            ),
            n8n_typed_approval_plan_digest(
                "eec",
                "workflow-1",
                "publish",
                "publish_workflow",
                payload,
                &input,
                precondition,
                "00000000-0000-4000-8000-000000000001",
                EXPIRY + 1,
                NOW,
            ),
        ];
        assert!(
            cases
                .into_iter()
                .all(|candidate| candidate.as_deref() != Some(exact.as_str()))
        );
        assert!(
            n8n_typed_approval_plan_digest(
                "eec",
                "workflow-1",
                "publish",
                "update_workflow",
                payload,
                &input,
                precondition,
                "00000000-0000-4000-8000-000000000001",
                EXPIRY,
                NOW,
            )
            .is_none()
        );
        assert!(
            n8n_typed_approval_plan_digest(
                "eec",
                "workflow-1",
                "publish",
                "publish_workflow",
                payload,
                &input,
                precondition,
                "00000000-0000-4000-8000-000000000001",
                EXPIRY,
                EXPIRY,
            )
            .is_none()
        );

        let mut changed_resource = N8nApprovalPlan::from_official_mcp(
            N8nApprovalServer::Eec,
            "workflow-1",
            N8nLifecycleOperation::Publish,
            "publish_workflow",
            "fwc-mcp-bridge://eec",
            payload,
            &input,
            precondition,
            "00000000-0000-4000-8000-000000000001",
            EXPIRY,
        )
        .expect("official plan");
        assert_eq!(
            changed_resource.resource_uri,
            "fwc-n8n://eec/workflows/workflow%2D1"
        );
        changed_resource.resource_uri = "fwc-n8n://eec/workflows/other".to_string();
        changed_resource.refresh_digest();
        assert_ne!(changed_resource.plan_digest, exact);
    }

    fn issue_request() -> N8nApprovalIssueRequest {
        let mut request = N8nApprovalIssueRequest {
            schema: APPROVAL_REQUEST_SCHEMA.to_owned(),
            server: N8nApprovalServer::Eec,
            workflow_id: "workflow-1".to_owned(),
            operation: N8nLifecycleOperation::Publish,
            input: json!({
                "id": "workflow-1",
                "action": "publish",
                "versionId": "version-2",
                "guard": {
                    "approvalRef": "approval-1",
                    "idempotencyKey": "00000000-0000-4000-8000-000000000001",
                    "precondition": {
                        "versionId": "version-1",
                        "activeVersionId": null,
                        "active": false,
                        "isArchived": false,
                        "stateDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                }
            }),
            official_mcp_tool: "publish_workflow".to_owned(),
            official_mcp_resource_uri: "fwc-mcp-bridge://eec".to_owned(),
            official_mcp_payload_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            parent_binding_sha256: String::new(),
            expires_at_ms: NOW + MAX_APPROVAL_TTL_MS,
        };
        let plan = N8nApprovalPlan::from_official_mcp(
            request.server,
            &request.workflow_id,
            request.operation,
            &request.official_mcp_tool,
            &request.official_mcp_resource_uri,
            &request.official_mcp_payload_digest,
            &request.input,
            &request.input["guard"]["precondition"],
            request.input["guard"]["idempotencyKey"]
                .as_str()
                .expect("idempotency key"),
            request.expires_at_ms,
        )
        .expect("plan");
        request.parent_binding_sha256 = n8n_parent_binding_digest(
            request.server,
            &plan.resource_uri,
            request.operation.operation_id(),
            &request.input,
        )
        .expect("parent binding");
        request
    }

    fn direct_rest_issue_request(
        operation: N8nLifecycleOperation,
    ) -> Result<N8nApprovalIssueRequest, N8nApprovalError> {
        let (workflow_id, input) = match operation {
            N8nLifecycleOperation::CreateDraft => (
                String::new(),
                json!({
                    "name": "Draft",
                    "project_id": "project-1",
                    "graph": {"nodes": [], "connections": {}},
                    "guard": {
                        "approvalRef": "approval-create",
                        "idempotencyKey": "00000000-0000-4000-8000-000000000002",
                        "precondition": {}
                    }
                }),
            ),
            N8nLifecycleOperation::DeleteDisposable => (
                "workflow-1".to_owned(),
                json!({
                    "id": "workflow-1",
                    "creationReceipt": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "guard": {
                        "approvalRef": "approval-delete",
                        "idempotencyKey": "00000000-0000-4000-8000-000000000003",
                        "precondition": {
                            "versionId": "version-1",
                            "activeVersionId": null,
                            "active": false,
                            "isArchived": false,
                            "stateDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    }
                }),
            ),
            _ => {
                return Err(N8nApprovalError::InvalidPlan(
                    "operation is not direct REST",
                ));
            }
        };
        let mut request = N8nApprovalIssueRequest {
            schema: APPROVAL_REQUEST_SCHEMA.to_owned(),
            server: N8nApprovalServer::Eec,
            workflow_id,
            operation,
            input,
            official_mcp_tool: String::new(),
            official_mcp_resource_uri: String::new(),
            official_mcp_payload_digest: String::new(),
            parent_binding_sha256: String::new(),
            expires_at_ms: NOW + MAX_APPROVAL_TTL_MS,
        };
        let resource_uri = if operation == N8nLifecycleOperation::CreateDraft {
            "fwc-n8n://eec/projects/project%2D1"
        } else {
            "fwc-n8n://eec/workflows/workflow%2D1"
        };
        let canonical_binding = to_deterministic_cbor(&json!({
            "server_id": "eec",
            "resource_uri": resource_uri,
            "operation": operation.operation_id(),
            "input": request.input.clone(),
        }))
        .expect("canonical direct REST binding");
        request.parent_binding_sha256 = hex::encode(blake3::hash(&canonical_binding).as_bytes());
        Ok(request)
    }

    #[test]
    fn direct_rest_issuer_matches_host_binding_for_create_and_disposable_delete() {
        for operation in [
            N8nLifecycleOperation::CreateDraft,
            N8nLifecycleOperation::DeleteDisposable,
        ] {
            let request = direct_rest_issue_request(operation).expect("direct REST fixture");
            let token = build_unsigned_n8n_approval_token(&request, NOW)
                .expect("direct REST unsigned approval");
            assert!(matches!(token.scope, ApprovalScope::Execution(_)));
            let ApprovalScope::Execution(scope) = token.scope else {
                return;
            };
            assert_eq!(scope.connector_id, "fcp.n8n");
            assert_eq!(scope.method_pattern, operation.operation_id());
            assert!(scope.input_constraints.is_empty());
            assert_eq!(
                scope.input_hash,
                Some(
                    hex::decode(request.parent_binding_sha256)
                        .expect("raw direct REST binding")
                        .try_into()
                        .expect("32-byte direct REST binding"),
                )
            );
        }
    }

    #[test]
    fn direct_rest_issuer_rejects_mcp_metadata_and_non_exact_delete_guard() {
        let mut wrong_mcp =
            direct_rest_issue_request(N8nLifecycleOperation::CreateDraft).expect("create fixture");
        wrong_mcp.official_mcp_tool = "publish_workflow".to_owned();
        assert!(build_unsigned_n8n_approval_token(&wrong_mcp, NOW).is_err());

        let mut wrong_delete = direct_rest_issue_request(N8nLifecycleOperation::DeleteDisposable)
            .expect("delete fixture");
        wrong_delete.input["guard"]["precondition"]["active"] = Value::Bool(true);
        assert!(build_unsigned_n8n_approval_token(&wrong_delete, NOW).is_err());

        let mut archived_delete =
            direct_rest_issue_request(N8nLifecycleOperation::DeleteDisposable)
                .expect("delete fixture");
        archived_delete.input["guard"]["precondition"]["isArchived"] = Value::Bool(true);
        assert!(build_unsigned_n8n_approval_token(&archived_delete, NOW).is_err());

        let mut active_version_delete =
            direct_rest_issue_request(N8nLifecycleOperation::DeleteDisposable)
                .expect("delete fixture");
        active_version_delete.input["guard"]["precondition"]["activeVersionId"] =
            Value::String("version-2".to_owned());
        assert!(build_unsigned_n8n_approval_token(&active_version_delete, NOW).is_err());

        let mut changed_receipt =
            direct_rest_issue_request(N8nLifecycleOperation::DeleteDisposable)
                .expect("delete fixture");
        changed_receipt.input["creationReceipt"] = Value::String(
            "blake3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_owned(),
        );
        assert!(build_unsigned_n8n_approval_token(&changed_receipt, NOW).is_err());

        let mut wrong_create =
            direct_rest_issue_request(N8nLifecycleOperation::CreateDraft).expect("create fixture");
        wrong_create.workflow_id = "workflow-1".to_owned();
        assert!(build_unsigned_n8n_approval_token(&wrong_create, NOW).is_err());
    }

    #[test]
    fn direct_rest_issued_token_shape_requires_exact_parent_binding() {
        let request =
            direct_rest_issue_request(N8nLifecycleOperation::CreateDraft).expect("create fixture");
        let mut token = build_unsigned_n8n_approval_token(&request, NOW)
            .expect("direct REST unsigned approval");
        assert!(matches!(token.scope, ApprovalScope::Execution(_)));
        let scope = match &mut token.scope {
            ApprovalScope::Execution(scope) => scope,
            _ => return,
        };
        scope.input_hash = Some([0_u8; 32]);
        let plan = N8nApprovalPlan::from_official_mcp(
            request.server,
            &request.workflow_id,
            request.operation,
            &request.official_mcp_tool,
            &request.official_mcp_resource_uri,
            &request.official_mcp_payload_digest,
            &request.input,
            &request.input["guard"]["precondition"],
            request.input["guard"]["idempotencyKey"]
                .as_str()
                .expect("idempotency key"),
            request.expires_at_ms,
        )
        .expect("direct REST plan");
        assert!(matches!(
            validate_issued_token_shape(&token, &plan, NOW),
            Err(N8nApprovalError::InvalidIssuedToken)
        ));
    }

    #[test]
    fn issued_token_has_host_parity_and_valid_signature() {
        let request = issue_request();
        let mut token = build_unsigned_n8n_approval_token(&request, NOW).expect("unsigned token");
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let bytes = canonical_approval_token_bytes(&token).expect("canonical token");
        token.signature = Some(signing_key.sign(&bytes).to_bytes().to_vec());
        let signature = fcp_crypto::ed25519::Ed25519Signature::try_from_slice(
            token.signature.as_deref().expect("signature"),
        )
        .expect("signature bytes");
        signing_key
            .verifying_key()
            .verify(
                &canonical_approval_token_bytes(&token).expect("canonical signed token"),
                &signature,
            )
            .expect("valid signature");
        assert!(matches!(token.scope, ApprovalScope::Execution(_)));
        let ApprovalScope::Execution(scope) = token.scope else {
            return;
        };
        assert_eq!(scope.connector_id, "fcp.mcp-bridge");
        assert_eq!(scope.method_pattern, OFFICIAL_MCP_WRAPPER_OPERATION);
        assert_eq!(scope.input_constraints.len(), 8);
        assert_eq!(
            scope
                .input_constraints
                .iter()
                .map(|constraint| constraint.pointer.as_str())
                .collect::<Vec<_>>(),
            vec![
                "/operation",
                "/parent_binding_sha256",
                "/payload_sha256",
                "/provider",
                "/resource_uri",
                "/server_id",
                "/tool_name",
                "/typed_plan_sha256",
            ]
        );
        assert!(scope.input_constraints.iter().any(|constraint| {
            constraint.pointer == "/parent_binding_sha256"
                && constraint.expected == Value::String(request.parent_binding_sha256.clone())
        }));
    }

    #[test]
    fn issuer_rejects_wrong_server_tool_precondition_idempotency_and_expiry() {
        let unknown_server = serde_json::from_value::<N8nApprovalIssueRequest>(json!({
            "schema": APPROVAL_REQUEST_SCHEMA,
            "server": "legacy",
            "workflow_id": "workflow-1",
            "operation": "publish",
            "input": {},
            "official_mcp_tool": "publish_workflow",
            "official_mcp_resource_uri": "fwc-mcp-bridge://legacy",
            "official_mcp_payload_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "parent_binding_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "expires_at_ms": NOW + 1,
        }));
        assert!(unknown_server.is_err());

        let mut wrong_tool = issue_request();
        wrong_tool.official_mcp_tool = "update_workflow".to_owned();
        assert!(build_unsigned_n8n_approval_token(&wrong_tool, NOW).is_err());

        let mut wrong_precondition = issue_request();
        wrong_precondition.input["guard"]["precondition"]["active"] = Value::String("false".into());
        assert!(build_unsigned_n8n_approval_token(&wrong_precondition, NOW).is_err());

        let mut wrong_idempotency = issue_request();
        wrong_idempotency.input["guard"]["idempotencyKey"] = Value::String("not-a-uuid".into());
        assert!(build_unsigned_n8n_approval_token(&wrong_idempotency, NOW).is_err());

        let mut stale = issue_request();
        stale.expires_at_ms = NOW;
        assert!(build_unsigned_n8n_approval_token(&stale, NOW).is_err());
        let mut too_long = issue_request();
        too_long.expires_at_ms = NOW + MAX_APPROVAL_TTL_MS + 1;
        assert!(build_unsigned_n8n_approval_token(&too_long, NOW).is_err());
    }

    #[test]
    fn issuer_rejects_parent_binding_that_does_not_match_request() {
        let mut request = issue_request();
        request.parent_binding_sha256 =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned();
        assert!(build_unsigned_n8n_approval_token(&request, NOW).is_err());
    }

    #[test]
    fn issue_request_debug_redacts_workflow_and_high_level_payload() {
        let debug = format!("{:?}", issue_request());
        assert!(!debug.contains("workflow-1"));
        assert!(!debug.contains("approval-1"));
        assert!(!debug.contains("version-2"));
    }
}
