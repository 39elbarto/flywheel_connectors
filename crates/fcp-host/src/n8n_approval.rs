//! Typed owner-confirmation seam for n8n lifecycle writes.
//!
//! This module deliberately does not own durable provider state, mint tokens,
//! read KeePass, or perform provider I/O. The production run-once path in
//! `fcp-host` remains the only authority for cryptographic verification,
//! request binding, replay protection, provider-attempt receipts, and
//! `unknown` recovery. This module only represents the exact plan that an
//! eventual trusted owner adapter may confirm and turn into the existing FCP
//! `ApprovalToken` format.

#![allow(dead_code)]

use std::fmt;

use blake3::Hasher;
use fcp_prelude::{ApprovalScope, ApprovalToken, Uuid, ZoneId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

const PLAN_DOMAIN: &[u8] = b"fwc-n8n.owner-approval-plan.v1";
const INPUT_DOMAIN: &[u8] = b"fwc-n8n.owner-approval-input.v1";
const PRECONDITION_DOMAIN: &[u8] = b"fwc-n8n.owner-approval-precondition.v1";

/// The typed lifecycle/archive operations covered by this seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum N8nLifecycleOperation {
    Publish,
    Unpublish,
    Archive,
}

impl N8nLifecycleOperation {
    pub(crate) const fn operation_id(self) -> &'static str {
        match self {
            Self::Publish | Self::Unpublish => "n8n.workflows.lifecycle",
            Self::Archive => "n8n.workflows.archive",
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Unpublish => "unpublish",
            Self::Archive => "archive",
        }
    }
}

/// An explicit provider target. Legacy LeviLaser is intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum N8nApprovalServer {
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

/// Redaction-safe owner-confirmation plan.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct N8nApprovalPlan {
    pub(crate) server: N8nApprovalServer,
    pub(crate) resource_uri: String,
    pub(crate) workflow_id: String,
    pub(crate) operation: N8nLifecycleOperation,
    pub(crate) canonical_input_digest: String,
    pub(crate) precondition_digest: String,
    pub(crate) idempotency_key: String,
    pub(crate) expires_at_ms: u64,
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
            .field("precondition_digest", &self.precondition_digest)
            .field("idempotency_key", &"[REDACTED]")
            .field("expires_at_ms", &self.expires_at_ms)
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
        if workflow_id.is_empty()
            || workflow_id.len() > 128
            || !workflow_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~')
            })
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
        let resource_uri = format!("fwc-n8n://{}/workflows/{workflow_id}", server.as_str());
        let canonical_input_digest = digest(INPUT_DOMAIN, input);
        let precondition_digest = digest(PRECONDITION_DOMAIN, precondition);
        let plan_digest = digest(
            PLAN_DOMAIN,
            &json!({
                "server": server.as_str(),
                "resource_uri": resource_uri,
                "workflow_id": workflow_id,
                "operation": operation.as_str(),
                "canonical_input_digest": canonical_input_digest,
                "precondition_digest": precondition_digest,
                "idempotency_key": idempotency_key,
                "expires_at_ms": expires_at_ms,
            }),
        );
        Ok(Self {
            server,
            resource_uri,
            workflow_id,
            operation,
            canonical_input_digest,
            precondition_digest,
            idempotency_key,
            expires_at_ms,
            plan_digest,
        })
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
    if scope.connector_id != "fcp.mcp-bridge"
        || scope.method_pattern != plan.operation.operation_id()
        || scope.request_object_id.is_some()
    {
        return Err(N8nApprovalError::InvalidIssuedToken);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum N8nApprovalError {
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

    fn token(plan: &N8nApprovalPlan) -> ApprovalToken {
        ApprovalToken::approved(
            "token-test",
            NOW,
            EXPIRY,
            "owner",
            ApprovalScope::Execution(fcp_prelude::ExecutionScope {
                connector_id: "fcp.mcp-bridge".to_owned(),
                method_pattern: plan.operation.operation_id().to_owned(),
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
}
