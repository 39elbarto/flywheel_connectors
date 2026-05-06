//! Secretless Matrix E2EE crypto adapter boundary.
//!
//! This module keeps the Matrix crypto boundary secretless. It pins the
//! dependency, exposes the no-network-I/O adapter contract, and only authorizes
//! decrypted projection from a verified crypto result supplied by that boundary.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::MatrixError;
use crate::types::{
    MatrixDeviceKeysQueryResponse, MatrixE2eeConfig, MatrixE2eeDeviceListStatus,
    MatrixE2eeMaterialStatus, MatrixEncryptedEventPolicy, MatrixStatePersistenceBackend,
    MatrixStatePersistenceConfig, MatrixUndecryptedRetryConfig,
};

/// Feature name that enables the audited Rust Matrix crypto backend.
pub const MATRIX_SDK_CRYPTO_BACKEND_FEATURE: &str = "matrix-sdk-crypto-backend";
/// Rust-1.85-compatible matrix-sdk-crypto version selected for this workspace.
pub const MATRIX_SDK_CRYPTO_VERSION: &str = "0.13.0";
/// Matrix SDK crypto is a sans-network-I/O state machine.
pub const MATRIX_CRYPTO_NETWORK_IO_MODEL: &str = "sans_network_io_push_pull";
/// Matrix Megolm room-event algorithm supported by the trust-gated projection.
pub const MATRIX_MEGOLM_ALGORITHM: &str = "m.megolm.v1.aes-sha2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixCryptoBackendKind {
    /// The matrix-sdk-crypto dependency is compiled behind the feature gate.
    MatrixSdkCrypto,
    /// The backend was not compiled and decrypted delivery must stay disabled.
    NotCompiled,
}

impl MatrixCryptoBackendKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MatrixSdkCrypto => "matrix-sdk-crypto",
            Self::NotCompiled => "not_compiled",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MatrixCryptoEngine {
    backend: MatrixCryptoBackendKind,
}

impl std::fmt::Debug for MatrixCryptoEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixCryptoEngine")
            .field("backend", &self.backend.label())
            .field("feature", &MATRIX_SDK_CRYPTO_BACKEND_FEATURE)
            .field("verified_decryption_available", &false)
            .finish_non_exhaustive()
    }
}

impl Default for MatrixCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MatrixCryptoEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            backend: compiled_backend_kind(),
        }
    }

    #[must_use]
    pub const fn backend(&self) -> MatrixCryptoBackendKind {
        self.backend
    }

    #[must_use]
    pub const fn backend_compiled(&self) -> bool {
        matches!(self.backend, MatrixCryptoBackendKind::MatrixSdkCrypto)
    }

    #[must_use]
    pub const fn verified_decryption_available(&self) -> bool {
        match self.backend {
            MatrixCryptoBackendKind::MatrixSdkCrypto | MatrixCryptoBackendKind::NotCompiled => {
                false
            }
        }
    }

    #[must_use]
    pub const fn encrypted_event_decision(
        &self,
        policy: MatrixEncryptedEventPolicy,
        e2ee: &MatrixE2eeConfig,
    ) -> MatrixEncryptedEventDecision {
        let delivery_policy = match policy {
            MatrixEncryptedEventPolicy::FailClosed => "fail_closed",
            MatrixEncryptedEventPolicy::MetadataOnly => "metadata_only",
        };
        let verified_decryption_available = self.verified_decryption_available();
        if e2ee.verified_decryption_requested {
            MatrixEncryptedEventDecision {
                delivery_policy,
                verified_decryption_available,
                decryption_status: "denied_unavailable",
                reason_code: "matrix_e2ee_verified_crypto_unimplemented",
                reason_message: "Verified Matrix E2EE decryption is not implemented in this connector yet, so encrypted payloads remain blocked and ciphertext is never emitted",
            }
        } else {
            MatrixEncryptedEventDecision {
                delivery_policy,
                verified_decryption_available,
                decryption_status: "not_attempted",
                reason_code: "verified_e2ee_decryption_not_requested",
                reason_message: "verified_e2ee_decryption_not_requested",
            }
        }
    }

    #[must_use]
    pub fn status_snapshot(&self, e2ee: &MatrixE2eeConfig) -> Value {
        json!({
            "dependency": "matrix-sdk-crypto",
            "dependency_version": MATRIX_SDK_CRYPTO_VERSION,
            "selected_backend": self.backend.label(),
            "compiled_feature": self.backend_compiled(),
            "feature_name": MATRIX_SDK_CRYPTO_BACKEND_FEATURE,
            "backend_available": self.backend_compiled(),
            "network_io_model": MATRIX_CRYPTO_NETWORK_IO_MODEL,
            "adapter_state": "boundary_only",
            "olm_machine_type": olm_machine_type_name(),
            "verified_decryption_requested": e2ee.verified_decryption_requested,
            "verified_decryption_available": self.verified_decryption_available(),
            "outgoing_requests": MatrixCryptoOutgoingRequestSummary::default().snapshot(),
            "maintenance_driver": maintenance_driver_snapshot(e2ee),
            "no_secret_persistence": true,
            "ciphertext_delivery": "never",
        })
    }

    #[must_use]
    pub fn trust_state_snapshot(
        &self,
        e2ee: &MatrixE2eeConfig,
        state_persistence: &MatrixStatePersistenceConfig,
    ) -> Value {
        MatrixCryptoTrustState::from_config(e2ee, state_persistence).snapshot()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixEncryptedEventDecision {
    pub delivery_policy: &'static str,
    pub verified_decryption_available: bool,
    pub decryption_status: &'static str,
    pub reason_code: &'static str,
    pub reason_message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixProjectionVerificationStatus {
    Verified,
    Unverified,
}

impl MatrixProjectionVerificationStatus {
    #[must_use]
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixEncryptedEventRedactionState {
    Clear,
    Redacted,
}

impl MatrixEncryptedEventRedactionState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Redacted => "redacted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixEncryptedEventProjectionContext {
    pub room_id: String,
    pub event_id: Option<String>,
    pub sender: Option<String>,
    pub origin_server_ts: Option<u64>,
    pub algorithm: Option<String>,
    pub session_id: Option<String>,
    pub redaction_state: MatrixEncryptedEventRedactionState,
    pub retry_attempts_used: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixVerifiedDecryptedMessageEvent {
    pub room_id: String,
    pub sender: String,
    pub sender_device_id: String,
    pub sender_device_trust: MatrixProjectionVerificationStatus,
    pub cross_signing_trust: MatrixProjectionVerificationStatus,
    pub session_id: String,
    pub session_room_id: String,
    pub session_trust: MatrixProjectionVerificationStatus,
    pub algorithm: String,
    pub replay_key: String,
    pub msgtype: String,
    pub body: String,
    pub format: Option<String>,
    pub formatted_body: Option<String>,
    pub redaction_state: MatrixEncryptedEventRedactionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixTrustGatedDecryptedProjection {
    pub authorized_event: Option<Value>,
    pub metadata_event: Value,
    pub dropped_reason: Option<&'static str>,
}

#[must_use]
pub fn project_trust_gated_decrypted_event(
    input: &MatrixEncryptedEventProjectionContext,
    candidate: Option<&MatrixVerifiedDecryptedMessageEvent>,
    e2ee: &MatrixE2eeConfig,
    state_persistence: &MatrixStatePersistenceConfig,
    seen_replay_keys: &[String],
) -> MatrixTrustGatedDecryptedProjection {
    if !e2ee.verified_decryption_requested {
        return denied_decrypted_projection(
            input,
            e2ee,
            state_persistence,
            "not_attempted",
            "verified_e2ee_decryption_not_requested",
            &[],
        );
    }

    let Some(candidate) = candidate else {
        let retry = undecrypted_retry_decision_snapshot(
            input.event_id.as_deref(),
            &input.room_id,
            input.retry_attempts_used,
            &e2ee.undecrypted_retry,
        );
        let outcome = retry
            .get("outcome")
            .and_then(Value::as_str)
            .unwrap_or("retry_scheduled");
        let reason = if outcome == MatrixCryptoMaintenanceOutcome::FinalFailure.label() {
            "undecrypted_retry_budget_exhausted"
        } else {
            "matrix_e2ee_verified_plaintext_unavailable"
        };
        return denied_decrypted_projection_with_retry(
            input,
            e2ee,
            state_persistence,
            outcome,
            reason,
            &[reason],
            retry,
        );
    };

    let denial_reasons = decrypted_projection_denial_reasons(
        input,
        candidate,
        e2ee,
        state_persistence,
        seen_replay_keys,
    );
    if let Some(reason) = denial_reasons.first().copied() {
        return denied_decrypted_projection(
            input,
            e2ee,
            state_persistence,
            "denied",
            reason,
            &denial_reasons,
        );
    }

    let provenance = json!({
        "source_event_type": "m.room.encrypted",
        "algorithm": candidate.algorithm,
        "session": redacted_identifier_snapshot(Some(&candidate.session_id)),
        "sender_device": redacted_identifier_snapshot(Some(&candidate.sender_device_id)),
        "sender_device_trust": candidate.sender_device_trust.label(),
        "cross_signing_trust": candidate.cross_signing_trust.label(),
        "session_trust": candidate.session_trust.label(),
        "room_binding_verified": true,
        "sender_binding_verified": true,
        "replay_key": redacted_identifier_snapshot(Some(&candidate.replay_key)),
        "ciphertext_redacted": true,
        "contains_secret_material": false,
    });
    let authorized_event = json!({
        "room_id": input.room_id,
        "event_id": input.event_id,
        "sender": input.sender,
        "origin_server_ts": input.origin_server_ts,
        "msgtype": candidate.msgtype,
        "body": candidate.body,
        "format": candidate.format,
        "formatted_body": candidate.formatted_body,
        "delivery_body": candidate.body,
        "delivery_context": {
            "verified_decryption": true,
            "policy_source": "matrix_e2ee_trust_gate",
            "e2ee_provenance": provenance,
        },
    });
    let metadata_event = decrypted_projection_metadata(
        input,
        e2ee,
        state_persistence,
        "authorized_decrypted",
        "verified_decrypted",
        &[],
        json!({
            "classification": "not_needed",
            "outcome": "authorized_decrypted",
            "contains_secret_material": false,
        }),
        true,
    );

    MatrixTrustGatedDecryptedProjection {
        authorized_event: Some(authorized_event),
        metadata_event,
        dropped_reason: None,
    }
}

fn decrypted_projection_denial_reasons(
    input: &MatrixEncryptedEventProjectionContext,
    candidate: &MatrixVerifiedDecryptedMessageEvent,
    e2ee: &MatrixE2eeConfig,
    state_persistence: &MatrixStatePersistenceConfig,
    seen_replay_keys: &[String],
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if input.redaction_state == MatrixEncryptedEventRedactionState::Redacted
        || candidate.redaction_state == MatrixEncryptedEventRedactionState::Redacted
    {
        reasons.push("redacted_event_denied");
    }
    if input.algorithm.as_deref() != Some(MATRIX_MEGOLM_ALGORITHM)
        || candidate.algorithm != MATRIX_MEGOLM_ALGORITHM
    {
        reasons.push("unsupported_algorithm");
    }
    if input.room_id != candidate.room_id || input.room_id != candidate.session_room_id {
        reasons.push("wrong_room");
    }
    if input.sender.as_deref() != Some(candidate.sender.as_str()) {
        reasons.push("wrong_sender_device");
    }
    if input.session_id.as_deref() != Some(candidate.session_id.as_str()) {
        reasons.push("session_provenance_mismatch");
    }
    if e2ee
        .account_user_id
        .as_deref()
        .is_none_or(|user_id| !matrix_user_id_valid(user_id))
    {
        reasons.push("account_identity_unverified");
    }
    if e2ee
        .device_id
        .as_deref()
        .is_none_or(|device_id| !matrix_device_id_valid(device_id))
    {
        reasons.push("device_identity_unverified");
    }
    if state_persistence.account_user_id.is_some()
        && state_persistence.account_user_id.as_deref() != e2ee.account_user_id.as_deref()
    {
        reasons.push("state_account_scope_mismatch");
    }
    if state_persistence.device_id.is_some()
        && state_persistence.device_id.as_deref() != e2ee.device_id.as_deref()
    {
        reasons.push("state_device_scope_mismatch");
    }
    if e2ee.trust_state.device_keys != MatrixE2eeMaterialStatus::Verified {
        reasons.push("device_keys_unverified");
    }
    if e2ee.trust_state.device_list.status != MatrixE2eeDeviceListStatus::Fresh {
        reasons.push("device_list_not_fresh");
    }
    if e2ee.trust.require_verified_device_trust
        && e2ee.trust_state.own_device != MatrixE2eeMaterialStatus::Verified
    {
        reasons.push("own_device_unverified");
    }
    if e2ee.trust.require_cross_signing
        && e2ee.trust_state.cross_signing != MatrixE2eeMaterialStatus::Verified
    {
        reasons.push("cross_signing_unverified");
    }
    if e2ee.trust.require_room_key_backup
        && e2ee.room_key_backup.status != MatrixE2eeMaterialStatus::Verified
    {
        reasons.push("room_key_backup_unverified");
    }
    if e2ee.recovery.status != MatrixE2eeMaterialStatus::Verified {
        reasons.push("recovery_material_unverified");
    }
    if !candidate.sender_device_trust.is_verified() {
        reasons.push("sender_device_untrusted");
    }
    if e2ee.trust.require_cross_signing && !candidate.cross_signing_trust.is_verified() {
        reasons.push("sender_cross_signing_unverified");
    }
    if !candidate.session_trust.is_verified() {
        reasons.push("session_unverified");
    }
    if seen_replay_keys
        .iter()
        .any(|seen| seen == &candidate.replay_key)
    {
        reasons.push("replay_duplicate");
    }
    reasons
}

fn denied_decrypted_projection(
    input: &MatrixEncryptedEventProjectionContext,
    e2ee: &MatrixE2eeConfig,
    state_persistence: &MatrixStatePersistenceConfig,
    outcome: &'static str,
    reason_code: &'static str,
    denial_reasons: &[&'static str],
) -> MatrixTrustGatedDecryptedProjection {
    denied_decrypted_projection_with_retry(
        input,
        e2ee,
        state_persistence,
        outcome,
        reason_code,
        denial_reasons,
        undecrypted_retry_decision_snapshot(
            input.event_id.as_deref(),
            &input.room_id,
            input.retry_attempts_used,
            &e2ee.undecrypted_retry,
        ),
    )
}

fn denied_decrypted_projection_with_retry(
    input: &MatrixEncryptedEventProjectionContext,
    e2ee: &MatrixE2eeConfig,
    state_persistence: &MatrixStatePersistenceConfig,
    outcome: &'static str,
    reason_code: &'static str,
    denial_reasons: &[&'static str],
    retry: Value,
) -> MatrixTrustGatedDecryptedProjection {
    MatrixTrustGatedDecryptedProjection {
        authorized_event: None,
        metadata_event: decrypted_projection_metadata(
            input,
            e2ee,
            state_persistence,
            outcome,
            reason_code,
            denial_reasons,
            retry,
            false,
        ),
        dropped_reason: Some(reason_code),
    }
}

fn decrypted_projection_metadata(
    input: &MatrixEncryptedEventProjectionContext,
    e2ee: &MatrixE2eeConfig,
    state_persistence: &MatrixStatePersistenceConfig,
    outcome: &'static str,
    reason_code: &'static str,
    denial_reasons: &[&'static str],
    retry: Value,
    plaintext_emitted: bool,
) -> Value {
    json!({
        "room_id": input.room_id,
        "event_id": input.event_id,
        "sender": input.sender,
        "origin_server_ts": input.origin_server_ts,
        "algorithm": input.algorithm,
        "session": redacted_identifier_snapshot(input.session_id.as_deref()),
        "redaction_state": input.redaction_state.label(),
        "verified_decryption_requested": e2ee.verified_decryption_requested,
        "decryption_status": outcome,
        "decryption_reason": reason_code,
        "denial_reason_codes": denial_reasons,
        "plaintext_emitted": plaintext_emitted,
        "ciphertext_redacted": true,
        "trust_state": MatrixCryptoTrustState::from_config(e2ee, state_persistence).snapshot(),
        "undecrypted_retry": retry,
        "fcp_error_mapping": decrypted_projection_fcp_error_mapping(reason_code),
        "contains_secret_material": false,
    })
}

fn decrypted_projection_fcp_error_mapping(reason_code: &str) -> Value {
    let code = if matches!(
        reason_code,
        "verified_decrypted"
            | "verified_e2ee_decryption_not_requested"
            | "matrix_e2ee_verified_plaintext_unavailable"
            | "undecrypted_retry_budget_exhausted"
    ) {
        None
    } else if matches!(
        reason_code,
        "wrong_room" | "replay_duplicate" | "redacted_event_denied" | "unsupported_algorithm"
    ) {
        Some("FCP-1006")
    } else {
        Some("FCP-2001")
    };
    json!({
        "code": code,
        "category": match code {
            Some("FCP-1006") => Some("invalid_request"),
            Some("FCP-2001") => Some("unauthorized"),
            _ => None,
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixCryptoOutgoingRequestKind {
    DeviceKeysUpload,
    DeviceKeysQuery,
    DeviceKeysClaim,
    ToDevice,
    RoomKeyBackupVersion,
    RoomKeyBackupUpload,
    Unknown,
}

impl MatrixCryptoOutgoingRequestKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeviceKeysUpload => "device_keys_upload",
            Self::DeviceKeysQuery => "device_keys_query",
            Self::DeviceKeysClaim => "device_keys_claim",
            Self::ToDevice => "to_device",
            Self::RoomKeyBackupVersion => "room_key_backup_version",
            Self::RoomKeyBackupUpload => "room_key_backup_upload",
            Self::Unknown => "unknown",
        }
    }
}

#[must_use]
pub fn classify_outgoing_request_endpoint(endpoint: &str) -> MatrixCryptoOutgoingRequestKind {
    if endpoint.contains("/keys/upload") {
        MatrixCryptoOutgoingRequestKind::DeviceKeysUpload
    } else if endpoint.contains("/keys/query") {
        MatrixCryptoOutgoingRequestKind::DeviceKeysQuery
    } else if endpoint.contains("/keys/claim") {
        MatrixCryptoOutgoingRequestKind::DeviceKeysClaim
    } else if endpoint.contains("/sendToDevice/") {
        MatrixCryptoOutgoingRequestKind::ToDevice
    } else if endpoint.contains("/room_keys/version") {
        MatrixCryptoOutgoingRequestKind::RoomKeyBackupVersion
    } else if endpoint.contains("/room_keys/keys") {
        MatrixCryptoOutgoingRequestKind::RoomKeyBackupUpload
    } else {
        MatrixCryptoOutgoingRequestKind::Unknown
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatrixCryptoOutgoingRequestSummary {
    pub device_keys_upload: usize,
    pub device_keys_query: usize,
    pub device_keys_claim: usize,
    pub to_device: usize,
    pub room_key_backup_version: usize,
    pub room_key_backup_upload: usize,
    pub unknown: usize,
}

impl MatrixCryptoOutgoingRequestSummary {
    #[must_use]
    pub fn from_endpoints<'a>(endpoints: impl IntoIterator<Item = &'a str>) -> Self {
        let mut summary = Self::default();
        for endpoint in endpoints {
            summary.record(classify_outgoing_request_endpoint(endpoint));
        }
        summary
    }

    pub const fn record(&mut self, kind: MatrixCryptoOutgoingRequestKind) {
        match kind {
            MatrixCryptoOutgoingRequestKind::DeviceKeysUpload => self.device_keys_upload += 1,
            MatrixCryptoOutgoingRequestKind::DeviceKeysQuery => self.device_keys_query += 1,
            MatrixCryptoOutgoingRequestKind::DeviceKeysClaim => self.device_keys_claim += 1,
            MatrixCryptoOutgoingRequestKind::ToDevice => self.to_device += 1,
            MatrixCryptoOutgoingRequestKind::RoomKeyBackupVersion => {
                self.room_key_backup_version += 1;
            }
            MatrixCryptoOutgoingRequestKind::RoomKeyBackupUpload => {
                self.room_key_backup_upload += 1;
            }
            MatrixCryptoOutgoingRequestKind::Unknown => self.unknown += 1,
        }
    }

    #[must_use]
    pub const fn total(&self) -> usize {
        self.device_keys_upload
            + self.device_keys_query
            + self.device_keys_claim
            + self.to_device
            + self.room_key_backup_version
            + self.room_key_backup_upload
            + self.unknown
    }

    #[must_use]
    pub fn snapshot(&self) -> Value {
        json!({
            "total_pending": self.total(),
            "by_kind": {
                "device_keys_upload": self.device_keys_upload,
                "device_keys_query": self.device_keys_query,
                "device_keys_claim": self.device_keys_claim,
                "to_device": self.to_device,
                "room_key_backup_version": self.room_key_backup_version,
                "room_key_backup_upload": self.room_key_backup_upload,
                "unknown": self.unknown,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixCryptoMaintenanceOutcome {
    Pending,
    Sent,
    RetryScheduled,
    FinalFailure,
    Denied,
}

impl MatrixCryptoMaintenanceOutcome {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::RetryScheduled => "retry_scheduled",
            Self::FinalFailure => "final_failure",
            Self::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixCryptoMaintenanceDecision {
    pub request_kind: MatrixCryptoOutgoingRequestKind,
    pub outcome: MatrixCryptoMaintenanceOutcome,
    pub attempts_used: u32,
    pub next_attempt: Option<u32>,
    pub retry_after_ms: Option<u64>,
    pub reason_code: &'static str,
    pub operator_guidance: &'static str,
}

impl MatrixCryptoMaintenanceDecision {
    #[must_use]
    pub fn snapshot(&self) -> Value {
        json!({
            "request_kind": self.request_kind.label(),
            "outcome": self.outcome.label(),
            "attempts_used": self.attempts_used,
            "next_attempt": self.next_attempt,
            "retry_after_ms": self.retry_after_ms,
            "reason_code": self.reason_code,
            "operator_guidance": self.operator_guidance,
            "contains_secret_material": false,
        })
    }
}

#[must_use]
pub const fn mark_outgoing_request_sent(
    request_kind: MatrixCryptoOutgoingRequestKind,
) -> MatrixCryptoMaintenanceDecision {
    MatrixCryptoMaintenanceDecision {
        request_kind,
        outcome: MatrixCryptoMaintenanceOutcome::Sent,
        attempts_used: 1,
        next_attempt: None,
        retry_after_ms: None,
        reason_code: "homeserver_request_marked_sent",
        operator_guidance: "Mark the crypto request as sent only after the homeserver accepts it.",
    }
}

#[must_use]
pub fn classify_outgoing_request_failure(
    request_kind: MatrixCryptoOutgoingRequestKind,
    error: &MatrixError,
    attempts_used: u32,
    retry: &MatrixUndecryptedRetryConfig,
) -> MatrixCryptoMaintenanceDecision {
    if matches!(
        error,
        MatrixError::Unauthorized(_) | MatrixError::Forbidden(_)
    ) {
        return MatrixCryptoMaintenanceDecision {
            request_kind,
            outcome: MatrixCryptoMaintenanceOutcome::Denied,
            attempts_used,
            next_attempt: None,
            retry_after_ms: None,
            reason_code: "non_retryable_auth_failure",
            operator_guidance: "Refresh Matrix credentials or host credential injection before retrying crypto maintenance.",
        };
    }

    if error.is_retryable() && attempts_used < retry.max_attempts {
        let retry_after_ms = error
            .retry_after()
            .map_or(retry.retry_after_ms, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            });
        MatrixCryptoMaintenanceDecision {
            request_kind,
            outcome: MatrixCryptoMaintenanceOutcome::RetryScheduled,
            attempts_used,
            next_attempt: Some(attempts_used.saturating_add(1)),
            retry_after_ms: Some(retry_after_ms),
            reason_code: "retryable_homeserver_failure",
            operator_guidance: "Retry the outgoing crypto request without logging request bodies or key material.",
        }
    } else {
        MatrixCryptoMaintenanceDecision {
            request_kind,
            outcome: MatrixCryptoMaintenanceOutcome::FinalFailure,
            attempts_used,
            next_attempt: None,
            retry_after_ms: None,
            reason_code: if error.is_retryable() {
                "retry_budget_exhausted"
            } else {
                "non_retryable_homeserver_failure"
            },
            operator_guidance: "Surface the failure to operators and keep encrypted events undecrypted until recovery succeeds.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRoomKeyBackupDecision {
    pub required: bool,
    pub outcome: MatrixCryptoMaintenanceOutcome,
    pub version_matches: Option<bool>,
    pub reason_code: &'static str,
    pub operator_guidance: &'static str,
    expected_version: Option<String>,
    observed_version: Option<String>,
}

impl MatrixRoomKeyBackupDecision {
    #[must_use]
    pub fn snapshot(&self) -> Value {
        json!({
            "required": self.required,
            "outcome": self.outcome.label(),
            "version_matches": self.version_matches,
            "expected_version": redacted_identifier_snapshot(self.expected_version.as_deref()),
            "observed_version": redacted_identifier_snapshot(self.observed_version.as_deref()),
            "reason_code": self.reason_code,
            "operator_guidance": self.operator_guidance,
            "contains_secret_material": false,
        })
    }
}

#[must_use]
pub fn room_key_backup_version_decision(
    required: bool,
    expected_version: Option<&str>,
    observed_version: Option<&str>,
) -> MatrixRoomKeyBackupDecision {
    let version_matches = expected_version
        .zip(observed_version)
        .map(|(expected, observed)| expected == observed);
    let (outcome, reason_code, operator_guidance) = if !required {
        (
            MatrixCryptoMaintenanceOutcome::Sent,
            "room_key_backup_optional",
            "Room-key backup is optional for this connector instance.",
        )
    } else if observed_version.is_none() {
        (
            MatrixCryptoMaintenanceOutcome::Denied,
            "room_key_backup_missing",
            "Create or restore a Matrix room-key backup before enabling verified decrypted delivery.",
        )
    } else if version_matches == Some(false) {
        (
            MatrixCryptoMaintenanceOutcome::Denied,
            "room_key_backup_version_mismatch",
            "Reconcile the configured backup version with the homeserver before sharing or restoring room keys.",
        )
    } else {
        (
            MatrixCryptoMaintenanceOutcome::Sent,
            "room_key_backup_version_verified",
            "Room-key backup version matches the configured trust boundary.",
        )
    };

    MatrixRoomKeyBackupDecision {
        required,
        outcome,
        version_matches,
        reason_code,
        operator_guidance,
        expected_version: expected_version.map(ToOwned::to_owned),
        observed_version: observed_version.map(ToOwned::to_owned),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixStaleRoomKeyAction {
    None,
    Reupload,
    DeleteThenReupload,
}

impl MatrixStaleRoomKeyAction {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Reupload => "reupload",
            Self::DeleteThenReupload => "delete_then_reupload",
        }
    }
}

#[must_use]
pub fn stale_room_key_decision_snapshot(stale: bool, delete_remote_before_reupload: bool) -> Value {
    let action = if !stale {
        MatrixStaleRoomKeyAction::None
    } else if delete_remote_before_reupload {
        MatrixStaleRoomKeyAction::DeleteThenReupload
    } else {
        MatrixStaleRoomKeyAction::Reupload
    };
    json!({
        "action": action.label(),
        "delete_remote_before_reupload": matches!(action, MatrixStaleRoomKeyAction::DeleteThenReupload),
        "reupload": matches!(action, MatrixStaleRoomKeyAction::Reupload | MatrixStaleRoomKeyAction::DeleteThenReupload),
        "reason_code": match action {
            MatrixStaleRoomKeyAction::None => "room_key_current",
            MatrixStaleRoomKeyAction::Reupload => "stale_room_key_reupload",
            MatrixStaleRoomKeyAction::DeleteThenReupload => "stale_room_key_delete_then_reupload",
        },
        "contains_secret_material": false,
    })
}

#[must_use]
pub fn key_share_after_initial_sync_snapshot(
    initial_sync_complete: bool,
    tracked_room_count: usize,
) -> Value {
    let allowed = initial_sync_complete && tracked_room_count > 0;
    json!({
        "allowed": allowed,
        "initial_sync_complete": initial_sync_complete,
        "tracked_room_count": tracked_room_count,
        "reason_code": if allowed {
            "key_share_allowed_after_initial_sync"
        } else if !initial_sync_complete {
            "key_share_waiting_for_initial_sync"
        } else {
            "key_share_waiting_for_tracked_rooms"
        },
        "contains_secret_material": false,
    })
}

#[must_use]
pub fn recovery_guidance_snapshot(e2ee: &MatrixE2eeConfig) -> Value {
    let mut actions = Vec::new();
    if e2ee.recovery.status != MatrixE2eeMaterialStatus::Verified {
        actions.push("verify_recovery_material_out_of_band");
    }
    if e2ee.trust.require_room_key_backup
        && e2ee.room_key_backup.status != MatrixE2eeMaterialStatus::Verified
    {
        actions.push("repair_or_restore_room_key_backup");
    }
    if e2ee.trust.require_cross_signing
        && e2ee.trust_state.cross_signing != MatrixE2eeMaterialStatus::Verified
    {
        actions.push("verify_cross_signing_chain");
    }
    if e2ee.trust_state.device_list.status != MatrixE2eeDeviceListStatus::Fresh {
        actions.push("refresh_tracked_device_lists");
    }

    json!({
        "action_required": !actions.is_empty(),
        "actions": actions,
        "account": redacted_identifier_snapshot(e2ee.account_user_id.as_deref()),
        "device": redacted_identifier_snapshot(e2ee.device_id.as_deref()),
        "never_log_or_store_recovery_keys": true,
        "contains_secret_material": false,
    })
}

#[must_use]
pub fn undecrypted_retry_decision_snapshot(
    event_id: Option<&str>,
    room_id: &str,
    attempts_used: u32,
    retry: &MatrixUndecryptedRetryConfig,
) -> Value {
    let final_failure = attempts_used >= retry.max_attempts;
    json!({
        "classification": if final_failure {
            "final_failure"
        } else {
            "retryable_until_budget_exhausted"
        },
        "outcome": if final_failure {
            MatrixCryptoMaintenanceOutcome::FinalFailure.label()
        } else {
            MatrixCryptoMaintenanceOutcome::RetryScheduled.label()
        },
        "attempts_used": attempts_used,
        "max_attempts": retry.max_attempts,
        "next_attempt": if final_failure {
            None
        } else {
            Some(attempts_used.saturating_add(1))
        },
        "retry_after_ms": if final_failure {
            None
        } else {
            Some(retry.retry_after_ms)
        },
        "event": redacted_identifier_snapshot(event_id),
        "room": redacted_identifier_snapshot(Some(room_id)),
        "reason_code": if final_failure {
            "undecrypted_retry_budget_exhausted"
        } else {
            "undecrypted_event_waiting_for_key_maintenance"
        },
        "contains_secret_material": false,
    })
}

#[must_use]
pub fn maintenance_driver_snapshot(e2ee: &MatrixE2eeConfig) -> Value {
    json!({
        "enabled": e2ee.verified_decryption_requested,
        "network_io_model": MATRIX_CRYPTO_NETWORK_IO_MODEL,
        "transport": "matrix_client_explicit_methods",
        "supported_request_kinds": [
            MatrixCryptoOutgoingRequestKind::DeviceKeysUpload.label(),
            MatrixCryptoOutgoingRequestKind::DeviceKeysQuery.label(),
            MatrixCryptoOutgoingRequestKind::DeviceKeysClaim.label(),
            MatrixCryptoOutgoingRequestKind::ToDevice.label(),
            MatrixCryptoOutgoingRequestKind::RoomKeyBackupVersion.label(),
            MatrixCryptoOutgoingRequestKind::RoomKeyBackupUpload.label(),
        ],
        "mark_sent_semantics": "only_after_homeserver_success",
        "retry_budget": {
            "max_attempts": e2ee.undecrypted_retry.max_attempts,
            "retry_after_ms": e2ee.undecrypted_retry.retry_after_ms,
        },
        "room_key_backup_check": room_key_backup_version_decision(
            e2ee.trust.require_room_key_backup,
            e2ee.room_key_backup.backup_version.as_deref(),
            e2ee.room_key_backup.backup_version.as_deref(),
        ).snapshot(),
        "recovery_guidance": recovery_guidance_snapshot(e2ee),
        "decrypted_delivery_enabled": false,
        "contains_secret_material": false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixDeviceKeyImportSummary {
    pub user_count: usize,
    pub device_count: usize,
    pub master_key_count: usize,
    pub self_signing_key_count: usize,
    pub user_signing_key_count: usize,
    pub failure_count: usize,
    pub mismatched_device_records: usize,
}

impl MatrixDeviceKeyImportSummary {
    #[must_use]
    pub fn from_query_response(response: &MatrixDeviceKeysQueryResponse) -> Self {
        let mut device_count = 0_usize;
        let mut mismatched_device_records = 0_usize;
        for (user_id, devices) in &response.device_keys {
            for (device_id, device) in devices {
                device_count = device_count.saturating_add(1);
                if device.user_id != *user_id || device.device_id != *device_id {
                    mismatched_device_records = mismatched_device_records.saturating_add(1);
                }
            }
        }

        Self {
            user_count: response.device_keys.len(),
            device_count,
            master_key_count: response.master_keys.len(),
            self_signing_key_count: response.self_signing_keys.len(),
            user_signing_key_count: response.user_signing_keys.len(),
            failure_count: response.failures.len(),
            mismatched_device_records,
        }
    }

    #[must_use]
    pub const fn trust_status(&self) -> MatrixE2eeMaterialStatus {
        if self.failure_count > 0 || self.mismatched_device_records > 0 {
            MatrixE2eeMaterialStatus::PresentUnverified
        } else if self.device_count == 0 {
            MatrixE2eeMaterialStatus::Missing
        } else {
            MatrixE2eeMaterialStatus::Verified
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Value {
        json!({
            "user_count": self.user_count,
            "device_count": self.device_count,
            "master_key_count": self.master_key_count,
            "self_signing_key_count": self.self_signing_key_count,
            "user_signing_key_count": self.user_signing_key_count,
            "failure_count": self.failure_count,
            "mismatched_device_records": self.mismatched_device_records,
            "import_status": material_status_label(self.trust_status()),
            "contains_secret_material": false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MatrixCryptoTrustState<'a> {
    e2ee: &'a MatrixE2eeConfig,
    state_persistence: &'a MatrixStatePersistenceConfig,
}

impl<'a> MatrixCryptoTrustState<'a> {
    const fn from_config(
        e2ee: &'a MatrixE2eeConfig,
        state_persistence: &'a MatrixStatePersistenceConfig,
    ) -> Self {
        Self {
            e2ee,
            state_persistence,
        }
    }

    fn snapshot(&self) -> Value {
        let denial_reasons = self.denial_reasons();
        json!({
            "store_scope": self.store_scope_snapshot(),
            "account_identity": {
                "configured": self.e2ee.account_user_id.is_some(),
                "valid_shape": self.e2ee.account_user_id.as_deref().map(matrix_user_id_valid),
                "redacted": redacted_identifier_snapshot(self.e2ee.account_user_id.as_deref()),
            },
            "own_device": {
                "configured": self.e2ee.device_id.is_some(),
                "valid_shape": self.e2ee.device_id.as_deref().map(matrix_device_id_valid),
                "trust_required": self.e2ee.trust.require_verified_device_trust,
                "status": material_status_label(self.e2ee.trust_state.own_device),
                "requirement_satisfied": self.device_trust_satisfied(),
                "redacted": redacted_identifier_snapshot(self.e2ee.device_id.as_deref()),
            },
            "device_keys": {
                "status": material_status_label(self.e2ee.trust_state.device_keys),
                "verified": self.e2ee.trust_state.device_keys == MatrixE2eeMaterialStatus::Verified,
            },
            "device_list": {
                "status": device_list_status_label(self.e2ee.trust_state.device_list.status),
                "stale": device_list_stale(self.e2ee.trust_state.device_list.status),
                "last_refresh_age_ms": self.e2ee.trust_state.device_list.last_refresh_age_ms,
                "fresh_enough_for_verified_decrypt": self.e2ee.trust_state.device_list.status == MatrixE2eeDeviceListStatus::Fresh,
            },
            "cross_signing": {
                "required": self.e2ee.trust.require_cross_signing,
                "status": material_status_label(self.e2ee.trust_state.cross_signing),
                "requirement_satisfied": self.cross_signing_satisfied(),
            },
            "tracked": {
                "user_count": self.e2ee.trust_state.tracked_users.len(),
                "room_count": self.e2ee.trust_state.tracked_rooms.len(),
                "users": redacted_identifier_snapshots(&self.e2ee.trust_state.tracked_users),
                "rooms": redacted_identifier_snapshots(&self.e2ee.trust_state.tracked_rooms),
            },
            "readiness": {
                "trust_state_ready": denial_reasons.is_empty(),
                "denial_reason_codes": denial_reasons,
                "decrypted_delivery_enabled": false,
            },
            "no_secret_material": true,
        })
    }

    fn store_scope_snapshot(&self) -> Value {
        let account_matches = match (
            self.state_persistence.account_user_id.as_deref(),
            self.e2ee.account_user_id.as_deref(),
        ) {
            (Some(state_account), Some(e2ee_account)) => Some(state_account == e2ee_account),
            _ => None,
        };
        let device_matches = match (
            self.state_persistence.device_id.as_deref(),
            self.e2ee.device_id.as_deref(),
        ) {
            (Some(state_device), Some(e2ee_device)) => Some(state_device == e2ee_device),
            _ => None,
        };

        json!({
            "lifecycle": if self.state_persistence.enabled {
                "host_managed_snapshot_restore_then_memory_only_crypto_store"
            } else {
                "memory_only_crypto_store"
            },
            "backend": state_persistence_backend_label(self.state_persistence.backend),
            "connector_local_secret_persistence": false,
            "zone_scope": redacted_identifier_snapshot(self.state_persistence.zone_id.as_deref()),
            "account_scope": redacted_identifier_snapshot(self.state_persistence.account_user_id.as_deref()),
            "device_scope": redacted_identifier_snapshot(self.state_persistence.device_id.as_deref()),
            "account_matches_e2ee": account_matches,
            "device_matches_e2ee": device_matches,
            "restore": {
                "last_sync_token_configured": self.state_persistence.restore.last_sync_token.is_some(),
                "dynamic_direct_message_room_count": self.state_persistence.restore.dynamic_direct_message_rooms.len(),
                "thread_participation_root_count": self.state_persistence.restore.thread_participation_roots.len(),
            },
        })
    }

    fn denial_reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self
            .e2ee
            .account_user_id
            .as_deref()
            .is_none_or(|user_id| !matrix_user_id_valid(user_id))
        {
            reasons.push("account_identity_unverified");
        }
        if self
            .e2ee
            .device_id
            .as_deref()
            .is_none_or(|device_id| !matrix_device_id_valid(device_id))
        {
            reasons.push("device_identity_unverified");
        }
        if self.e2ee.trust_state.device_keys != MatrixE2eeMaterialStatus::Verified {
            reasons.push("device_keys_unverified");
        }
        if self.e2ee.trust_state.device_list.status != MatrixE2eeDeviceListStatus::Fresh {
            reasons.push("device_list_not_fresh");
        }
        if !self.device_trust_satisfied() {
            reasons.push("own_device_unverified");
        }
        if !self.cross_signing_satisfied() {
            reasons.push("cross_signing_unverified");
        }
        if self.e2ee.trust.require_room_key_backup
            && self.e2ee.room_key_backup.status != MatrixE2eeMaterialStatus::Verified
        {
            reasons.push("room_key_backup_unverified");
        }
        if self.e2ee.recovery.status == MatrixE2eeMaterialStatus::PresentUnverified {
            reasons.push("recovery_material_unverified");
        }
        reasons
    }

    const fn device_trust_satisfied(&self) -> bool {
        !self.e2ee.trust.require_verified_device_trust
            || matches!(
                self.e2ee.trust_state.own_device,
                MatrixE2eeMaterialStatus::Verified
            )
    }

    const fn cross_signing_satisfied(&self) -> bool {
        !self.e2ee.trust.require_cross_signing
            || matches!(
                self.e2ee.trust_state.cross_signing,
                MatrixE2eeMaterialStatus::Verified
            )
    }
}

fn redacted_identifier_snapshot(value: Option<&str>) -> Value {
    value.map_or_else(
        || json!({ "configured": false }),
        |value| {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            json!({
                "configured": true,
                "sha256": format!("sha256:{}", hex::encode(hasher.finalize())),
                "length": value.len(),
            })
        },
    )
}

fn redacted_identifier_snapshots(values: &[String]) -> Vec<Value> {
    values
        .iter()
        .map(|value| redacted_identifier_snapshot(Some(value)))
        .collect()
}

const fn state_persistence_backend_label(backend: MatrixStatePersistenceBackend) -> &'static str {
    match backend {
        MatrixStatePersistenceBackend::InMemory => "in_memory",
        MatrixStatePersistenceBackend::HostManagedSnapshot => "host_managed_snapshot",
    }
}

const fn material_status_label(status: MatrixE2eeMaterialStatus) -> &'static str {
    match status {
        MatrixE2eeMaterialStatus::Unknown => "unknown",
        MatrixE2eeMaterialStatus::Missing => "missing",
        MatrixE2eeMaterialStatus::PresentUnverified => "present_unverified",
        MatrixE2eeMaterialStatus::Verified => "verified",
    }
}

const fn device_list_status_label(status: MatrixE2eeDeviceListStatus) -> &'static str {
    match status {
        MatrixE2eeDeviceListStatus::Unknown => "unknown",
        MatrixE2eeDeviceListStatus::Missing => "missing",
        MatrixE2eeDeviceListStatus::Stale => "stale",
        MatrixE2eeDeviceListStatus::Fresh => "fresh",
    }
}

const fn device_list_stale(status: MatrixE2eeDeviceListStatus) -> bool {
    !matches!(status, MatrixE2eeDeviceListStatus::Fresh)
}

fn matrix_user_id_valid(user_id: &str) -> bool {
    user_id.starts_with('@')
        && user_id.contains(':')
        && !user_id.chars().any(char::is_whitespace)
        && user_id.len() > 3
}

fn matrix_device_id_valid(device_id: &str) -> bool {
    !device_id.is_empty() && device_id.len() <= 255 && !device_id.chars().any(char::is_whitespace)
}

const fn compiled_backend_kind() -> MatrixCryptoBackendKind {
    if cfg!(feature = "matrix-sdk-crypto-backend") {
        MatrixCryptoBackendKind::MatrixSdkCrypto
    } else {
        MatrixCryptoBackendKind::NotCompiled
    }
}

#[cfg(feature = "matrix-sdk-crypto-backend")]
fn olm_machine_type_name() -> Option<&'static str> {
    Some(std::any::type_name::<matrix_sdk_crypto::OlmMachine>())
}

#[cfg(not(feature = "matrix-sdk-crypto-backend"))]
const fn olm_machine_type_name() -> Option<&'static str> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        MatrixCrossSigningKey, MatrixDeviceKey, MatrixE2eeBackupConfig, MatrixE2eeDeviceListConfig,
        MatrixE2eeRecoveryConfig, MatrixE2eeTrustRequirements, MatrixE2eeTrustStateConfig,
        MatrixStateRestoreConfig, MatrixUndecryptedRetryConfig,
    };
    use std::collections::BTreeMap;

    #[test]
    fn status_snapshot_reports_secretless_backend_boundary() {
        let engine = MatrixCryptoEngine::new();
        let config = MatrixE2eeConfig {
            verified_decryption_requested: true,
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            ..MatrixE2eeConfig::default()
        };

        let snapshot = engine.status_snapshot(&config);

        assert_eq!(snapshot["dependency"].as_str(), Some("matrix-sdk-crypto"));
        assert_eq!(
            snapshot["dependency_version"].as_str(),
            Some(MATRIX_SDK_CRYPTO_VERSION)
        );
        assert_eq!(
            snapshot["network_io_model"].as_str(),
            Some(MATRIX_CRYPTO_NETWORK_IO_MODEL)
        );
        assert_eq!(snapshot["adapter_state"].as_str(), Some("boundary_only"));
        assert_eq!(
            snapshot["verified_decryption_available"].as_bool(),
            Some(false)
        );
        assert_eq!(snapshot["ciphertext_delivery"].as_str(), Some("never"));
        assert!(!snapshot.to_string().contains("@bot:matrix.example"));
        assert!(!snapshot.to_string().contains("DEVICE123"));
    }

    #[test]
    fn encrypted_event_decision_preserves_fail_closed_unavailable_state() {
        let engine = MatrixCryptoEngine::new();
        let config = MatrixE2eeConfig {
            verified_decryption_requested: true,
            ..MatrixE2eeConfig::default()
        };

        let decision =
            engine.encrypted_event_decision(MatrixEncryptedEventPolicy::FailClosed, &config);

        assert_eq!(decision.delivery_policy, "fail_closed");
        assert!(!decision.verified_decryption_available);
        assert_eq!(decision.decryption_status, "denied_unavailable");
        assert_eq!(
            decision.reason_code,
            "matrix_e2ee_verified_crypto_unimplemented"
        );
    }

    #[test]
    fn outgoing_request_summary_classifies_matrix_crypto_endpoints() {
        let summary = MatrixCryptoOutgoingRequestSummary::from_endpoints([
            "/_matrix/client/v3/keys/upload",
            "/_matrix/client/v3/keys/query",
            "/_matrix/client/v3/keys/claim",
            "/_matrix/client/v3/sendToDevice/m.room.encrypted/txn",
            "/_matrix/client/v3/room_keys/version",
            "/_matrix/client/v3/room_keys/keys/!room/session",
            "/_matrix/client/v3/unknown",
        ]);

        assert_eq!(summary.total(), 7);
        assert_eq!(summary.device_keys_upload, 1);
        assert_eq!(summary.device_keys_query, 1);
        assert_eq!(summary.device_keys_claim, 1);
        assert_eq!(summary.to_device, 1);
        assert_eq!(summary.room_key_backup_version, 1);
        assert_eq!(summary.room_key_backup_upload, 1);
        assert_eq!(summary.unknown, 1);
    }

    #[test]
    fn outgoing_request_mark_sent_and_retry_budget_transitions_are_deterministic() {
        let retry = MatrixUndecryptedRetryConfig {
            max_attempts: 2,
            retry_after_ms: 500,
        };
        let sent = mark_outgoing_request_sent(MatrixCryptoOutgoingRequestKind::DeviceKeysUpload);
        assert_eq!(sent.outcome, MatrixCryptoMaintenanceOutcome::Sent);
        assert_eq!(sent.reason_code, "homeserver_request_marked_sent");

        let rate_limited = MatrixError::RateLimited {
            retry_after_ms: 250,
        };
        let retry_decision = classify_outgoing_request_failure(
            MatrixCryptoOutgoingRequestKind::ToDevice,
            &rate_limited,
            1,
            &retry,
        );
        assert_eq!(
            retry_decision.outcome,
            MatrixCryptoMaintenanceOutcome::RetryScheduled
        );
        assert_eq!(retry_decision.next_attempt, Some(2));
        assert_eq!(retry_decision.retry_after_ms, Some(250));

        let final_decision = classify_outgoing_request_failure(
            MatrixCryptoOutgoingRequestKind::ToDevice,
            &rate_limited,
            2,
            &retry,
        );
        assert_eq!(
            final_decision.outcome,
            MatrixCryptoMaintenanceOutcome::FinalFailure
        );
        assert_eq!(final_decision.reason_code, "retry_budget_exhausted");
    }

    #[test]
    fn outgoing_request_auth_failure_is_non_retryable_and_maps_to_fcp_unauthorized() {
        let error = MatrixError::Unauthorized("bad token".into());
        let decision = classify_outgoing_request_failure(
            MatrixCryptoOutgoingRequestKind::DeviceKeysQuery,
            &error,
            1,
            &MatrixUndecryptedRetryConfig::default(),
        );

        assert_eq!(decision.outcome, MatrixCryptoMaintenanceOutcome::Denied);
        assert_eq!(decision.reason_code, "non_retryable_auth_failure");
        assert_eq!(decision.next_attempt, None);
        assert!(matches!(
            error.to_fcp_error(),
            fcp_prelude::FcpError::Unauthorized { code: 2001, .. }
        ));
    }

    #[test]
    fn room_key_backup_mismatch_denies_and_redacts_versions() {
        let decision =
            room_key_backup_version_decision(true, Some("SECRET_EXPECTED_V1"), Some("remote-v2"));
        let snapshot = decision.snapshot();

        assert_eq!(decision.outcome, MatrixCryptoMaintenanceOutcome::Denied);
        assert_eq!(decision.version_matches, Some(false));
        assert_eq!(
            snapshot["reason_code"].as_str(),
            Some("room_key_backup_version_mismatch")
        );
        assert!(!snapshot.to_string().contains("SECRET_EXPECTED_V1"));
        assert_eq!(snapshot["contains_secret_material"].as_bool(), Some(false));
    }

    #[test]
    fn stale_room_key_decision_records_reupload_and_delete_paths() {
        let reupload = stale_room_key_decision_snapshot(true, false);
        let delete_then_reupload = stale_room_key_decision_snapshot(true, true);
        let current = stale_room_key_decision_snapshot(false, true);

        assert_eq!(reupload["action"].as_str(), Some("reupload"));
        assert_eq!(
            delete_then_reupload["action"].as_str(),
            Some("delete_then_reupload")
        );
        assert_eq!(
            delete_then_reupload["delete_remote_before_reupload"].as_bool(),
            Some(true)
        );
        assert_eq!(current["action"].as_str(), Some("none"));
    }

    #[test]
    fn key_share_after_initial_sync_gate_waits_for_sync_and_tracked_rooms() {
        let before_sync = key_share_after_initial_sync_snapshot(false, 1);
        let no_rooms = key_share_after_initial_sync_snapshot(true, 0);
        let allowed = key_share_after_initial_sync_snapshot(true, 2);

        assert_eq!(before_sync["allowed"].as_bool(), Some(false));
        assert_eq!(
            before_sync["reason_code"].as_str(),
            Some("key_share_waiting_for_initial_sync")
        );
        assert_eq!(
            no_rooms["reason_code"].as_str(),
            Some("key_share_waiting_for_tracked_rooms")
        );
        assert_eq!(allowed["allowed"].as_bool(), Some(true));
    }

    #[test]
    fn recovery_guidance_redacts_scope_and_never_requests_secret_logging() {
        let e2ee = MatrixE2eeConfig {
            verified_decryption_requested: true,
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("SECRET_DEVICE".into()),
            trust_state: MatrixE2eeTrustStateConfig {
                device_list: MatrixE2eeDeviceListConfig {
                    status: MatrixE2eeDeviceListStatus::Stale,
                    last_refresh_age_ms: Some(120_000),
                },
                ..MatrixE2eeTrustStateConfig::default()
            },
            recovery: MatrixE2eeRecoveryConfig {
                status: MatrixE2eeMaterialStatus::Missing,
            },
            room_key_backup: MatrixE2eeBackupConfig {
                status: MatrixE2eeMaterialStatus::PresentUnverified,
                backup_version: Some("SECRET_BACKUP".into()),
            },
            ..MatrixE2eeConfig::default()
        };

        let guidance = recovery_guidance_snapshot(&e2ee);
        let guidance_text = guidance.to_string();
        assert_eq!(guidance["action_required"].as_bool(), Some(true));
        assert_eq!(
            guidance["never_log_or_store_recovery_keys"].as_bool(),
            Some(true)
        );
        assert!(!guidance_text.contains("@bot:matrix.example"));
        assert!(!guidance_text.contains("SECRET_DEVICE"));
        assert!(!guidance_text.contains("SECRET_BACKUP"));
    }

    #[test]
    fn undecrypted_retry_decision_redacts_ids_and_marks_final_failure() {
        let retry = MatrixUndecryptedRetryConfig {
            max_attempts: 2,
            retry_after_ms: 500,
        };
        let retrying = undecrypted_retry_decision_snapshot(
            Some("$event-secret"),
            "!room:matrix.example",
            1,
            &retry,
        );
        let final_failure = undecrypted_retry_decision_snapshot(
            Some("$event-secret"),
            "!room:matrix.example",
            2,
            &retry,
        );

        assert_eq!(
            retrying["classification"].as_str(),
            Some("retryable_until_budget_exhausted")
        );
        assert_eq!(retrying["next_attempt"].as_u64(), Some(2));
        assert_eq!(
            final_failure["classification"].as_str(),
            Some("final_failure")
        );
        assert_eq!(final_failure["retry_after_ms"].as_u64(), None);
        assert!(!retrying.to_string().contains("$event-secret"));
        assert!(!retrying.to_string().contains("!room:matrix.example"));
    }

    #[test]
    fn maintenance_driver_snapshot_keeps_decrypted_delivery_disabled() {
        let e2ee = MatrixE2eeConfig {
            verified_decryption_requested: true,
            room_key_backup: MatrixE2eeBackupConfig {
                status: MatrixE2eeMaterialStatus::Verified,
                backup_version: Some("1".into()),
            },
            undecrypted_retry: MatrixUndecryptedRetryConfig {
                max_attempts: 5,
                retry_after_ms: 250,
            },
            ..MatrixE2eeConfig::default()
        };
        let snapshot = maintenance_driver_snapshot(&e2ee);

        assert_eq!(snapshot["enabled"].as_bool(), Some(true));
        assert_eq!(
            snapshot["transport"].as_str(),
            Some("matrix_client_explicit_methods")
        );
        assert_eq!(
            snapshot["mark_sent_semantics"].as_str(),
            Some("only_after_homeserver_success")
        );
        assert_eq!(
            snapshot["decrypted_delivery_enabled"].as_bool(),
            Some(false)
        );
        assert_eq!(snapshot["contains_secret_material"].as_bool(), Some(false));
    }

    fn ready_verified_e2ee() -> MatrixE2eeConfig {
        MatrixE2eeConfig {
            verified_decryption_requested: true,
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            trust_state: MatrixE2eeTrustStateConfig {
                own_device: MatrixE2eeMaterialStatus::Verified,
                device_keys: MatrixE2eeMaterialStatus::Verified,
                device_list: MatrixE2eeDeviceListConfig {
                    status: MatrixE2eeDeviceListStatus::Fresh,
                    last_refresh_age_ms: Some(5),
                },
                cross_signing: MatrixE2eeMaterialStatus::Verified,
                tracked_users: vec!["@alice:matrix.example".into()],
                tracked_rooms: vec!["!room:matrix.example".into()],
            },
            recovery: MatrixE2eeRecoveryConfig {
                status: MatrixE2eeMaterialStatus::Verified,
            },
            room_key_backup: MatrixE2eeBackupConfig {
                status: MatrixE2eeMaterialStatus::Verified,
                backup_version: Some("1".into()),
            },
            ..MatrixE2eeConfig::default()
        }
    }

    fn encrypted_projection_input() -> MatrixEncryptedEventProjectionContext {
        MatrixEncryptedEventProjectionContext {
            room_id: "!room:matrix.example".into(),
            event_id: Some("$encrypted".into()),
            sender: Some("@alice:matrix.example".into()),
            origin_server_ts: Some(42),
            algorithm: Some(MATRIX_MEGOLM_ALGORITHM.into()),
            session_id: Some("SESSION1".into()),
            redaction_state: MatrixEncryptedEventRedactionState::Clear,
            retry_attempts_used: 0,
        }
    }

    fn verified_decrypted_candidate() -> MatrixVerifiedDecryptedMessageEvent {
        MatrixVerifiedDecryptedMessageEvent {
            room_id: "!room:matrix.example".into(),
            sender: "@alice:matrix.example".into(),
            sender_device_id: "ALICEDEVICE".into(),
            sender_device_trust: MatrixProjectionVerificationStatus::Verified,
            cross_signing_trust: MatrixProjectionVerificationStatus::Verified,
            session_id: "SESSION1".into(),
            session_room_id: "!room:matrix.example".into(),
            session_trust: MatrixProjectionVerificationStatus::Verified,
            algorithm: MATRIX_MEGOLM_ALGORITHM.into(),
            replay_key: "SESSION1:$encrypted:0".into(),
            msgtype: "m.text".into(),
            body: "trusted plaintext".into(),
            format: None,
            formatted_body: None,
            redaction_state: MatrixEncryptedEventRedactionState::Clear,
        }
    }

    #[test]
    fn trust_gated_decrypted_projection_authorizes_verified_message_and_redacts_provenance() {
        let state = MatrixStatePersistenceConfig {
            enabled: true,
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            ..MatrixStatePersistenceConfig::default()
        };
        let projection = project_trust_gated_decrypted_event(
            &encrypted_projection_input(),
            Some(&verified_decrypted_candidate()),
            &ready_verified_e2ee(),
            &state,
            &[],
        );

        let authorized = projection
            .authorized_event
            .as_ref()
            .expect("verified plaintext authorizes delivery");
        assert_eq!(authorized["body"].as_str(), Some("trusted plaintext"));
        assert_eq!(
            authorized["delivery_context"]["verified_decryption"].as_bool(),
            Some(true)
        );
        assert_eq!(
            projection.metadata_event["decryption_status"].as_str(),
            Some("authorized_decrypted")
        );
        assert_eq!(
            projection.metadata_event["plaintext_emitted"].as_bool(),
            Some(true)
        );
        let projection_text = projection.metadata_event.to_string();
        assert!(!projection_text.contains("trusted plaintext"));
        assert!(!projection_text.contains("ALICEDEVICE"));
        assert_eq!(projection.dropped_reason, None);
    }

    #[test]
    fn trust_gated_decrypted_projection_denies_wrong_room_sender_and_session() {
        let mut candidate = verified_decrypted_candidate();
        candidate.session_room_id = "!other:matrix.example".into();
        candidate.sender = "@mallory:matrix.example".into();
        candidate.session_id = "OTHERSESSION".into();

        let projection = project_trust_gated_decrypted_event(
            &encrypted_projection_input(),
            Some(&candidate),
            &ready_verified_e2ee(),
            &MatrixStatePersistenceConfig::default(),
            &[],
        );
        let reasons = projection.metadata_event["denial_reason_codes"]
            .as_array()
            .expect("denial reasons")
            .iter()
            .map(|value| value.as_str().expect("reason string"))
            .collect::<Vec<_>>();

        assert!(projection.authorized_event.is_none());
        assert!(reasons.contains(&"wrong_room"));
        assert!(reasons.contains(&"wrong_sender_device"));
        assert!(reasons.contains(&"session_provenance_mismatch"));
        assert_eq!(
            projection.metadata_event["fcp_error_mapping"]["category"].as_str(),
            Some("invalid_request")
        );
    }

    #[test]
    fn trust_gated_decrypted_projection_denies_untrusted_device_and_backup_state() {
        let mut e2ee = ready_verified_e2ee();
        e2ee.trust_state.own_device = MatrixE2eeMaterialStatus::PresentUnverified;
        e2ee.trust_state.cross_signing = MatrixE2eeMaterialStatus::Missing;
        e2ee.room_key_backup.status = MatrixE2eeMaterialStatus::Missing;
        e2ee.recovery.status = MatrixE2eeMaterialStatus::PresentUnverified;
        let mut candidate = verified_decrypted_candidate();
        candidate.sender_device_trust = MatrixProjectionVerificationStatus::Unverified;
        candidate.cross_signing_trust = MatrixProjectionVerificationStatus::Unverified;

        let projection = project_trust_gated_decrypted_event(
            &encrypted_projection_input(),
            Some(&candidate),
            &e2ee,
            &MatrixStatePersistenceConfig::default(),
            &[],
        );
        let reasons = projection.metadata_event["denial_reason_codes"]
            .as_array()
            .expect("denial reasons")
            .iter()
            .map(|value| value.as_str().expect("reason string"))
            .collect::<Vec<_>>();

        assert!(reasons.contains(&"own_device_unverified"));
        assert!(reasons.contains(&"cross_signing_unverified"));
        assert!(reasons.contains(&"room_key_backup_unverified"));
        assert!(reasons.contains(&"recovery_material_unverified"));
        assert!(reasons.contains(&"sender_device_untrusted"));
        assert_eq!(
            projection.metadata_event["fcp_error_mapping"]["category"].as_str(),
            Some("unauthorized")
        );
    }

    #[test]
    fn trust_gated_decrypted_projection_denies_redacted_unsupported_and_replayed_events() {
        let mut input = encrypted_projection_input();
        input.algorithm = Some("m.olm.v1.curve25519-aes-sha2".into());
        input.redaction_state = MatrixEncryptedEventRedactionState::Redacted;
        let mut candidate = verified_decrypted_candidate();
        candidate.redaction_state = MatrixEncryptedEventRedactionState::Redacted;

        let projection = project_trust_gated_decrypted_event(
            &input,
            Some(&candidate),
            &ready_verified_e2ee(),
            &MatrixStatePersistenceConfig::default(),
            &[candidate.replay_key.clone()],
        );
        let reasons = projection.metadata_event["denial_reason_codes"]
            .as_array()
            .expect("denial reasons")
            .iter()
            .map(|value| value.as_str().expect("reason string"))
            .collect::<Vec<_>>();

        assert!(reasons.contains(&"redacted_event_denied"));
        assert!(reasons.contains(&"unsupported_algorithm"));
        assert!(reasons.contains(&"replay_duplicate"));
    }

    #[test]
    fn trust_gated_decrypted_projection_records_retry_and_final_failure_without_plaintext() {
        let retry = MatrixUndecryptedRetryConfig {
            max_attempts: 2,
            retry_after_ms: 500,
        };
        let e2ee = MatrixE2eeConfig {
            verified_decryption_requested: true,
            undecrypted_retry: retry,
            ..ready_verified_e2ee()
        };
        let mut input = encrypted_projection_input();
        input.retry_attempts_used = 2;

        let projection = project_trust_gated_decrypted_event(
            &input,
            None,
            &e2ee,
            &MatrixStatePersistenceConfig::default(),
            &[],
        );

        assert!(projection.authorized_event.is_none());
        assert_eq!(
            projection.metadata_event["decryption_status"].as_str(),
            Some("final_failure")
        );
        assert_eq!(
            projection.metadata_event["decryption_reason"].as_str(),
            Some("undecrypted_retry_budget_exhausted")
        );
        assert_eq!(
            projection.metadata_event["plaintext_emitted"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn engine_debug_does_not_include_configured_secret_identifiers() {
        let engine = MatrixCryptoEngine::new();
        let debug = format!("{engine:?}");

        assert!(debug.contains("MatrixCryptoEngine"));
        assert!(debug.contains(MATRIX_SDK_CRYPTO_BACKEND_FEATURE));
        assert!(!debug.contains("@bot:matrix.example"));
        assert!(!debug.contains("DEVICE123"));
    }

    #[test]
    fn trust_state_snapshot_redacts_scope_and_reports_ready_gate_without_enabling_decrypt() {
        let engine = MatrixCryptoEngine::new();
        let e2ee = MatrixE2eeConfig {
            verified_decryption_requested: true,
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            trust_state: MatrixE2eeTrustStateConfig {
                own_device: MatrixE2eeMaterialStatus::Verified,
                device_keys: MatrixE2eeMaterialStatus::Verified,
                device_list: MatrixE2eeDeviceListConfig {
                    status: MatrixE2eeDeviceListStatus::Fresh,
                    last_refresh_age_ms: Some(42),
                },
                cross_signing: MatrixE2eeMaterialStatus::Verified,
                tracked_users: vec!["@alice:matrix.example".into()],
                tracked_rooms: vec!["!room:matrix.example".into()],
            },
            recovery: MatrixE2eeRecoveryConfig {
                status: MatrixE2eeMaterialStatus::Verified,
            },
            room_key_backup: MatrixE2eeBackupConfig {
                status: MatrixE2eeMaterialStatus::Verified,
                backup_version: Some("1".into()),
            },
            ..MatrixE2eeConfig::default()
        };
        let state = MatrixStatePersistenceConfig {
            enabled: true,
            backend: MatrixStatePersistenceBackend::HostManagedSnapshot,
            zone_id: Some("z:work".into()),
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            restore: MatrixStateRestoreConfig {
                last_sync_token: Some("sync-token".into()),
                dynamic_direct_message_rooms: vec!["!dm:matrix.example".into()],
                thread_participation_roots: vec!["$thread-root".into()],
            },
            ..MatrixStatePersistenceConfig::default()
        };

        let snapshot = engine.trust_state_snapshot(&e2ee, &state);

        assert_eq!(
            snapshot["store_scope"]["lifecycle"].as_str(),
            Some("host_managed_snapshot_restore_then_memory_only_crypto_store")
        );
        assert_eq!(
            snapshot["store_scope"]["account_matches_e2ee"].as_bool(),
            Some(true)
        );
        assert_eq!(
            snapshot["store_scope"]["device_matches_e2ee"].as_bool(),
            Some(true)
        );
        assert_eq!(
            snapshot["readiness"]["trust_state_ready"].as_bool(),
            Some(true)
        );
        assert_eq!(
            snapshot["readiness"]["decrypted_delivery_enabled"].as_bool(),
            Some(false)
        );
        assert!(!snapshot.to_string().contains("@bot:matrix.example"));
        assert!(!snapshot.to_string().contains("DEVICE123"));
        assert!(!snapshot.to_string().contains("sync-token"));
    }

    #[test]
    fn trust_state_snapshot_reports_stale_device_list_and_required_cross_signing_denials() {
        let engine = MatrixCryptoEngine::new();
        let e2ee = MatrixE2eeConfig {
            verified_decryption_requested: true,
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            trust_state: MatrixE2eeTrustStateConfig {
                own_device: MatrixE2eeMaterialStatus::PresentUnverified,
                device_keys: MatrixE2eeMaterialStatus::Verified,
                device_list: MatrixE2eeDeviceListConfig {
                    status: MatrixE2eeDeviceListStatus::Stale,
                    last_refresh_age_ms: Some(120_000),
                },
                cross_signing: MatrixE2eeMaterialStatus::Missing,
                ..MatrixE2eeTrustStateConfig::default()
            },
            room_key_backup: MatrixE2eeBackupConfig {
                status: MatrixE2eeMaterialStatus::Verified,
                backup_version: None,
            },
            ..MatrixE2eeConfig::default()
        };

        let snapshot = engine.trust_state_snapshot(&e2ee, &MatrixStatePersistenceConfig::default());
        let reasons = snapshot
            .pointer("/readiness/denial_reason_codes")
            .and_then(Value::as_array)
            .expect("trust snapshot includes denial reasons")
            .iter()
            .map(|value| value.as_str().expect("denial reason is a string"))
            .collect::<Vec<_>>();

        assert_eq!(
            snapshot
                .pointer("/device_list/status")
                .and_then(Value::as_str),
            Some("stale")
        );
        assert!(reasons.contains(&"device_list_not_fresh"));
        assert!(reasons.contains(&"own_device_unverified"));
        assert!(reasons.contains(&"cross_signing_unverified"));
    }

    #[test]
    fn trust_state_allows_optional_cross_signing_without_losing_other_gates() {
        let engine = MatrixCryptoEngine::new();
        let e2ee = MatrixE2eeConfig {
            verified_decryption_requested: true,
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            trust: MatrixE2eeTrustRequirements {
                require_cross_signing: false,
                require_room_key_backup: false,
                ..MatrixE2eeTrustRequirements::default()
            },
            trust_state: MatrixE2eeTrustStateConfig {
                own_device: MatrixE2eeMaterialStatus::Verified,
                device_keys: MatrixE2eeMaterialStatus::Verified,
                device_list: MatrixE2eeDeviceListConfig {
                    status: MatrixE2eeDeviceListStatus::Fresh,
                    last_refresh_age_ms: None,
                },
                cross_signing: MatrixE2eeMaterialStatus::Missing,
                ..MatrixE2eeTrustStateConfig::default()
            },
            ..MatrixE2eeConfig::default()
        };

        let snapshot = engine.trust_state_snapshot(&e2ee, &MatrixStatePersistenceConfig::default());

        assert_eq!(
            snapshot["cross_signing"]["requirement_satisfied"].as_bool(),
            Some(true)
        );
        assert!(
            !snapshot["readiness"]["denial_reason_codes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .any(|reason| reason == "cross_signing_unverified")
        );
    }

    #[test]
    fn device_key_import_summary_classifies_failures_and_mismatched_records() {
        let response = MatrixDeviceKeysQueryResponse {
            failures: BTreeMap::from([("remote.example".to_string(), json!({ "timeout": true }))]),
            device_keys: BTreeMap::from([(
                "@bot:matrix.example".to_string(),
                BTreeMap::from([(
                    "DEVICE123".to_string(),
                    MatrixDeviceKey {
                        user_id: "@other:matrix.example".into(),
                        device_id: "OTHERDEVICE".into(),
                        algorithms: vec!["m.olm.v1.curve25519-aes-sha2".into()],
                        keys: BTreeMap::from([(
                            "ed25519:DEVICE123".to_string(),
                            "public-key".to_string(),
                        )]),
                        signatures: BTreeMap::new(),
                        unsigned: json!({}),
                    },
                )]),
            )]),
            master_keys: BTreeMap::from([(
                "@bot:matrix.example".to_string(),
                MatrixCrossSigningKey {
                    user_id: "@bot:matrix.example".into(),
                    usage: vec!["master".into()],
                    keys: BTreeMap::new(),
                    signatures: BTreeMap::new(),
                },
            )]),
            ..MatrixDeviceKeysQueryResponse::default()
        };

        let summary = MatrixDeviceKeyImportSummary::from_query_response(&response);
        let snapshot = summary.snapshot();

        assert_eq!(summary.user_count, 1);
        assert_eq!(summary.device_count, 1);
        assert_eq!(summary.failure_count, 1);
        assert_eq!(summary.mismatched_device_records, 1);
        assert_eq!(
            summary.trust_status(),
            MatrixE2eeMaterialStatus::PresentUnverified
        );
        assert_eq!(snapshot["contains_secret_material"].as_bool(), Some(false));
    }
}
