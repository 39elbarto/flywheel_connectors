//! Linux request-scoped MCP stdio supervision for the fixed local n8n catalog.
//!
//! This is an internal host primitive for the later typed n8n router. It does
//! not expose a generic `tools/call` operation and it never accepts a command,
//! argument, environment, or path from model input.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fcp_manifest::{LOCAL_MCP_PROTOCOL_VERSION, LocalMcpPolicy, local_mcp_schema_digest};
use fcp_sandbox::{OwnedProcess, ProcessGroupError, ProcessMemorySample, ProcessSpec};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// n8n-mcp selects rewritten schemas for names containing "n8n" or "langchain".
// Request the canonical catalog whose input-schema digests the release pins.
const CLIENT_NAME: &str = "fcp-local-provider";
const CLIENT_VERSION: &str = "0.1.0";

/// Proof derived only from the provider's already-admitted metadata digest and
/// fixed changed files. It cannot be deserialized from a caller/native reply.
pub struct VerifiedVersionedValidationSource {
    metadata: String,
    patch: String,
    package_tree: String,
}

impl VerifiedVersionedValidationSource {
    pub(crate) fn metadata_digest(&self) -> &str {
        &self.metadata
    }

    pub(crate) fn patch_digest(&self) -> &str {
        &self.patch
    }

    pub(crate) fn package_tree_digest(&self) -> &str {
        &self.package_tree
    }

    #[cfg(test)]
    pub(crate) fn synthetic_fixture() -> Self {
        Self {
            metadata: "0".repeat(64),
            patch: "391a6acf86de476e45a7a65ad286719dca569abe7d216c2a50eaae7efc1fd832".to_owned(),
            package_tree: "1".repeat(64),
        }
    }
}

/// Closed server binding in the existing signed n8n release receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum N8nReceiptServer {
    Eec,
    Hetzner,
}

impl N8nReceiptServer {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eec => "eec",
            Self::Hetzner => "hetzner",
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct N8nReceiptBinding {
    pub server: N8nReceiptServer,
    pub archive_input_schema_digest: String,
    pub archive_output_schema_digest: String,
    pub execute_input_schema_digest: String,
    pub execute_output_schema_digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct N8nReceiptArtifact {
    pub path: String,
    pub digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct N8nReleaseSignature {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

impl std::fmt::Debug for N8nReceiptBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("N8nReceiptBinding")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for N8nReleaseSignature {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("N8nReleaseSignature")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct N8nSignedReleaseReceipt {
    pub schema: String,
    pub release_id: String,
    pub git_revision: String,
    pub bindings: Vec<N8nReceiptBinding>,
    pub artifacts: Vec<N8nReceiptArtifact>,
    pub signature: N8nReleaseSignature,
}

/// Canonical existing receipt bytes, shared by signer and read-only verifier.
/// This serialization does not validate or authorize the receipt.
///
/// # Errors
/// Rejects serialization failure.
pub fn n8n_unsigned_receipt_bytes(
    receipt: &N8nSignedReleaseReceipt,
) -> Result<Vec<u8>, LocalMcpError> {
    #[derive(Serialize)]
    struct UnsignedReceipt {
        schema: String,
        release_id: String,
        git_revision: String,
        bindings: Vec<N8nReceiptBinding>,
        artifacts: Vec<N8nReceiptArtifact>,
    }
    let mut bindings = receipt.bindings.clone();
    bindings.sort_by_key(|binding| binding.server);
    let mut artifacts = receipt.artifacts.clone();
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    serde_json::to_vec(&UnsignedReceipt {
        schema: receipt.schema.clone(),
        release_id: receipt.release_id.clone(),
        git_revision: receipt.git_revision.clone(),
        bindings,
        artifacts,
    })
    .map_err(|_| LocalMcpError::InvalidPolicy)
}

/// Existing domain-separated signing payload. Binding validation belongs to
/// the caller; this primitive grants no current/predecessor policy exception.
#[must_use]
pub fn n8n_release_signing_payload(
    receipt: &N8nSignedReleaseReceipt,
    receipt_digest: &str,
    provision_digest: &str,
) -> Vec<u8> {
    fn append(payload: &mut Vec<u8>, field: &[u8]) {
        payload.extend_from_slice(&(field.len() as u64).to_le_bytes());
        payload.extend_from_slice(field);
    }
    let mut bindings = receipt.bindings.clone();
    bindings.sort_by_key(|binding| binding.server);
    let mut payload = Vec::from(b"FCP-N8N-RELEASE-SIGNING-V1\0".as_slice());
    for field in [
        receipt.release_id.as_bytes(),
        receipt.git_revision.as_bytes(),
        receipt_digest.as_bytes(),
        provision_digest.as_bytes(),
    ] {
        append(&mut payload, field);
    }
    for binding in bindings {
        for field in [
            binding.server.as_str().as_bytes(),
            binding.archive_input_schema_digest.as_bytes(),
            binding.archive_output_schema_digest.as_bytes(),
            binding.execute_input_schema_digest.as_bytes(),
            binding.execute_output_schema_digest.as_bytes(),
        ] {
            append(&mut payload, field);
        }
    }
    payload
}

/// Verify the existing immutable n8n receipt signature.
///
/// This primitive accepts
/// public material only; its caller must first validate the closed receipt and
/// construct the canonical signing payload. It grants no provider policy or
/// filesystem authority by itself.
///
/// # Errors
/// Rejects a malformed key, a different key identity, or an invalid signature.
pub fn verify_n8n_release_signature_bytes(
    public_key: &[u8; fcp_crypto::ed25519::PUBLIC_KEY_SIZE],
    expected_key_id: &str,
    signature: &[u8; fcp_crypto::ed25519::SIGNATURE_SIZE],
    payload: &[u8],
) -> Result<(), LocalMcpError> {
    use fcp_crypto::ed25519::{Ed25519Signature, Ed25519VerifyingKey};

    let key =
        Ed25519VerifyingKey::from_bytes(public_key).map_err(|_| LocalMcpError::InvalidPolicy)?;
    if key.key_id().to_string() != expected_key_id {
        return Err(LocalMcpError::InvalidPolicy);
    }
    key.verify_with_context(
        b"fwc-n8n immutable release v1",
        payload,
        &Ed25519Signature::from_bytes(signature),
    )
    .map_err(|_| LocalMcpError::InvalidPolicy)
}

/// One fixed local MCP tool call. The tool name is checked against policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpCall {
    pub tool: String,
    pub arguments: Value,
}

/// One bounded request containing sequential calls only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpRequest {
    pub correlation_id: String,
    pub calls: Vec<LocalMcpCall>,
}

/// Redacted startup evidence. No endpoint, payload, tool name, or provider
/// response is included.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpStartupReceipt {
    pub pid: u32,
    pub pgid: i32,
    pub session_id: i32,
    pub start_time_ticks: u64,
    pub launcher_digest: String,
    pub runtime_executable_digest: String,
    pub network_disabled: bool,
    pub memory_before: ProcessMemorySample,
}

/// Redacted shutdown evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpSignalEvidence {
    pub term_sent: bool,
    pub kill_sent: bool,
}

/// Independent completion facts; neither implies the other.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpCompletionEvidence {
    pub reaped: bool,
    pub group_absent: bool,
}

/// Redacted shutdown evidence with the original flat wire fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpShutdownReceipt {
    pub reason: LocalMcpShutdownReason,
    #[serde(flatten)]
    pub signals: LocalMcpSignalEvidence,
    #[serde(flatten)]
    pub completion: LocalMcpCompletionEvidence,
    pub stderr_bytes: u64,
    pub memory_after: ProcessMemorySample,
}

/// Why the request-scoped child was torn down.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalMcpShutdownReason {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

/// Bounded provider result. Tool result data is returned to the intended
/// caller, while lifecycle evidence remains content-safe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpResult {
    pub correlation_id: String,
    pub responses: Vec<Value>,
    pub startup: LocalMcpStartupReceipt,
    pub shutdown: LocalMcpShutdownReceipt,
    pub memory_samples: Vec<ProcessMemorySample>,
    pub status: LocalMcpResultStatus,
    pub teardown_error_code: Option<String>,
    pub result_code: String,
    /// Only the already received JSON-RPC diagnostic, never stderr or request data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_diagnostic: Option<Value>,
    pub telemetry: LocalMcpTelemetry,
}

/// Preserve authorized diagnostic content as bounded JSON data, not instructions.
///
/// Callers select only message/details/node fields from the current response.
/// The shared budget bounds content across all findings in one invocation.
#[must_use]
pub fn project_native_diagnostic(
    message: Option<&Value>,
    details: Option<&Value>,
    node: Option<&Value>,
    source: &str,
    stage: &str,
    budget: &mut usize,
) -> Value {
    fn text(value: Option<&Value>, budget: &mut usize) -> (Value, &'static str) {
        let Some(value) = value else {
            return (Value::Null, "missing");
        };
        let Some(value) = value.as_str() else {
            return (Value::Null, "non_text");
        };
        let limit = (*budget).min(8192);
        let mut encoded = 0;
        let mut end = 0;
        for (index, character) in value.char_indices() {
            let bytes = match character {
                '"' | '\\' | '\n' | '\r' | '\t' => 2,
                c if c <= '\u{001f}' => 6,
                c => c.len_utf8(),
            };
            if encoded + bytes > limit {
                break;
            }
            encoded += bytes;
            end = index + character.len_utf8();
        }
        *budget = budget.saturating_sub(encoded);
        (
            json!(&value[..end]),
            if end == value.len() {
                "present"
            } else {
                "truncated"
            },
        )
    }
    let (message, message_status) = text(message, budget);
    let (node, node_status) = text(node, budget);
    let (details, details_status, prefix) = details.map_or(
        (Value::Null, "missing", Value::Null),
        |value| match serde_json::to_vec(value) {
            Ok(encoded) if encoded.len() <= (*budget).min(8192) => {
                *budget -= encoded.len();
                (value.clone(), "present", Value::Null)
            }
            Ok(encoded) => String::from_utf8(encoded).map_or(
                (Value::Null, "unavailable", Value::Null),
                |encoded| {
                    let (prefix, _) = text(Some(&json!(encoded)), budget);
                    (Value::Null, "truncated", prefix)
                },
            ),
            Err(_) => (Value::Null, "unavailable", Value::Null),
        },
    );
    json!({"source":source,"stage":stage,"message":message,"messageStatus":message_status,
        "node":node,"nodeStatus":node_status,"details":details,"detailsStatus":details_status,
        "detailsTextPrefix":prefix,
        "truncated":message_status=="truncated" || node_status=="truncated" || details_status=="truncated"})
}

/// Safe completion status. A post-spawn failure is returned with lifecycle
/// evidence rather than being collapsed into a plain error.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalMcpResultStatus {
    Completed,
    Failed,
}

/// Redacted timing and byte counters for one request-scoped session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpTelemetry {
    pub startup_latency_ms: u64,
    pub provider_latency_ms: u64,
    pub total_latency_ms: u64,
    pub shutdown_latency_ms: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
}

/// Safe failures from the local provider boundary.
#[derive(Debug, thiserror::Error)]
pub enum LocalMcpError {
    #[error("local MCP provider is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("local MCP provider policy is invalid")]
    InvalidPolicy,
    #[error("local MCP request is invalid")]
    InvalidRequest,
    #[error("local MCP provider process could not start")]
    ProcessStart,
    #[error("local MCP package identity could not be verified")]
    PackageIdentity,
    #[error("local MCP provider process identity could not be verified")]
    ProcessIdentity,
    #[error("local MCP provider process could not be stopped safely")]
    ProcessStop,
    #[error("local MCP provider startup timed out")]
    StartupTimeout,
    #[error("local MCP provider request timed out")]
    RequestTimeout,
    #[error("local MCP provider cancellation requested")]
    Cancelled,
    #[error("local MCP provider returned an invalid MCP frame")]
    InvalidFrame,
    #[error("local MCP provider returned an unexpected catalog")]
    CatalogMismatch,
    #[error("local MCP tool is not allowed")]
    UnknownTool,
    #[error("local MCP request exceeds its sequential-call bound")]
    TooManyCalls,
    #[error("local MCP frame exceeds the configured bound")]
    FrameTooLarge,
    #[error("local MCP provider returned an error")]
    ProviderError,
}

impl LocalMcpError {
    const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::InvalidPolicy => "invalid_policy",
            Self::InvalidRequest => "invalid_request",
            Self::ProcessStart => "process_start",
            Self::PackageIdentity => "package_identity",
            Self::ProcessIdentity => "process_identity",
            Self::ProcessStop => "process_stop",
            Self::StartupTimeout => "startup_timeout",
            Self::RequestTimeout => "request_timeout",
            Self::Cancelled => "cancelled",
            Self::InvalidFrame => "invalid_frame",
            Self::CatalogMismatch => "catalog_mismatch",
            Self::UnknownTool => "unknown_tool",
            Self::TooManyCalls => "too_many_calls",
            Self::FrameTooLarge => "frame_too_large",
            Self::ProviderError => "provider_error",
        }
    }
}

/// Request-scoped fixed-policy local MCP provider.
#[derive(Debug, Clone)]
pub struct LocalMcpProvider {
    policy: LocalMcpPolicy,
    signed_current: Option<crate::n8n_release_read::VerifiedSignedLocalProvider>,
    observer: Option<Arc<crate::admin_state::RuntimeObservedLaunch>>,
}

impl LocalMcpProvider {
    /// Construct a provider only from a validated signed-manifest policy.
    ///
    /// # Errors
    /// Rejects an invalid fixed policy before any process is launched.
    pub fn new(policy: LocalMcpPolicy) -> Result<Self, LocalMcpError> {
        policy
            .validate()
            .map_err(|_| LocalMcpError::InvalidPolicy)?;
        if policy.package_binding.is_some() {
            return Err(LocalMcpError::InvalidPolicy);
        }
        Ok(Self {
            policy,
            signed_current: None,
            observer: None,
        })
    }

    /// Production factory with no caller-supplied policy, key, or release path.
    /// Only the ordinary signed installed current can authorize this provider.
    ///
    /// # Errors
    /// Rejects unsigned/predecessor releases and changed policy/artifact trees.
    pub fn from_signed_current() -> Result<Self, LocalMcpError> {
        let proof = crate::n8n_release_read::verify_signed_local_provider_current()
            .map_err(|_| LocalMcpError::InvalidPolicy)?;
        Self::from_verified_signed_current(proof)
    }

    /// Consume only a sealed verifier-produced proof, preserving a caller's
    /// distinction between bundle verification and provider policy failures.
    ///
    /// # Errors
    /// Rejects an invalid policy before launching any process.
    pub fn from_verified_signed_current(
        proof: crate::n8n_release_read::VerifiedSignedLocalProvider,
    ) -> Result<Self, LocalMcpError> {
        proof
            .policy()
            .validate()
            .map_err(|_| LocalMcpError::InvalidPolicy)?;
        Ok(Self {
            policy: proof.policy().clone(),
            signed_current: Some(proof),
            observer: None,
        })
    }

    /// Return the fixed policy for host-side inspection.
    #[must_use]
    pub const fn policy(&self) -> &LocalMcpPolicy {
        &self.policy
    }

    /// Inspect a derived package only under the existing signed-current proof.
    /// This grants no launch/admission and performs no process/provider call.
    ///
    /// # Errors
    /// Refuses changed metadata/files, malformed provenance or unsigned policy.
    pub fn versioned_validation_source(
        &self,
    ) -> Result<Option<VerifiedVersionedValidationSource>, LocalMcpError> {
        if let Some(proof) = &self.signed_current {
            proof
                .revalidate()
                .map_err(|_| LocalMcpError::InvalidPolicy)?;
        }
        verify_package_metadata(&self.policy)?;
        let source = verify_derived_validation_source(&self.policy)?;
        if source.is_some() && self.signed_current.is_none() {
            return Err(LocalMcpError::PackageIdentity);
        }
        if let Some(proof) = &self.signed_current {
            proof
                .revalidate()
                .map_err(|_| LocalMcpError::InvalidPolicy)?;
        }
        Ok(source)
    }

    /// Run one bounded provider request and always execute the teardown path.
    ///
    /// # Errors
    /// Rejects invalid requests, package identity mismatches, and process launch failures.
    pub fn run_once(&self, request: LocalMcpRequest) -> Result<LocalMcpResult, LocalMcpError> {
        self.run_once_with_cancel(request, &std::sync::atomic::AtomicBool::new(false))
    }

    /// Run one request while observing a host-owned cancellation flag.
    ///
    /// The flag is polled while waiting for provider frames. Cancellation
    /// never skips teardown and never causes a retry.
    ///
    /// # Errors
    /// Rejects cancellation, invalid policy/request/package bindings, and launch failures.
    pub fn run_once_with_cancel(
        &self,
        request: LocalMcpRequest,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<LocalMcpResult, LocalMcpError> {
        self.run_once_until(request, cancelled, None)
    }

    /// Run under an invocation-owned total deadline, which can only tighten
    /// the signed provider time limits. Teardown remains mandatory.
    ///
    /// # Errors
    /// Rejects expired deadlines and the same invalid bindings as `run_once`.
    pub fn run_once_until(
        &self,
        request: LocalMcpRequest,
        cancelled: &std::sync::atomic::AtomicBool,
        deadline: Option<Instant>,
    ) -> Result<LocalMcpResult, LocalMcpError> {
        if !cfg!(target_os = "linux") {
            return Err(LocalMcpError::UnsupportedPlatform);
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(LocalMcpError::Cancelled);
        }
        if self.policy.protocol_version != LOCAL_MCP_PROTOCOL_VERSION {
            return Err(LocalMcpError::InvalidPolicy);
        }
        validate_request(&self.policy, &request)?;
        verify_package_metadata(&self.policy)?;

        let spec = ProcessSpec {
            launcher_path: PathBuf::from(&self.policy.launcher_path),
            launcher_digest: self.policy.launcher_digest.clone(),
            runtime_executable: PathBuf::from(&self.policy.runtime_executable),
            expected_runtime_executable_digest: self.policy.runtime_executable_digest.clone(),
            fixed_args: self.policy.fixed_args.iter().map(OsString::from).collect(),
            fixed_env: self
                .policy
                .fixed_env
                .iter()
                .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                .collect(),
            network_disabled: self.policy.network_disabled,
        };

        let total_started = Instant::now();
        self.revalidate_before_spawn()?;
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return Err(LocalMcpError::RequestTimeout);
        }
        let process = self.spawn_observed_process(&spec)?;
        let identity = process.identity().clone();
        let memory_before = zero_memory_sample();
        let memory_during = process
            .memory_sample()
            .unwrap_or_else(|_| unavailable_memory_sample());
        let startup = LocalMcpStartupReceipt {
            pid: identity.pid,
            pgid: identity.pgid,
            session_id: identity.session_id,
            start_time_ticks: identity.start_time_ticks,
            launcher_digest: self.policy.launcher_digest.clone(),
            runtime_executable_digest: identity.runtime_executable_digest,
            network_disabled: self.policy.network_disabled,
            memory_before,
        };

        let mut session = LocalMcpSession::new(process, self.policy.max_frame_bytes as usize);
        session.memory_during = memory_during;
        let provider_started = Instant::now();
        let outcome = session.execute(&self.policy, &request, cancelled, deadline);
        let provider_latency_ms = elapsed_ms(provider_started.elapsed());
        let reason = match &outcome {
            Ok(_) => LocalMcpShutdownReason::Completed,
            Err(LocalMcpError::StartupTimeout | LocalMcpError::RequestTimeout) => {
                LocalMcpShutdownReason::TimedOut
            }
            Err(LocalMcpError::Cancelled) => LocalMcpShutdownReason::Cancelled,
            Err(_) => LocalMcpShutdownReason::Failed,
        };
        let shutdown_started = Instant::now();
        let (shutdown, memory_samples, mut teardown_error) = session.finish(&self.policy, reason);
        if teardown_error.is_none() {
            teardown_error = self.observe_completed_session(&session, &shutdown).err();
        }
        let shutdown_latency_ms = elapsed_ms(shutdown_started.elapsed());
        let result_code = outcome.as_ref().err().map_or_else(
            || {
                teardown_error
                    .as_ref()
                    .map_or_else(|| "ok".to_string(), |error| error.code().to_string())
            },
            |error| error.code().to_string(),
        );
        let status = if outcome.is_ok() && teardown_error.is_none() {
            LocalMcpResultStatus::Completed
        } else {
            LocalMcpResultStatus::Failed
        };
        Ok(LocalMcpResult {
            correlation_id: request.correlation_id,
            responses: outcome.unwrap_or_default(),
            startup,
            shutdown,
            memory_samples,
            status,
            teardown_error_code: teardown_error.map(|error| error.code().to_string()),
            telemetry: LocalMcpTelemetry {
                startup_latency_ms: session.startup_latency_ms,
                provider_latency_ms,
                total_latency_ms: elapsed_ms(total_started.elapsed()),
                shutdown_latency_ms,
                request_bytes: session.request_bytes,
                response_bytes: session.response_bytes,
            },
            result_code,
            native_diagnostic: session.native_diagnostic.take(),
        })
    }
    fn revalidate_before_spawn(&self) -> Result<(), LocalMcpError> {
        if let Some(proof) = &self.signed_current {
            proof
                .revalidate()
                .map_err(|_| LocalMcpError::InvalidPolicy)?;
        }
        // Recheck external immutable closure immediately before spawn, after
        // signed-current revalidation; never fall back to the global package.
        if self.policy.package_binding.is_some() {
            verify_package_metadata(&self.policy)?;
        }
        Ok(())
    }

    fn spawn_observed_process(&self, spec: &ProcessSpec) -> Result<OwnedProcess, LocalMcpError> {
        if let Some(observer) = &self.observer {
            observer
                .claim(&spec.expected_runtime_executable_digest)
                .map_err(|_| LocalMcpError::ProcessIdentity)?;
        }
        let mut process = OwnedProcess::spawn(spec)
            .map_err(|error| map_process_error(&error, ProcessPhase::Spawn))?;
        if self
            .observer
            .as_ref()
            .is_some_and(|observer| observer.attach(process.identity()).is_err())
        {
            let _ = process.terminate(millis(self.policy.shutdown_timeout_ms));
            return Err(LocalMcpError::ProcessIdentity);
        }
        Ok(process)
    }

    fn observe_completed_session(
        &self,
        session: &LocalMcpSession,
        shutdown: &LocalMcpShutdownReceipt,
    ) -> Result<(), LocalMcpError> {
        let Some(observer) = &self.observer else {
            return Ok(());
        };
        if !session.teardown_complete || !session.workers_joined {
            return Err(LocalMcpError::ProcessStop);
        }
        let mut report = fcp_sandbox::TerminationReport::default();
        report.completion.reaped = shutdown.completion.reaped;
        report.completion.group_absent = shutdown.completion.group_absent;
        observer
            .retire(report)
            .map_err(|_| LocalMcpError::ProcessStop)
    }
}

fn validate_request(
    policy: &LocalMcpPolicy,
    request: &LocalMcpRequest,
) -> Result<(), LocalMcpError> {
    if request.correlation_id.is_empty()
        || request.correlation_id.len() > 128
        || request
            .correlation_id
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(LocalMcpError::InvalidRequest);
    }
    if request.calls.is_empty() {
        return Err(LocalMcpError::InvalidRequest);
    }
    if request.calls.len() > usize::from(policy.max_sequential_calls) {
        return Err(LocalMcpError::TooManyCalls);
    }
    for call in &request.calls {
        if !policy.callable_tools.iter().any(|tool| tool == &call.tool) {
            return Err(LocalMcpError::UnknownTool);
        }
        if !call.arguments.is_object() {
            return Err(LocalMcpError::InvalidRequest);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum LocalMcpPhase {
    Startup,
    Call,
}

impl LocalMcpPhase {
    const fn timeout_error(self) -> LocalMcpError {
        match self {
            Self::Startup => LocalMcpError::StartupTimeout,
            Self::Call => LocalMcpError::RequestTimeout,
        }
    }
}

fn decode_rpc_response(
    response: &Value,
    id: u64,
    phase: LocalMcpPhase,
) -> Result<Value, (LocalMcpError, Option<Value>)> {
    // Authenticate the invocation/phase binding before exposing any error text.
    if response.get("id") != Some(&json!(id)) || response["jsonrpc"] != "2.0" {
        return Err((LocalMcpError::InvalidFrame, None));
    }
    if let Some(error) = response.get("error") {
        let mut diagnostic = project_native_diagnostic(
            if error.is_string() {
                Some(error)
            } else {
                error.get("message")
            },
            error.get("data"),
            None,
            "local_mcp.jsonrpc",
            match phase {
                LocalMcpPhase::Startup => "startup",
                LocalMcpPhase::Call => "request",
            },
            &mut 16384,
        );
        diagnostic["severity"] = json!("error");
        diagnostic["rpcCode"] = error
            .get("code")
            .filter(|code| code.as_i64().is_some())
            .cloned()
            .unwrap_or(Value::Null);
        return Err((LocalMcpError::ProviderError, Some(diagnostic)));
    }
    response
        .get("result")
        .cloned()
        .ok_or((LocalMcpError::InvalidFrame, None))
}

struct LocalMcpSession {
    process: Option<OwnedProcess>,
    writer: Option<LocalMcpWriter>,
    frames: Receiver<Result<Vec<u8>, FrameReadError>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    stderr_bytes: Arc<AtomicU64>,
    next_id: u64,
    max_frame_bytes: usize,
    memory_during: ProcessMemorySample,
    startup_latency_ms: u64,
    request_bytes: u64,
    response_bytes: u64,
    stdout_overflow: Arc<AtomicBool>,
    teardown_complete: bool,
    workers_joined: bool,
    native_diagnostic: Option<Value>,
}

impl LocalMcpSession {
    fn new(mut process: OwnedProcess, max_frame_bytes: usize) -> Self {
        let (frame_tx, frame_rx) = mpsc::sync_channel(8);
        let stdout_overflow = Arc::new(AtomicBool::new(false));
        let stdout_thread = process.take_stdout().map(|stdout| {
            spawn_stdout_reader(
                stdout,
                frame_tx.clone(),
                max_frame_bytes,
                Arc::clone(&stdout_overflow),
            )
        });
        let stderr_bytes = Arc::new(AtomicU64::new(0));
        let stderr_counter = Arc::clone(&stderr_bytes);
        let stderr_thread = process.take_stderr().map(|stderr| {
            thread::spawn(move || {
                let mut reader = BufReader::new(stderr);
                let mut buffer = [0_u8; 4096];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(bytes) => {
                            stderr_counter.fetch_add(
                                u64::try_from(bytes).unwrap_or(u64::MAX),
                                Ordering::Relaxed,
                            );
                        }
                    }
                }
            })
        });
        if stdout_thread.is_none() {
            let _ = frame_tx.try_send(Err(FrameReadError::Io));
        }

        let writer = process.take_stdin().map(LocalMcpWriter::new);
        Self {
            process: Some(process),
            writer,
            frames: frame_rx,
            stdout_thread,
            stderr_thread,
            stderr_bytes,
            next_id: 1,
            max_frame_bytes,
            memory_during: unavailable_memory_sample(),
            startup_latency_ms: 0,
            request_bytes: 0,
            response_bytes: 0,
            stdout_overflow,
            teardown_complete: false,
            workers_joined: false,
            native_diagnostic: None,
        }
    }
}

struct LocalMcpWriter {
    sender: Option<SyncSender<WriteCommand>>,
    join: Option<JoinHandle<()>>,
}

struct WriteCommand {
    frame: Vec<u8>,
    acknowledged: SyncSender<Result<(), ()>>,
}

impl LocalMcpWriter {
    fn new(mut stdin: std::process::ChildStdin) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<WriteCommand>(2);
        let join = thread::spawn(move || {
            while let Ok(command) = receiver.recv() {
                let result = stdin
                    .write_all(&command.frame)
                    .and_then(|()| stdin.write_all(b"\n"))
                    .and_then(|()| stdin.flush())
                    .map_err(|_| ());
                let failed = result.is_err();
                let _ = command.acknowledged.send(result);
                if failed {
                    break;
                }
            }
        });
        Self {
            sender: Some(sender),
            join: Some(join),
        }
    }

    fn submit(
        &self,
        frame: Vec<u8>,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<(), LocalMcpError> {
        let (ack_sender, ack_receiver) = mpsc::sync_channel(0);
        let mut command = WriteCommand {
            frame,
            acknowledged: ack_sender,
        };
        let sender = self.sender.as_ref().ok_or(LocalMcpError::ProcessStart)?;
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(LocalMcpError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(phase.timeout_error());
            }
            match sender.try_send(command) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(returned)) => {
                    command = returned;
                    thread::sleep(Duration::from_millis(5));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(LocalMcpError::ProcessStart);
                }
            }
        }
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(LocalMcpError::Cancelled);
            }
            let timeout = deadline.saturating_duration_since(Instant::now());
            if timeout.is_zero() {
                return Err(phase.timeout_error());
            }
            match ack_receiver.recv_timeout(timeout.min(Duration::from_millis(50))) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(())) | Err(RecvTimeoutError::Disconnected) => {
                    return Err(LocalMcpError::ProcessStart);
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn stop_and_join(&mut self) -> bool {
        self.sender.take();
        self.join.take().is_some_and(|join| join.join().is_ok())
    }

    fn detach(&mut self) {
        self.sender.take();
        self.join.take();
    }
}

impl LocalMcpSession {
    fn execute(
        &mut self,
        policy: &LocalMcpPolicy,
        request: &LocalMcpRequest,
        cancelled: &std::sync::atomic::AtomicBool,
        total_deadline: Option<Instant>,
    ) -> Result<Vec<Value>, LocalMcpError> {
        let startup_started = Instant::now();
        if cancelled.load(Ordering::Acquire) {
            self.startup_latency_ms = elapsed_ms(startup_started.elapsed());
            return Err(LocalMcpError::Cancelled);
        }
        let startup_deadline = bounded_provider_deadline(
            Instant::now() + millis(policy.startup_timeout_ms),
            total_deadline,
        );
        let startup_result = (|| {
            let initialize = self.request(
                policy,
                "initialize",
                &json!({
                    "protocolVersion": policy.protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}
                }),
                startup_deadline,
                cancelled,
                LocalMcpPhase::Startup,
            )?;
            validate_initialize(policy, &initialize)?;
            self.notify(
                policy,
                "notifications/initialized",
                &json!({}),
                startup_deadline,
                cancelled,
                LocalMcpPhase::Startup,
            )?;
            let catalog = self.request(
                policy,
                "tools/list",
                &json!({}),
                startup_deadline,
                cancelled,
                LocalMcpPhase::Startup,
            )?;
            validate_catalog(policy, request, &catalog)
        })();
        self.startup_latency_ms = elapsed_ms(startup_started.elapsed());
        startup_result?;

        let mut responses = Vec::with_capacity(request.calls.len());
        for call in &request.calls {
            let result = self.request(
                policy,
                "tools/call",
                &json!({"name": call.tool, "arguments": call.arguments}),
                bounded_provider_deadline(
                    Instant::now() + millis(policy.request_timeout_ms),
                    total_deadline,
                ),
                cancelled,
                LocalMcpPhase::Call,
            )?;
            if serde_json::to_vec(&result)
                .map_err(|_| LocalMcpError::InvalidFrame)?
                .len()
                > policy.max_result_bytes as usize
            {
                return Err(LocalMcpError::FrameTooLarge);
            }
            responses.push(result);
        }
        Ok(responses)
    }

    fn notify(
        &mut self,
        policy: &LocalMcpPolicy,
        method: &str,
        params: &Value,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<(), LocalMcpError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(LocalMcpError::Cancelled);
        }
        if !policy
            .allowed_methods
            .iter()
            .any(|allowed| allowed == method)
        {
            return Err(LocalMcpError::InvalidPolicy);
        }
        let frame = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
        .map_err(|_| LocalMcpError::InvalidFrame)?;
        self.write_frame(policy, frame, deadline, cancelled, phase)
    }

    fn request(
        &mut self,
        policy: &LocalMcpPolicy,
        method: &str,
        params: &Value,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<Value, LocalMcpError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(LocalMcpError::Cancelled);
        }
        if !policy
            .allowed_methods
            .iter()
            .any(|allowed| allowed == method)
        {
            return Err(LocalMcpError::InvalidPolicy);
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let frame = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|_| LocalMcpError::InvalidFrame)?;
        self.write_frame(policy, frame, deadline, cancelled, phase)?;

        let bytes = self.recv_frame(deadline, cancelled, phase)?;
        self.response_bytes = self
            .response_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let response: Value =
            serde_json::from_slice(&bytes).map_err(|_| LocalMcpError::InvalidFrame)?;
        decode_rpc_response(&response, id, phase).map_err(|(error, diagnostic)| {
            self.native_diagnostic = diagnostic;
            error
        })
    }

    fn write_frame(
        &mut self,
        policy: &LocalMcpPolicy,
        frame: Vec<u8>,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<(), LocalMcpError> {
        if frame.len() > self.max_frame_bytes || frame.len() > policy.max_request_bytes as usize {
            return Err(LocalMcpError::FrameTooLarge);
        }
        let bytes = u64::try_from(frame.len()).unwrap_or(u64::MAX);
        let writer = self.writer.as_ref().ok_or(LocalMcpError::ProcessStart)?;
        writer.submit(frame, deadline, cancelled, phase)?;
        self.request_bytes = self.request_bytes.saturating_add(bytes);
        Ok(())
    }

    fn recv_frame(
        &self,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<Vec<u8>, LocalMcpError> {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(LocalMcpError::Cancelled);
            }
            if self.stdout_overflow.load(Ordering::Acquire) {
                return Err(LocalMcpError::FrameTooLarge);
            }
            let timeout = deadline.saturating_duration_since(Instant::now());
            if timeout.is_zero() {
                return Err(phase.timeout_error());
            }
            let poll = timeout.min(Duration::from_millis(50));
            match self.frames.recv_timeout(poll) {
                Ok(Ok(frame)) => return Ok(frame),
                Ok(Err(FrameReadError::Oversized)) => return Err(LocalMcpError::FrameTooLarge),
                Ok(Err(_)) => return Err(LocalMcpError::InvalidFrame),
                Err(RecvTimeoutError::Disconnected) => {
                    return if self.stdout_overflow.load(Ordering::Acquire) {
                        Err(LocalMcpError::FrameTooLarge)
                    } else {
                        Err(LocalMcpError::InvalidFrame)
                    };
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn finish(
        &mut self,
        policy: &LocalMcpPolicy,
        reason: LocalMcpShutdownReason,
    ) -> (
        LocalMcpShutdownReceipt,
        Vec<ProcessMemorySample>,
        Option<LocalMcpError>,
    ) {
        let mut samples = vec![zero_memory_sample(), self.memory_during];
        let mut teardown_error = None;
        let mut termination = None;
        let mut memory_after = unavailable_memory_sample();
        let process = self.process.as_mut();
        if let Some(process) = process {
            if let Ok(sample) = process.memory_sample() {
                samples.push(sample);
            }
            match process.terminate(millis(policy.shutdown_timeout_ms)) {
                Ok(report) => {
                    if report.completion.group_absent {
                        if let Ok(sample) = process.memory_sample() {
                            memory_after = sample;
                            samples.push(sample);
                        }
                    } else {
                        teardown_error = Some(LocalMcpError::ProcessStop);
                    }
                    termination = Some(report);
                }
                Err(error) => {
                    if matches!(&error, ProcessGroupError::IdentityMismatch) {
                        let _ = process.reap_direct_child_until(millis(policy.shutdown_timeout_ms));
                    }
                    termination = Some(process.termination_report(false));
                    teardown_error = Some(map_process_error(&error, ProcessPhase::Stop));
                }
            }
        } else {
            teardown_error = Some(LocalMcpError::ProcessStop);
        }
        self.close_or_detach(termination.is_some_and(|report| report.completion.group_absent));
        let report = termination.unwrap_or_default();
        let receipt = LocalMcpShutdownReceipt {
            reason,
            signals: LocalMcpSignalEvidence {
                term_sent: report.signals.term_sent,
                kill_sent: report.signals.kill_sent,
            },
            completion: LocalMcpCompletionEvidence {
                reaped: report.completion.reaped,
                group_absent: report.completion.group_absent,
            },
            stderr_bytes: self.stderr_bytes.load(Ordering::Relaxed),
            memory_after,
        };
        (receipt, samples, teardown_error)
    }

    fn close_or_detach(&mut self, group_absent: bool) {
        if self.teardown_complete {
            return;
        }
        if group_absent {
            if let Some(process) = self.process.as_mut() {
                process.abandon();
            }
            let writer_joined = self
                .writer
                .as_mut()
                .is_some_and(LocalMcpWriter::stop_and_join);
            let readers_joined = self.join_readers();
            self.workers_joined = writer_joined && readers_joined;
        } else {
            self.detach_after_teardown_failure();
        }
        self.teardown_complete = true;
    }

    fn detach_after_teardown_failure(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            writer.detach();
        }
        self.stdout_thread.take();
        self.stderr_thread.take();
        if let Some(process) = self.process.as_mut() {
            process.abandon();
        }
    }

    fn join_readers(&mut self) -> bool {
        let stdout = self
            .stdout_thread
            .take()
            .is_some_and(|thread| thread.join().is_ok());
        let stderr = self
            .stderr_thread
            .take()
            .is_some_and(|thread| thread.join().is_ok());
        stdout && stderr
    }
}

fn bounded_provider_deadline(policy_deadline: Instant, total_deadline: Option<Instant>) -> Instant {
    total_deadline.map_or(policy_deadline, |deadline| deadline.min(policy_deadline))
}

impl Drop for LocalMcpSession {
    fn drop(&mut self) {
        if self.teardown_complete {
            return;
        }
        let group_absent = self
            .process
            .as_mut()
            .and_then(|process| process.terminate(Duration::from_secs(1)).ok())
            .is_some_and(|report| report.completion.group_absent);
        self.close_or_detach(group_absent);
    }
}

#[derive(Debug)]
enum FrameReadError {
    Oversized,
    Io,
    InvalidUtf8,
}

fn spawn_stdout_reader(
    stdout: std::process::ChildStdout,
    sender: SyncSender<Result<Vec<u8>, FrameReadError>>,
    max_frame_bytes: usize,
    overflow: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            match read_bounded_frame(&mut reader, max_frame_bytes) {
                Ok(Some(line)) => {
                    if std::str::from_utf8(&line).is_err() {
                        let _ = sender.try_send(Err(FrameReadError::InvalidUtf8));
                        break;
                    }
                    if sender.try_send(Ok(line)).is_err() {
                        overflow.store(true, Ordering::Release);
                        break;
                    }
                }
                Ok(None) | Err(FrameReadError::Io) => {
                    let _ = sender.try_send(Err(FrameReadError::Io));
                    break;
                }
                Err(error) => {
                    let _ = sender.try_send(Err(error));
                    break;
                }
            }
        }
    })
}

fn read_bounded_frame(
    reader: &mut BufReader<std::process::ChildStdout>,
    max_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, FrameReadError> {
    let mut line = Vec::new();
    let limit = max_frame_bytes.saturating_add(1);
    loop {
        let available = reader.fill_buf().map_err(|_| FrameReadError::Io)?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(FrameReadError::Io)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let available_limit = limit.saturating_sub(line.len());
        if available_limit == 0 {
            return Err(FrameReadError::Oversized);
        }
        let requested = newline.map_or(available.len(), |position| position + 1);
        let take = requested.min(available_limit);
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if take < requested {
            return Err(FrameReadError::Oversized);
        }
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.len() > max_frame_bytes {
                return Err(FrameReadError::Oversized);
            }
            return Ok(Some(line));
        }
        if line.len() >= limit {
            return Err(FrameReadError::Oversized);
        }
    }
}

fn validate_catalog(
    policy: &LocalMcpPolicy,
    request: &LocalMcpRequest,
    result: &Value,
) -> Result<(), LocalMcpError> {
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(LocalMcpError::CatalogMismatch)?;
    if result
        .get("nextCursor")
        .is_some_and(|cursor| !cursor.is_null())
    {
        return Err(LocalMcpError::CatalogMismatch);
    }
    let mut seen = BTreeMap::new();
    for tool in tools {
        let object = tool.as_object().ok_or(LocalMcpError::CatalogMismatch)?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or(LocalMcpError::CatalogMismatch)?;
        if name.is_empty()
            || name.len() > 256
            || name
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
            || object.get("title").is_some_and(|value| !value.is_string())
            || object
                .get("annotations")
                .is_some_and(|value| !value.is_object())
            || object.get("_meta").is_some_and(|value| !value.is_object())
            || object
                .get("description")
                .is_some_and(|value| !value.is_string())
            || object
                .get("outputSchema")
                .is_some_and(|value| !value.is_object())
        {
            return Err(LocalMcpError::CatalogMismatch);
        }
        let schema = object
            .get("inputSchema")
            .filter(|value| value.is_object())
            .ok_or(LocalMcpError::CatalogMismatch)?;
        if seen
            .insert(name.to_string(), (schema, object.get("outputSchema")))
            .is_some()
        {
            return Err(LocalMcpError::CatalogMismatch);
        }
    }
    // Preflight the entire sequence before its first call. Unrequested tools
    // never gain authority and do not disable an unrelated reviewed route.
    if request.calls.iter().any(|call| {
        let Some((input, output)) = seen.get(&call.tool) else {
            return true;
        };
        let Some(pin) = policy.expected_catalog.get(&call.tool) else {
            return true;
        };
        policy.reviewed_schemas.get(&call.tool).map_or_else(
            || {
                &local_mcp_schema_digest(input) != pin
                    || fcp_manifest::local_mcp_output_schema_digest(*output)
                        != policy
                            .expected_output_catalog
                            .get(&call.tool)
                            .cloned()
                            .unwrap_or_else(|| fcp_manifest::local_mcp_output_schema_digest(None))
            },
            |reviewed| !reviewed.matches(input, *output),
        )
    }) {
        return Err(LocalMcpError::CatalogMismatch);
    }
    Ok(())
}

fn validate_initialize(policy: &LocalMcpPolicy, result: &Value) -> Result<(), LocalMcpError> {
    if result.get("protocolVersion") != Some(&Value::from(policy.protocol_version.as_str())) {
        return Err(LocalMcpError::InvalidFrame);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ProcessPhase {
    Spawn,
    Stop,
}

const fn map_process_error(error: &ProcessGroupError, phase: ProcessPhase) -> LocalMcpError {
    match error {
        ProcessGroupError::UnsupportedPlatform => LocalMcpError::UnsupportedPlatform,
        ProcessGroupError::LauncherDigestMismatch | ProcessGroupError::InvalidSpec => {
            LocalMcpError::ProcessStart
        }
        ProcessGroupError::IdentityMismatch => LocalMcpError::ProcessIdentity,
        ProcessGroupError::TeardownTimeout | ProcessGroupError::TeardownTerminal => {
            LocalMcpError::ProcessStop
        }
        ProcessGroupError::Io(_) => match phase {
            ProcessPhase::Spawn => LocalMcpError::ProcessStart,
            ProcessPhase::Stop => LocalMcpError::ProcessStop,
        },
    }
}

const fn millis(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

const fn zero_memory_sample() -> ProcessMemorySample {
    ProcessMemorySample {
        available: true,
        process_count: 0,
        rss_bytes: Some(0),
        pss_bytes: Some(0),
        private_bytes: Some(0),
    }
}

const fn unavailable_memory_sample() -> ProcessMemorySample {
    ProcessMemorySample {
        available: false,
        process_count: 0,
        rss_bytes: None,
        pss_bytes: None,
        private_bytes: None,
    }
}

fn verify_package_metadata(policy: &LocalMcpPolicy) -> Result<(), LocalMcpError> {
    if let Some(binding) = &policy.package_binding {
        verify_immutable_package(binding, &binding.release_id)?;
    }
    let path = Path::new(&policy.package_metadata_path);
    let bytes = read_package_metadata(path)?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    if digest != policy.package_metadata_digest {
        return Err(LocalMcpError::PackageIdentity);
    }
    let metadata = crate::credential_metadata_unique_json(&bytes)
        .map_err(|_| LocalMcpError::PackageIdentity)?;
    let name = metadata.get("name").and_then(Value::as_str);
    if name != Some(policy.package_id.as_str()) {
        return Err(LocalMcpError::PackageIdentity);
    }
    verify_derived_validation_metadata(&metadata, path)?;
    Ok(())
}

/// Verify the fixed adopted package without launching it or granting authority.
/// The caller must separately bind `release_id` to a verified release root.
/// # Errors
/// Rejects recipe, owner, path, closure, payload or deployed-mode drift.
pub fn verify_immutable_package(
    binding: &fcp_manifest::LocalMcpPackageBinding,
    release_id: &str,
) -> Result<(), LocalMcpError> {
    use sha2::{Digest, Sha256};
    binding
        .validate()
        .map_err(|_| LocalMcpError::InvalidPolicy)?;
    if binding.release_id != release_id {
        return Err(LocalMcpError::PackageIdentity);
    }
    let root = Path::new(&binding.package_root);
    verify_derived_directory(root)?;
    if hex::encode(Sha256::digest(read_derived_package_file(
        Path::new("/usr/bin/node"),
        128 * 1024 * 1024,
    )?)) != "d0efb6fcb9d023ba4e2b160ec2384dc28fe4f17732141ef47f676828fa960505"
    {
        return Err(LocalMcpError::PackageIdentity);
    }
    for parent in root
        .parent()
        .ok_or(LocalMcpError::PackageIdentity)?
        .ancestors()
    {
        match std::fs::symlink_metadata(parent.join("node_modules")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(LocalMcpError::PackageIdentity),
        }
    }
    verify_immutable_package_at(root, binding, 0, 0)
}

/// Fixed protected preparation DATA; never a runtime/provider policy override.
pub const IMMUTABLE_PACKAGE_PREPARATION_PATH: &str =
    "/usr/local/lib/fwc-n8n/admissions/local-mcp-package.json";

/// Read the one root-owned closed preparation input and verify its package.
/// This performs no catalog discovery, process launch or signing/admission.
/// # Errors
/// Rejects any other path, input hash, recipe, release or package tree.
#[cfg(target_os = "linux")]
pub fn verify_immutable_package_preparation(
    path: &Path,
    sha256: &str,
    release_id: &str,
) -> Result<fcp_manifest::LocalMcpPackageBinding, LocalMcpError> {
    use sha2::{Digest, Sha256};
    if path != Path::new(IMMUTABLE_PACKAGE_PREPARATION_PATH) {
        return Err(LocalMcpError::PackageIdentity);
    }
    verify_derived_directory(path.parent().ok_or(LocalMcpError::PackageIdentity)?)?;
    let bytes = read_immutable_file(path, 0, 0, 0o600, 16 * 1024)?;
    if hex::encode(Sha256::digest(&bytes)) != sha256 {
        return Err(LocalMcpError::PackageIdentity);
    }
    let value = crate::credential_metadata_unique_json(&bytes)
        .map_err(|_| LocalMcpError::PackageIdentity)?;
    let binding = serde_json::from_value(value).map_err(|_| LocalMcpError::InvalidPolicy)?;
    verify_immutable_package(&binding, release_id)?;
    Ok(binding)
}

#[cfg(target_os = "linux")]
fn read_immutable_file(
    path: &Path,
    owner: u32,
    group: u32,
    mode: u32,
    limit: u64,
) -> Result<Vec<u8>, LocalMcpError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let invalid = || LocalMcpError::PackageIdentity;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| invalid())?;
    let before = file.metadata().map_err(|_| invalid())?;
    if !before.is_file()
        || before.uid() != owner
        || before.gid() != group
        || before.mode() & 0o7777 != mode
        || before.nlink() != 1
        || before.len() > limit
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if u64::try_from(bytes.len()).map_err(|_| invalid())? > limit
        || metadata_identity(&before) != metadata_identity(&file.metadata().map_err(|_| invalid())?)
        || metadata_identity(&before)
            != metadata_identity(&std::fs::symlink_metadata(path).map_err(|_| invalid())?)
    {
        return Err(invalid());
    }
    Ok(bytes)
}

fn immutable_mode(row: &Value) -> Result<u32, LocalMcpError> {
    let mode = row["mode"]
        .as_u64()
        .filter(|mode| *mode <= 0o777 && mode & 0o022 == 0)
        .ok_or(LocalMcpError::PackageIdentity)?;
    match row["kind"].as_str() {
        Some("directory") => Ok(0o555),
        Some("file") => Ok(if mode & 0o111 == 0 { 0o444 } else { 0o555 }),
        _ => Err(LocalMcpError::PackageIdentity),
    }
}

#[cfg(target_os = "linux")]
fn verify_immutable_package_at(
    root: &Path,
    binding: &fcp_manifest::LocalMcpPackageBinding,
    owner: u32,
    group: u32,
) -> Result<(), LocalMcpError> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let invalid = || LocalMcpError::PackageIdentity;
    let root_device = std::fs::symlink_metadata(root)
        .map_err(|_| invalid())?
        .dev();
    for control in ["derived-provenance.json", "original-stage-receipt.json"] {
        if std::fs::symlink_metadata(root.join(control))
            .map_err(|_| invalid())?
            .dev()
            != root_device
        {
            return Err(invalid());
        }
    }
    let derived_bytes = read_immutable_file(
        &root.join("derived-provenance.json"),
        owner,
        group,
        0o444,
        16 * 1024 * 1024,
    )?;
    let original = read_immutable_file(
        &root.join("original-stage-receipt.json"),
        owner,
        group,
        0o444,
        256 * 1024,
    )?;
    if hex::encode(Sha256::digest(&derived_bytes)) != binding.derived_receipt_sha256
        || hex::encode(Sha256::digest(&original)) != binding.original_receipt_sha256
    {
        return Err(invalid());
    }
    let receipt = crate::credential_metadata_unique_json(&derived_bytes).map_err(|_| invalid())?;
    let original = crate::credential_metadata_unique_json(&original).map_err(|_| invalid())?;
    if receipt["schema"] != "fwc.n8n.derived-validator-preparation.v1"
        || receipt["admitted"] != false
        || receipt["installed"] != false
        || receipt["patchSha256"]
            != "391a6acf86de476e45a7a65ad286719dca569abe7d216c2a50eaae7efc1fd832"
        || original["schema"] != "fwc.n8n.local-mcp-verification-receipt.v1"
        || original["status"] != "verified"
        || original["version"] != "2.91.0"
        || original["registryIntegrity"] != receipt["registryTarballSha512"]
        || receipt["registryTarballSha256"]
            != "19aeb9c6654155e67026b1a2479a498a4c46d2f63b2cb9bbbabe3e9141ff6f41"
        || receipt["upstreamTreeSha256"]
            != "d69ab91b3fb36fc34f8ca0877f6a2598485c44487178d8d5495f57e3fe6e701c"
    {
        return Err(invalid());
    }
    verify_immutable_recipe_rows(&receipt)?;
    verify_immutable_rows(root, &receipt, binding, owner, group)
}

fn verify_immutable_recipe_rows(receipt: &Value) -> Result<(), LocalMcpError> {
    let rows = receipt["files"]
        .as_array()
        .ok_or(LocalMcpError::PackageIdentity)?;
    for required in [
        "package-lock.json",
        "node_modules/n8n-mcp/package.json",
        "node_modules/n8n-mcp/dist/mcp/stdio-wrapper.js",
        "node_modules/n8n-mcp/data/nodes.db",
    ] {
        if rows
            .iter()
            .filter(|row| row["path"] == required && row["kind"] == "file")
            .count()
            != 1
        {
            return Err(LocalMcpError::PackageIdentity);
        }
    }
    let lock = rows
        .iter()
        .find(|row| row["path"] == "package-lock.json")
        .ok_or(LocalMcpError::PackageIdentity)?;
    let metadata = rows
        .iter()
        .find(|row| row["path"] == "node_modules/n8n-mcp/package.json")
        .ok_or(LocalMcpError::PackageIdentity)?;
    if lock["sha256"] != "c544ba17dd05a966699d24511e3b836e84ca2b22cc9af9b9e59ea88a50ff7f66"
        || metadata["sha256"] != receipt["packageMetadataSha256"]
        || receipt["packageMetadataSha256"]
            != "475c78c44a1f91a7db94672d229bee1ffc82d60b76a02f00d9b8ba2645b23739"
    {
        return Err(LocalMcpError::PackageIdentity);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_immutable_package_at(
    _root: &Path,
    _binding: &fcp_manifest::LocalMcpPackageBinding,
    _owner: u32,
    _group: u32,
) -> Result<(), LocalMcpError> {
    Err(LocalMcpError::UnsupportedPlatform)
}

fn project_immutable_rows(
    receipt: &Value,
    binding: &fcp_manifest::LocalMcpPackageBinding,
) -> Result<BTreeMap<String, Value>, LocalMcpError> {
    use sha2::{Digest, Sha256};
    let invalid = || LocalMcpError::PackageIdentity;
    let rows = receipt["files"]
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= 20_000)
        .ok_or_else(invalid)?;
    if hex::encode(Sha256::digest(
        serde_json::to_vec(rows).map_err(|_| invalid())?,
    )) != binding.source_tree_sha256
        || receipt["resultTreeSha256"] != binding.source_tree_sha256
    {
        return Err(invalid());
    }
    let mut expected = BTreeMap::new();
    let mut projected = Vec::with_capacity(rows.len());
    let mut previous: Option<&str> = None;
    for row in rows {
        let path = row["path"].as_str().ok_or_else(invalid)?;
        if !path.is_ascii()
            || path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            || path.bytes().any(|byte| byte.is_ascii_control())
            || previous.is_some_and(|previous| previous >= path)
            || matches!(
                path,
                "derived-provenance.json" | "original-stage-receipt.json"
            )
        {
            return Err(invalid());
        }
        previous = Some(path);
        let mut deployed = row.clone();
        deployed["mode"] = json!(immutable_mode(row)?);
        projected.push(deployed.clone());
        expected.insert(path.to_owned(), deployed);
    }
    if hex::encode(Sha256::digest(
        serde_json::to_vec(&projected).map_err(|_| invalid())?,
    )) != binding.deployed_tree_sha256
    {
        return Err(invalid());
    }
    Ok(expected)
}

#[cfg(target_os = "linux")]
fn verify_immutable_rows(
    root: &Path,
    receipt: &Value,
    binding: &fcp_manifest::LocalMcpPackageBinding,
    owner: u32,
    group: u32,
) -> Result<(), LocalMcpError> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let invalid = || LocalMcpError::PackageIdentity;
    let expected = project_immutable_rows(receipt, binding)?;
    let mut pending = vec![root.to_path_buf()];
    let mut observed = std::collections::BTreeSet::new();
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        let before = std::fs::symlink_metadata(&directory).map_err(|_| invalid())?;
        if !before.is_dir()
            || before.uid() != owner
            || before.gid() != group
            || before.mode() & 0o7777 != 0o555
            || std::fs::canonicalize(&directory).map_err(|_| invalid())? != directory
            || before.dev()
                != std::fs::symlink_metadata(root)
                    .map_err(|_| invalid())?
                    .dev()
        {
            return Err(invalid());
        }
        for entry in std::fs::read_dir(&directory).map_err(|_| invalid())? {
            let path = entry.map_err(|_| invalid())?.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| invalid())?
                .to_str()
                .ok_or_else(invalid)?
                .to_owned();
            if matches!(
                relative.as_str(),
                "derived-provenance.json" | "original-stage-receipt.json"
            ) {
                continue;
            }
            let row = expected.get(&relative).ok_or_else(invalid)?;
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| invalid())?;
            if !observed.insert(relative.clone()) || metadata.dev() != before.dev() {
                return Err(invalid());
            }
            if row["kind"] == "directory" && row.as_object().is_some_and(|row| row.len() == 3) {
                if !metadata.is_dir() {
                    return Err(invalid());
                }
                pending.push(path);
            } else if row["kind"] == "file" && row.as_object().is_some_and(|row| row.len() == 5) {
                let bytes = read_immutable_file(
                    &path,
                    owner,
                    group,
                    immutable_mode(row)?,
                    128 * 1024 * 1024,
                )?;
                total = total.checked_add(metadata.len()).ok_or_else(invalid)?;
                if total > 512 * 1024 * 1024
                    || row["size"].as_u64() != Some(metadata.len())
                    || row["sha256"].as_str() != Some(hex::encode(Sha256::digest(&bytes)).as_str())
                {
                    return Err(invalid());
                }
            } else {
                return Err(invalid());
            }
        }
        if metadata_identity(&before)
            != metadata_identity(&std::fs::symlink_metadata(&directory).map_err(|_| invalid())?)
        {
            return Err(invalid());
        }
    }
    if observed.len() != expected.len() {
        return Err(invalid());
    }
    Ok(())
}

fn verify_derived_validation_source(
    policy: &LocalMcpPolicy,
) -> Result<Option<VerifiedVersionedValidationSource>, LocalMcpError> {
    use sha2::{Digest, Sha256};

    let path = Path::new(&policy.package_metadata_path);
    let bytes = read_package_metadata(path)?;
    if blake3::hash(&bytes).to_hex().as_str() != policy.package_metadata_digest {
        return Err(LocalMcpError::PackageIdentity);
    }
    let metadata = crate::credential_metadata_unique_json(&bytes)
        .map_err(|_| LocalMcpError::PackageIdentity)?;
    let Some(patch_digest) = verify_derived_validation_metadata(&metadata, path)? else {
        return Ok(None);
    };
    let package_tree_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&metadata["fwcDerivedValidation"]["packageFiles"])
            .map_err(|_| LocalMcpError::PackageIdentity)?,
    ));
    Ok(Some(VerifiedVersionedValidationSource {
        metadata: policy.package_metadata_digest.clone(),
        patch: patch_digest,
        package_tree: package_tree_digest,
    }))
}

fn verify_derived_validation_metadata(
    metadata: &Value,
    path: &Path,
) -> Result<Option<String>, LocalMcpError> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    const PATCH: &str = "391a6acf86de476e45a7a65ad286719dca569abe7d216c2a50eaae7efc1fd832";
    const FILES: [&str; 5] = [
        "dist/mcp/server.js",
        "dist/services/workflow-validator.js",
        "dist/services/config-validator.js",
        "dist/services/enhanced-config-validator.js",
        "dist/services/type-structure-service.js",
    ];
    let Some(derived) = metadata.get("fwcDerivedValidation") else {
        return Ok(None);
    };
    let invalid = || LocalMcpError::PackageIdentity;
    let fields = [
        "schema",
        "upstreamVersion",
        "upstreamMetadataSha256",
        "patchSha256",
        "registryTarballSha256",
        "registryTarballSha512",
        "files",
        "packageFiles",
    ];
    let object = derived.as_object().ok_or_else(invalid)?;
    if metadata["name"] != "n8n-mcp"
        || metadata["version"] != "2.91.0"
        || object.len() != fields.len()
        || object.keys().any(|key| !fields.contains(&key.as_str()))
        || derived["schema"] != "fwc.n8n.derived-validator.v1"
        || derived["upstreamVersion"] != "2.91.0"
        || derived["patchSha256"] != PATCH
        || ["upstreamMetadataSha256", "registryTarballSha256"]
            .iter()
            .any(|key| {
                derived[*key].as_str().is_none_or(|s| {
                    s.len() != 64
                        || !s
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                })
            })
        || derived["registryTarballSha512"]
            .as_str()
            .and_then(|s| s.strip_prefix("sha512-"))
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .is_none_or(|bytes| bytes.len() != 64)
    {
        return Err(invalid());
    }
    let files = derived["files"].as_object().ok_or_else(invalid)?;
    if files.len() != FILES.len() || files.keys().any(|key| !FILES.contains(&key.as_str())) {
        return Err(invalid());
    }
    let root = path.parent().ok_or_else(invalid)?;
    let strict_metadata = read_derived_package_file(path, 4 * 1024 * 1024)?;
    if crate::credential_metadata_unique_json(&strict_metadata).map_err(|_| invalid())? != *metadata
    {
        return Err(invalid());
    }
    let package_files = derived["packageFiles"].as_object().ok_or_else(invalid)?;
    verify_derived_package_tree(root, package_files)?;
    for relative in FILES {
        let file = root.join(relative);
        let identity = std::fs::symlink_metadata(&file).map_err(|_| invalid())?;
        if !identity.is_file() || identity.len() > 8 * 1024 * 1024 {
            return Err(invalid());
        }
        let bytes = read_derived_package_file(&file, 8 * 1024 * 1024)?;
        if hex::encode(Sha256::digest(&bytes)) != files[relative].as_str().ok_or_else(invalid)? {
            return Err(invalid());
        }
    }
    Ok(Some(PATCH.to_owned()))
}

fn verify_derived_package_tree(
    root: &Path,
    package_files: &serde_json::Map<String, Value>,
) -> Result<(), LocalMcpError> {
    use sha2::{Digest, Sha256};

    let invalid = || LocalMcpError::PackageIdentity;
    if package_files.is_empty() || package_files.len() > 20_000 {
        return Err(invalid());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut observed = std::collections::BTreeSet::new();
    let mut total = 0_u64;
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        verify_derived_directory(&directory)?;
        let before = std::fs::symlink_metadata(&directory).map_err(|_| invalid())?;
        for entry in std::fs::read_dir(&directory).map_err(|_| invalid())? {
            let entry = entry.map_err(|_| invalid())?;
            visited += 1;
            if visited > 20_000 {
                return Err(invalid());
            }
            let file = entry.path();
            let identity = std::fs::symlink_metadata(&file).map_err(|_| invalid())?;
            if identity.is_dir() {
                verify_derived_directory(&file)?;
                pending.push(file);
                continue;
            }
            if !identity.is_file() {
                return Err(invalid());
            }
            let relative = file
                .strip_prefix(root)
                .map_err(|_| invalid())?
                .to_str()
                .ok_or_else(invalid)?
                .to_owned();
            if relative == "package.json" {
                continue;
            }
            let expected = package_files
                .get(&relative)
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            total = total.checked_add(identity.len()).ok_or_else(invalid)?;
            if total > 512 * 1024 * 1024 || !observed.insert(relative) {
                return Err(invalid());
            }
            let bytes = read_derived_package_file(&file, 128 * 1024 * 1024)?;
            if hex::encode(Sha256::digest(&bytes)) != expected {
                return Err(invalid());
            }
        }
        if metadata_identity(&before)
            != metadata_identity(&std::fs::symlink_metadata(&directory).map_err(|_| invalid())?)
        {
            return Err(invalid());
        }
    }
    if observed.len() != package_files.len() {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
type PackageFileIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

#[cfg(target_os = "linux")]
fn metadata_identity(m: &std::fs::Metadata) -> PackageFileIdentity {
    use std::os::unix::fs::MetadataExt;
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

#[cfg(not(target_os = "linux"))]
fn metadata_identity(m: &std::fs::Metadata) -> (u64, bool) {
    (m.len(), m.is_dir())
}

fn verify_derived_directory(path: &Path) -> Result<(), LocalMcpError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        for parent in path.ancestors() {
            let m =
                std::fs::symlink_metadata(parent).map_err(|_| LocalMcpError::PackageIdentity)?;
            if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7022 != 0 {
                return Err(LocalMcpError::PackageIdentity);
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(LocalMcpError::UnsupportedPlatform)
    }
}

fn read_package_metadata(path: &Path) -> Result<Vec<u8>, LocalMcpError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let invalid = || LocalMcpError::PackageIdentity;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| invalid())?;
        let before = file.metadata().map_err(|_| invalid())?;
        if !before.is_file() || before.len() > 4 * 1024 * 1024 {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() > 4 * 1024 * 1024
            || metadata_identity(&before)
                != metadata_identity(&file.metadata().map_err(|_| invalid())?)
            || metadata_identity(&before)
                != metadata_identity(&std::fs::symlink_metadata(path).map_err(|_| invalid())?)
        {
            return Err(invalid());
        }
        Ok(bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(LocalMcpError::UnsupportedPlatform)
    }
}

fn read_derived_package_file(path: &Path, limit: u64) -> Result<Vec<u8>, LocalMcpError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let invalid = || LocalMcpError::PackageIdentity;
        verify_derived_directory(path.parent().ok_or_else(invalid)?)?;
        if std::fs::canonicalize(path).map_err(|_| invalid())? != path {
            return Err(invalid());
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| invalid())?;
        let before = file.metadata().map_err(|_| invalid())?;
        if !before.is_file()
            || before.uid() != 0
            || before.gid() != 0
            || before.mode() & 0o7022 != 0
            || before.nlink() != 1
            || before.len() > limit
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        let identity = |m: &std::fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.uid(),
                m.gid(),
                m.mode(),
                m.nlink(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        if bytes.len() as u64 > limit
            || identity(&before) != identity(&file.metadata().map_err(|_| invalid())?)
            || identity(&before)
                != identity(&std::fs::symlink_metadata(path).map_err(|_| invalid())?)
        {
            return Err(invalid());
        }
        Ok(bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, limit);
        Err(LocalMcpError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires an exact rootless derived2.91 candidate; controlled native component, not signed/installed acceptance"]
    fn derived_validator_owned_native_to_public_projector() {
        let root = std::env::var("FCP_N8N_DERIVED_VALIDATOR_TEST_ROOT")
            .expect("explicit retained derived package fixture required");
        let script = std::fs::canonicalize(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/tests/n8n_versioned_validation_native.js"),
        )
        .unwrap();
        assert_eq!(
            blake3::hash(&std::fs::read(&script).unwrap()),
            blake3::hash(include_bytes!(
                "../../../scripts/tests/n8n_versioned_validation_native.js"
            ))
        );
        let node = PathBuf::from("/usr/bin/node");
        let digest = blake3::hash(&std::fs::read(&node).unwrap())
            .to_hex()
            .to_string();
        let spec = ProcessSpec {
            launcher_path: node.clone(), launcher_digest: digest.clone(),
            runtime_executable: std::fs::canonicalize(node).unwrap(),
            expected_runtime_executable_digest: digest,
            fixed_args: vec![script.into_os_string(), root.into()],
            fixed_env: BTreeMap::from([
                ("N8N_MCP_TELEMETRY_DISABLED".into(), "true".into()),
                ("DISABLE_CONSOLE_OUTPUT".into(), "true".into()),
                ("NODE_ENV".into(), "test".into()),
                ("NODE_PATH".into(), "/srv/dev-ssd/fcp/nqm81-35/versioned-validation-candidate-20261009-1/borrowed-dependencies".into()),
            ]),
            network_disabled: true,
        };
        let process = OwnedProcess::spawn(&spec).expect("owned controlled native launch");
        let mut session = LocalMcpSession::new(process, 256 * 1024);
        let frame = session.frames.recv_timeout(Duration::from_secs(30));
        // Teardown and IO joins happen BEFORE any result assertion/decoding.
        let (shutdown, _, error) =
            session.finish(&test_policy(), LocalMcpShutdownReason::Completed);
        let completion = json!({"errorCode":error.as_ref().map(LocalMcpError::code),
            "reaped":shutdown.completion.reaped,"groupAbsent":shutdown.completion.group_absent,
            "workersJoined":session.workers_joined});
        assert!(error.is_none(), "{completion}");
        assert!(
            shutdown.completion.reaped
                && shutdown.completion.group_absent
                && session.workers_joined,
            "{completion}"
        );
        let frame = frame
            .ok()
            .and_then(Result::ok)
            .expect("bounded synthetic native result");
        let result: Value = serde_json::from_slice(&frame).expect("closed synthetic result JSON");
        assert!(
            result["status"] == "native_fixture_pass"
                && result["checks"].as_u64().is_some_and(|n| n >= 12)
        );
        let graph = json!({"nodes":[{"id":"synthetic-0","name":"SYNTHETIC_CANARY_0",
            "type":"n8n-nodes-base.nocoDb","typeVersion":4,"position":[0,0],
            "parameters":{"projectId":"p","table":"t","resource":"row","operation":"update","version":3}}],"connections":{}});
        let context = crate::LocalN8nDiagnosticContext::from_verified_versioned_source(
            &graph,
            crate::LocalN8nValidationProfile::Runtime,
            &VerifiedVersionedValidationSource::synthetic_fixture(),
        )
        .unwrap();
        let native = json!({"content":[{"type":"text","text":result["nativeResponse"].to_string()}],
            "structuredContent":result["nativeResponse"]});
        let projected = crate::project_local_n8n_validation_with_context(&native, Some(&context))
            .expect("actual native serialization through actual public projector");
        assert!(
            projected["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["code"] == "configuration_special_type_mismatch")
        );
        assert!(!projected.to_string().contains("CANARY"));
        assert_eq!(
            projected["errors"].as_array().unwrap().len(),
            result["nativeResponse"]["errors"].as_array().unwrap().len()
        );
        assert_eq!(
            projected["warnings"].as_array().unwrap().len(),
            result["nativeResponse"]["warnings"]
                .as_array()
                .unwrap()
                .len()
        );
    }

    #[test]
    fn derived_metadata_is_closed_and_never_implicit_upstream_admission() {
        let path = Path::new("/nonexistent/package.json");
        assert!(
            verify_derived_validation_metadata(&json!({"name":"n8n-mcp","version":"2.91.0"}), path)
                .unwrap()
                .is_none()
        );
        for derived in [
            Value::Null,
            json!({}),
            json!({"schema":"fwc.n8n.derived-validator.v1",
            "upstreamVersion":"2.91.0","upstreamMetadataSha256":"0".repeat(64),
            "patchSha256":"0".repeat(64),"registryTarballSha256":"0".repeat(64),
            "registryTarballSha512":"sha512-invalid","files":{},"packageFiles":{}}),
        ] {
            assert!(
                verify_derived_validation_metadata(
                    &json!({"name":"n8n-mcp","version":"2.91.0",
                "fwcDerivedValidation":derived}),
                    path
                )
                .is_err()
            );
        }
    }

    #[test]
    fn invocation_deadline_only_tightens_native_time_bounds() {
        let now = Instant::now();
        let policy = now + Duration::from_secs(10);
        assert_eq!(bounded_provider_deadline(policy, None), policy);
        assert_eq!(
            bounded_provider_deadline(policy, Some(now + Duration::from_secs(20))),
            policy
        );
        assert_eq!(
            bounded_provider_deadline(policy, Some(now + Duration::from_secs(1))),
            now + Duration::from_secs(1)
        );
        assert_eq!(bounded_provider_deadline(policy, Some(now)), now);
    }

    #[test]
    fn shared_release_signature_verifier_binds_key_payload_and_context() {
        use super::*;
        let key = fcp_crypto::ed25519::Ed25519SigningKey::from_bytes(&[7_u8; 32])
            .expect("synthetic signing key");
        let verifying = key.verifying_key();
        let payload = b"synthetic canonical receipt";
        let signature = key.sign_with_context(b"fwc-n8n immutable release v1", payload);
        let public = verifying.to_bytes();
        let key_id = verifying.key_id().to_string();
        assert!(
            verify_n8n_release_signature_bytes(&public, &key_id, &signature.to_bytes(), payload,)
                .is_ok()
        );
        assert!(
            verify_n8n_release_signature_bytes(
                &public,
                "wrong-key",
                &signature.to_bytes(),
                payload,
            )
            .is_err()
        );
        assert!(
            verify_n8n_release_signature_bytes(
                &public,
                &key_id,
                &signature.to_bytes(),
                b"changed receipt",
            )
            .is_err()
        );
        let wrong_context = key.sign_with_context(b"different context", payload);
        assert!(
            verify_n8n_release_signature_bytes(
                &public,
                &key_id,
                &wrong_context.to_bytes(),
                payload,
            )
            .is_err()
        );
    }

    #[test]
    fn shutdown_receipt_preserves_all_independent_flat_wire_facts() {
        use super::*;
        for bits in 0_u8..16 {
            let receipt = LocalMcpShutdownReceipt {
                reason: LocalMcpShutdownReason::Completed,
                signals: LocalMcpSignalEvidence {
                    term_sent: bits & 1 != 0,
                    kill_sent: bits & 2 != 0,
                },
                completion: LocalMcpCompletionEvidence {
                    reaped: bits & 4 != 0,
                    group_absent: bits & 8 != 0,
                },
                stderr_bytes: 7,
                memory_after: zero_memory_sample(),
            };
            let expected = serde_json::json!({
                "reason": "Completed",
                "term_sent": bits & 1 != 0,
                "kill_sent": bits & 2 != 0,
                "reaped": bits & 4 != 0,
                "group_absent": bits & 8 != 0,
                "stderr_bytes": 7,
                "memory_after": zero_memory_sample(),
            });
            assert_eq!(serde_json::to_value(&receipt).expect("serialize"), expected);
            assert_eq!(
                serde_json::from_value::<LocalMcpShutdownReceipt>(expected.clone())
                    .expect("deserialize"),
                receipt
            );
            for key in ["term_sent", "kill_sent", "reaped", "group_absent"] {
                let mut missing = expected.clone();
                missing.as_object_mut().expect("object").remove(key);
                assert!(serde_json::from_value::<LocalMcpShutdownReceipt>(missing).is_err());
            }
        }
    }
    use super::*;
    use fcp_manifest::{LOCAL_MCP_CATALOG_TOOLS, LOCAL_MCP_METHODS};

    #[test]
    fn client_identity_requests_canonical_catalog() {
        assert!(!CLIENT_NAME.contains("n8n"));
        assert!(!CLIENT_NAME.contains("langchain"));
    }

    #[test]
    fn request_rejects_unknown_tool_before_spawn() {
        let policy = test_policy();
        let provider = LocalMcpProvider::new(policy).expect("policy");
        let error = provider
            .run_once(LocalMcpRequest {
                correlation_id: "test".into(),
                calls: vec![LocalMcpCall {
                    tool: "unknown".into(),
                    arguments: json!({}),
                }],
            })
            .expect_err("unknown tool must fail closed");
        assert!(matches!(error, LocalMcpError::UnknownTool));
    }

    #[test]
    fn request_rejects_overlength_correlation_id_before_spawn() {
        let policy = test_policy();
        let request = LocalMcpRequest {
            correlation_id: "a".repeat(129),
            calls: vec![LocalMcpCall {
                tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
                arguments: json!({}),
            }],
        };
        assert!(matches!(
            validate_request(&policy, &request),
            Err(LocalMcpError::InvalidRequest)
        ));
    }

    #[test]
    fn request_rejects_disallowed_correlation_id_characters_before_spawn() {
        let policy = test_policy();
        let request = LocalMcpRequest {
            correlation_id: "bad/slash".into(),
            calls: vec![LocalMcpCall {
                tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
                arguments: json!({}),
            }],
        };
        assert!(matches!(
            validate_request(&policy, &request),
            Err(LocalMcpError::InvalidRequest)
        ));
    }

    #[test]
    fn n8n_contract_invariants_catalog_schema_and_name_pins() {
        let policy = test_policy();
        let expected_tools: Vec<Value> = LOCAL_MCP_CATALOG_TOOLS
            .iter()
            .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
            .collect();
        let mut result = json!({"tools": expected_tools});
        let request = LocalMcpRequest {
            correlation_id: "catalog-test".into(),
            calls: vec![LocalMcpCall {
                tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
                arguments: json!({}),
            }],
        };
        assert!(validate_catalog(&policy, &request, &result).is_ok());
        result["tools"][0]["inputSchema"] = json!({"type": "string"});
        assert!(matches!(
            validate_catalog(&policy, &request, &result),
            Err(LocalMcpError::CatalogMismatch)
        ));
        result["tools"] = json!([{"name":"unexpected","inputSchema":{}}]);
        assert!(matches!(
            validate_catalog(&policy, &request, &result),
            Err(LocalMcpError::CatalogMismatch)
        ));
    }

    #[test]
    fn catalog_preflights_requested_subset_but_validates_unrelated_entries() {
        let policy = test_policy();
        let request = LocalMcpRequest {
            correlation_id: "catalog-subset".into(),
            calls: vec![LocalMcpCall {
                tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
                arguments: json!({}),
            }],
        };
        let valid = json!({"tools":[
            {"name":LOCAL_MCP_CATALOG_TOOLS[0], "inputSchema":{"type":"object"}},
            {"name":LOCAL_MCP_CATALOG_TOOLS[1], "inputSchema":{"type":"string"}},
            {"name":"new-tool", "inputSchema":{"type":"object"}}
        ]});
        assert!(validate_catalog(&policy, &request, &valid).is_ok());
        let mut sequence = request.clone();
        sequence.calls.push(LocalMcpCall {
            tool: LOCAL_MCP_CATALOG_TOOLS[1].into(),
            arguments: json!({}),
        });
        assert!(validate_catalog(&policy, &sequence, &valid).is_err());
        for malformed in [
            json!(null),
            json!({}),
            json!({"tools":{}}),
            json!({"tools":[]}),
            json!({"tools":[null]}),
            json!({"tools":[{"name":"x", "inputSchema":null}]}),
            json!({"tools":[{"name":"x", "inputSchema":{}, "outputSchema":null}]}),
        ] {
            assert!(validate_catalog(&policy, &request, &malformed).is_err());
        }
        let mut incomplete = valid;
        incomplete["nextCursor"] = json!("more");
        assert!(validate_catalog(&policy, &request, &incomplete).is_err());
    }

    #[test]
    fn n8n_contract_invariants_local_mcp_version_digest_and_name_pins() {
        let directory = tempfile::tempdir()
            .expect("package metadata directory")
            .keep();
        let path = directory.join("package.json");
        let mut policy = test_policy();
        policy.package_metadata_path = path.to_string_lossy().into_owned();

        let accepted_metadata = br#"{"name":"test-provider","version":"99.7.1"}"#;
        std::fs::write(&path, accepted_metadata).expect("write package metadata");
        policy.package_metadata_digest = blake3::hash(accepted_metadata).to_hex().to_string();
        assert!(verify_package_metadata(&policy).is_ok());

        let changed_metadata = br#"{"name":"test-provider","version":"1.0.0"}"#;
        std::fs::write(&path, changed_metadata).expect("write changed package metadata");
        assert!(matches!(
            verify_package_metadata(&policy),
            Err(LocalMcpError::PackageIdentity)
        ));

        let wrong_name_metadata = br#"{"name":"other-provider","version":"99.7.1"}"#;
        std::fs::write(&path, wrong_name_metadata).expect("write wrong-name package metadata");
        policy.package_metadata_digest = blake3::hash(wrong_name_metadata).to_hex().to_string();
        assert!(matches!(
            verify_package_metadata(&policy),
            Err(LocalMcpError::PackageIdentity)
        ));
        std::fs::write(&path, accepted_metadata).expect("restore accepted package metadata");
        policy.package_metadata_digest = blake3::hash(accepted_metadata).to_hex().to_string();
        assert!(verify_package_metadata(&policy).is_ok());
        println!("package_metadata_version_evidence={}", path.display());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observer_fixture_local_session_requires_physical_teardown_and_worker_joins() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::Builder::new()
            .prefix("observer-local-")
            .tempdir_in("/srv/dev-ssd/fcp/nqm81-35")
            .unwrap()
            .keep();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store =
            crate::admin_state::HostAdminStateStore::observer_fixture(root.join("state.json"));
        let launcher = PathBuf::from("/bin/sh");
        let runtime = std::fs::canonicalize(&launcher).unwrap();
        let digest = blake3::hash(&std::fs::read(&runtime).unwrap())
            .to_hex()
            .to_string();
        let proof = store
            .observer_fixture_pending("local-owned", &digest)
            .unwrap();
        let mut provider = LocalMcpProvider::new(test_policy()).unwrap();
        provider.observer = Some(proof);
        let spec = ProcessSpec {
            launcher_path: launcher.clone(),
            launcher_digest: blake3::hash(&std::fs::read(&launcher).unwrap())
                .to_hex()
                .to_string(),
            runtime_executable: runtime,
            expected_runtime_executable_digest: digest,
            fixed_args: vec!["-c".into(), "while IFS= read -r line; do :; done".into()],
            fixed_env: BTreeMap::new(),
            network_disabled: true,
        };
        let process = provider.spawn_observed_process(&spec).unwrap();
        assert!(process.identity().pid > 0 && process.identity().start_time_ticks > 0);
        let mut session = LocalMcpSession::new(process, 4096);
        let (shutdown, _, teardown_error) =
            session.finish(provider.policy(), LocalMcpShutdownReason::Completed);
        assert!(teardown_error.is_none());
        assert!(shutdown.completion.reaped && shutdown.completion.group_absent);
        assert!(session.workers_joined);
        let mut incomplete = shutdown.clone();
        incomplete.completion.reaped = false;
        assert!(
            provider
                .observe_completed_session(&session, &incomplete)
                .is_err()
        );
        incomplete = shutdown.clone();
        incomplete.completion.group_absent = false;
        assert!(
            provider
                .observe_completed_session(&session, &incomplete)
                .is_err()
        );
        assert_eq!(store.observer_fixture_status().unwrap(), (None, 1));
        provider
            .observe_completed_session(&session, &shutdown)
            .unwrap();
        store.observer_fixture_complete_coverage();
        assert_eq!(store.observer_fixture_status().unwrap(), (Some(true), 0));
        assert!(
            provider.spawn_observed_process(&spec).is_err(),
            "replay refuses before another physical spawn"
        );
        session.workers_joined = false;
        assert!(
            provider
                .observe_completed_session(&session, &shutdown)
                .is_err(),
            "negative-only worker evidence cannot authorize completion"
        );
    }

    fn test_policy() -> LocalMcpPolicy {
        let expected_catalog = LOCAL_MCP_CATALOG_TOOLS
            .iter()
            .map(|tool| {
                (
                    (*tool).to_string(),
                    local_mcp_schema_digest(&json!({"type":"object"})),
                )
            })
            .collect();
        LocalMcpPolicy {
            package_id: "test-provider".into(),
            package_version: semver::Version::new(1, 0, 0),
            launcher_path: "/bin/sh".into(),
            launcher_digest: "0".repeat(64),
            runtime_executable: "/usr/bin/dash".into(),
            runtime_executable_digest: "0".repeat(64),
            package_metadata_path: "/usr/share/fcp/package.json".into(),
            package_metadata_digest: "0".repeat(64),
            package_binding: None,
            protocol_version: LOCAL_MCP_PROTOCOL_VERSION.into(),
            fixed_args: Vec::new(),
            fixed_env: BTreeMap::new(),
            allowed_methods: LOCAL_MCP_METHODS
                .iter()
                .map(|value| (*value).into())
                .collect(),
            expected_catalog,
            expected_output_catalog: BTreeMap::new(),
            reviewed_schemas: BTreeMap::new(),
            callable_tools: LOCAL_MCP_CATALOG_TOOLS
                .iter()
                .map(|value| (*value).into())
                .collect(),
            max_frame_bytes: 64 * 1024,
            max_request_bytes: 64 * 1024,
            max_result_bytes: 64 * 1024,
            max_sequential_calls: 7,
            startup_timeout_ms: 1000,
            request_timeout_ms: 1000,
            shutdown_timeout_ms: 1000,
            idle_window_ms: 0,
            network_disabled: true,
        }
    }
}
