//! Compact, provider-neutral n8n entry point.
//!
//! The thin wrapper resolves and routes typed operations. Read-only provider
//! execution uses a fixed one-shot credential broker and verified host bridge.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, io,
    io::Read,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand, ValueEnum};
use fcp_crypto::ZeroizingSecret;
use fcp_host::{
    LocalMcpProvider, LocalN8nDispatchErrorCode, LocalN8nDispatchRequest, LocalN8nDispatcher,
};
use fcp_n8n::router::{
    CapabilitySnapshot, OperationIntent, ProviderRouter, ResolvedTarget, TargetQuery,
    TargetResolution, TargetResolver,
};
use fcp_n8n::update::{ComponentSnapshot, detect_update};
use fcp_n8n_broker_protocol::{BrokerClient, BrokerCredentialPurpose, BrokerRequest, BrokerServer};
use fcp_prelude::ApprovalToken;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[path = "fwc_n8n_bridge.rs"]
#[allow(dead_code)]
mod fwc_n8n_bridge;
#[path = "fwc_n8n_bundle.rs"]
mod fwc_n8n_bundle;
#[path = "fwc_n8n_provision.rs"]
#[allow(dead_code)]
mod fwc_n8n_provision;
#[path = "fwc_n8n_update_host.rs"]
#[allow(dead_code)]
mod fwc_n8n_update_host;

const MAX_INPUT_BYTES: usize = 256 * 1024;
const STDIN_READ_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_RUN_ONCE_SCHEMA: &str = "fwc.n8n.host-run-once.v1";
const HOST_RUN_ONCE_ZONE: &str = "z:work";
const HOST_RUN_ONCE_DEFAULT_DEADLINE_MS: u64 = 30_000;
const HOST_RUN_ONCE_MAX_DEADLINE_MS: u64 = 60_000;
const LOCAL_RUN_ONCE_SCHEMA: &str = "fwc.n8n.local-run-once.v1";
const PROVISION_INPUT_SCHEMA: &str = "fwc.n8n.provision-request.v1";
const PROVISION_OUTPUT_SCHEMA: &str = "fwc.n8n.provision-result.v1";
const MAX_PROVISION_INPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "fwc-n8n",
    version,
    about = "On-demand typed n8n provider router"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Resolve a target query read from stdin without contacting a provider.
    Resolve,
    /// Route a public operation using target/capability input read from stdin.
    Route { operation: String },
    /// Validate a public operation, then defer execution to host-owned dispatch.
    #[command(name = "run-once")]
    RunOnce { operation: String },
    /// Detect exact review-first component updates without applying.
    #[command(name = "update-review")]
    UpdateReview {
        #[command(subcommand)]
        command: UpdateReviewCommand,
    },
    /// Validate or owner-promote a fixed-root staged release.
    Provision {
        #[arg(long, value_enum, default_value_t = ProvisionMode::Preflight)]
        mode: ProvisionMode,
    },
    /// Report this request-scoped wrapper's idle state.
    Status,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum UpdateReviewCommand {
    /// Diff current and candidate safe capability snapshots without applying.
    Detect,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum ProvisionMode {
    Preflight,
    Apply,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteInput {
    target: TargetQuery,
    capabilities: CapabilitySnapshot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UpdateDetectInput {
    current: ComponentSnapshot,
    candidate: ComponentSnapshot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionInput {
    schema: String,
    release_id: String,
    git_revision: String,
    bindings: Vec<fwc_n8n_provision::OfficialMcpBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum HostRunOnceServerId {
    Eec,
    Hetzner,
}

impl HostRunOnceServerId {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Eec => "eec",
            Self::Hetzner => "hetzner",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum HostRunOnceOperation {
    #[serde(rename = "n8n.capabilities.inspect")]
    CapabilitiesInspect,
    #[serde(rename = "n8n.credentials.list")]
    CredentialsList,
    #[serde(rename = "n8n.executions.get")]
    ExecutionsGet,
    #[serde(rename = "n8n.executions.list")]
    ExecutionsList,
    #[serde(rename = "n8n.folders.get")]
    FoldersGet,
    #[serde(rename = "n8n.folders.list")]
    FoldersList,
    #[serde(rename = "n8n.projects.list")]
    ProjectsList,
    #[serde(rename = "n8n.tags.list")]
    TagsList,
    #[serde(rename = "n8n.workflows.get")]
    WorkflowsGet,
    #[serde(rename = "n8n.workflows.list")]
    WorkflowsList,
    #[serde(rename = "n8n.workflows.create_draft")]
    WorkflowsCreateDraft,
    #[serde(rename = "n8n.workflows.update_draft")]
    WorkflowsUpdateDraft,
    #[serde(rename = "n8n.workflows.lifecycle")]
    WorkflowsLifecycle,
    #[serde(rename = "n8n.workflows.archive")]
    WorkflowsArchive,
    #[serde(rename = "n8n.workflows.execute")]
    WorkflowsExecute,
    #[serde(rename = "n8n.workflows.delete_disposable")]
    WorkflowsDeleteDisposable,
    #[serde(rename = "n8n.mcp_access.reconcile")]
    McpAccessReconcile,
}

impl HostRunOnceOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilitiesInspect => "n8n.capabilities.inspect",
            Self::CredentialsList => "n8n.credentials.list",
            Self::ExecutionsGet => "n8n.executions.get",
            Self::ExecutionsList => "n8n.executions.list",
            Self::FoldersGet => "n8n.folders.get",
            Self::FoldersList => "n8n.folders.list",
            Self::ProjectsList => "n8n.projects.list",
            Self::TagsList => "n8n.tags.list",
            Self::WorkflowsGet => "n8n.workflows.get",
            Self::WorkflowsList => "n8n.workflows.list",
            Self::WorkflowsCreateDraft => "n8n.workflows.create_draft",
            Self::WorkflowsUpdateDraft => "n8n.workflows.update_draft",
            Self::WorkflowsLifecycle => "n8n.workflows.lifecycle",
            Self::WorkflowsArchive => "n8n.workflows.archive",
            Self::WorkflowsExecute => "n8n.workflows.execute",
            Self::WorkflowsDeleteDisposable => "n8n.workflows.delete_disposable",
            Self::McpAccessReconcile => "n8n.mcp_access.reconcile",
        }
    }

    fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "n8n.capabilities.inspect" => Ok(Self::CapabilitiesInspect),
            "n8n.credentials.list" => Ok(Self::CredentialsList),
            "n8n.executions.get" => Ok(Self::ExecutionsGet),
            "n8n.executions.list" => Ok(Self::ExecutionsList),
            "n8n.folders.get" => Ok(Self::FoldersGet),
            "n8n.folders.list" => Ok(Self::FoldersList),
            "n8n.projects.list" => Ok(Self::ProjectsList),
            "n8n.tags.list" => Ok(Self::TagsList),
            "n8n.workflows.get" => Ok(Self::WorkflowsGet),
            "n8n.workflows.list" => Ok(Self::WorkflowsList),
            "n8n.workflows.create_draft" => Ok(Self::WorkflowsCreateDraft),
            "n8n.workflows.update_draft" => Ok(Self::WorkflowsUpdateDraft),
            "n8n.workflows.lifecycle" => Ok(Self::WorkflowsLifecycle),
            "n8n.workflows.archive" => Ok(Self::WorkflowsArchive),
            "n8n.workflows.execute" => Ok(Self::WorkflowsExecute),
            "n8n.workflows.delete_disposable" => Ok(Self::WorkflowsDeleteDisposable),
            "n8n.mcp_access.reconcile" => Ok(Self::McpAccessReconcile),
            _ => Err(AppError::new("operation_not_allowed")),
        }
    }

    const fn credential_purpose(self) -> BrokerCredentialPurpose {
        match self {
            Self::CapabilitiesInspect => BrokerCredentialPurpose::OfficialMcp,
            Self::CredentialsList
            | Self::ExecutionsGet
            | Self::ExecutionsList
            | Self::FoldersGet
            | Self::FoldersList
            | Self::ProjectsList
            | Self::TagsList
            | Self::WorkflowsGet
            | Self::WorkflowsList
            | Self::WorkflowsCreateDraft
            | Self::WorkflowsUpdateDraft
            | Self::McpAccessReconcile => BrokerCredentialPurpose::RestApi,
            Self::WorkflowsLifecycle | Self::WorkflowsArchive | Self::WorkflowsExecute => {
                BrokerCredentialPurpose::OfficialMcp
            }
            Self::WorkflowsDeleteDisposable => BrokerCredentialPurpose::RestApi,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRunOnceInput {
    server_id: HostRunOnceServerId,
    input: Value,
    #[serde(default)]
    approval_token: Option<ApprovalToken>,
    #[serde(default)]
    deadline_ms: Option<u64>,
    #[serde(default)]
    correlation_id: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRunOnceInput {
    input: Value,
    #[serde(default)]
    correlation_id: Option<String>,
}

impl fmt::Debug for LocalRunOnceInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRunOnceInput")
            .field("input", &"[REDACTED]")
            .field(
                "correlation_id",
                &self.correlation_id.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl fmt::Debug for HostRunOnceInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRunOnceInput")
            .field("server_id", &self.server_id)
            .field("input", &"[REDACTED]")
            .field(
                "approval_token",
                &self.approval_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("deadline_ms", &self.deadline_ms)
            .field(
                "correlation_id",
                &self.correlation_id.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone, Serialize)]
struct HostRunOnceEnvelope {
    schema: &'static str,
    server_id: HostRunOnceServerId,
    operation: HostRunOnceOperation,
    zone_id: &'static str,
    resource_uri: String,
    input: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_token: Option<ApprovalToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    correlation_id: Option<String>,
}

impl fmt::Debug for HostRunOnceEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRunOnceEnvelope")
            .field("schema", &self.schema)
            .field("server_id", &self.server_id)
            .field("operation", &self.operation)
            .field("zone_id", &self.zone_id)
            .field("resource_uri", &"[REDACTED]")
            .field("input", &"[REDACTED]")
            .field(
                "approval_token",
                &self.approval_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("deadline_ms", &self.deadline_ms)
            .field(
                "correlation_id",
                &self.correlation_id.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope {
    schema: &'static str,
    status: &'static str,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<&'static str>,
    correlation_id: String,
}

#[derive(Debug)]
struct AppError {
    code: &'static str,
    diagnostic: Option<&'static str>,
}

impl AppError {
    const fn new(code: &'static str) -> Self {
        Self {
            code,
            diagnostic: None,
        }
    }

    const fn with_diagnostic(code: &'static str, diagnostic: Option<&'static str>) -> Self {
        Self { code, diagnostic }
    }
}

fn main() {
    let correlation_id = Uuid::new_v4().to_string();
    let result = execute(Cli::parse());
    match result {
        Ok(value) => {
            if let Ok(encoded) = serde_json::to_string(&value) {
                println!("{encoded}");
                if value.get("status").and_then(Value::as_str) == Some("failed") {
                    std::process::exit(1);
                }
            } else {
                print_error("output_encoding_failed", None, &correlation_id);
                std::process::exit(1);
            }
        }
        Err(error) => {
            print_error(error.code, error.diagnostic, &correlation_id);
            std::process::exit(1);
        }
    }
}

fn print_error(code: &str, diagnostic: Option<&'static str>, correlation_id: &str) {
    let envelope = ErrorEnvelope {
        schema: "fwc.n8n.error.v1",
        status: "error",
        code: code.to_string(),
        diagnostic,
        correlation_id: correlation_id.to_string(),
    };
    let encoded = serde_json::to_string(&envelope).unwrap_or_else(|_| {
        "{\"schema\":\"fwc.n8n.error.v1\",\"status\":\"error\",\"code\":\"output_encoding_failed\"}".to_string()
    });
    println!("{encoded}");
}

fn execute(cli: Cli) -> Result<Value, AppError> {
    match cli.command {
        Command::Resolve => {
            let query: TargetQuery = read_stdin_json()?;
            let resolution = TargetResolver::resolve(&query)
                .map_err(|error| AppError::new(target_error_code(error.code())))?;
            serde_json::to_value(resolution).map_err(|_| AppError::new("output_encoding_failed"))
        }
        Command::Route { operation } => {
            let intent = public_operation_intent(&operation)?;
            let input: RouteInput = read_stdin_json()?;
            let resolution = TargetResolver::resolve(&input.target)
                .map_err(|error| AppError::new(target_error_code(error.code())))?;
            let target = exact_target(&resolution)?;
            let route = ProviderRouter::route(intent, Some(target), &input.capabilities)
                .map_err(|error| AppError::new(route_error_code(error.code())))?;
            serde_json::to_value(route).map_err(|_| AppError::new("output_encoding_failed"))
        }
        Command::RunOnce { operation } => run_once(&operation),
        Command::UpdateReview { command } => run_update_review(command),
        Command::Provision { mode } => run_provision(mode),
        Command::Status => Ok(json!({
            "bundleAvailable": fwc_n8n_bundle::verify_current_release_bundle().is_ok(),
        })),
    }
}

fn run_update_review(command: UpdateReviewCommand) -> Result<Value, AppError> {
    match command {
        UpdateReviewCommand::Detect => {
            let input: UpdateDetectInput = read_stdin_json()?;
            detect_update_input(input)
        }
    }
}

fn detect_update_input(input: UpdateDetectInput) -> Result<Value, AppError> {
    let outcome = detect_update(input.current, input.candidate)
        .map_err(|_| AppError::new("update_review_invalid"))?;
    serde_json::to_value(outcome).map_err(|_| AppError::new("output_encoding_failed"))
}

fn run_provision(mode: ProvisionMode) -> Result<Value, AppError> {
    let input = read_provision_input()?;
    if mode == ProvisionMode::Apply && !effective_uid_is_root() {
        return Err(AppError::new("provision_owner_required"));
    }
    let owner_verification =
        fwc_n8n_provision::OwnerVerificationConfig::from_immutable_production_config()
            .map_err(map_provision_error)?;
    let request = fwc_n8n_provision::ProvisionRequest::fixed(
        input.release_id.clone(),
        input.git_revision,
        input.bindings,
        owner_verification,
    )
    .map_err(map_provision_error)?;
    let plan = request.validate().map_err(map_provision_error)?;
    if mode == ProvisionMode::Preflight {
        return Ok(provision_result(
            mode,
            &input.release_id,
            "preflight_ok",
            false,
        ));
    }
    let proof = plan.revalidate().map_err(map_provision_error)?;
    let installer = fwc_n8n_provision::FilesystemOwnerAtomicInstaller::new();
    fwc_n8n_provision::OwnerAtomicInstaller::promote(&installer, proof)
        .map_err(map_provision_error)?;
    Ok(provision_result(mode, &input.release_id, "promoted", true))
}

fn provision_result(
    mode: ProvisionMode,
    release_id: &str,
    status: &'static str,
    current_changed: bool,
) -> Value {
    json!({
        "schema": PROVISION_OUTPUT_SCHEMA,
        "status": status,
        "mode": match mode {
            ProvisionMode::Preflight => "preflight",
            ProvisionMode::Apply => "apply",
        },
        "releaseId": release_id,
        "promotion": "temporary_symlink_rename",
        "currentChanged": current_changed,
        "rollback": "separate_owner_gated_boundary",
    })
}

fn read_provision_input() -> Result<ProvisionInput, AppError> {
    let deadline = Instant::now()
        .checked_add(STDIN_READ_TIMEOUT)
        .ok_or_else(|| AppError::new("input_read_timeout"))?;
    let bytes = read_input_until(io::stdin(), deadline)?;
    parse_provision_input_bytes(&bytes)
}

fn parse_provision_input_bytes(bytes: &[u8]) -> Result<ProvisionInput, AppError> {
    if bytes.len() > MAX_PROVISION_INPUT_BYTES {
        return Err(AppError::new("input_too_large"));
    }
    let input: ProvisionInput =
        serde_json::from_slice(bytes).map_err(|_| AppError::new("invalid_input"))?;
    if input.schema != PROVISION_INPUT_SCHEMA
        || !is_fixed_release_id(&input.release_id)
        || !is_fixed_git_revision(&input.git_revision)
        || input.bindings.len() != 2
    {
        return Err(AppError::new("invalid_input"));
    }
    Ok(input)
}

fn is_fixed_release_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn is_fixed_git_revision(value: &str) -> bool {
    (7..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn effective_uid_is_root() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().as_raw() == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn map_provision_error(_error: fwc_n8n_provision::ProvisionError) -> AppError {
    AppError::new("provision_denied")
}

fn run_once(operation: &str) -> Result<Value, AppError> {
    let request_started_at = Instant::now();
    let input_deadline = request_started_at
        .checked_add(STDIN_READ_TIMEOUT)
        .ok_or_else(|| AppError::new("input_read_timeout"))?;
    let bytes = read_input_until(io::stdin(), input_deadline)?;
    if matches!(operation, "n8n.knowledge.query" | "n8n.validation.run") {
        return run_local_once_from_bytes(operation, &bytes, execute_local_run_once);
    }
    run_once_from_bytes_at(operation, &bytes, request_started_at, execute_host_run_once)
}

fn run_local_once_from_bytes<F>(
    operation: &str,
    bytes: &[u8],
    dispatch: F,
) -> Result<Value, AppError>
where
    F: FnOnce(LocalN8nDispatchRequest) -> Result<Value, AppError>,
{
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(AppError::new("input_too_large"));
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(AppError::new("input_empty"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let input = LocalRunOnceInput::deserialize(&mut deserializer)
        .map_err(|_| AppError::new("invalid_input"))?;
    deserializer
        .end()
        .map_err(|_| AppError::new("trailing_input"))?;

    let mut operation_input = input
        .input
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::new("input_object_required"))?;
    if operation_input.contains_key("correlation_id") {
        return Err(AppError::new("invalid_operation_input"));
    }
    let correlation_id = input
        .correlation_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if Uuid::parse_str(&correlation_id).is_err() {
        return Err(AppError::new("invalid_correlation_id"));
    }
    operation_input.insert("correlation_id".into(), Value::String(correlation_id));
    let request = serde_json::from_value(json!({
        "operation": operation,
        "input": Value::Object(operation_input),
    }))
    .map_err(|_| AppError::new("invalid_operation_input"))?;
    dispatch(request)
}

fn execute_local_run_once(request: LocalN8nDispatchRequest) -> Result<Value, AppError> {
    let bundle = fwc_n8n_bundle::verify_current_release_bundle_for_bridge()
        .map_err(|_| AppError::new("bundle_unavailable"))?;
    let provider = LocalMcpProvider::new(bundle.local_mcp_policy().clone())
        .map_err(|_| AppError::new("local_provider_policy_invalid"))?;
    let dispatcher = LocalN8nDispatcher::new(provider);
    let response = dispatcher
        .dispatch(request, Arc::new(AtomicBool::new(false)))
        .map_err(map_local_dispatch_error)?;
    Ok(json!({
        "schema": LOCAL_RUN_ONCE_SCHEMA,
        "provider": "local_mcp",
        "response": response,
    }))
}

const fn map_local_dispatch_error(code: fcp_host::LocalN8nDispatchError) -> AppError {
    let code = match code.code() {
        LocalN8nDispatchErrorCode::InvalidRequest => "invalid_operation_input",
        LocalN8nDispatchErrorCode::InputTooLarge => "input_too_large",
        LocalN8nDispatchErrorCode::UnsupportedPlatform => "unsupported_platform",
        LocalN8nDispatchErrorCode::Cancelled => "cancelled",
        LocalN8nDispatchErrorCode::ProviderError => "local_provider_failed",
    };
    AppError::new(code)
}

fn read_input_until<R>(reader: R, deadline: Instant) -> Result<Vec<u8>, AppError>
where
    R: Read + Send + 'static,
{
    if Instant::now() >= deadline {
        return Err(AppError::new("input_read_timeout"));
    }

    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("fwc-n8n-stdin".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = reader
                .take((MAX_INPUT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send(result);
        })
        .map_err(|_| AppError::new("input_read_failed"))?;

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(AppError::new("input_read_timeout"));
    }
    match receiver.recv_timeout(remaining) {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(AppError::new("input_read_failed"))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(AppError::new("input_read_timeout")),
    }
}

fn run_once_from_bytes_at<F>(
    operation: &str,
    bytes: &[u8],
    request_started_at: Instant,
    dispatch: F,
) -> Result<Value, AppError>
where
    F: FnOnce(HostRunOnceEnvelope, Instant) -> Result<Value, AppError>,
{
    let operation = HostRunOnceOperation::parse(operation)?;
    let input = parse_host_run_once_input(bytes)?;
    let envelope = build_host_run_once_envelope(operation, input)?;
    let deadline_ms = envelope
        .deadline_ms
        .ok_or_else(|| AppError::new("invalid_deadline"))?;
    let request_deadline_at = request_started_at
        .checked_add(std::time::Duration::from_millis(deadline_ms))
        .ok_or_else(|| AppError::new("deadline_exceeded"))?;
    ensure_request_deadline(request_deadline_at)?;
    dispatch(envelope, request_deadline_at)
}

fn broker_credential_for(
    server_id: HostRunOnceServerId,
    purpose: BrokerCredentialPurpose,
    deadline: Instant,
) -> Result<ZeroizingSecret, AppError> {
    let server = match server_id {
        HostRunOnceServerId::Eec => BrokerServer::Eec,
        HostRunOnceServerId::Hetzner => BrokerServer::Hetzner,
    };
    let client = BrokerClient::fixed();
    #[cfg(unix)]
    {
        let mut transport = client.connect(deadline).map_err(map_broker_error)?;
        client
            .request(&mut transport, BrokerRequest { server, purpose }, deadline)
            .map_err(map_broker_error)
    }
    #[cfg(not(unix))]
    {
        let _ = (client, server, purpose, deadline);
        Err(AppError::new("credential_broker_unavailable"))
    }
}

fn run_host_bridge_once(
    bundle: &fwc_n8n_bundle::VerifiedBundle,
    envelope: &HostRunOnceEnvelope,
    purpose: BrokerCredentialPurpose,
    deadline: Instant,
) -> Result<Value, AppError> {
    let credential = broker_credential_for(envelope.server_id, purpose, deadline)?;
    let mut envelope = envelope.clone();
    envelope.deadline_ms = Some(remaining_deadline_ms(deadline)?);
    fwc_n8n_bridge::run_verified_host_bridge(bundle, &envelope, credential, deadline).map_err(
        |error| {
            let lifecycle = matches!(purpose, BrokerCredentialPurpose::OfficialMcp)
                && matches!(
                    envelope.operation,
                    HostRunOnceOperation::WorkflowsLifecycle
                        | HostRunOnceOperation::WorkflowsArchive
                        | HostRunOnceOperation::WorkflowsExecute
                );
            let code = if lifecycle {
                official_mcp_workflow_bridge_error_code(error.code())
            } else {
                error.code()
            };
            let diagnostic = (lifecycle && code == "unknown_outcome")
                .then(|| error.diagnostic())
                .flatten();
            AppError::with_diagnostic(code, diagnostic)
        },
    )
}

fn official_mcp_workflow_bridge_error_code(code: &str) -> &'static str {
    match code {
        "host_connector_not_found" => "official_mcp_connector_not_found",
        "host_preflight_denied" => "official_mcp_preflight_denied",
        "host_connector_unavailable" => "official_mcp_connector_unavailable",
        "host_connector_frame_limit" => "official_mcp_connector_frame_limit",
        "host_n8n_input_failed" => "official_mcp_input_failed",
        "host_n8n_config_failed" => "official_mcp_config_failed",
        "host_n8n_plan_failed" => "official_mcp_plan_failed",
        "host_n8n_credential_failed" => "official_mcp_credential_failed",
        "host_n8n_policy_failed" => "official_mcp_policy_failed",
        "host_n8n_runtime_state_failed" => "official_mcp_runtime_state_failed",
        "host_n8n_manifest_failed" => "official_mcp_manifest_failed",
        "host_n8n_capability_failed" => "official_mcp_capability_failed",
        // The child may have reached the provider, or may have failed while
        // decoding/transporting its result. Keep these fail-closed and
        // indistinguishable from an unknown side-effect outcome.
        _ => "unknown_outcome",
    }
}

fn lifecycle_get_envelope(envelope: &HostRunOnceEnvelope) -> Result<HostRunOnceEnvelope, AppError> {
    let id = envelope
        .input
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let mut get = envelope.clone();
    get.operation = HostRunOnceOperation::WorkflowsGet;
    get.approval_token = None;
    get.resource_uri = expected_host_run_once_resource_uri(
        envelope.server_id,
        HostRunOnceOperation::WorkflowsGet,
        &json!({"id": id}),
    )?;
    get.input = json!({"id": id});
    Ok(get)
}

fn response_result(response: Value, unknown_code: &'static str) -> Result<Value, AppError> {
    if response.get("status").and_then(Value::as_str) != Some("ok")
        || response.get("error").is_some_and(|error| !error.is_null())
    {
        return Err(AppError::new(unknown_code));
    }
    response
        .get("result")
        .cloned()
        .filter(Value::is_object)
        .ok_or_else(|| AppError::new(unknown_code))
}

fn verify_lifecycle_baseline(input: &Value, state: &Value) -> Result<(), AppError> {
    let id = input
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let precondition = input
        .pointer("/guard/precondition")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if state.get("id").and_then(Value::as_str) != Some(id)
        || state.get("versionId") != precondition.get("versionId")
        || state.get("activeVersionId").is_none()
        || state.get("activeVersionId") != precondition.get("activeVersionId")
        || state.get("active") != precondition.get("active")
        || state.get("isArchived") != precondition.get("isArchived")
        || state.get("stateDigest") != precondition.get("stateDigest")
    {
        return Err(AppError::new("stale_precondition"));
    }
    Ok(())
}

fn decode_official_mcp_lifecycle_result(
    response: Value,
    action: &str,
    workflow_id: &str,
) -> Result<Value, AppError> {
    let mut result = response_result(response, "unknown_outcome")?;
    if let Some(structured) = result.get("structuredContent").cloned() {
        result = structured;
    } else if let Some(content) = result.get("content").and_then(Value::as_array) {
        let text = content.iter().find_map(|item| {
            (item.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| item.get("text").and_then(Value::as_str))
                .flatten()
        });
        let text = text.ok_or_else(|| AppError::new("unknown_outcome"))?;
        result = serde_json::from_str(text).map_err(|_| AppError::new("unknown_outcome"))?;
    }
    let object = result
        .as_object()
        .ok_or_else(|| AppError::new("unknown_outcome"))?;
    if !matches!(action, "publish" | "unpublish") {
        return Err(AppError::new("unknown_outcome"));
    }
    if let Some(result_action) = object.get("action") {
        if result_action.as_str() != Some(action) {
            return Err(AppError::new("unknown_outcome"));
        }
    }
    if object.get("success").and_then(Value::as_bool) != Some(true)
        || object.get("workflowId").and_then(Value::as_str) != Some(workflow_id)
    {
        return Err(AppError::new("unknown_outcome"));
    }
    if object.get("error").is_some_and(|error| !error.is_null()) {
        return Err(AppError::new("unknown_outcome"));
    }
    let active_version_id = object.get("activeVersionId");
    if active_version_id
        .is_some_and(|value| !value.is_null() && value.as_str().is_none_or(str::is_empty))
    {
        return Err(AppError::new("unknown_outcome"));
    }
    if action == "unpublish" && active_version_id.is_some_and(|value| !value.is_null()) {
        return Err(AppError::new("unknown_outcome"));
    }
    let mut safe = serde_json::Map::new();
    safe.insert("action".to_string(), Value::String(action.to_string()));
    safe.insert("success".to_string(), Value::Bool(true));
    safe.insert(
        "workflowId".to_string(),
        Value::String(workflow_id.to_string()),
    );
    if let Some(active_version_id) = active_version_id {
        safe.insert("activeVersionId".to_string(), active_version_id.clone());
    }
    Ok(Value::Object(safe))
}

fn decode_official_mcp_archive_result(
    response: Value,
    workflow_id: &str,
) -> Result<Value, AppError> {
    let mut result = response_result(response, "unknown_outcome")?;
    if let Some(structured) = result.get("structuredContent").cloned() {
        result = structured;
    } else if let Some(content) = result.get("content").and_then(Value::as_array) {
        let text = content.iter().find_map(|item| {
            (item.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| item.get("text").and_then(Value::as_str))
                .flatten()
        });
        let text = text.ok_or_else(|| AppError::new("unknown_outcome"))?;
        result = serde_json::from_str(text).map_err(|_| AppError::new("unknown_outcome"))?;
    }
    let object = result
        .as_object()
        .ok_or_else(|| AppError::new("unknown_outcome"))?;
    if object.get("archived").and_then(Value::as_bool) != Some(true)
        || object.get("workflowId").and_then(Value::as_str) != Some(workflow_id)
        || object
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(AppError::new("unknown_outcome"));
    }
    Ok(json!({"archived": true, "workflowId": workflow_id}))
}

fn is_lifecycle_blake3_digest(value: &str) -> bool {
    value.len() == 75
        && value.starts_with("blake3-256:")
        && value[11..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_lifecycle_graph_summary(value: &Value, nullable: bool) -> Result<(), AppError> {
    if nullable && value.is_null() {
        return Ok(());
    }
    let object = value
        .as_object()
        .ok_or_else(|| AppError::new("unknown_outcome"))?;
    if object.len() != 2
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "versionId" | "graphDigest"))
        || object
            .get("versionId")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || !object
            .get("graphDigest")
            .and_then(Value::as_str)
            .is_some_and(is_lifecycle_blake3_digest)
    {
        return Err(AppError::new("unknown_outcome"));
    }
    Ok(())
}

fn validate_lifecycle_state_summary(state: &Value) -> Result<(), AppError> {
    let object = state
        .as_object()
        .ok_or_else(|| AppError::new("readback_mismatch"))?;
    if object
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || object
            .get("versionId")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object.get("active").and_then(Value::as_bool).is_none()
        || !object.contains_key("activeVersionId")
        || object
            .get("activeVersionId")
            .is_some_and(|value| !value.is_null() && value.as_str().is_none_or(str::is_empty))
        || object.get("isArchived").and_then(Value::as_bool).is_none()
        || !object
            .get("stateDigest")
            .and_then(Value::as_str)
            .is_some_and(is_lifecycle_blake3_digest)
    {
        return Err(AppError::new("readback_mismatch"));
    }
    validate_lifecycle_graph_summary(
        object
            .get("draft")
            .ok_or_else(|| AppError::new("readback_mismatch"))?,
        false,
    )
    .map_err(|_| AppError::new("readback_mismatch"))?;
    validate_lifecycle_graph_summary(
        object
            .get("published")
            .ok_or_else(|| AppError::new("readback_mismatch"))?,
        true,
    )
    .map_err(|_| AppError::new("readback_mismatch"))
}

fn verify_lifecycle_readback(
    input: &Value,
    baseline: &Value,
    provider: &Value,
    readback: &Value,
) -> Result<String, AppError> {
    let action = input
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    validate_lifecycle_state_summary(baseline)?;
    validate_lifecycle_state_summary(readback)?;
    if baseline.get("id") != readback.get("id")
        || baseline.get("versionId") != readback.get("versionId")
    {
        return Err(AppError::new("readback_mismatch"));
    }
    if baseline.get("draft") != readback.get("draft") {
        return Err(AppError::new("readback_mismatch"));
    }
    let expected_version = if action == "publish" {
        input
            .get("versionId")
            .and_then(Value::as_str)
            .or_else(|| provider.get("activeVersionId").and_then(Value::as_str))
            .or_else(|| readback.get("activeVersionId").and_then(Value::as_str))
            .ok_or_else(|| AppError::new("unknown_outcome"))?
    } else {
        ""
    };
    if action == "publish" {
        if provider
            .get("activeVersionId")
            .and_then(Value::as_str)
            .is_some_and(|provider_version| provider_version != expected_version)
        {
            return Err(AppError::new("unknown_outcome"));
        }
    } else if action == "unpublish" {
        if provider
            .get("activeVersionId")
            .is_some_and(|active_version_id| !active_version_id.is_null())
        {
            return Err(AppError::new("unknown_outcome"));
        }
    } else {
        return Err(AppError::new("invalid_operation_input"));
    }
    if action == "publish" {
        if readback.get("active").and_then(Value::as_bool) != Some(true)
            || readback.get("isArchived").and_then(Value::as_bool) != Some(false)
            || readback.get("activeVersionId").and_then(Value::as_str) != Some(expected_version)
            || readback
                .pointer("/published/versionId")
                .and_then(Value::as_str)
                != Some(expected_version)
            || readback
                .pointer("/published/graphDigest")
                .and_then(Value::as_str)
                .is_none_or(|digest| !is_lifecycle_blake3_digest(digest))
        {
            return Err(AppError::new("readback_mismatch"));
        }
    } else if readback.get("active").and_then(Value::as_bool) != Some(false)
        || !readback.get("activeVersionId").is_some_and(Value::is_null)
        || readback.get("isArchived") != baseline.get("isArchived")
        || !readback.get("published").is_some_and(Value::is_null)
    {
        return Err(AppError::new("readback_mismatch"));
    }
    Ok(expected_version.to_string())
}

fn execute_workflow_lifecycle_official_mcp(
    bundle: &fwc_n8n_bundle::VerifiedBundle,
    envelope: HostRunOnceEnvelope,
    request_deadline_at: Instant,
) -> Result<Value, AppError> {
    let get = lifecycle_get_envelope(&envelope)?;
    let baseline_response = run_host_bridge_once(
        bundle,
        &get,
        BrokerCredentialPurpose::RestApi,
        request_deadline_at,
    )?;
    let baseline = response_result(baseline_response, "unknown_outcome")?;
    verify_lifecycle_baseline(&envelope.input, &baseline)?;

    let provider_response = run_host_bridge_once(
        bundle,
        &envelope,
        BrokerCredentialPurpose::OfficialMcp,
        request_deadline_at,
    )?;
    let workflow_id = envelope
        .input
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let action = envelope
        .input
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let provider = decode_official_mcp_lifecycle_result(provider_response, action, workflow_id)?;

    let readback_response = run_host_bridge_once(
        bundle,
        &get,
        BrokerCredentialPurpose::RestApi,
        request_deadline_at,
    )?;
    let readback = response_result(readback_response, "unknown_outcome")?;
    let _ = verify_lifecycle_readback(&envelope.input, &baseline, &provider, &readback)?;
    Ok(json!({
        "status": "verified",
        "operation": "n8n.workflows.lifecycle",
        "action": action,
        "provider": "official_mcp",
        "retry": "never_automatic",
        "readback": "independent_get",
        "before": baseline,
        "after": readback,
    }))
}

fn execute_workflow_archive_official_mcp(
    bundle: &fwc_n8n_bundle::VerifiedBundle,
    envelope: HostRunOnceEnvelope,
    request_deadline_at: Instant,
) -> Result<Value, AppError> {
    let get = lifecycle_get_envelope(&envelope)?;
    let baseline_response = run_host_bridge_once(
        bundle,
        &get,
        BrokerCredentialPurpose::RestApi,
        request_deadline_at,
    )?;
    let baseline = response_result(baseline_response, "unknown_outcome")?;
    verify_lifecycle_baseline(&envelope.input, &baseline)?;

    let provider_response = run_host_bridge_once(
        bundle,
        &envelope,
        BrokerCredentialPurpose::OfficialMcp,
        request_deadline_at,
    )?;
    let workflow_id = envelope
        .input
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let provider = decode_official_mcp_archive_result(provider_response, workflow_id)?;
    let readback_response = run_host_bridge_once(
        bundle,
        &get,
        BrokerCredentialPurpose::RestApi,
        request_deadline_at,
    )?;
    let readback = response_result(readback_response, "unknown_outcome")?;
    validate_lifecycle_state_summary(&readback)?;
    if baseline.get("id") != readback.get("id")
        || baseline.get("versionId") != readback.get("versionId")
        || baseline.get("draft") != readback.get("draft")
        || baseline.get("published") != readback.get("published")
        || readback.get("active") != Some(&Value::Bool(false))
        || !readback.get("activeVersionId").is_some_and(Value::is_null)
        || readback.get("isArchived") != Some(&Value::Bool(true))
    {
        return Err(AppError::new("readback_mismatch"));
    }
    Ok(json!({
        "status": "verified",
        "operation": "n8n.workflows.archive",
        "provider": "official_mcp",
        "retry": "never_automatic",
        "readback": "independent_get",
        "before": baseline,
        "after": readback,
        "providerResult": provider,
    }))
}

fn decode_official_mcp_execute_result(
    response: Value,
    workflow_id: &str,
) -> Result<Value, AppError> {
    let mut result = response_result(response, "unknown_outcome")?;
    if let Some(structured) = result.get("structuredContent").cloned() {
        result = structured;
    } else if let Some(content) = result.get("content").and_then(Value::as_array) {
        let text = content
            .iter()
            .find_map(|item| {
                (item.get("type").and_then(Value::as_str) == Some("text"))
                    .then(|| item.get("text").and_then(Value::as_str))
                    .flatten()
            })
            .ok_or_else(|| AppError::new("unknown_outcome"))?;
        result = serde_json::from_str(text).map_err(|_| AppError::new("unknown_outcome"))?;
    }
    let object = result
        .as_object()
        .ok_or_else(|| AppError::new("unknown_outcome"))?;
    if object.get("success").and_then(Value::as_bool) != Some(true)
        || object.get("workflowId").and_then(Value::as_str) != Some(workflow_id)
        || object
            .get("executionId")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object.get("error").is_some_and(|value| !value.is_null())
    {
        return Err(AppError::new("unknown_outcome"));
    }
    let execution_id = object
        .get("executionId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if execution_id.len() > 256 || execution_id.chars().any(char::is_control) {
        return Err(AppError::new("unknown_outcome"));
    }
    let initial_status = object
        .get("initialStatus")
        .or_else(|| object.get("status"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("unknown_outcome"))?;
    if initial_status.len() > 64
        || initial_status.chars().any(char::is_control)
        || !matches!(
            initial_status,
            "accepted"
                | "new"
                | "running"
                | "success"
                | "error"
                | "waiting"
                | "canceled"
                | "crashed"
        )
    {
        return Err(AppError::new("unknown_outcome"));
    }
    Ok(json!({
        "success": true,
        "workflowId": workflow_id,
        "executionId": execution_id,
        "initialStatus": initial_status,
    }))
}

fn executions_get_envelope(
    envelope: &HostRunOnceEnvelope,
    workflow_id: &str,
    execution_id: &str,
) -> Result<HostRunOnceEnvelope, AppError> {
    let mut get = envelope.clone();
    get.operation = HostRunOnceOperation::ExecutionsGet;
    get.approval_token = None;
    get.input = json!({"workflow_id": workflow_id, "id": execution_id});
    get.resource_uri = expected_host_run_once_resource_uri(
        envelope.server_id,
        HostRunOnceOperation::ExecutionsGet,
        &get.input,
    )?;
    Ok(get)
}

fn verify_execution_readback(
    input: &Value,
    execution_id: &str,
    readback: &Value,
) -> Result<(), AppError> {
    let workflow_id = input
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let mode = input
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let version_id = input
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if readback.get("id").and_then(Value::as_str) != Some(execution_id)
        || readback.get("workflowId").and_then(Value::as_str) != Some(workflow_id)
        || readback.get("mode").and_then(Value::as_str) != Some(mode)
        || readback.get("workflowVersionId").and_then(Value::as_str) != Some(version_id)
    {
        return Err(AppError::new("readback_mismatch"));
    }
    let status = readback
        .get("status")
        .and_then(Value::as_str)
        .filter(|status| {
            !status.is_empty()
                && status.len() <= 64
                && matches!(
                    *status,
                    "new" | "running" | "success" | "error" | "waiting" | "canceled" | "crashed"
                )
        })
        .ok_or_else(|| AppError::new("readback_mismatch"))?;
    if status.chars().any(char::is_control) {
        return Err(AppError::new("readback_mismatch"));
    }
    Ok(())
}

fn terminal_execute_readback<T>(result: Result<T, AppError>) -> Result<T, AppError> {
    result.map_err(|_| AppError::new("unknown_outcome"))
}

fn execute_workflow_execute_official_mcp(
    bundle: &fwc_n8n_bundle::VerifiedBundle,
    envelope: HostRunOnceEnvelope,
    request_deadline_at: Instant,
) -> Result<Value, AppError> {
    let get = lifecycle_get_envelope(&envelope)?;
    let baseline_response = run_host_bridge_once(
        bundle,
        &get,
        BrokerCredentialPurpose::RestApi,
        request_deadline_at,
    )?;
    let baseline = response_result(baseline_response, "unknown_outcome")?;
    verify_lifecycle_baseline(&envelope.input, &baseline)?;
    let provider_response = run_host_bridge_once(
        bundle,
        &envelope,
        BrokerCredentialPurpose::OfficialMcp,
        request_deadline_at,
    )?;
    let workflow_id = envelope
        .input
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let provider = decode_official_mcp_execute_result(provider_response, workflow_id)?;
    let execution_id = provider
        .get("executionId")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("unknown_outcome"))?;
    let execution_get = terminal_execute_readback(executions_get_envelope(
        &envelope,
        workflow_id,
        execution_id,
    ))?;
    let readback_response = terminal_execute_readback(run_host_bridge_once(
        bundle,
        &execution_get,
        BrokerCredentialPurpose::RestApi,
        request_deadline_at,
    ))?;
    let readback =
        terminal_execute_readback(response_result(readback_response, "unknown_outcome"))?;
    terminal_execute_readback(verify_execution_readback(
        &envelope.input,
        execution_id,
        &readback,
    ))?;
    let mode = envelope
        .input
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let version_id = envelope
        .input
        .get("versionId")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(json!({
        "status": "submitted",
        "operation": "n8n.workflows.execute",
        "provider": "official_mcp",
        "workflowId": provider.get("workflowId").cloned().unwrap_or(Value::Null),
        "mode": mode,
        "versionId": version_id,
        "executionId": provider.get("executionId").cloned().unwrap_or(Value::Null),
        "initialStatus": provider.get("initialStatus").cloned().unwrap_or(Value::Null),
        "retry": "never_automatic",
        "readback": "independent_execution_get",
    }))
}

fn execute_host_run_once(
    mut envelope: HostRunOnceEnvelope,
    request_deadline_at: Instant,
) -> Result<Value, AppError> {
    let bundle = fwc_n8n_bundle::verify_current_release_bundle_for_bridge()
        .map_err(|_| AppError::new("bundle_unavailable"))?;
    ensure_request_deadline(request_deadline_at)?;

    let operation = envelope.operation;
    let server_id = envelope.server_id;
    if operation == HostRunOnceOperation::WorkflowsLifecycle {
        return execute_workflow_lifecycle_official_mcp(&bundle, envelope, request_deadline_at);
    }
    if operation == HostRunOnceOperation::WorkflowsArchive {
        return execute_workflow_archive_official_mcp(&bundle, envelope, request_deadline_at);
    }
    if operation == HostRunOnceOperation::WorkflowsExecute {
        return execute_workflow_execute_official_mcp(&bundle, envelope, request_deadline_at);
    }
    let mut reconciliation_ledger = if operation == HostRunOnceOperation::McpAccessReconcile {
        Some(
            fwc_n8n_update_host::McpAccessReconciliationLedger::production()
                .map_err(|error| AppError::new(error.code()))?,
        )
    } else {
        None
    };
    let reconciliation_binding = if operation == HostRunOnceOperation::McpAccessReconcile {
        fwc_n8n_update_host::derive_mcp_access_binding(
            operation.as_str(),
            server_id.as_str(),
            &envelope.input,
        )
        .map_err(|error| AppError::new(error.code()))?
    } else {
        None
    };
    let reconciliation_expectation = if operation == HostRunOnceOperation::McpAccessReconcile {
        Some(
            fwc_n8n_update_host::derive_mcp_access_receipt_expectation(
                server_id.as_str(),
                &envelope.input,
            )
            .map_err(|error| AppError::new(error.code()))?,
        )
    } else {
        None
    };
    let mut dispatch_provider = || -> Result<Value, AppError> {
        let server = match envelope.server_id {
            HostRunOnceServerId::Eec => BrokerServer::Eec,
            HostRunOnceServerId::Hetzner => BrokerServer::Hetzner,
        };
        let credential_purpose = envelope.operation.credential_purpose();
        let client = BrokerClient::fixed();
        #[cfg(unix)]
        let credential = {
            let mut transport = client
                .connect(request_deadline_at)
                .map_err(map_broker_error)?;
            client
                .request(
                    &mut transport,
                    BrokerRequest {
                        server,
                        purpose: credential_purpose,
                    },
                    request_deadline_at,
                )
                .map_err(map_broker_error)?
        };
        #[cfg(not(unix))]
        let credential = {
            let _ = (client, server);
            return Err(AppError::new("credential_broker_unavailable"));
        };

        envelope.deadline_ms = Some(remaining_deadline_ms(request_deadline_at)?);
        let response = fwc_n8n_bridge::run_verified_host_bridge(
            &bundle,
            &envelope,
            credential,
            request_deadline_at,
        )
        .map_err(|error| AppError::new(error.code()))?;
        normalize_host_run_once_response(operation, server_id, response)
    };

    if operation == HostRunOnceOperation::McpAccessReconcile {
        let ledger = reconciliation_ledger
            .as_mut()
            .ok_or_else(|| AppError::new("mcp_access_ledger_unavailable"))?;
        let binding = reconciliation_binding
            .as_ref()
            .ok_or_else(|| AppError::new("mcp_access_binding_missing"))?;
        let expectation = reconciliation_expectation
            .as_ref()
            .ok_or_else(|| AppError::new("mcp_access_binding_missing"))?;
        dispatch_mcp_access_once(ledger, binding, expectation, dispatch_provider)
    } else {
        dispatch_provider()
    }
}

trait McpAccessLedgerPort {
    fn begin_for_request(
        &mut self,
        binding: &fwc_n8n_update_host::McpAccessLedgerBinding,
        expectation: &fwc_n8n_update_host::McpAccessReceiptExpectation,
    ) -> Result<fwc_n8n_update_host::McpAccessLedgerBegin, fwc_n8n_update_host::McpAccessLedgerError>;

    fn commit_for_request(
        &mut self,
        binding: &fwc_n8n_update_host::McpAccessLedgerBinding,
        receipt: &Value,
        expectation: &fwc_n8n_update_host::McpAccessReceiptExpectation,
    ) -> Result<(), fwc_n8n_update_host::McpAccessLedgerError>;
}

impl McpAccessLedgerPort for fwc_n8n_update_host::McpAccessReconciliationLedger {
    fn begin_for_request(
        &mut self,
        binding: &fwc_n8n_update_host::McpAccessLedgerBinding,
        expectation: &fwc_n8n_update_host::McpAccessReceiptExpectation,
    ) -> Result<fwc_n8n_update_host::McpAccessLedgerBegin, fwc_n8n_update_host::McpAccessLedgerError>
    {
        fwc_n8n_update_host::McpAccessReconciliationLedger::begin_for_request(
            self,
            binding,
            Some(expectation),
        )
    }

    fn commit_for_request(
        &mut self,
        binding: &fwc_n8n_update_host::McpAccessLedgerBinding,
        receipt: &Value,
        expectation: &fwc_n8n_update_host::McpAccessReceiptExpectation,
    ) -> Result<(), fwc_n8n_update_host::McpAccessLedgerError> {
        fwc_n8n_update_host::McpAccessReconciliationLedger::commit_for_request(
            self,
            binding,
            receipt,
            Some(expectation),
        )
    }
}

fn dispatch_mcp_access_once<L, F>(
    ledger: &mut L,
    binding: &fwc_n8n_update_host::McpAccessLedgerBinding,
    expectation: &fwc_n8n_update_host::McpAccessReceiptExpectation,
    provider_attempt: F,
) -> Result<Value, AppError>
where
    L: McpAccessLedgerPort,
    F: FnOnce() -> Result<Value, AppError>,
{
    match ledger
        .begin_for_request(binding, expectation)
        .map_err(|error| AppError::new(error.code()))?
    {
        fwc_n8n_update_host::McpAccessLedgerBegin::Claimed => {}
        fwc_n8n_update_host::McpAccessLedgerBegin::Replayed(receipt) => {
            return Ok(replay_mcp_access_response(receipt));
        }
    }
    let response = provider_attempt()?;
    let receipt = response
        .get("result")
        .and_then(Value::as_object)
        .and_then(|result| result.get("receipt"))
        .cloned()
        .ok_or_else(|| AppError::new("mcp_access_receipt_missing"))?;
    ledger
        .commit_for_request(binding, &receipt, expectation)
        .map_err(|error| AppError::new(error.code()))?;
    Ok(response)
}

fn replay_mcp_access_response(receipt: Value) -> Value {
    let readback_digest = receipt
        .get("readbackDigest")
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "status": "ok",
        "result": {
            "planned": [],
            "changed": [],
            "skipped": [],
            "exceptions": [],
            "readbackDigest": readback_digest,
            "receipt": receipt,
        }
    })
}

fn normalize_host_run_once_response(
    operation: HostRunOnceOperation,
    server_id: HostRunOnceServerId,
    mut response: Value,
) -> Result<Value, AppError> {
    if operation != HostRunOnceOperation::CapabilitiesInspect
        || response.get("status").and_then(Value::as_str) != Some("ok")
    {
        return Ok(response);
    }

    let result = response
        .get_mut("result")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| AppError::new("official_mcp_response_invalid"))?;
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::new("official_mcp_response_invalid"))?;
    if tools.len() > 256 {
        return Err(AppError::new("official_mcp_response_invalid"));
    }

    let mut names = BTreeSet::new();
    let mut compact = Vec::with_capacity(tools.len());
    for tool in tools {
        let tool = tool
            .as_object()
            .ok_or_else(|| AppError::new("official_mcp_response_invalid"))?;
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| valid_capability_tool_name(name))
            .ok_or_else(|| AppError::new("official_mcp_response_invalid"))?;
        if !names.insert(name.to_owned()) {
            return Err(AppError::new("official_mcp_response_invalid"));
        }
        if tool
            .get("injection_findings")
            .and_then(Value::as_array)
            .is_none_or(|findings| !findings.is_empty())
        {
            return Err(AppError::new("official_mcp_catalog_blocked"));
        }
        let input_schema = tool.get("inputSchema").unwrap_or(&Value::Null);
        let output_schema = tool.get("outputSchema").unwrap_or(&Value::Null);
        if (!input_schema.is_null() && !input_schema.is_object())
            || (!output_schema.is_null() && !output_schema.is_object())
        {
            return Err(AppError::new("official_mcp_response_invalid"));
        }
        compact.push(json!({
            "name": name,
            "inputSchemaDigest": digest_capability_schema(input_schema)?,
            "outputSchemaDigest": digest_capability_schema(output_schema)?,
            "class": "unknown",
            "status": "unreviewed",
        }));
    }
    compact.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });

    *result = serde_json::Map::from_iter([(
        "capabilities".to_owned(),
        json!({
            "schema": "fwc.n8n.capabilities.v1",
            "serverId": server_id.as_str(),
            "provider": "official_mcp",
            "toolCount": compact.len(),
            "tools": compact,
        }),
    )]);
    Ok(response)
}

fn valid_capability_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn digest_capability_schema(value: &Value) -> Result<String, AppError> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut ordered = BTreeMap::new();
                for (key, value) in map {
                    ordered.insert(key.clone(), canonical(value));
                }
                Value::Object(ordered.into_iter().collect())
            }
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }

    let bytes = serde_json::to_vec(&canonical(value))
        .map_err(|_| AppError::new("official_mcp_response_invalid"))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn ensure_request_deadline(deadline: Instant) -> Result<(), AppError> {
    if Instant::now() >= deadline {
        Err(AppError::new("deadline_exceeded"))
    } else {
        Ok(())
    }
}

fn remaining_deadline_ms(deadline: Instant) -> Result<u64, AppError> {
    ensure_request_deadline(deadline)?;
    u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
    .ok()
    .filter(|milliseconds| *milliseconds > 0)
    .ok_or_else(|| AppError::new("deadline_exceeded"))
}

fn map_broker_error(error: fcp_n8n_broker_protocol::BrokerError) -> AppError {
    let code = match error.code() {
        "deadline_exceeded" => "deadline_exceeded",
        "socket_rejected" => "credential_broker_rejected",
        "backend_unavailable" => "credential_broker_unavailable",
        "backend_failed" => "credential_backend_failed",
        "empty_secret" => "credential_empty",
        "oversized_secret" => "credential_oversized",
        "invalid_secret" => "credential_invalid",
        "invalid_request" | "request_oversized" => "credential_broker_protocol_failed",
        "response_invalid" | "response_oversized" => "credential_broker_response_invalid",
        _ => "credential_broker_io_failed",
    };
    AppError::new(code)
}

fn parse_host_run_once_input(bytes: &[u8]) -> Result<HostRunOnceInput, AppError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(AppError::new("input_too_large"));
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(AppError::new("input_empty"));
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let input = HostRunOnceInput::deserialize(&mut deserializer)
        .map_err(|_| AppError::new("invalid_input"))?;
    deserializer
        .end()
        .map_err(|_| AppError::new("trailing_input"))?;
    Ok(input)
}

fn build_host_run_once_envelope(
    operation: HostRunOnceOperation,
    input: HostRunOnceInput,
) -> Result<HostRunOnceEnvelope, AppError> {
    validate_host_run_once_input(operation, &input.input)?;
    let resource_uri =
        expected_host_run_once_resource_uri(input.server_id, operation, &input.input)?;
    if input
        .deadline_ms
        .is_some_and(|deadline| deadline == 0 || deadline > HOST_RUN_ONCE_MAX_DEADLINE_MS)
    {
        return Err(AppError::new("invalid_deadline"));
    }
    if input
        .correlation_id
        .as_deref()
        .is_some_and(|correlation_id| Uuid::parse_str(correlation_id).is_err())
    {
        return Err(AppError::new("invalid_correlation_id"));
    }

    Ok(HostRunOnceEnvelope {
        schema: HOST_RUN_ONCE_SCHEMA,
        server_id: input.server_id,
        operation,
        zone_id: HOST_RUN_ONCE_ZONE,
        resource_uri,
        input: input.input,
        approval_token: input.approval_token,
        deadline_ms: Some(
            input
                .deadline_ms
                .unwrap_or(HOST_RUN_ONCE_DEFAULT_DEADLINE_MS),
        ),
        correlation_id: input.correlation_id,
    })
}

fn validate_host_run_once_input(
    operation: HostRunOnceOperation,
    input: &Value,
) -> Result<(), AppError> {
    let object = input
        .as_object()
        .ok_or_else(|| AppError::new("input_object_required"))?;
    let (allowed, required): (&[&str], &[&str]) = match operation {
        HostRunOnceOperation::CapabilitiesInspect => (&[], &[]),
        HostRunOnceOperation::CredentialsList
        | HostRunOnceOperation::ExecutionsList
        | HostRunOnceOperation::ProjectsList
        | HostRunOnceOperation::TagsList
        | HostRunOnceOperation::WorkflowsList => (&["cursor", "limit"], &[]),
        HostRunOnceOperation::ExecutionsGet => (&["id", "workflow_id"], &["id", "workflow_id"]),
        HostRunOnceOperation::FoldersGet => {
            (&["folder_id", "project_id"], &["folder_id", "project_id"])
        }
        HostRunOnceOperation::FoldersList => (
            &["parent_folder_id", "project_id", "skip", "take"],
            &["project_id"],
        ),
        HostRunOnceOperation::WorkflowsGet => (&["id"], &["id"]),
        HostRunOnceOperation::WorkflowsCreateDraft => (
            &["name", "project_id", "parent_folder_id", "graph", "guard"],
            &["name", "graph", "guard"],
        ),
        HostRunOnceOperation::WorkflowsUpdateDraft => (
            &[
                "id",
                "name",
                "project_id",
                "parent_folder_id",
                "graph",
                "guard",
            ],
            &["id", "graph", "guard"],
        ),
        HostRunOnceOperation::WorkflowsLifecycle => (
            &["id", "action", "versionId", "guard"],
            &["id", "action", "guard"],
        ),
        HostRunOnceOperation::WorkflowsArchive => (&["id", "guard"], &["id", "guard"]),
        HostRunOnceOperation::WorkflowsExecute => (
            &["id", "mode", "versionId", "inputs", "guard"],
            &["id", "mode", "versionId", "guard"],
        ),
        HostRunOnceOperation::WorkflowsDeleteDisposable => (
            &["id", "creationReceipt", "guard"],
            &["id", "creationReceipt", "guard"],
        ),
        HostRunOnceOperation::McpAccessReconcile => (
            &[
                "scope",
                "desired",
                "dryRun",
                "projectId",
                "folderId",
                "workflowIds",
                "guard",
            ],
            &["scope", "desired", "dryRun"],
        ),
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || required.iter().any(|key| !object.contains_key(*key))
    {
        return Err(AppError::new("invalid_operation_input"));
    }

    match operation {
        HostRunOnceOperation::CapabilitiesInspect => Ok(()),
        HostRunOnceOperation::CredentialsList
        | HostRunOnceOperation::ExecutionsList
        | HostRunOnceOperation::ProjectsList
        | HostRunOnceOperation::TagsList
        | HostRunOnceOperation::WorkflowsList => validate_page_input(object),
        HostRunOnceOperation::ExecutionsGet => {
            host_run_once_input_id(input, "id")?;
            host_run_once_input_id(input, "workflow_id")?;
            Ok(())
        }
        HostRunOnceOperation::FoldersGet => {
            host_run_once_input_id(input, "folder_id")?;
            host_run_once_input_id(input, "project_id")?;
            Ok(())
        }
        HostRunOnceOperation::FoldersList => {
            host_run_once_input_id(input, "project_id")?;
            if object.contains_key("parent_folder_id") {
                host_run_once_input_id(input, "parent_folder_id")?;
            }
            validate_bounded_integer(object, "skip", 0, u64::MAX)?;
            validate_bounded_integer(object, "take", 1, 200)
        }
        HostRunOnceOperation::WorkflowsGet => {
            host_run_once_input_id(input, "id")?;
            Ok(())
        }
        HostRunOnceOperation::WorkflowsCreateDraft | HostRunOnceOperation::WorkflowsUpdateDraft => {
            validate_workflow_draft_input(operation, input, object)
        }
        HostRunOnceOperation::WorkflowsLifecycle => validate_workflow_lifecycle_input(object),
        HostRunOnceOperation::WorkflowsArchive => validate_workflow_archive_input(object),
        HostRunOnceOperation::WorkflowsExecute => validate_workflow_execute_input(object),
        HostRunOnceOperation::WorkflowsDeleteDisposable => {
            validate_workflow_delete_disposable_input(object)
        }
        HostRunOnceOperation::McpAccessReconcile => validate_mcp_access_input(input, object),
    }
}

fn validate_workflow_lifecycle_input(
    object: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    host_run_once_input_id(&json!({"id": id}), "id")?;
    if !matches!(
        object.get("action").and_then(Value::as_str),
        Some("publish" | "unpublish")
    ) {
        return Err(AppError::new("invalid_operation_input"));
    }
    if let Some(version_id) = object.get("versionId") {
        if object.get("action").and_then(Value::as_str) == Some("unpublish")
            || version_id
                .as_str()
                .is_none_or(|value| value.is_empty() || value.len() > 256 || value.trim() != value)
        {
            return Err(AppError::new("invalid_operation_input"));
        }
    }
    let guard = object
        .get("guard")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if guard.keys().any(|key| {
        !matches!(
            key.as_str(),
            "approvalRef" | "idempotencyKey" | "precondition"
        )
    }) {
        return Err(AppError::new("invalid_operation_input"));
    }
    let approval_ref = guard
        .get("approvalRef")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256 && value.trim() == *value)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if approval_ref.chars().any(char::is_control)
        || guard
            .get("idempotencyKey")
            .and_then(Value::as_str)
            .is_none_or(|value| uuid::Uuid::parse_str(value).is_err())
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    let precondition = guard
        .get("precondition")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    const REQUIRED: [&str; 5] = [
        "versionId",
        "activeVersionId",
        "active",
        "isArchived",
        "stateDigest",
    ];
    if precondition
        .keys()
        .any(|key| !REQUIRED.contains(&key.as_str()))
        || REQUIRED.iter().any(|key| !precondition.contains_key(*key))
        || precondition
            .get("versionId")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value.len() > 256 || value.trim() != value)
        || precondition
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
        || precondition.get("activeVersionId").is_some_and(|value| {
            value
                .as_str()
                .is_some_and(|id| id.is_empty() || id.len() > 256 || id.trim() != id)
                || !(value.is_null() || value.is_string())
        })
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    Ok(())
}

fn validate_workflow_archive_input(
    object: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "id" | "guard"))
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    host_run_once_input_id(&json!({"id": id}), "id")?;
    let guard = object
        .get("guard")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if guard.keys().any(|key| {
        !matches!(
            key.as_str(),
            "approvalRef" | "idempotencyKey" | "precondition"
        )
    }) {
        return Err(AppError::new("invalid_operation_input"));
    }
    let approval_ref = guard
        .get("approvalRef")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256 && value.trim() == *value)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if approval_ref.chars().any(char::is_control)
        || guard
            .get("idempotencyKey")
            .and_then(Value::as_str)
            .is_none_or(|value| uuid::Uuid::parse_str(value).is_err())
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    let precondition = guard
        .get("precondition")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    const REQUIRED: [&str; 5] = [
        "versionId",
        "activeVersionId",
        "active",
        "isArchived",
        "stateDigest",
    ];
    if precondition
        .keys()
        .any(|key| !REQUIRED.contains(&key.as_str()))
        || REQUIRED.iter().any(|key| !precondition.contains_key(*key))
        || precondition
            .get("versionId")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value.len() > 256 || value.trim() != value)
        || precondition.get("active") != Some(&Value::Bool(false))
        || precondition.get("isArchived") != Some(&Value::Bool(false))
        || !precondition
            .get("activeVersionId")
            .is_some_and(Value::is_null)
        || precondition
            .get("stateDigest")
            .and_then(Value::as_str)
            .is_none_or(|value| !is_blake3_digest(value))
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    Ok(())
}

fn validate_workflow_delete_disposable_input(
    object: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "id" | "creationReceipt" | "guard"))
        || !["id", "creationReceipt", "guard"]
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    let receipt = object
        .get("creationReceipt")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == "blake3-256:".len() + 64
                && value.starts_with("blake3-256:")
                && value["blake3-256:".len()..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let _ = receipt;
    let mut archive_input = object.clone();
    archive_input.remove("creationReceipt");
    validate_workflow_archive_input(&archive_input)
}

fn validate_workflow_execute_input(
    object: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let encoded =
        serde_json::to_vec(object).map_err(|_| AppError::new("invalid_operation_input"))?;
    if encoded.len() > 64 * 1024 {
        return Err(AppError::new("invalid_operation_input"));
    }
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "id" | "mode" | "versionId" | "inputs" | "guard"
        )
    }) {
        return Err(AppError::new("invalid_operation_input"));
    }
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    host_run_once_input_id(&json!({"id": id}), "id")?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "manual" | "production"))
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let version_id = object
        .get("versionId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256 && value.trim() == *value)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let guard = object
        .get("guard")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if guard.keys().any(|key| {
        !matches!(
            key.as_str(),
            "approvalRef" | "idempotencyKey" | "precondition" | "inputClass" | "sideEffectSummary"
        )
    }) {
        return Err(AppError::new("invalid_operation_input"));
    }
    let approval_ref = guard
        .get("approvalRef")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256 && value.trim() == *value)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if approval_ref.chars().any(char::is_control)
        || guard
            .get("idempotencyKey")
            .and_then(Value::as_str)
            .is_none_or(|value| uuid::Uuid::parse_str(value).is_err())
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    let input_class = guard
        .get("inputClass")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "none" | "bounded_json"))
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let side_effect_summary = guard
        .get("sideEffectSummary")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    let inputs = object.get("inputs");
    if (inputs.is_some() && input_class != "bounded_json")
        || (inputs.is_none() && input_class != "none")
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    if let Some(inputs) = inputs {
        let bytes =
            serde_json::to_vec(inputs).map_err(|_| AppError::new("invalid_operation_input"))?;
        if !inputs.is_object() || bytes.len() > 64 * 1024 || !bounded_execute_json(inputs, 0) {
            return Err(AppError::new("invalid_operation_input"));
        }
    }
    let precondition = guard
        .get("precondition")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    const REQUIRED: [&str; 5] = [
        "versionId",
        "activeVersionId",
        "active",
        "isArchived",
        "stateDigest",
    ];
    if precondition
        .keys()
        .any(|key| !REQUIRED.contains(&key.as_str()))
        || REQUIRED.iter().any(|key| !precondition.contains_key(*key))
        || precondition.get("versionId") != Some(&Value::String(version_id.to_owned()))
        || precondition
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
        || precondition.get("activeVersionId").is_some_and(|value| {
            !value.is_null()
                && value.as_str().is_none_or(|value| {
                    value.is_empty() || value.len() > 256 || value.trim() != value
                })
        })
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    if mode == "production"
        && (precondition.get("active") != Some(&Value::Bool(true))
            || precondition.get("isArchived") != Some(&Value::Bool(false))
            || precondition.get("activeVersionId") != Some(&Value::String(version_id.to_owned())))
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    let _ = side_effect_summary;
    Ok(())
}

fn bounded_execute_json(value: &Value, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    match value {
        Value::Object(object) => {
            object.len() <= 64
                && object.iter().all(|(key, value)| {
                    let lowered = key.to_ascii_lowercase();
                    key.len() <= 128
                        && ![
                            "secret",
                            "token",
                            "credential",
                            "header",
                            "authorization",
                            "cookie",
                            "api_key",
                            "apikey",
                            "password",
                            "url",
                            "command",
                            "path",
                            "data",
                        ]
                        .iter()
                        .any(|marker| lowered.contains(marker))
                        && bounded_execute_json(value, depth + 1)
                })
        }
        Value::Array(array) => {
            array.len() <= 128
                && array
                    .iter()
                    .all(|value| bounded_execute_json(value, depth + 1))
        }
        Value::String(value) => value.len() <= 4096 && !value.chars().any(char::is_control),
        _ => true,
    }
}

fn validate_mcp_access_input(
    input: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    const MAX_WORKFLOW_IDS: usize = 1_000;
    let scope = object
        .get("scope")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if !matches!(scope, "workflow_ids" | "project" | "folder" | "all_current")
        || object.get("desired").and_then(Value::as_bool).is_none()
        || object.get("dryRun").and_then(Value::as_bool).is_none()
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    let dry_run = object
        .get("dryRun")
        .and_then(Value::as_bool)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    match (dry_run, object.get("guard")) {
        (false, Some(Value::Object(guard))) => {
            if guard.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "approvalRef" | "dryRunDigest" | "idempotencyKey"
                )
            }) || guard
                .get("approvalRef")
                .and_then(Value::as_str)
                .is_none_or(|value| value.is_empty() || value.len() > 256 || value.trim() != value)
                || guard
                    .get("dryRunDigest")
                    .and_then(Value::as_str)
                    .is_none_or(|value| {
                        value.is_empty() || value.len() > 256 || !is_blake3_digest(value)
                    })
                || guard
                    .get("idempotencyKey")
                    .and_then(Value::as_str)
                    .is_none_or(|value| uuid::Uuid::parse_str(value).is_err())
            {
                return Err(AppError::new("invalid_operation_input"));
            }
        }
        (true, None) => {}
        _ => return Err(AppError::new("invalid_operation_input")),
    }

    match scope {
        "workflow_ids" => {
            let ids = object
                .get("workflowIds")
                .and_then(Value::as_array)
                .filter(|ids| !ids.is_empty() && ids.len() <= MAX_WORKFLOW_IDS)
                .ok_or_else(|| AppError::new("invalid_operation_input"))?;
            let mut unique = std::collections::BTreeSet::new();
            for id in ids {
                let id = id
                    .as_str()
                    .ok_or_else(|| AppError::new("invalid_operation_input"))?;
                host_run_once_input_id(&json!({"id": id}), "id")?;
                if !unique.insert(id) {
                    return Err(AppError::new("invalid_operation_input"));
                }
            }
            if object.contains_key("projectId") || object.contains_key("folderId") {
                return Err(AppError::new("invalid_operation_input"));
            }
        }
        "project" => {
            host_run_once_input_id(input, "projectId")?;
            if object.contains_key("folderId") || object.contains_key("workflowIds") {
                return Err(AppError::new("invalid_operation_input"));
            }
        }
        "folder" => {
            host_run_once_input_id(input, "folderId")?;
            if object.contains_key("projectId") || object.contains_key("workflowIds") {
                return Err(AppError::new("invalid_operation_input"));
            }
        }
        "all_current" => {
            if object.contains_key("projectId")
                || object.contains_key("folderId")
                || object.contains_key("workflowIds")
            {
                return Err(AppError::new("invalid_operation_input"));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn is_blake3_digest(value: &str) -> bool {
    value.len() == "blake3-256:".len() + 64
        && value.starts_with("blake3-256:")
        && value["blake3-256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn validate_workflow_draft_input(
    operation: HostRunOnceOperation,
    input: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    if object.contains_key("project_id") {
        host_run_once_input_id(input, "project_id")?;
    }
    if object.contains_key("parent_folder_id") {
        host_run_once_input_id(input, "parent_folder_id")?;
    }
    let graph = object
        .get("graph")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if graph.keys().any(|key| {
        !matches!(
            key.as_str(),
            "nodes" | "connections" | "settings" | "staticData" | "pinData"
        )
    }) || graph.get("nodes").and_then(Value::as_array).is_none()
        || graph
            .get("connections")
            .and_then(Value::as_object)
            .is_none()
        || graph
            .get("nodes")
            .and_then(Value::as_array)
            .is_some_and(|nodes| nodes.len() > 10_000 || nodes.iter().any(|node| !node.is_object()))
    {
        return Err(AppError::new("invalid_operation_input"));
    }

    let guard = object
        .get("guard")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::new("invalid_operation_input"))?;
    if guard.keys().any(|key| {
        !matches!(
            key.as_str(),
            "approvalRef" | "idempotencyKey" | "precondition"
        )
    }) || guard
        .get("approvalRef")
        .and_then(Value::as_str)
        .is_none_or(|value| value.is_empty() || value.len() > 256 || value.trim() != value)
        || guard
            .get("idempotencyKey")
            .and_then(Value::as_str)
            .is_none_or(|value| uuid::Uuid::parse_str(value).is_err())
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    let empty_precondition = serde_json::Map::new();
    let precondition = guard
        .get("precondition")
        .map(|value| {
            value
                .as_object()
                .ok_or_else(|| AppError::new("invalid_operation_input"))
        })
        .transpose()?
        .unwrap_or(&empty_precondition);
    if precondition.keys().any(|key| {
        !matches!(
            key.as_str(),
            "versionId" | "activeVersionId" | "active" | "isArchived" | "stateDigest"
        )
    }) {
        return Err(AppError::new("invalid_operation_input"));
    }
    if matches!(operation, HostRunOnceOperation::WorkflowsUpdateDraft)
        && ![
            "versionId",
            "activeVersionId",
            "active",
            "isArchived",
            "stateDigest",
        ]
        .iter()
        .all(|field| precondition.contains_key(*field))
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    Ok(())
}

fn validate_page_input(object: &serde_json::Map<String, Value>) -> Result<(), AppError> {
    if let Some(cursor) = object.get("cursor") {
        let cursor = cursor
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 4096)
            .ok_or_else(|| AppError::new("invalid_operation_input"))?;
        if cursor.trim() != cursor || cursor.chars().any(char::is_control) {
            return Err(AppError::new("invalid_operation_input"));
        }
    }
    validate_bounded_integer(object, "limit", 1, 200)
}

fn validate_bounded_integer(
    object: &serde_json::Map<String, Value>,
    field: &str,
    minimum: u64,
    maximum: u64,
) -> Result<(), AppError> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    if value
        .as_u64()
        .is_none_or(|value| value < minimum || value > maximum)
    {
        return Err(AppError::new("invalid_operation_input"));
    }
    Ok(())
}

fn expected_host_run_once_resource_uri(
    server_id: HostRunOnceServerId,
    operation: HostRunOnceOperation,
    input: &Value,
) -> Result<String, AppError> {
    let root = format!("fwc-n8n://{}", server_id.as_str());
    match operation {
        HostRunOnceOperation::CapabilitiesInspect => {
            Ok(format!("fwc-mcp-bridge://{}", server_id.as_str()))
        }
        HostRunOnceOperation::CredentialsList
        | HostRunOnceOperation::ExecutionsList
        | HostRunOnceOperation::ProjectsList
        | HostRunOnceOperation::TagsList
        | HostRunOnceOperation::WorkflowsList
        | HostRunOnceOperation::McpAccessReconcile => Ok(root),
        HostRunOnceOperation::WorkflowsLifecycle => {
            let tool = match input.get("action").and_then(Value::as_str) {
                Some("publish") => "publish_workflow",
                Some("unpublish") => "unpublish_workflow",
                _ => return Err(AppError::new("invalid_operation_input")),
            };
            Ok(format!(
                "fwc-mcp-bridge://{}/tools/{}",
                server_id.as_str(),
                encode_host_resource_segment(tool)
            ))
        }
        HostRunOnceOperation::WorkflowsArchive => Ok(format!(
            "fwc-mcp-bridge://{}/tools/archive%5Fworkflow",
            server_id.as_str()
        )),
        HostRunOnceOperation::WorkflowsExecute => Ok(format!(
            "fwc-mcp-bridge://{}/tools/execute%5Fworkflow",
            server_id.as_str()
        )),
        HostRunOnceOperation::WorkflowsGet
        | HostRunOnceOperation::WorkflowsUpdateDraft
        | HostRunOnceOperation::WorkflowsDeleteDisposable => Ok(format!(
            "{root}/workflows/{}",
            encode_host_resource_segment(host_run_once_input_id(input, "id")?)
        )),
        HostRunOnceOperation::WorkflowsCreateDraft => input
            .get("project_id")
            .map(|_| {
                Ok(format!(
                    "{root}/projects/{}",
                    encode_host_resource_segment(host_run_once_input_id(input, "project_id")?)
                ))
            })
            .unwrap_or(Ok(root)),
        HostRunOnceOperation::ExecutionsGet => Ok(format!(
            "{root}/workflows/{}/executions/{}",
            encode_host_resource_segment(host_run_once_input_id(input, "workflow_id")?),
            encode_host_resource_segment(host_run_once_input_id(input, "id")?)
        )),
        HostRunOnceOperation::FoldersList => Ok(format!(
            "{root}/projects/{}",
            encode_host_resource_segment(host_run_once_input_id(input, "project_id")?)
        )),
        HostRunOnceOperation::FoldersGet => Ok(format!(
            "{root}/folders/{}",
            encode_host_resource_segment(host_run_once_input_id(input, "folder_id")?)
        )),
    }
}

fn host_run_once_input_id<'a>(input: &'a Value, field: &str) -> Result<&'a str, AppError> {
    let value = input
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.trim() == *value && value.len() <= 4096)
        .ok_or_else(|| AppError::new("invalid_resource_id"))?;
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || value.contains('&')
        || value.contains('=')
        || value.contains('%')
        || value.chars().any(char::is_control)
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(AppError::new("invalid_resource_id"));
    }
    Ok(value)
}

fn encode_host_resource_segment(value: &str) -> String {
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

fn public_operation_intent(operation: &str) -> Result<OperationIntent, AppError> {
    let intent = match operation {
        "n8n.capabilities.inspect" => OperationIntent::CapabilitiesInspection,
        "n8n.knowledge.query" => OperationIntent::NodeKnowledge,
        "n8n.validation.run" => OperationIntent::Validation,
        "n8n.workflows.get" | "n8n.executions.get" => OperationIntent::KnownIdRead,
        "n8n.workflows.search" | "n8n.executions.search" | "n8n.structure.search" => {
            OperationIntent::Search
        }
        "n8n.workflows.compare" => OperationIntent::Comparison,
        "n8n.workflows.create_draft" | "n8n.workflows.update_draft" => {
            OperationIntent::WorkflowDraftWrite
        }
        "n8n.workflows.lifecycle" => OperationIntent::Lifecycle,
        "n8n.workflows.execute" => OperationIntent::Execution,
        "n8n.credentials.list" => OperationIntent::CredentialMetadata,
        "n8n.data_tables.search" | "n8n.data_tables.mutate" => OperationIntent::DataTables,
        "n8n.audit.inspect" => OperationIntent::Audit,
        "n8n.workflows.versions" => OperationIntent::VersionHistory,
        "n8n.mcp_access.reconcile" => OperationIntent::McpAccessReconcile,
        _ => return Err(AppError::new("unknown_public_operation")),
    };
    Ok(intent)
}

fn read_stdin_json<T>() -> Result<T, AppError>
where
    T: for<'de> Deserialize<'de>,
{
    let deadline = Instant::now()
        .checked_add(STDIN_READ_TIMEOUT)
        .ok_or_else(|| AppError::new("input_read_timeout"))?;
    let bytes = read_input_until(io::stdin(), deadline)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(AppError::new("input_too_large"));
    }
    serde_json::from_slice(&bytes).map_err(|_| AppError::new("invalid_input"))
}

const fn exact_target(resolution: &TargetResolution) -> Result<&ResolvedTarget, AppError> {
    match resolution {
        TargetResolution::Resolved(target) => Ok(target),
        TargetResolution::Ambiguous { .. } => Err(AppError::new("target_ambiguous")),
    }
}

const fn target_error_code(code: fcp_n8n::router::TargetResolveCode) -> &'static str {
    use fcp_n8n::router::TargetResolveCode as Code;
    match code {
        Code::InvalidServer => "invalid_server",
        Code::InvalidIdentifier => "invalid_identifier",
        Code::InvalidResourceUri => "invalid_resource_uri",
        Code::MissingTargetProof => "missing_target_proof",
        Code::NameOnlyTarget => "name_only_target",
        Code::NameNeedsSelection => "name_needs_selection",
        Code::TargetNotFound => "target_not_found",
        Code::CrossServerCollision => "cross_server_collision",
        Code::ConflictingEvidence => "conflicting_evidence",
        Code::IdentifierProvenanceRequired => "identifier_provenance_required",
        Code::LegacyOptInRequired => "legacy_opt_in_required",
        Code::CandidateLimitExceeded => "candidate_limit_exceeded",
    }
}

const fn route_error_code(code: fcp_n8n::router::RouteErrorCode) -> &'static str {
    use fcp_n8n::router::RouteErrorCode as Code;
    match code {
        Code::TargetRequired => "target_required",
        Code::TargetMustBeInstance => "target_must_be_instance",
        Code::TargetMustBeExactResource => "target_must_be_exact_resource",
        Code::TargetMustBeWorkflow => "target_must_be_workflow",
        Code::LocalTargetRequired => "local_target_required",
        Code::ProviderUnavailable => "provider_unavailable",
        Code::CapabilityUnavailable => "capability_unavailable",
        Code::UnknownWriteCapability => "unknown_write_capability",
        Code::FallbackNotEquivalent => "fallback_not_equivalent",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_n8n::router::{Provider, ProviderCapability, ServerId};

    fn execute_input_fixture() -> Value {
        json!({
            "id": "workflow-1",
            "mode": "manual",
            "versionId": "version-1",
            "inputs": {"items": [1, true, "bounded"]},
            "guard": {
                "approvalRef": "chat-approval",
                "idempotencyKey": "11111111-2222-4333-8444-555555555555",
                "inputClass": "bounded_json",
                "sideEffectSummary": "run one approved workflow",
                "precondition": {
                    "versionId": "version-1",
                    "activeVersionId": null,
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        })
    }

    #[test]
    fn execute_handle_and_post_readback_failures_are_bounded_unknown() {
        let response = json!({
            "status": "ok",
            "result": {
                "structuredContent": {
                    "success": true,
                    "workflowId": "workflow-1",
                    "executionId": "execution-1",
                    "initialStatus": "accepted"
                }
            }
        });
        let handle =
            decode_official_mcp_execute_result(response, "workflow-1").expect("typed handle");
        assert_eq!(handle["workflowId"], "workflow-1");
        assert_eq!(handle["initialStatus"], "accepted");

        let input = execute_input_fixture();
        let readback = json!({
            "id": "execution-1",
            "workflowId": "workflow-1",
            "workflowVersionId": "version-1",
            "mode": "manual",
            "status": "running"
        });
        verify_execution_readback(&input, "execution-1", &readback).expect("readback");
        let mismatch = verify_execution_readback(
            &input,
            "execution-1",
            &json!({"id": "execution-1", "workflowId": "other", "mode": "manual", "workflowVersionId": "version-1", "status": "running"}),
        );
        assert_eq!(
            terminal_execute_readback(mismatch)
                .expect_err("mismatch")
                .code,
            "unknown_outcome"
        );
        let transport: Result<Value, AppError> = Err(AppError::new("timeout"));
        assert_eq!(
            terminal_execute_readback(transport)
                .expect_err("transport")
                .code,
            "unknown_outcome"
        );
    }

    #[test]
    fn execute_handle_missing_status_fails_closed() {
        let response = json!({
            "status": "ok",
            "result": {
                "structuredContent": {
                    "success": true,
                    "workflowId": "workflow-1",
                    "executionId": "execution-1"
                }
            }
        });
        assert_eq!(
            decode_official_mcp_execute_result(response, "workflow-1")
                .expect_err("missing status must be denied")
                .code,
            "unknown_outcome"
        );
    }

    #[test]
    fn execute_input_parity_rejects_recursive_secret_shapes_and_oversize() {
        let input = execute_input_fixture();
        validate_workflow_execute_input(input.as_object().expect("object")).expect("valid input");

        let mut marker = input.clone();
        marker["inputs"] = json!({"nested": {"apiKey": "redacted"}});
        assert!(validate_workflow_execute_input(marker.as_object().expect("object")).is_err());

        let mut array = input.clone();
        array["inputs"] = json!(["top-level arrays are denied"]);
        assert!(validate_workflow_execute_input(array.as_object().expect("object")).is_err());

        let mut oversized = input;
        oversized["inputs"] = json!({"value": "x".repeat(65_000)});
        assert!(validate_workflow_execute_input(oversized.as_object().expect("object")).is_err());
    }

    #[cfg(target_os = "linux")]
    use fcp_crypto::ZeroizingSecret;
    #[cfg(target_os = "linux")]
    use fcp_sandbox::{
        FCP_HOST_RUN_ONCE_CREDENTIAL_FD, FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT,
        FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT_VALUE, FCP_HOST_RUN_ONCE_SUPERVISOR_CONTROL_FD,
        ProcessSpec, TerminationReport, claim_inherited_host_egress_channel,
    };
    #[cfg(target_os = "linux")]
    use std::collections::BTreeMap;
    #[cfg(target_os = "linux")]
    use std::io::{Read, Write};
    #[cfg(target_os = "linux")]
    use std::process::ExitStatus;

    #[cfg(target_os = "linux")]
    const FAKE_CHILD_ENV: &str = "FWC_N8N_FAKE_CHILD";
    #[cfg(target_os = "linux")]
    const FAKE_CHILD_OUTPUT_MARKER: &str = "FWC_N8N_FAKE_JSON:";
    #[cfg(target_os = "linux")]
    const SUPERVISOR_START_PREFIX: &[u8] = b"FCP-HOST-RUN-ONCE/v1/START";
    #[cfg(target_os = "linux")]
    const SUPERVISOR_READY_FRAME: &[u8] = b"FCP-HOST-RUN-ONCE/v1/READY";
    #[cfg(target_os = "linux")]
    const SUPERVISOR_GO_FRAME: &[u8] = b"FCP-HOST-RUN-ONCE/v1/GO";
    #[cfg(target_os = "linux")]
    const SUPERVISOR_MAX_BUDGET_MS: u32 = 60_000;

    #[cfg(target_os = "linux")]
    #[derive(Debug)]
    struct BridgeObservation {
        envelope_bytes: usize,
        credential_bytes: usize,
        stdout_bytes: usize,
        stderr_bytes: usize,
        child_status: ExitStatus,
        termination: TerminationReport,
    }

    #[cfg(target_os = "linux")]
    fn validate_fake_credential(secret: &[u8]) -> Result<(), AppError> {
        if secret.is_empty() {
            return Err(AppError::new("credential_empty"));
        }
        if secret.len() > 4096 {
            return Err(AppError::new("credential_oversized"));
        }
        let value =
            std::str::from_utf8(secret).map_err(|_| AppError::new("credential_invalid_utf8"))?;
        if value.trim() != value
            || secret
                .iter()
                .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
        {
            return Err(AppError::new("credential_invalid_header"));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn fake_child_process_spec() -> ProcessSpec {
        let executable =
            std::fs::canonicalize(std::env::current_exe().expect("current test executable"))
                .expect("canonical test executable");
        let digest = blake3::hash(&std::fs::read(&executable).expect("test executable bytes"))
            .to_hex()
            .to_string();
        let mut fixed_env = BTreeMap::new();
        fixed_env.insert(FAKE_CHILD_ENV.into(), "1".into());
        ProcessSpec {
            launcher_path: executable.clone(),
            launcher_digest: digest.clone(),
            runtime_executable: executable,
            expected_runtime_executable_digest: digest,
            fixed_args: vec![
                "--exact".into(),
                "tests::run_once_bridge_child_probe".into(),
                "--nocapture".into(),
                "--test-threads=1".into(),
            ],
            fixed_env,
            network_disabled: false,
        }
    }

    #[cfg(target_os = "linux")]
    fn fake_child_working_directory() -> std::path::PathBuf {
        let executable =
            std::fs::canonicalize(std::env::current_exe().expect("current test executable"))
                .expect("canonical test executable");
        executable
            .parent()
            .expect("test executable parent")
            .to_path_buf()
    }

    #[cfg(target_os = "linux")]
    fn parse_fake_child_output(
        stdout: &[u8],
        expected_envelope_bytes: usize,
        expected_credential_bytes: usize,
    ) -> Result<(), AppError> {
        let text =
            std::str::from_utf8(stdout).map_err(|_| AppError::new("bridge_output_invalid_utf8"))?;
        let payload = text
            .lines()
            .find_map(|line| {
                line.split_once(FAKE_CHILD_OUTPUT_MARKER)
                    .map(|(_, value)| value)
            })
            .ok_or_else(|| AppError::new("bridge_output_missing"))?;
        let value: Value = serde_json::from_str(payload)
            .map_err(|_| AppError::new("bridge_output_invalid_json"))?;
        if value.get("status").and_then(Value::as_str) != Some("ok")
            || value.get("envelopeBytes").and_then(Value::as_u64)
                != Some(expected_envelope_bytes as u64)
            || value.get("credentialBytes").and_then(Value::as_u64)
                != Some(expected_credential_bytes as u64)
            || value.get("nestedSetSidDescendant").and_then(Value::as_bool) != Some(true)
        {
            return Err(AppError::new("bridge_output_mismatch"));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn run_fake_bridge(
        envelope: &HostRunOnceEnvelope,
        secret: &[u8],
    ) -> Result<BridgeObservation, AppError> {
        let envelope_bytes = serde_json::to_vec(envelope)
            .map_err(|_| AppError::new("bridge_envelope_encode_failed"))?;
        let output = fwc_n8n_bridge::run_process(
            &fake_child_process_spec(),
            envelope,
            ZeroizingSecret::from(secret),
            &fake_child_working_directory(),
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .map_err(|error| AppError::new(error.code()))?;
        let credential_bytes = secret.len();
        parse_fake_child_output(&output.stdout, envelope_bytes.len(), credential_bytes)?;
        Ok(BridgeObservation {
            envelope_bytes: envelope_bytes.len(),
            credential_bytes,
            stdout_bytes: output.stdout.len(),
            stderr_bytes: output.stderr.len(),
            child_status: output.status,
            termination: output.termination,
        })
    }

    #[cfg(target_os = "linux")]
    fn read_bounded_child_input<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, ()> {
        let mut input = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let bytes = reader.read(&mut buffer).map_err(|_| ())?;
            if bytes == 0 {
                return Ok(input);
            }
            if input.len().saturating_add(bytes) > max_bytes {
                return Err(());
            }
            input.extend_from_slice(&buffer[..bytes]);
        }
    }

    #[cfg(target_os = "linux")]
    fn spawn_nested_setsid_descendant() -> Result<(), ()> {
        let mut descendant = std::process::Command::new("/usr/bin/setsid")
            .args(["/usr/bin/sleep", "60"])
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| ())?;
        match descendant.try_wait().map_err(|_| ())? {
            None => Ok(()),
            Some(_) => Err(()),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_once_bridge_child_probe() {
        if std::env::var_os(FAKE_CHILD_ENV).is_none() {
            return;
        }
        let result = (|| -> Result<(), ()> {
            let control_fd = std::env::var(FCP_HOST_RUN_ONCE_SUPERVISOR_CONTROL_FD)
                .map_err(|_| ())?
                .parse::<i32>()
                .map_err(|_| ())?;
            if control_fd < 3 {
                return Err(());
            }
            let mut control = claim_inherited_host_egress_channel(control_fd).map_err(|_| ())?;
            let mut start = [0_u8; SUPERVISOR_START_PREFIX.len() + 4];
            control.read_exact(&mut start).map_err(|_| ())?;
            if &start[..SUPERVISOR_START_PREFIX.len()] != SUPERVISOR_START_PREFIX {
                return Err(());
            }
            let budget = u32::from_be_bytes(
                start[SUPERVISOR_START_PREFIX.len()..]
                    .try_into()
                    .map_err(|_| ())?,
            );
            if !(1..=SUPERVISOR_MAX_BUDGET_MS).contains(&budget) {
                return Err(());
            }
            control.set_nonblocking(true).map_err(|_| ())?;
            let mut extra = [0_u8; 1];
            let start_probe = control.read(&mut extra);
            let start_restore = control.set_nonblocking(false);
            let start_has_extra = match start_probe {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(_) => true,
            };
            if start_restore.is_err() || start_has_extra {
                return Err(());
            }
            control.write_all(SUPERVISOR_READY_FRAME).map_err(|_| ())?;
            let mut decision = [0_u8; SUPERVISOR_GO_FRAME.len()];
            control.read_exact(&mut decision).map_err(|_| ())?;
            if decision != SUPERVISOR_GO_FRAME {
                return Err(());
            }
            control.set_nonblocking(true).map_err(|_| ())?;
            let mut trailing = [0_u8; 1];
            let decision_probe = control.read(&mut trailing);
            let decision_restore = control.set_nonblocking(false);
            let decision_has_extra = match decision_probe {
                Ok(0) => false,
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(_) => true,
            };
            if decision_restore.is_err() || decision_has_extra {
                return Err(());
            }
            let mut stdin = std::io::stdin().lock();
            let envelope = read_bounded_child_input(&mut stdin, MAX_INPUT_BYTES)?;
            drop(stdin);
            let envelope_value: Value = serde_json::from_slice(&envelope).map_err(|_| ())?;
            if envelope_value.get("schema").and_then(Value::as_str) != Some(HOST_RUN_ONCE_SCHEMA)
                || envelope_value.get("zone_id").and_then(Value::as_str) != Some(HOST_RUN_ONCE_ZONE)
                || envelope_value.get("server_id").and_then(Value::as_str) != Some("eec")
                || envelope_value.get("operation").and_then(Value::as_str)
                    != Some("n8n.workflows.get")
                || envelope_value.get("resource_uri").and_then(Value::as_str)
                    != Some("fwc-n8n://eec/workflows/workflow%2D1")
                || envelope_value
                    .get("input")
                    .and_then(|input| input.get("id"))
                    .and_then(Value::as_str)
                    != Some("workflow-1")
                || envelope_value.get("deadline_ms").and_then(Value::as_u64)
                    != Some(HOST_RUN_ONCE_DEFAULT_DEADLINE_MS)
                || envelope_value.get("correlation_id").is_some()
            {
                return Err(());
            }
            let transport =
                std::env::var(FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT).map_err(|_| ())?;
            if transport != FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT_VALUE {
                return Err(());
            }
            let fd = std::env::var(FCP_HOST_RUN_ONCE_CREDENTIAL_FD)
                .map_err(|_| ())?
                .parse::<i32>()
                .map_err(|_| ())?;
            if fd < 3 {
                return Err(());
            }
            let mut credential = claim_inherited_host_egress_channel(fd).map_err(|_| ())?;
            let mut header = [0_u8; 9];
            credential.read_exact(&mut header).map_err(|_| ())?;
            if &header[..4] != b"FCPK" || header[4] != 1 {
                return Err(());
            }
            let length = u32::from_be_bytes(header[5..9].try_into().map_err(|_| ())?) as usize;
            if length == 0 || length > 4096 {
                return Err(());
            }
            let mut secret_bytes = vec![0_u8; length];
            credential.read_exact(&mut secret_bytes).map_err(|_| ())?;
            let secret = ZeroizingSecret::with_zeroize_drop(secret_bytes);
            secret
                .with_bytes(validate_fake_credential)
                .map_err(|_| ())?;
            let mut trailing = [0_u8; 1];
            if credential.read(&mut trailing).map_err(|_| ())? != 0 {
                return Err(());
            }
            spawn_nested_setsid_descendant()?;
            println!(
                "{FAKE_CHILD_OUTPUT_MARKER}{}",
                json!({
                    "schema": "fwc.n8n.fake-child.v1",
                    "status": "ok",
                    "envelopeBytes": envelope.len(),
                    "credentialBytes": length,
                    "nestedSetSidDescendant": true,
                })
            );
            Ok(())
        })();
        assert!(result.is_ok(), "fake child protocol failure");
    }

    #[test]
    fn upstream_tool_name_is_not_a_public_operation() {
        let error = public_operation_intent("n8n_delete_workflow").expect_err("must deny");
        assert_eq!(error.code, "unknown_public_operation");
    }

    struct DelayedEof(std::time::Duration);

    impl std::io::Read for DelayedEof {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.0);
            Ok(0)
        }
    }

    #[test]
    fn public_input_read_is_bounded_without_eof() {
        let error = read_input_until(
            DelayedEof(std::time::Duration::from_millis(50)),
            Instant::now() + std::time::Duration::from_millis(5),
        )
        .expect_err("input reader must not pin the public wrapper");
        assert_eq!(error.code, "input_read_timeout");
    }

    #[test]
    fn public_input_read_returns_bounded_bytes_after_eof() {
        let bytes = read_input_until(
            std::io::Cursor::new(b"bounded".to_vec()),
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .expect("bounded input");
        assert_eq!(bytes, b"bounded");
    }

    #[test]
    fn local_run_once_builds_only_the_typed_local_dispatch_request() {
        let input = json!({
            "input": {
                "action": {
                    "search_nodes": {
                        "query": "webhook",
                        "limit": 3
                    }
                }
            },
            "correlation_id": Uuid::new_v4().to_string(),
        });
        let value = run_local_once_from_bytes(
            "n8n.knowledge.query",
            &serde_json::to_vec(&input).expect("local input"),
            |request| {
                assert_eq!(
                    request.operation_kind(),
                    fcp_host::LocalN8nOperationKind::KnowledgeQuery
                );
                assert_eq!(request.internal_tool(), fcp_host::LocalN8nTool::SearchNodes);
                Ok(json!({"dispatched": true}))
            },
        )
        .expect("typed local request");
        assert_eq!(value, json!({"dispatched": true}));
    }

    #[test]
    fn local_run_once_rejects_provider_and_correlation_smuggling() {
        for input in [
            json!({
                "input": {
                    "correlation_id": Uuid::new_v4().to_string(),
                    "action": {"search_nodes": {"query": "webhook"}}
                }
            }),
            json!({
                "input": {"action": {"search_nodes": {"query": "webhook"}}},
                "correlation_id": "not-a-uuid"
            }),
            json!({
                "input": {"action": {"unknown_tool": {}}}
            }),
        ] {
            let error = run_local_once_from_bytes(
                "n8n.knowledge.query",
                &serde_json::to_vec(&input).expect("local input"),
                |_| panic!("invalid input must fail before dispatch"),
            )
            .expect_err("local smuggling must fail closed");
            assert!(matches!(
                error.code,
                "invalid_operation_input" | "invalid_correlation_id"
            ));
        }
    }

    #[test]
    fn run_once_dispatches_validated_envelope_under_one_absolute_deadline() {
        let started = Instant::now();
        let value = run_once_from_bytes_at(
            "n8n.workflows.list",
            br#"{"server_id":"eec","input":{},"deadline_ms":1000}"#,
            started,
            |envelope, deadline| {
                assert_eq!(envelope.server_id, HostRunOnceServerId::Eec);
                assert_eq!(envelope.operation, HostRunOnceOperation::WorkflowsList);
                assert_eq!(envelope.deadline_ms, Some(1000));
                assert!(deadline > Instant::now());
                assert!(deadline <= started + std::time::Duration::from_millis(1000));
                Ok(json!({"status": "ok"}))
            },
        )
        .expect("validated request must reach the fixed dispatch seam");
        assert_eq!(value.get("status").and_then(Value::as_str), Some("ok"));
    }

    #[derive(Default)]
    struct LifecycleBridgeProbe {
        requests: Vec<String>,
        readback_mismatch: bool,
    }

    impl LifecycleBridgeProbe {
        fn dispatch(
            &mut self,
            envelope: HostRunOnceEnvelope,
            _deadline: Instant,
        ) -> Result<Value, AppError> {
            assert_eq!(envelope.operation, HostRunOnceOperation::WorkflowsLifecycle);
            assert_eq!(envelope.server_id, HostRunOnceServerId::Eec);
            assert_eq!(
                envelope.resource_uri,
                "fwc-mcp-bridge://eec/tools/publish%5Fworkflow"
            );
            assert_eq!(envelope.input["id"], "1001");
            assert_eq!(envelope.input["action"], "publish");
            assert_eq!(
                envelope.input["guard"]["precondition"]["activeVersionId"],
                Value::Null
            );

            self.requests.push("bridge:validated-envelope".to_owned());
            self.requests
                .push("child:GET /api/v1/workflows/1001".to_owned());
            self.requests.push(
                "child:MCP tools/call publish_workflow {\"workflowId\":\"1001\",\"versionId\":\"version-1\"}"
                    .to_owned(),
            );
            self.requests
                .push("child:GET /api/v1/workflows/1001".to_owned());

            if self.readback_mismatch {
                return Err(AppError::new("lifecycle_readback_mismatch"));
            }
            Ok(json!({
                "status": "ok",
                "result": {
                    "action": "publish",
                    "active": true,
                    "activeVersionId": "version-1"
                }
            }))
        }
    }

    fn lifecycle_host_input() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "server_id": "eec",
            "input": {
                "id": "1001",
                "action": "publish",
                "versionId": "version-1",
                "guard": {
                    "approvalRef": "chat-approval-1",
                    "idempotencyKey": "00000000-0000-4000-8000-000000000003",
                    "precondition": {
                        "versionId": "draft-v1",
                        "activeVersionId": null,
                        "active": false,
                        "isArchived": false,
                        "stateDigest": "blake3-256:0000000000000000000000000000000000000000000000000000000000000000"
                    }
                }
            },
            "deadline_ms": 1000
        }))
        .expect("lifecycle host input")
    }

    #[test]
    fn host_run_once_lifecycle_publish_bridges_exact_write_and_readback_once() {
        let mut bridge = LifecycleBridgeProbe::default();
        let value = run_once_from_bytes_at(
            "n8n.workflows.lifecycle",
            &lifecycle_host_input(),
            Instant::now(),
            |envelope, deadline| bridge.dispatch(envelope, deadline),
        )
        .expect("validated lifecycle envelope should reach bridge seam");
        assert_eq!(value["status"], "ok");
        assert_eq!(
            bridge.requests,
            vec![
                "bridge:validated-envelope",
                "child:GET /api/v1/workflows/1001",
                "child:MCP tools/call publish_workflow {\"workflowId\":\"1001\",\"versionId\":\"version-1\"}",
                "child:GET /api/v1/workflows/1001",
            ]
        );
        assert_eq!(
            bridge
                .requests
                .iter()
                .filter(|request| request.starts_with("child:MCP tools/call"))
                .count(),
            1
        );
    }

    #[test]
    fn host_run_once_lifecycle_readback_mismatch_is_terminal_without_second_write() {
        let mut bridge = LifecycleBridgeProbe {
            readback_mismatch: true,
            ..Default::default()
        };
        let error = run_once_from_bytes_at(
            "n8n.workflows.lifecycle",
            &lifecycle_host_input(),
            Instant::now(),
            |envelope, deadline| bridge.dispatch(envelope, deadline),
        )
        .expect_err("readback mismatch must fail closed");
        assert_eq!(error.code, "lifecycle_readback_mismatch");
        assert_eq!(
            bridge
                .requests
                .iter()
                .filter(|request| request.starts_with("child:MCP tools/call"))
                .count(),
            1
        );
        assert_eq!(
            bridge.requests.last().map(String::as_str),
            Some("child:GET /api/v1/workflows/1001")
        );
    }

    fn lifecycle_state(active: bool, active_version_id: Value, is_archived: bool) -> Value {
        json!({
            "id": "1001",
            "name": null,
            "projectId": null,
            "folderId": null,
            "versionId": "draft-v1",
            "active": active,
            "activeVersionId": active_version_id,
            "isArchived": is_archived,
            "draft": {"versionId": "draft-v1", "graphDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "published": if active {
                json!({"versionId": "version-1", "graphDigest": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
            } else {
                Value::Null
            },
            "stateDigest": "blake3-256:0000000000000000000000000000000000000000000000000000000000000000",
            "updatedAt": null,
        })
    }

    #[test]
    fn official_mcp_lifecycle_result_is_strictly_decoded_and_redacted() {
        let provider = json!({
            "success": true,
            "workflowId": "1001",
            "activeVersionId": "version-1",
            "secret": "drop-me"
        });
        let response = json!({
            "status": "ok",
            "result": {
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string(&provider).expect("provider JSON")
                }]
            }
        });
        let safe = decode_official_mcp_lifecycle_result(response, "publish", "1001")
            .expect("official lifecycle response");
        assert_eq!(
            safe,
            json!({
                "action": "publish",
                "success": true,
                "workflowId": "1001",
                "activeVersionId": "version-1"
            })
        );
        assert!(
            decode_official_mcp_lifecycle_result(
                json!({"status": "ok", "result": {"success": true, "workflowId": "other"}}),
                "publish",
                "1001"
            )
            .is_err()
        );
    }

    #[test]
    fn official_mcp_lifecycle_minimal_unpublish_response_is_accepted() {
        let response = json!({
            "status": "ok",
            "result": {
                "success": true,
                "workflowId": "1001",
                "error": null
            }
        });
        assert_eq!(
            decode_official_mcp_lifecycle_result(response, "unpublish", "1001")
                .expect("minimal official unpublish response"),
            json!({
                "action": "unpublish",
                "success": true,
                "workflowId": "1001"
            })
        );

        let response_with_null_version = json!({
            "status": "ok",
            "result": {
                "success": true,
                "workflowId": "1001",
                "activeVersionId": null,
                "error": null
            }
        });
        assert!(
            decode_official_mcp_lifecycle_result(response_with_null_version, "unpublish", "1001")
                .is_ok()
        );
    }

    #[test]
    fn official_mcp_archive_result_is_typed_and_redacted() {
        let response = json!({
            "status": "ok",
            "result": {
                "archived": true,
                "workflowId": "1001",
                "name": "private workflow name",
                "secret": "drop-me"
            }
        });
        assert_eq!(
            decode_official_mcp_archive_result(response, "1001").expect("archive result"),
            json!({"archived": true, "workflowId": "1001"})
        );
        assert!(decode_official_mcp_archive_result(
            json!({"status": "ok", "result": {"archived": false, "workflowId": "1001", "name": "x"}}),
            "1001"
        )
        .is_err());
        assert!(decode_official_mcp_archive_result(
            json!({"status": "ok", "result": {"archived": true, "workflowId": "other", "name": "x"}}),
            "1001"
        )
        .is_err());
    }

    #[test]
    fn archive_input_requires_inactive_unarchived_baseline() {
        let mut input = json!({
            "id": "1001",
            "guard": {
                "approvalRef": "chat-approval-1",
                "idempotencyKey": "00000000-0000-4000-8000-000000000004",
                "precondition": {
                    "versionId": "draft-v1",
                    "activeVersionId": null,
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        });
        run_once_from_bytes_at(
            "n8n.workflows.archive",
            &serde_json::to_vec(
                &json!({"server_id": "eec", "input": input.clone(), "deadline_ms": 1000}),
            )
            .expect("archive input"),
            Instant::now(),
            |envelope, _| {
                assert_eq!(envelope.operation, HostRunOnceOperation::WorkflowsArchive);
                assert_eq!(
                    envelope.resource_uri,
                    "fwc-mcp-bridge://eec/tools/archive%5Fworkflow"
                );
                Ok(json!({"status": "ok"}))
            },
        )
        .expect("archive preflight should reach the owned seam");
        input["guard"]["precondition"]["active"] = json!(true);
        assert!(
            run_once_from_bytes_at(
                "n8n.workflows.archive",
                &serde_json::to_vec(
                    &json!({"server_id": "eec", "input": input, "deadline_ms": 1000})
                )
                .expect("archive input"),
                Instant::now(),
                |_envelope, _| Ok(json!({"status": "ok"}))
            )
            .is_err()
        );
    }

    #[test]
    fn official_mcp_lifecycle_decoder_rejects_action_and_result_shape_mismatch() {
        let wrong_action = json!({
            "status": "ok",
            "result": {
                "action": "unpublish",
                "success": true,
                "workflowId": "1001"
            }
        });
        assert!(decode_official_mcp_lifecycle_result(wrong_action, "publish", "1001").is_err());

        let wrong_version_type = json!({
            "status": "ok",
            "result": {
                "success": true,
                "workflowId": "1001",
                "activeVersionId": 7
            }
        });
        assert!(
            decode_official_mcp_lifecycle_result(wrong_version_type, "publish", "1001").is_err()
        );

        let non_null_unpublish_version = json!({
            "status": "ok",
            "result": {
                "success": true,
                "workflowId": "1001",
                "activeVersionId": "version-1"
            }
        });
        assert!(
            decode_official_mcp_lifecycle_result(non_null_unpublish_version, "unpublish", "1001")
                .is_err()
        );
    }

    #[test]
    fn official_mcp_lifecycle_readback_requires_preserved_draft_and_action_state() {
        let input = json!({"id": "1001", "action": "publish", "versionId": "version-1"});
        let baseline = lifecycle_state(false, Value::Null, false);
        let provider = json!({
            "success": true,
            "workflowId": "1001",
            "active": true,
            "isArchived": false,
            "activeVersionId": "version-1",
            "draft": {
                "versionId": "draft-v1",
                "graphDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "published": {
                "versionId": "version-1",
                "graphDigest": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "stateDigest": "blake3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        });
        let after = lifecycle_state(true, json!("version-1"), false);
        let mut after = after;
        after["stateDigest"] = provider["stateDigest"].clone();
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &after)
                .expect("publish readback"),
            "version-1"
        );

        let mut mismatched = after;
        mismatched["draft"]["graphDigest"] = json!("blake3-256:changed");
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &mismatched)
                .expect_err("draft mutation must fail closed")
                .code,
            "readback_mismatch"
        );
    }

    #[test]
    fn official_mcp_lifecycle_readback_rejects_published_or_state_digest_drift() {
        let input = json!({"id": "1001", "action": "publish", "versionId": "version-1"});
        let baseline = lifecycle_state(false, Value::Null, false);
        let provider = json!({
            "success": true,
            "workflowId": "1001",
            "active": true,
            "isArchived": false,
            "activeVersionId": "version-1",
            "draft": {
                "versionId": "draft-v1",
                "graphDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "published": {
                "versionId": "version-1",
                "graphDigest": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "stateDigest": "blake3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        });
        let mut after = lifecycle_state(true, json!("version-1"), false);
        after["stateDigest"] = provider["stateDigest"].clone();
        after["published"]["versionId"] = json!("version-2");
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &after)
                .expect_err("published graph drift must fail closed")
                .code,
            "readback_mismatch"
        );

        let mut after = lifecycle_state(true, json!("version-1"), false);
        after["stateDigest"] = json!("not-a-digest");
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &after)
                .expect_err("state digest drift must fail closed")
                .code,
            "readback_mismatch"
        );
    }

    #[test]
    fn official_mcp_lifecycle_rejects_provider_version_drift() {
        let input = json!({"id": "1001", "action": "publish", "versionId": "version-1"});
        let baseline = lifecycle_state(false, Value::Null, false);
        let provider = json!({
            "success": true,
            "workflowId": "1001",
            "active": true,
            "isArchived": false,
            "activeVersionId": "version-2",
            "draft": {
                "versionId": "draft-v1",
                "graphDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "published": {
                "versionId": "version-2",
                "graphDigest": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "stateDigest": "blake3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        });
        let mut after = lifecycle_state(true, json!("version-2"), false);
        after["stateDigest"] = provider["stateDigest"].clone();
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &after)
                .expect_err("provider version drift must be unknown")
                .code,
            "unknown_outcome"
        );
    }

    #[test]
    fn official_mcp_lifecycle_rejects_unpublish_provider_still_active() {
        let input = json!({"id": "1001", "action": "unpublish"});
        let baseline = lifecycle_state(true, json!("version-1"), false);
        let mut provider = json!({
            "success": true,
            "workflowId": "1001",
            "active": true,
            "isArchived": false,
            "activeVersionId": "version-1",
            "draft": {
                "versionId": "draft-v1",
                "graphDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "published": {
                "versionId": "version-1",
                "graphDigest": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "stateDigest": "blake3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        });
        let mut after = lifecycle_state(false, Value::Null, false);
        after["stateDigest"] = provider["stateDigest"].clone();
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &after)
                .expect_err("provider active state must be unknown")
                .code,
            "unknown_outcome"
        );

        provider["active"] = json!(false);
        provider["activeVersionId"] = Value::Null;
        provider["published"] = Value::Null;
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &after)
                .expect("normalized unpublish provider"),
            ""
        );
    }

    #[test]
    fn official_mcp_lifecycle_unpublish_preserves_draft_and_normalized_state() {
        let input = json!({"id": "1001", "action": "unpublish"});
        let baseline = lifecycle_state(true, json!("version-1"), false);
        let provider = json!({
            "success": true,
            "workflowId": "1001",
            "active": false,
            "isArchived": false,
            "activeVersionId": null,
            "draft": {
                "versionId": "draft-v1",
                "graphDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "published": null,
            "stateDigest": "blake3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        });
        let mut after = lifecycle_state(false, Value::Null, false);
        after["stateDigest"] = provider["stateDigest"].clone();
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &after)
                .expect("unpublish readback"),
            ""
        );

        after["draft"]["graphDigest"] =
            json!("blake3-256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        assert_eq!(
            verify_lifecycle_readback(&input, &baseline, &provider, &after)
                .expect_err("unpublish draft drift must fail closed")
                .code,
            "readback_mismatch"
        );
    }

    #[test]
    fn official_mcp_lifecycle_unknown_result_is_terminal() {
        let error = decode_official_mcp_lifecycle_result(
            json!({"status": "error", "error": {"code": "timeout"}}),
            "publish",
            "1001",
        )
        .expect_err("provider ambiguity must be unknown");
        assert_eq!(error.code, "unknown_outcome");
    }

    #[test]
    fn official_mcp_lifecycle_exposes_only_safe_preflight_categories() {
        let safe_categories = [
            ("host_n8n_policy_failed", "official_mcp_policy_failed"),
            (
                "host_n8n_capability_failed",
                "official_mcp_capability_failed",
            ),
            ("host_n8n_manifest_failed", "official_mcp_manifest_failed"),
            ("host_n8n_plan_failed", "official_mcp_plan_failed"),
        ];
        for (bridge_code, public_code) in safe_categories {
            assert_eq!(
                official_mcp_workflow_bridge_error_code(bridge_code),
                public_code
            );
        }
        for ambiguous_code in [
            "host_n8n_invoke_failed",
            "child_failed",
            "timeout",
            "output_invalid",
            "process_spawn_failed",
        ] {
            assert_eq!(
                official_mcp_workflow_bridge_error_code(ambiguous_code),
                "unknown_outcome"
            );
        }
    }

    #[test]
    fn unknown_lifecycle_error_envelope_carries_only_optional_safe_diagnostic() {
        let error = AppError::with_diagnostic("unknown_outcome", Some("response_capability"));
        let encoded = serde_json::to_value(ErrorEnvelope {
            schema: "fwc.n8n.error.v1",
            status: "error",
            code: error.code.to_string(),
            diagnostic: error.diagnostic,
            correlation_id: "00000000-0000-0000-0000-000000000000".to_string(),
        })
        .expect("safe error envelope");
        assert_eq!(encoded["code"], "unknown_outcome");
        assert_eq!(encoded["diagnostic"], "response_capability");
        assert!(encoded.get("provider").is_none());

        let without_diagnostic = AppError::new("unknown_outcome");
        let encoded_without_diagnostic = serde_json::to_value(ErrorEnvelope {
            schema: "fwc.n8n.error.v1",
            status: "error",
            code: without_diagnostic.code.to_string(),
            diagnostic: without_diagnostic.diagnostic,
            correlation_id: "00000000-0000-0000-0000-000000000000".to_string(),
        })
        .expect("error envelope without diagnostic");
        assert!(encoded_without_diagnostic.get("diagnostic").is_none());
    }

    #[test]
    fn run_once_deadline_includes_time_before_dispatch() {
        let started = Instant::now() - std::time::Duration::from_millis(10);
        let error = run_once_from_bytes_at(
            "n8n.workflows.list",
            br#"{"server_id":"eec","input":{},"deadline_ms":1}"#,
            started,
            |_, _| panic!("expired request must not dispatch"),
        )
        .expect_err("expired request");
        assert_eq!(error.code, "deadline_exceeded");
    }

    #[derive(Default)]
    struct MockMcpLedger {
        events: Arc<std::sync::Mutex<Vec<&'static str>>>,
        replay: Option<Value>,
        commit_error: Option<fwc_n8n_update_host::McpAccessLedgerError>,
        pending: bool,
    }

    impl McpAccessLedgerPort for MockMcpLedger {
        fn begin_for_request(
            &mut self,
            _binding: &fwc_n8n_update_host::McpAccessLedgerBinding,
            _expectation: &fwc_n8n_update_host::McpAccessReceiptExpectation,
        ) -> Result<
            fwc_n8n_update_host::McpAccessLedgerBegin,
            fwc_n8n_update_host::McpAccessLedgerError,
        > {
            self.events.lock().expect("events lock").push("claim");
            if self.pending {
                return Err(fwc_n8n_update_host::McpAccessLedgerError::Unknown);
            }
            if let Some(receipt) = self.replay.take() {
                Ok(fwc_n8n_update_host::McpAccessLedgerBegin::Replayed(receipt))
            } else {
                self.pending = true;
                Ok(fwc_n8n_update_host::McpAccessLedgerBegin::Claimed)
            }
        }

        fn commit_for_request(
            &mut self,
            _binding: &fwc_n8n_update_host::McpAccessLedgerBinding,
            _receipt: &Value,
            _expectation: &fwc_n8n_update_host::McpAccessReceiptExpectation,
        ) -> Result<(), fwc_n8n_update_host::McpAccessLedgerError> {
            self.events.lock().expect("events lock").push("commit");
            if let Some(error) = self.commit_error {
                return Err(error);
            }
            self.pending = false;
            Ok(())
        }
    }

    fn mock_mcp_binding_and_expectation() -> (
        fwc_n8n_update_host::McpAccessLedgerBinding,
        fwc_n8n_update_host::McpAccessReceiptExpectation,
    ) {
        let binding = fwc_n8n_update_host::McpAccessLedgerBinding {
            key_digest:
                "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            binding_digest:
                "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        };
        let expectation = fwc_n8n_update_host::McpAccessReceiptExpectation {
            binding_digest: binding.binding_digest.clone(),
            server_id: "eec".into(),
            scope: "all_current".into(),
            desired: true,
            dry_run: true,
            plan_digest: None,
            approval_digest: None,
            idempotency_digest: None,
        };
        (binding, expectation)
    }

    fn mock_mcp_response() -> Value {
        json!({
            "status": "ok",
            "result": {
                "receipt": {
                    "schema": "fwc.n8n.mcp-access-receipt.v1",
                    "operation": "n8n.mcp_access.reconcile",
                    "serverId": "eec",
                    "scope": "all_current",
                    "desired": true,
                    "dryRun": true,
                    "status": "planned",
                    "planDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "readbackDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "items": [],
                    "receiptDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }
        })
    }

    #[test]
    fn host_reconciliation_claims_before_provider_access() {
        let (binding, expectation) = mock_mcp_binding_and_expectation();
        let mut ledger = MockMcpLedger::default();
        let events = Arc::clone(&ledger.events);
        let result = dispatch_mcp_access_once(&mut ledger, &binding, &expectation, || {
            events.lock().expect("events lock").push("provider");
            Ok(mock_mcp_response())
        })
        .expect("mock reconciliation");
        assert_eq!(result["status"], "ok");
        assert_eq!(
            ledger.events.lock().expect("events lock").as_slice(),
            ["claim", "provider", "commit"]
        );
    }

    #[test]
    fn host_reconciliation_replay_skips_provider_attempt() {
        let (binding, expectation) = mock_mcp_binding_and_expectation();
        let mut ledger = MockMcpLedger {
            replay: Some(json!({"status": "replayed"})),
            ..Default::default()
        };
        let result = dispatch_mcp_access_once(&mut ledger, &binding, &expectation, || {
            panic!("exact replay must not call provider")
        })
        .expect("replay");
        assert_eq!(result["status"], "ok");
        assert_eq!(
            ledger.events.lock().expect("events lock").as_slice(),
            ["claim"]
        );
    }

    #[test]
    fn host_reconciliation_commit_failure_is_not_a_success() {
        let (binding, expectation) = mock_mcp_binding_and_expectation();
        let mut ledger = MockMcpLedger {
            commit_error: Some(fwc_n8n_update_host::McpAccessLedgerError::Unavailable),
            ..Default::default()
        };
        let error = dispatch_mcp_access_once(&mut ledger, &binding, &expectation, || {
            Ok(mock_mcp_response())
        })
        .expect_err("commit failure");
        assert_eq!(error.code, "mcp_access_ledger_unavailable");
        assert!(ledger.pending, "failed commit leaves pending unknown");
        let retry = dispatch_mcp_access_once(&mut ledger, &binding, &expectation, || {
            panic!("unknown outcome must not retry provider")
        })
        .expect_err("pending claim is unknown");
        assert_eq!(retry.code, "mcp_access_unknown_outcome");
    }

    #[test]
    fn host_reconciliation_durable_commit_precedes_response() {
        let (binding, expectation) = mock_mcp_binding_and_expectation();
        let mut ledger = MockMcpLedger::default();
        let events = Arc::clone(&ledger.events);
        let result = dispatch_mcp_access_once(&mut ledger, &binding, &expectation, || {
            events.lock().expect("events lock").push("provider");
            Ok(mock_mcp_response())
        })
        .expect("durable dry-run receipt");
        assert_eq!(
            ledger.events.lock().expect("events lock").as_slice(),
            ["claim", "provider", "commit"]
        );
        assert_eq!(result["status"], "ok");
    }

    #[cfg(target_os = "linux")]
    #[ignore = "requires separately approved delegated cgroup-v2 live integration"]
    #[test]
    fn run_once_fake_parent_bridge_roundtrip_is_bounded_and_group_owned() {
        let operation = HostRunOnceOperation::parse("n8n.workflows.get").expect("operation");
        let envelope = build_host_run_once_envelope(
            operation,
            host_input(HostRunOnceServerId::Eec, json!({"id": "workflow-1"})),
        )
        .expect("validated envelope");
        let observation = run_fake_bridge(&envelope, b"FAKE-ROUNDTRIP-API-KEY")
            .expect("fake parent bridge roundtrip");
        assert_eq!(
            observation.envelope_bytes,
            serde_json::to_vec(&envelope).unwrap().len()
        );
        assert_eq!(
            observation.credential_bytes,
            b"FAKE-ROUNDTRIP-API-KEY".len()
        );
        assert!(observation.stdout_bytes > 0);
        assert_eq!(observation.stderr_bytes, 0);
        assert!(observation.child_status.success());
        assert!(observation.termination.group_absent);
        assert!(observation.termination.reaped);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_once_production_runner_rejects_malformed_material_before_spawn() {
        let operation = HostRunOnceOperation::parse("n8n.workflows.get").expect("operation");
        let envelope = build_host_run_once_envelope(
            operation,
            host_input(HostRunOnceServerId::Eec, json!({"id": "workflow-1"})),
        )
        .expect("validated envelope");
        let spec = fake_child_process_spec();
        let working_directory = fake_child_working_directory();
        for (secret, expected) in [
            (&b""[..], "credential_empty"),
            (&b" leading"[..], "credential_invalid_header"),
            (&b"trailing "[..], "credential_invalid_header"),
            (&b"line\nfeed"[..], "credential_invalid_header"),
            (&b"\xc3\xa9"[..], "credential_invalid_header"),
            (&[0xff_u8][..], "credential_invalid_utf8"),
        ] {
            let error = fwc_n8n_bridge::run_process(
                &spec,
                &envelope,
                ZeroizingSecret::from(secret),
                &working_directory,
                Instant::now() + std::time::Duration::from_secs(30),
            )
            .expect_err("invalid secret");
            assert_eq!(error.code(), expected);
        }
        let oversized = vec![b'a'; 4097];
        let error = fwc_n8n_bridge::run_process(
            &spec,
            &envelope,
            ZeroizingSecret::from(oversized.as_slice()),
            &working_directory,
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .expect_err("oversized secret");
        assert_eq!(error.code(), "credential_oversized");
    }

    fn host_input(server_id: HostRunOnceServerId, input: Value) -> HostRunOnceInput {
        HostRunOnceInput {
            server_id,
            input,
            approval_token: None,
            deadline_ms: None,
            correlation_id: None,
        }
    }

    #[test]
    fn host_run_once_maps_allowed_operations_to_canonical_resources() {
        let cases = [
            (
                "n8n.capabilities.inspect",
                json!({}),
                "fwc-mcp-bridge://eec",
            ),
            ("n8n.credentials.list", json!({}), "fwc-n8n://eec"),
            (
                "n8n.executions.get",
                json!({"workflow_id": "workflow-1", "id": "execution-1"}),
                "fwc-n8n://eec/workflows/workflow%2D1/executions/execution%2D1",
            ),
            ("n8n.executions.list", json!({}), "fwc-n8n://eec"),
            (
                "n8n.folders.get",
                json!({"project_id": "project-1", "folder_id": "folder-1"}),
                "fwc-n8n://eec/folders/folder%2D1",
            ),
            (
                "n8n.folders.list",
                json!({"project_id": "project-1"}),
                "fwc-n8n://eec/projects/project%2D1",
            ),
            ("n8n.projects.list", json!({}), "fwc-n8n://eec"),
            ("n8n.tags.list", json!({}), "fwc-n8n://eec"),
            (
                "n8n.workflows.get",
                json!({"id": "workflow-1"}),
                "fwc-n8n://eec/workflows/workflow%2D1",
            ),
            (
                "n8n.workflows.lifecycle",
                json!({
                    "id": "workflow-1",
                    "action": "publish",
                    "guard": {
                        "approvalRef": "chat-approval-publish",
                        "idempotencyKey": "33333333-4444-4555-8666-777777777777",
                        "precondition": {
                            "versionId": "version-1",
                            "activeVersionId": null,
                            "active": false,
                            "isArchived": false,
                            "stateDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    }
                }),
                "fwc-mcp-bridge://eec/tools/publish%5Fworkflow",
            ),
            (
                "n8n.workflows.lifecycle",
                json!({
                    "id": "workflow-1",
                    "action": "unpublish",
                    "guard": {
                        "approvalRef": "chat-approval-unpublish",
                        "idempotencyKey": "44444444-5555-4666-8777-888888888888",
                        "precondition": {
                            "versionId": "version-1",
                            "activeVersionId": "version-1",
                            "active": true,
                            "isArchived": false,
                            "stateDigest": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        }
                    }
                }),
                "fwc-mcp-bridge://eec/tools/unpublish%5Fworkflow",
            ),
            ("n8n.workflows.list", json!({}), "fwc-n8n://eec"),
            (
                "n8n.workflows.create_draft",
                json!({
                    "name": "Draft",
                    "project_id": "project-1",
                    "graph": {"nodes": [], "connections": {}},
                    "guard": {
                        "approvalRef": "chat-approval-1",
                        "idempotencyKey": "11111111-2222-4333-8444-555555555555",
                        "precondition": {}
                    }
                }),
                "fwc-n8n://eec/projects/project%2D1",
            ),
            (
                "n8n.workflows.create_draft",
                json!({
                    "name": "Personal draft",
                    "graph": {"nodes": [], "connections": {}},
                    "guard": {
                        "approvalRef": "chat-approval-personal",
                        "idempotencyKey": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                        "precondition": {}
                    }
                }),
                "fwc-n8n://eec",
            ),
            (
                "n8n.workflows.update_draft",
                json!({
                    "id": "workflow-1",
                    "graph": {"nodes": [], "connections": {}},
                    "guard": {
                        "approvalRef": "chat-approval-2",
                        "idempotencyKey": "22222222-3333-4444-8555-666666666666",
                        "precondition": {
                            "versionId": "version-1",
                            "activeVersionId": null,
                            "active": false,
                            "isArchived": false,
                            "stateDigest": "blake3-256:state"
                        }
                    }
                }),
                "fwc-n8n://eec/workflows/workflow%2D1",
            ),
        ];

        for (operation, input, resource_uri) in cases {
            let operation = HostRunOnceOperation::parse(operation).expect("closed operation");
            let envelope = build_host_run_once_envelope(
                operation,
                host_input(HostRunOnceServerId::Eec, input),
            )
            .expect("valid host envelope");
            assert_eq!(envelope.schema, HOST_RUN_ONCE_SCHEMA);
            assert_eq!(envelope.zone_id, HOST_RUN_ONCE_ZONE);
            assert_eq!(envelope.resource_uri, resource_uri);
            assert_eq!(
                envelope.deadline_ms,
                Some(HOST_RUN_ONCE_DEFAULT_DEADLINE_MS)
            );
        }
    }

    #[test]
    fn credential_purpose_is_closed_by_operation() {
        assert_eq!(
            HostRunOnceOperation::CapabilitiesInspect.credential_purpose(),
            BrokerCredentialPurpose::OfficialMcp
        );
        assert_eq!(
            HostRunOnceOperation::WorkflowsGet.credential_purpose(),
            BrokerCredentialPurpose::RestApi
        );
    }

    #[test]
    fn host_run_once_disposable_delete_binds_receipt_and_workflow_resource() {
        let operation = HostRunOnceOperation::parse("n8n.workflows.delete_disposable")
            .expect("closed disposable delete operation");
        let input = json!({
            "id": "workflow-1",
            "creationReceipt": format!("blake3-256:{}", "0".repeat(64)),
            "guard": {
                "approvalRef": "chat-disposable-delete",
                "idempotencyKey": "55555555-6666-4777-8888-999999999999",
                "precondition": {
                    "versionId": "draft-v1",
                    "activeVersionId": null,
                    "active": false,
                    "isArchived": false,
                    "stateDigest": format!("blake3-256:{}", "1".repeat(64)),
                }
            }
        });
        let envelope = build_host_run_once_envelope(
            operation,
            host_input(HostRunOnceServerId::Hetzner, input),
        )
        .expect("valid disposable delete envelope");
        assert_eq!(
            envelope.resource_uri,
            "fwc-n8n://hetzner/workflows/workflow%2D1"
        );
        assert_eq!(
            operation.credential_purpose(),
            BrokerCredentialPurpose::RestApi
        );
    }

    #[test]
    fn official_mcp_catalog_is_compacted_and_untrusted_text_is_removed() {
        let response = json!({
            "type": "response",
            "id": "request-1",
            "status": "ok",
            "result": {
                "tools": [
                    {
                        "name": "z_tool",
                        "description": "PRIVATE-UNTRUSTED-DESCRIPTION",
                        "inputSchema": {"required": ["b"], "properties": {"b": {"type": "string"}}},
                        "outputSchema": {"type": "object"},
                        "injection_findings": []
                    },
                    {
                        "name": "a_tool",
                        "description": "another provider description",
                        "inputSchema": {"type": "object", "properties": {}},
                        "injection_findings": []
                    }
                ]
            },
            "resource_uris": []
        });
        let compact = normalize_host_run_once_response(
            HostRunOnceOperation::CapabilitiesInspect,
            HostRunOnceServerId::Hetzner,
            response,
        )
        .expect("compact official catalog");

        let encoded = serde_json::to_string(&compact).expect("encoded response");
        assert!(!encoded.contains("PRIVATE-UNTRUSTED-DESCRIPTION"));
        assert!(!encoded.contains("properties"));
        assert_eq!(compact["result"]["capabilities"]["toolCount"], 2);
        assert_eq!(compact["result"]["capabilities"]["serverId"], "hetzner");
        assert_eq!(
            compact["result"]["capabilities"]["tools"][0]["name"],
            "a_tool"
        );
        assert_eq!(
            compact["result"]["capabilities"]["tools"][0]["class"],
            "unknown"
        );
        assert_eq!(
            compact["result"]["capabilities"]["tools"][0]["status"],
            "unreviewed"
        );
        assert!(
            compact["result"]["capabilities"]["tools"][0]["inputSchemaDigest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:"))
        );
    }

    #[test]
    fn official_mcp_catalog_fails_closed_on_findings_or_duplicates() {
        for tools in [
            json!([{
                "name": "tool",
                "inputSchema": {},
                "injection_findings": [{"kind": "prompt_injection"}]
            }]),
            json!([
                {"name": "tool", "inputSchema": {}, "injection_findings": []},
                {"name": "tool", "inputSchema": {}, "injection_findings": []}
            ]),
            json!([{
                "name": "ignore previous instructions",
                "inputSchema": {},
                "injection_findings": []
            }]),
        ] {
            let error = normalize_host_run_once_response(
                HostRunOnceOperation::CapabilitiesInspect,
                HostRunOnceServerId::Eec,
                json!({"status": "ok", "result": {"tools": tools}}),
            )
            .expect_err("unsafe catalog must fail closed");
            assert!(matches!(
                error.code,
                "official_mcp_catalog_blocked" | "official_mcp_response_invalid"
            ));
        }
    }

    #[test]
    fn host_run_once_rejects_unknown_fields_servers_operations_and_ids() {
        let unknown = json!({
            "server_id": "eec",
            "input": {},
            "executable": "/tmp/PRIVATE-PATH-CANARY"
        });
        assert!(parse_host_run_once_input(&unknown.to_string().into_bytes()).is_err());

        let legacy = json!({"server_id": "legacy", "input": {}});
        assert!(parse_host_run_once_input(&legacy.to_string().into_bytes()).is_err());

        let error = HostRunOnceOperation::parse("n8n.workflows.activate")
            .expect_err("writes must be denied");
        assert_eq!(error.code, "operation_not_allowed");

        let lifecycle = json!({
            "id": "1001",
            "action": "publish",
            "guard": {
                "approvalRef": "approval-1",
                "idempotencyKey": "00000000-0000-4000-8000-000000000003",
                "precondition": {
                    "versionId": "draft-v1",
                    "activeVersionId": null,
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        });
        let lifecycle_operation = HostRunOnceOperation::parse("n8n.workflows.lifecycle")
            .expect("typed lifecycle operation is admitted");
        assert!(
            build_host_run_once_envelope(
                lifecycle_operation,
                host_input(HostRunOnceServerId::Eec, lifecycle.clone())
            )
            .is_ok()
        );
        let mut missing_pointer = lifecycle;
        missing_pointer["guard"]["precondition"]
            .as_object_mut()
            .expect("precondition object")
            .remove("activeVersionId");
        assert!(
            build_host_run_once_envelope(
                lifecycle_operation,
                host_input(HostRunOnceServerId::Eec, missing_pointer)
            )
            .is_err()
        );

        for (operation, input) in [
            ("n8n.workflows.get", json!({"id": "id/../admin"})),
            (
                "n8n.executions.get",
                json!({"workflow_id": "workflow-1", "id": "id?query"}),
            ),
            (
                "n8n.folders.get",
                json!({"project_id": "project-1", "folder_id": "id%2Fadmin"}),
            ),
            ("n8n.folders.list", json!({"project_id": "id\\admin"})),
        ] {
            let operation = HostRunOnceOperation::parse(operation).expect("closed operation");
            let error = build_host_run_once_envelope(
                operation,
                host_input(HostRunOnceServerId::Eec, input),
            )
            .expect_err("unsafe resource ID must be denied");
            assert_eq!(error.code, "invalid_resource_id");
        }

        for (operation, input) in [
            (
                "n8n.capabilities.inspect",
                json!({"tool_name": "n8n_update_full_workflow"}),
            ),
            ("n8n.workflows.list", json!({"api_key": "PRIVATE-KEY"})),
            (
                "n8n.executions.list",
                json!({"authorization": "PRIVATE-TOKEN"}),
            ),
            ("n8n.workflows.get", json!({})),
            ("n8n.credentials.list", json!({"limit": 201})),
            ("n8n.folders.list", json!({"project_id": "p", "skip": -1})),
        ] {
            let operation = HostRunOnceOperation::parse(operation).expect("closed operation");
            let error = build_host_run_once_envelope(
                operation,
                host_input(HostRunOnceServerId::Eec, input),
            )
            .expect_err("unknown, secret, missing, or out-of-range input must be denied");
            assert_eq!(error.code, "invalid_operation_input");
        }

        let create_with_id = json!({
            "id": "workflow-1",
            "name": "Draft",
            "project_id": "project-1",
            "graph": {"nodes": [], "connections": {}},
            "guard": {
                "approvalRef": "approval",
                "idempotencyKey": "11111111-2222-4333-8444-555555555555",
                "precondition": {}
            }
        });
        let operation =
            HostRunOnceOperation::parse("n8n.workflows.create_draft").expect("create operation");
        assert_eq!(
            build_host_run_once_envelope(
                operation,
                host_input(HostRunOnceServerId::Eec, create_with_id),
            )
            .expect_err("create must reject caller-selected id")
            .code,
            "invalid_operation_input"
        );

        let update_without_active_version = json!({
            "id": "workflow-1",
            "graph": {"nodes": [], "connections": {}},
            "guard": {
                "approvalRef": "approval",
                "idempotencyKey": "22222222-3333-4444-8555-666666666666",
                "precondition": {
                    "versionId": "version-1",
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:state"
                }
            }
        });
        let operation =
            HostRunOnceOperation::parse("n8n.workflows.update_draft").expect("update operation");
        assert_eq!(
            build_host_run_once_envelope(
                operation,
                host_input(HostRunOnceServerId::Eec, update_without_active_version),
            )
            .expect_err("update must require explicit activeVersionId")
            .code,
            "invalid_operation_input"
        );
    }

    #[test]
    fn host_run_once_redacts_input_from_debug_and_errors() {
        let canary = "PRIVATE-HOST-DTO-CANARY";
        let input = host_input(HostRunOnceServerId::Hetzner, json!({"id": canary}));
        let debug = format!("{input:?}");
        assert!(!debug.contains(canary));

        let envelope = build_host_run_once_envelope(HostRunOnceOperation::WorkflowsGet, input)
            .expect("valid envelope");
        assert!(!format!("{envelope:?}").contains(canary));

        let error = run_once_from_bytes_at(
            "n8n.workflows.get",
            br#"{"server_id":"eec","input":{"id":"workflow-1","marker":"PRIVATE-HOST-DTO-CANARY"}}"#,
            Instant::now(),
            |_, _| panic!("invalid request must not dispatch"),
        )
        .expect_err("bridge remains fail-closed");
        assert!(!format!("{error:?}").contains(canary));
    }

    #[test]
    fn route_known_read_prefers_typed_rest() {
        let query = TargetQuery {
            workflow_provenance: Some(
                fcp_n8n::router::WorkflowIdProvenance::new(ServerId::Eec, "wf-1")
                    .expect("workflow provenance"),
            ),
            ..TargetQuery::default()
        };
        let resolution = TargetResolver::resolve(&query).expect("resolution");
        let target = exact_target(&resolution).expect("exact target");
        let capabilities = CapabilitySnapshot::default()
            .with(Provider::TypedRest, ProviderCapability::KnownIdRead);
        let route =
            ProviderRouter::route(OperationIntent::KnownIdRead, Some(target), &capabilities)
                .expect("known ID route");
        assert_eq!(route.selected, Provider::TypedRest);
    }

    fn safe_update_snapshot(version: &str) -> ComponentSnapshot {
        ComponentSnapshot {
            component: fcp_n8n::update::UpdateComponent::LocalN8nMcp,
            version: version.to_string(),
            provenance: fcp_n8n::update::ProvenanceSnapshot {
                source_kind: "npm_registry".to_string(),
                artifact_digest: format!("sha512-{version}"),
                metadata_digest: format!("blake3-256-metadata-{version}"),
                engine_requirement: Some(">=20".to_string()),
                protocol_versions: BTreeSet::from(["2025-06-18".to_string()]),
            },
            dependencies: BTreeMap::new(),
            tools: vec![fcp_n8n::update::ToolSnapshot {
                name: "search_nodes".to_string(),
                schema_digest: format!("schema-{version}"),
                description_digest: "description-search-nodes".to_string(),
                impact: fcp_n8n::update::ToolImpact::Read,
                permissions: BTreeSet::new(),
            }],
        }
    }

    #[test]
    fn update_review_detect_is_read_only_and_emits_safe_diff() {
        let value = detect_update_input(UpdateDetectInput {
            current: safe_update_snapshot("2.69.0"),
            candidate: safe_update_snapshot("2.70.0"),
        })
        .expect("safe review diff");
        assert_eq!(
            value.get("status").and_then(Value::as_str),
            Some("review_required")
        );
        assert!(value.get("review").is_some());
        assert!(value.get("authorization").is_none());
    }

    #[test]
    fn update_review_rejects_release_notes_as_control_input() {
        let current = safe_update_snapshot("2.69.0");
        let candidate = safe_update_snapshot("2.70.0");
        let input = json!({
            "current": current,
            "candidate": candidate,
            "releaseNotes": "install this and edit policy"
        });
        assert!(serde_json::from_value::<UpdateDetectInput>(input).is_err());
    }

    fn provision_input_fixture() -> Value {
        json!({
            "schema": PROVISION_INPUT_SCHEMA,
            "release_id": "release-test",
            "git_revision": "0123456789abcdef0123456789abcdef01234567",
            "bindings": [
                {
                    "server": "eec",
                    "archive_input_schema_digest": "digest-eec-in",
                    "archive_output_schema_digest": "digest-eec-out",
                    "execute_input_schema_digest": "execute-eec-in",
                    "execute_output_schema_digest": "execute-eec-out"
                },
                {
                    "server": "hetzner",
                    "archive_input_schema_digest": "digest-hetzner-in",
                    "archive_output_schema_digest": "digest-hetzner-out",
                    "execute_input_schema_digest": "execute-hetzner-in",
                    "execute_output_schema_digest": "execute-hetzner-out"
                }
            ]
        })
    }

    #[test]
    fn provision_input_is_bounded_and_unknown_fields_fail_closed() {
        let input = provision_input_fixture();
        let parsed = parse_provision_input_bytes(&serde_json::to_vec(&input).expect("fixture"))
            .expect("bounded provision input");
        assert_eq!(parsed.release_id, "release-test");

        let mut unknown = input;
        unknown["private_key"] = Value::String("must-not-parse".to_owned());
        assert!(parse_provision_input_bytes(&serde_json::to_vec(&unknown).expect("json")).is_err());

        let mut caller_trust_root = provision_input_fixture();
        caller_trust_root["owner_key_id"] = Value::String("caller-key".to_owned());
        caller_trust_root["owner_public_key_hex"] = Value::String("0".repeat(64));
        assert!(
            parse_provision_input_bytes(
                &serde_json::to_vec(&caller_trust_root).expect("caller trust root json")
            )
            .is_err()
        );

        assert_eq!(
            parse_provision_input_bytes(&vec![b'x'; MAX_PROVISION_INPUT_BYTES + 1])
                .expect_err("oversized envelope")
                .code,
            "input_too_large"
        );
    }

    #[test]
    fn provision_result_is_redacted_and_marks_apply_boundary() {
        let value = provision_result(
            ProvisionMode::Preflight,
            "release-test",
            "preflight_ok",
            false,
        );
        assert_eq!(
            value.get("status").and_then(Value::as_str),
            Some("preflight_ok")
        );
        assert_eq!(value.get("currentChanged"), Some(&Value::Bool(false)));
        assert_eq!(
            value.get("rollback").and_then(Value::as_str),
            Some("separate_owner_gated_boundary")
        );
        assert!(!value.to_string().contains("public_key"));
        assert!(!value.to_string().contains("signature"));
    }

    #[test]
    fn status_reports_only_bundle_availability_without_process_scan() {
        let value = execute(Cli {
            command: Command::Status,
        })
        .expect("status");
        assert_eq!(
            value.get("bundleAvailable").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(value.as_object().expect("status object").len(), 1);
    }
}
