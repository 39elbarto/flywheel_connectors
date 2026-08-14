//! Compact, provider-neutral n8n entry point.
//!
//! The thin wrapper resolves and routes typed operations. Provider execution
//! remains host-owned and fails closed until that dispatch is wired.

use std::{fmt, io, io::Read};

use clap::{Parser, Subcommand};
use fcp_n8n::router::{
    CapabilitySnapshot, OperationIntent, ProviderRouter, ResolvedTarget, TargetQuery,
    TargetResolution, TargetResolver,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[path = "fwc_n8n_bundle.rs"]
mod fwc_n8n_bundle;

const MAX_INPUT_BYTES: usize = 256 * 1024;
const HOST_RUN_ONCE_SCHEMA: &str = "fwc.n8n.host-run-once.v1";
const HOST_RUN_ONCE_ZONE: &str = "z:work";
const HOST_RUN_ONCE_DEFAULT_DEADLINE_MS: u64 = 30_000;
const HOST_RUN_ONCE_MAX_DEADLINE_MS: u64 = 60_000;

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
    /// Report this request-scoped wrapper's idle state.
    Status,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteInput {
    target: TargetQuery,
    capabilities: CapabilitySnapshot,
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
}

impl HostRunOnceOperation {
    fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "n8n.credentials.list" => Ok(Self::CredentialsList),
            "n8n.executions.get" => Ok(Self::ExecutionsGet),
            "n8n.executions.list" => Ok(Self::ExecutionsList),
            "n8n.folders.get" => Ok(Self::FoldersGet),
            "n8n.folders.list" => Ok(Self::FoldersList),
            "n8n.projects.list" => Ok(Self::ProjectsList),
            "n8n.tags.list" => Ok(Self::TagsList),
            "n8n.workflows.get" => Ok(Self::WorkflowsGet),
            "n8n.workflows.list" => Ok(Self::WorkflowsList),
            _ => Err(AppError::new("operation_not_allowed")),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRunOnceInput {
    server_id: HostRunOnceServerId,
    input: Value,
    #[serde(default)]
    deadline_ms: Option<u64>,
    #[serde(default)]
    correlation_id: Option<String>,
}

impl fmt::Debug for HostRunOnceInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRunOnceInput")
            .field("server_id", &self.server_id)
            .field("input", &"[REDACTED]")
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
    correlation_id: String,
}

#[derive(Debug)]
struct AppError {
    code: &'static str,
}

impl AppError {
    const fn new(code: &'static str) -> Self {
        Self { code }
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
                print_error("output_encoding_failed", &correlation_id);
                std::process::exit(1);
            }
        }
        Err(error) => {
            print_error(error.code, &correlation_id);
            std::process::exit(1);
        }
    }
}

fn print_error(code: &str, correlation_id: &str) {
    let envelope = ErrorEnvelope {
        schema: "fwc.n8n.error.v1",
        status: "error",
        code: code.to_string(),
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
        Command::Status => Ok(json!({
            "bundleAvailable": fwc_n8n_bundle::verify_current_release_bundle().is_ok(),
        })),
    }
}

fn run_once(operation: &str) -> Result<Value, AppError> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| AppError::new("input_read_failed"))?;
    run_once_from_bytes(operation, &bytes)
}

fn run_once_from_bytes(operation: &str, bytes: &[u8]) -> Result<Value, AppError> {
    let operation = HostRunOnceOperation::parse(operation)?;
    let input = parse_host_run_once_input(bytes)?;
    let envelope = build_host_run_once_envelope(operation, input)?;
    serde_json::to_value(envelope).map_err(|_| AppError::new("output_encoding_failed"))?;
    Err(AppError::new("bridge_not_wired"))
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
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || required.iter().any(|key| !object.contains_key(*key))
    {
        return Err(AppError::new("invalid_operation_input"));
    }

    match operation {
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
    }
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
        HostRunOnceOperation::CredentialsList
        | HostRunOnceOperation::ExecutionsList
        | HostRunOnceOperation::ProjectsList
        | HostRunOnceOperation::TagsList
        | HostRunOnceOperation::WorkflowsList => Ok(root),
        HostRunOnceOperation::WorkflowsGet => Ok(format!(
            "{root}/workflows/{}",
            encode_host_resource_segment(host_run_once_input_id(input, "id")?)
        )),
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
        _ => return Err(AppError::new("unknown_public_operation")),
    };
    Ok(intent)
}

fn read_stdin_json<T>() -> Result<T, AppError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| AppError::new("input_read_failed"))?;
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

    #[cfg(target_os = "linux")]
    use fcp_crypto::ZeroizingSecret;
    #[cfg(target_os = "linux")]
    use fcp_sandbox::{
        FCP_HOST_RUN_ONCE_CREDENTIAL_FD, FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT,
        FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT_VALUE, OwnedProcess, ProcessSpec, TerminationReport,
        claim_inherited_host_egress_channel,
    };
    #[cfg(target_os = "linux")]
    use std::collections::BTreeMap;
    #[cfg(target_os = "linux")]
    use std::io::{Read, Write};
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixStream;
    #[cfg(target_os = "linux")]
    use std::process::{ChildStderr, ChildStdin, ChildStdout, ExitStatus};
    #[cfg(target_os = "linux")]
    use std::sync::mpsc::{self, Receiver};
    #[cfg(target_os = "linux")]
    use std::thread::{self, JoinHandle};
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    #[cfg(target_os = "linux")]
    const FAKE_CHILD_ENV: &str = "FWC_N8N_FAKE_CHILD";
    #[cfg(target_os = "linux")]
    const FAKE_CHILD_OUTPUT_MARKER: &str = "FWC_N8N_FAKE_JSON:";
    #[cfg(target_os = "linux")]
    const MAX_BRIDGE_OUTPUT_BYTES: usize = 64 * 1024;
    #[cfg(target_os = "linux")]
    const MAX_BRIDGE_STDERR_BYTES: usize = 16 * 1024;

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
    fn encode_fake_credential_frame(secret: &[u8]) -> Result<ZeroizingSecret, AppError> {
        validate_fake_credential(secret)?;
        let mut frame = Vec::with_capacity(9 + secret.len());
        frame.extend_from_slice(b"FCPK");
        frame.push(1);
        let length =
            u32::try_from(secret.len()).map_err(|_| AppError::new("credential_oversized"))?;
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(secret);
        Ok(ZeroizingSecret::with_zeroize_drop(frame))
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
    fn spawn_bounded_reader<R: Read + Send + 'static>(
        mut reader: R,
        max_bytes: usize,
    ) -> (Receiver<Result<Vec<u8>, AppError>>, JoinHandle<()>) {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            let mut output = Vec::with_capacity(max_bytes.min(4096));
            let mut buffer = [0_u8; 4096];
            let result = loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break Ok(output),
                    Ok(bytes) => {
                        if output.len().saturating_add(bytes) > max_bytes {
                            break Err(AppError::new("bridge_output_too_large"));
                        }
                        output.extend_from_slice(&buffer[..bytes]);
                    }
                    Err(_) => break Err(AppError::new("bridge_output_read_failed")),
                }
            };
            let _ = sender.send(result);
        });
        (receiver, join)
    }

    #[cfg(target_os = "linux")]
    fn spawn_stdin_writer(
        mut stdin: ChildStdin,
        envelope: Vec<u8>,
    ) -> (Receiver<Result<(), AppError>>, JoinHandle<()>) {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            let result = stdin
                .write_all(&envelope)
                .map_err(|_| AppError::new("bridge_stdin_write_failed"));
            drop(stdin);
            let _ = sender.send(result);
        });
        (receiver, join)
    }

    #[cfg(target_os = "linux")]
    fn cleanup_fake_process(
        process: &mut OwnedProcess,
        workers: Vec<JoinHandle<()>>,
    ) -> Result<TerminationReport, AppError> {
        let termination = process
            .terminate(Duration::from_millis(100))
            .map_err(|_| AppError::new("bridge_teardown_failed"))?;
        if !termination.group_absent {
            return Err(AppError::new("bridge_group_present"));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_| AppError::new("bridge_io_worker_failed"))?;
        }
        Ok(termination)
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
        {
            return Err(AppError::new("bridge_output_mismatch"));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_lines)] // Keeps the test-only launch lifecycle visible in one place.
    fn run_fake_bridge(
        envelope: &HostRunOnceEnvelope,
        secret: &[u8],
        timeout: Duration,
    ) -> Result<BridgeObservation, AppError> {
        let envelope_bytes = serde_json::to_vec(envelope)
            .map_err(|_| AppError::new("bridge_envelope_encode_failed"))?;
        if envelope_bytes.len() > MAX_INPUT_BYTES {
            return Err(AppError::new("bridge_envelope_too_large"));
        }
        let credential_frame = encode_fake_credential_frame(secret)?;
        let credential_bytes = secret.len();
        let (mut host_endpoint, child_endpoint) =
            UnixStream::pair().map_err(|_| AppError::new("bridge_channel_failed"))?;
        let mut process = OwnedProcess::spawn_with_run_once_credential_channel(
            &fake_child_process_spec(),
            child_endpoint,
        )
        .map_err(|_| AppError::new("bridge_spawn_failed"))?;
        let stdin = process
            .take_stdin()
            .ok_or_else(|| AppError::new("bridge_stdin_unavailable"))?;
        let stdout: ChildStdout = process
            .take_stdout()
            .ok_or_else(|| AppError::new("bridge_stdout_unavailable"))?;
        let stderr: ChildStderr = process
            .take_stderr()
            .ok_or_else(|| AppError::new("bridge_stderr_unavailable"))?;
        let (stdin_rx, stdin_join) = spawn_stdin_writer(stdin, envelope_bytes.clone());
        let (stdout_rx, stdout_join) = spawn_bounded_reader(stdout, MAX_BRIDGE_OUTPUT_BYTES);
        let (stderr_rx, stderr_join) = spawn_bounded_reader(stderr, MAX_BRIDGE_STDERR_BYTES);
        let workers = vec![stdin_join, stdout_join, stderr_join];

        let write_result = credential_frame.with_bytes(|frame| host_endpoint.write_all(frame));
        drop(credential_frame);
        drop(host_endpoint);
        if write_result.is_err() {
            cleanup_fake_process(&mut process, workers)?;
            return Err(AppError::new("bridge_credential_write_failed"));
        }

        let deadline = Instant::now() + timeout;
        let mut child_status = None;
        let mut stdin_result = None;
        let mut stdout_result = None;
        let mut stderr_result = None;
        let mut failure = None;
        while Instant::now() < deadline {
            if child_status.is_none() {
                match process.try_wait() {
                    Ok(status) => child_status = status,
                    Err(_) => failure = Some("bridge_wait_failed"),
                }
            }
            if stdin_result.is_none() {
                if let Ok(result) = stdin_rx.try_recv() {
                    stdin_result = Some(result);
                }
            }
            if stdout_result.is_none() {
                if let Ok(result) = stdout_rx.try_recv() {
                    stdout_result = Some(result);
                }
            }
            if stderr_result.is_none() {
                if let Ok(result) = stderr_rx.try_recv() {
                    stderr_result = Some(result);
                }
            }
            if failure.is_some()
                || stdin_result.as_ref().is_some_and(Result::is_err)
                || stdout_result.as_ref().is_some_and(Result::is_err)
                || stderr_result.as_ref().is_some_and(Result::is_err)
            {
                failure = failure.or(Some("bridge_io_failed"));
                break;
            }
            if child_status.is_some()
                && stdin_result.is_some()
                && stdout_result.is_some()
                && stderr_result.is_some()
            {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }

        if child_status.is_none()
            || stdin_result.is_none()
            || stdout_result.is_none()
            || stderr_result.is_none()
        {
            failure = failure.or(Some("bridge_timeout"));
        }
        if let Some(code) = failure {
            cleanup_fake_process(&mut process, workers)?;
            return Err(AppError::new(code));
        }

        let status = child_status.expect("child status after bounded wait");
        let stdout = stdout_result
            .expect("stdout result after bounded wait")
            .expect("stdout read success");
        let stderr = stderr_result
            .expect("stderr result after bounded wait")
            .expect("stderr read success");
        stdin_result
            .expect("stdin result after bounded wait")
            .expect("stdin write success");
        let termination = cleanup_fake_process(&mut process, workers)?;
        if !status.success() {
            return Err(AppError::new("bridge_child_failed"));
        }
        parse_fake_child_output(&stdout, envelope_bytes.len(), credential_bytes)?;
        Ok(BridgeObservation {
            envelope_bytes: envelope_bytes.len(),
            credential_bytes,
            stdout_bytes: stdout.len(),
            stderr_bytes: stderr.len(),
            child_status: status,
            termination,
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
    #[test]
    fn run_once_bridge_child_probe() {
        if std::env::var_os(FAKE_CHILD_ENV).is_none() {
            return;
        }
        let result = (|| -> Result<(), ()> {
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
            println!(
                "{FAKE_CHILD_OUTPUT_MARKER}{}",
                json!({
                    "schema": "fwc.n8n.fake-child.v1",
                    "status": "ok",
                    "envelopeBytes": envelope.len(),
                    "credentialBytes": length,
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

    #[test]
    fn run_once_fails_closed_after_strict_validation() {
        let error = run_once_from_bytes("n8n.workflows.list", br#"{"server_id":"eec","input":{}}"#)
            .expect_err("must remain host-owned");
        assert_eq!(error.code, "bridge_not_wired");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_once_fake_parent_bridge_roundtrip_is_bounded_and_group_owned() {
        let operation = HostRunOnceOperation::parse("n8n.workflows.get").expect("operation");
        let envelope = build_host_run_once_envelope(
            operation,
            host_input(HostRunOnceServerId::Eec, json!({"id": "workflow-1"})),
        )
        .expect("validated envelope");
        let observation = run_fake_bridge(
            &envelope,
            b"FAKE-ROUNDTRIP-API-KEY",
            Duration::from_secs(10),
        )
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
    fn run_once_fake_credential_frame_rejects_malformed_material_before_spawn() {
        for (secret, expected) in [
            (&b""[..], "credential_empty"),
            (&b" leading"[..], "credential_invalid_header"),
            (&b"trailing "[..], "credential_invalid_header"),
            (&b"line\nfeed"[..], "credential_invalid_header"),
            (&[0xff_u8][..], "credential_invalid_utf8"),
        ] {
            let error = encode_fake_credential_frame(secret).expect_err("invalid secret");
            assert_eq!(error.code, expected);
        }
        let oversized = vec![b'a'; 4097];
        let error = encode_fake_credential_frame(&oversized).expect_err("oversized secret");
        assert_eq!(error.code, "credential_oversized");
    }

    fn host_input(server_id: HostRunOnceServerId, input: Value) -> HostRunOnceInput {
        HostRunOnceInput {
            server_id,
            input,
            deadline_ms: None,
            correlation_id: None,
        }
    }

    #[test]
    fn host_run_once_maps_all_nine_operations_to_canonical_resources() {
        let cases = [
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
            ("n8n.workflows.list", json!({}), "fwc-n8n://eec"),
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

        let error = run_once_from_bytes(
            "n8n.workflows.get",
            br#"{"server_id":"eec","input":{"id":"workflow-1","marker":"PRIVATE-HOST-DTO-CANARY"}}"#,
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
