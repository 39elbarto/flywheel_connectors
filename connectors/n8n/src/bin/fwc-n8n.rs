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
            "schema": "fwc.n8n.status.v1",
            "scope": "request_process",
            "idle": true,
            "activeRuns": 0,
            "providers": []
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
    fn status_is_idle_and_does_not_scan_processes() {
        let value = execute(Cli {
            command: Command::Status,
        })
        .expect("status");
        assert_eq!(value["idle"], true);
        assert_eq!(value["scope"], "request_process");
        assert_eq!(value["activeRuns"], 0);
        assert_eq!(value["providers"], json!([]));
    }
}
