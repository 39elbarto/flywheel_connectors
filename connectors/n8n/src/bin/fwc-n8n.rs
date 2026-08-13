//! Compact, provider-neutral n8n entry point.
//!
//! The thin wrapper resolves and routes typed operations. Provider execution
//! remains host-owned and fails closed until that dispatch is wired.

use std::io::{self, Read};

use clap::{Parser, Subcommand};
use fcp_n8n::router::{
    CapabilitySnapshot, OperationIntent, ProviderRouter, ResolvedTarget, TargetQuery,
    TargetResolution, TargetResolver,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

const MAX_INPUT_BYTES: usize = 256 * 1024;

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
    public_operation_intent(operation)?;
    Err(AppError::new("provider_not_wired"))
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
    fn local_run_once_fails_closed_before_payload_read() {
        let error = run_once("n8n.knowledge.query").expect_err("must remain host-owned");
        assert_eq!(error.code, "provider_not_wired");
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
