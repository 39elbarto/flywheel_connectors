//! `fcp new` command implementation.
//!
//! Scaffolds new FCP2-compliant connector crates with correct structure,
//! manifest, and compliance prechecks.
//!
//! # Usage
//!
//! ```text
//! # Create a new connector
//! fcp new fcp.myservice
//! fcp new fcp.myservice --archetype streaming
//! fcp new fcp.myservice --zone z:project:myapp
//!
//! # Preview without writing
//! fcp new fcp.myservice --dry-run
//!
//! # Check an existing connector
//! fcp new --check connectors/myservice
//! ```

pub mod types;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use fcp_core::validate_canonical_id;
use fcp_manifest::{ConnectorManifest, ManifestError};

use types::{
    CheckResult, CheckSeverity, ConnectorArchetype, CreatedFile, PrecheckItem, PrecheckResults,
    ScaffoldResult, SuggestedFix,
};

/// Arguments for the `fcp new` command.
#[derive(Args, Debug)]
pub struct NewArgs {
    /// Connector ID (e.g., "fcp.myservice").
    ///
    /// Must start with "fcp." and contain only alphanumeric characters and dots.
    #[arg(required_unless_present = "check")]
    pub connector_id: Option<String>,

    /// Connector archetype.
    #[arg(long, short = 'a', value_enum, default_value_t = ArchetypeArg::RequestResponse)]
    pub archetype: ArchetypeArg,

    /// Zone binding (e.g., "z:project:myapp").
    #[arg(long, short = 'z', default_value = "z:project:default")]
    pub zone: String,

    /// Skip E2E test scaffolding.
    #[arg(long)]
    pub no_e2e: bool,

    /// Preview planned files without writing.
    #[arg(long)]
    pub dry_run: bool,

    /// Validate an existing connector directory instead of creating new.
    #[arg(long, value_name = "PATH")]
    pub check: Option<PathBuf>,

    /// Output JSON instead of human-readable format.
    #[arg(long)]
    pub json: bool,
}

/// Archetype argument enum (for clap's `ValueEnum` derive).
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ArchetypeArg {
    #[default]
    RequestResponse,
    Streaming,
    Bidirectional,
    Polling,
    Webhook,
    Queue,
    File,
    Database,
    Cli,
    Browser,
}

impl From<ArchetypeArg> for ConnectorArchetype {
    fn from(arg: ArchetypeArg) -> Self {
        match arg {
            ArchetypeArg::RequestResponse => Self::RequestResponse,
            ArchetypeArg::Streaming => Self::Streaming,
            ArchetypeArg::Bidirectional => Self::Bidirectional,
            ArchetypeArg::Polling => Self::Polling,
            ArchetypeArg::Webhook => Self::Webhook,
            ArchetypeArg::Queue => Self::Queue,
            ArchetypeArg::File => Self::File,
            ArchetypeArg::Database => Self::Database,
            ArchetypeArg::Cli => Self::Cli,
            ArchetypeArg::Browser => Self::Browser,
        }
    }
}

/// Run the new command.
pub fn run(args: &NewArgs) -> Result<()> {
    if let Some(check_path) = &args.check {
        run_check(check_path, args.json)
    } else {
        let connector_id = args
            .connector_id
            .as_ref()
            .context("connector_id is required when not using --check")?;
        run_scaffold(connector_id, args)
    }
}

/// Run compliance check on an existing connector.
fn run_check(path: &Path, json_output: bool) -> Result<()> {
    let result = check_connector(path)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_check_result(&result);
    }

    if !result.prechecks.passed {
        std::process::exit(1);
    }

    Ok(())
}

/// Run scaffold generation.
fn run_scaffold(connector_id: &str, args: &NewArgs) -> Result<()> {
    // Validate connector ID format
    validate_connector_id(connector_id)?;

    let archetype: ConnectorArchetype = args.archetype.into();
    let result = scaffold_connector(
        connector_id,
        archetype,
        &args.zone,
        args.no_e2e,
        args.dry_run,
    )?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_scaffold_result(&result, args.dry_run);
    }

    if !result.prechecks.passed {
        std::process::exit(1);
    }

    Ok(())
}

/// Validate connector ID format.
fn validate_connector_id(id: &str) -> Result<()> {
    if !id.starts_with("fcp.") {
        anyhow::bail!("connector ID must start with 'fcp.' (got: {id})");
    }

    let suffix = &id[4..];
    if suffix.is_empty() {
        anyhow::bail!("connector ID must have a name after 'fcp.'");
    }

    validate_canonical_id(id).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Check for consecutive dots
    if id.contains("..") {
        anyhow::bail!("connector ID cannot contain consecutive dots");
    }

    Ok(())
}

/// Extract the short name from a connector ID (e.g., "fcp.myservice" -> "myservice").
fn extract_short_name(connector_id: &str) -> &str {
    connector_id.strip_prefix("fcp.").unwrap_or(connector_id)
}

/// Normalize a connector short name into a crate-safe slug.
fn normalize_crate_slug(short_name: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;
    for ch in short_name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }
    slug.trim_matches('-').to_string()
}

fn find_workspace_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() {
            let content = fs::read_to_string(&manifest)?;
            if content.contains("[workspace]") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            bail!("workspace Cargo.toml not found (expected [workspace] section)");
        }
    }
}

fn update_workspace_members(
    workspace_root: &Path,
    member_path: &str,
    dry_run: bool,
) -> Result<Option<CreatedFile>> {
    let manifest_path = workspace_root.join("Cargo.toml");
    let content = fs::read_to_string(&manifest_path)?;
    let needle = format!("\"{member_path}\"");
    if content.contains(&needle) {
        return Ok(None);
    }

    let updated = insert_workspace_member(&content, member_path)?;
    if !dry_run {
        fs::write(&manifest_path, updated.as_bytes())?;
    }

    Ok(Some(CreatedFile {
        path: "Cargo.toml".to_string(),
        purpose: "Workspace members update".to_string(),
        size: updated.len(),
    }))
}

fn insert_workspace_member(content: &str, member_path: &str) -> Result<String> {
    let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
    let mut in_workspace = false;
    let mut in_members = false;
    let mut inserted = false;

    for i in 0..lines.len() {
        let trimmed = lines[i].trim_start();
        if trimmed.starts_with("[workspace]") {
            in_workspace = true;
            continue;
        }
        if in_workspace && trimmed.starts_with('[') && !trimmed.starts_with("[workspace]") {
            in_workspace = false;
        }
        if in_workspace && trimmed.starts_with("members") && trimmed.contains('[') {
            in_members = true;
            continue;
        }
        if in_members && trimmed.starts_with(']') {
            lines.insert(i, format!("    \"{member_path}\","));
            inserted = true;
            break;
        }
    }

    if !inserted {
        bail!("failed to locate [workspace].members list in Cargo.toml");
    }

    let mut out = lines.join("\n");
    out.push('\n');
    Ok(out)
}

/// Scaffold a new connector.
fn scaffold_connector(
    connector_id: &str,
    archetype: ConnectorArchetype,
    zone: &str,
    no_e2e: bool,
    dry_run: bool,
) -> Result<ScaffoldResult> {
    let short_name = extract_short_name(connector_id);
    let crate_slug = normalize_crate_slug(short_name);
    if crate_slug.is_empty() {
        anyhow::bail!("connector ID must include at least one alphanumeric character");
    }
    let crate_name = format!("fcp-{crate_slug}");
    let crate_path = format!("connectors/{crate_slug}");
    let workspace_root = find_workspace_root()?;
    let base_path = workspace_root.join(&crate_path);

    if base_path.exists() {
        anyhow::bail!(
            "connector directory already exists: {}",
            base_path.display()
        );
    }

    let mut files_created = Vec::new();

    // Generate all files
    let files = generate_files(
        connector_id,
        short_name,
        &crate_name,
        archetype,
        zone,
        no_e2e,
    )?;

    if !dry_run {
        // Create directory structure
        fs::create_dir_all(base_path.join("src"))?;
        fs::create_dir_all(base_path.join("tests"))?;

        // Write files
        for (rel_path, content, _purpose) in &files {
            let full_path = base_path.join(rel_path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = fs::File::create(&full_path)
                .with_context(|| format!("failed to create {}", full_path.display()))?;
            file.write_all(content.as_bytes())?;
        }
    }

    let workspace_update = update_workspace_members(&workspace_root, &crate_path, dry_run)?;

    // Record created files
    for (rel_path, content, purpose) in &files {
        files_created.push(CreatedFile {
            path: rel_path.clone(),
            purpose: purpose.clone(),
            size: content.len(),
        });
    }
    if let Some(update) = workspace_update {
        files_created.push(update);
    }

    // Run prechecks on generated content
    let prechecks = run_prechecks(&files, connector_id, zone);

    // Generate next steps
    let next_steps = generate_next_steps(connector_id, &crate_path, archetype, no_e2e);

    Ok(ScaffoldResult {
        connector_id: connector_id.to_string(),
        crate_path,
        files_created,
        prechecks,
        next_steps,
    })
}

/// Generate all scaffold files.
fn generate_files(
    connector_id: &str,
    short_name: &str,
    crate_name: &str,
    archetype: ConnectorArchetype,
    zone: &str,
    no_e2e: bool,
) -> Result<Vec<(String, String, String)>> {
    let manifest = generate_manifest_toml(connector_id, short_name, archetype, zone)?;
    let crate_ident = crate_name.replace('-', "_");
    let include_api = matches!(archetype, ConnectorArchetype::RequestResponse);
    let include_stream = matches!(
        archetype,
        ConnectorArchetype::Streaming | ConnectorArchetype::Bidirectional
    );
    let include_polling = matches!(archetype, ConnectorArchetype::Polling);
    let mut files = vec![
        (
            "Cargo.toml".to_string(),
            generate_cargo_toml(crate_name, short_name),
            "Crate manifest".to_string(),
        ),
        (
            "manifest.toml".to_string(),
            manifest,
            "FCP2 connector manifest".to_string(),
        ),
        (
            "src/main.rs".to_string(),
            generate_main_rs(short_name, &crate_ident),
            "FCP protocol loop entrypoint".to_string(),
        ),
        (
            "src/lib.rs".to_string(),
            generate_lib_rs(short_name, include_api, include_stream, include_polling),
            "Library exports".to_string(),
        ),
        (
            "src/config.rs".to_string(),
            generate_config_rs(short_name),
            "Connector configuration".to_string(),
        ),
        (
            "src/error.rs".to_string(),
            generate_error_rs(short_name),
            "Connector error taxonomy".to_string(),
        ),
        (
            "src/connector.rs".to_string(),
            generate_connector_rs(connector_id, short_name, archetype),
            "Connector implementation".to_string(),
        ),
        (
            "src/limits.rs".to_string(),
            generate_limits_rs(short_name),
            "Connector API limit constants".to_string(),
        ),
        (
            "src/types.rs".to_string(),
            generate_types_rs(short_name),
            "Request/response types".to_string(),
        ),
        (
            "tests/unit_tests.rs".to_string(),
            generate_unit_tests_rs(short_name, &crate_ident),
            "Unit test scaffolding".to_string(),
        ),
    ];
    if include_api {
        files.push((
            "src/api.rs".to_string(),
            generate_api_rs(short_name),
            "Request/response API client".to_string(),
        ));
    }
    if include_stream {
        files.push((
            "src/stream.rs".to_string(),
            generate_stream_rs(short_name),
            "Streaming supervisor scaffolding".to_string(),
        ));
    }
    if include_polling {
        files.push((
            "src/polling.rs".to_string(),
            generate_polling_rs(short_name),
            "Polling cursor/scaffold".to_string(),
        ));
    }

    if !no_e2e {
        files.push((
            "tests/e2e_tests.rs".to_string(),
            generate_e2e_tests_rs(connector_id, short_name, crate_name),
            "E2E test scaffolding".to_string(),
        ));
    }

    Ok(files)
}

/// Generate Cargo.toml content.
fn generate_cargo_toml(crate_name: &str, short_name: &str) -> String {
    format!(
        r#"[package]
name = "{crate_name}"
description = "FCP2 connector for {short_name}"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[[bin]]
name = "{crate_name}"
path = "src/main.rs"

[lints]
workspace = true

[dependencies]
fcp-sdk = {{ path = "../../crates/fcp-sdk" }}

anyhow.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = {{ workspace = true, features = ["full"] }}
tokio-stream.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
uuid.workspace = true
sha2.workspace = true
hex.workspace = true

[dev-dependencies]
assert_cmd = "2.0"
wiremock.workspace = true
tokio = {{ workspace = true, features = ["macros", "rt-multi-thread"] }}
"#
    )
}

const INTERFACE_HASH_PLACEHOLDER: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

/// Generate manifest.toml content.
fn generate_manifest_toml(
    connector_id: &str,
    short_name: &str,
    archetype: ConnectorArchetype,
    zone: &str,
) -> Result<String> {
    let archetype_str = manifest_archetype(archetype);
    let title_name = short_name
        .chars()
        .next()
        .map(|c| c.to_uppercase().collect::<String>() + &short_name[1..])
        .unwrap_or_default();

    let template = format!(
        r#"# FCP2 Connector Manifest
# Generated by `fcp new` - fill in placeholder values marked with TODO

[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
# Interface hash is auto-generated from declared operations.
interface_hash = "{INTERFACE_HASH_PLACEHOLDER}"

[connector]
id = "{connector_id}"
name = "{title_name} Connector"
version = "0.1.0"
description = "TODO: Add connector description"
archetypes = ["{archetype_str}"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
# Single-zone binding (FCP2 requirement)
home = "{zone}"
allowed_sources = ["{zone}"]
allowed_targets = ["{zone}"]
forbidden = ["z:public"]

[capabilities]
# TODO: Define required capabilities for your connector
required = ["network.dns", "network.outbound"]
optional = []
# Default-deny: explicitly forbid dangerous capabilities
forbidden = ["system.exec", "system.privileged"]

# TODO: Define your connector's operations
# Each operation should have:
# - A clear capability requirement
# - Appropriate risk level and safety tier
# - Network constraints (default-deny)
[provides.operations.placeholder_operation]
description = "TODO: Describe this operation"
capability = "{short_name}.placeholder"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "best_effort"
input_schema = {{ type = "object", properties = {{ }} }}
output_schema = {{ type = "object", properties = {{ }} }}
# Default-deny network constraints (replace with real endpoints)
[provides.operations.placeholder_operation.network_constraints]
host_allow = ["example.invalid"]
port_allow = [443]
require_sni = true
deny_ip_literals = true
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = true
max_redirects = 0
connect_timeout_ms = 5000
total_timeout_ms = 60000
max_response_bytes = 1048576

[provides.operations.placeholder_operation.ai_hints]
when_to_use = "TODO: Describe when an AI agent should use this operation"
common_mistakes = ["TODO: List common mistakes"]

[sandbox]
# Strict sandbox profile (FCP2 requirement)
profile = "strict"
memory_mb = 64
cpu_percent = 25
wall_clock_timeout_ms = 30000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true

# Signatures and supply chain metadata are added during `fcp install`
# Do not add placeholder values here
"#
    );

    finalize_manifest_toml(&template)
}

const fn manifest_archetype(archetype: ConnectorArchetype) -> &'static str {
    match archetype {
        ConnectorArchetype::RequestResponse
        | ConnectorArchetype::Polling
        | ConnectorArchetype::Cli
        | ConnectorArchetype::Browser => "operational",
        ConnectorArchetype::Streaming | ConnectorArchetype::Webhook => "streaming",
        ConnectorArchetype::Bidirectional | ConnectorArchetype::Queue => "bidirectional",
        ConnectorArchetype::File | ConnectorArchetype::Database => "storage",
    }
}

fn finalize_manifest_toml(template: &str) -> Result<String> {
    let manifest = ConnectorManifest::parse_str_unchecked(template)?;
    let interface_hash = manifest.compute_interface_hash()?;
    let rendered = template.replace(INTERFACE_HASH_PLACEHOLDER, &interface_hash.to_string());
    if rendered == template {
        bail!("failed to render interface hash placeholder");
    }
    ConnectorManifest::parse_str(&rendered)?;
    Ok(rendered)
}

/// Generate main.rs content.
#[allow(clippy::too_many_lines)]
fn generate_main_rs(short_name: &str, crate_ident: &str) -> String {
    let struct_name = to_pascal_case(short_name);

    format!(
        r#"//! FCP {struct_name} Connector - Main entrypoint
//!
//! This connector implements the Flywheel Connector Protocol (FCP2).

#![forbid(unsafe_code)]

use std::io::{{BufRead, Write}};

use anyhow::Result;
use fcp_sdk::prelude::*;
use tracing_subscriber::{{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt}};

use {crate_ident}::{struct_name}Connector;

fn main() -> Result<()> {{
    // Initialize tracing to stderr (stdout is for JSON-RPC protocol)
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP {struct_name} Connector starting");

    run_fcp_loop()?;

    Ok(())
}}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {{
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = {struct_name}Connector::new();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    for line in stdin.lock().lines() {{
        let line = line?;
        if line.is_empty() {{
            continue;
        }}

        let response = runtime.block_on(async {{ handle_message(&mut connector, &line).await }});

        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{{response_json}}")?;
        stdout.flush()?;
    }}

    Ok(())
}}

fn encode<T: serde::Serialize>(value: &T) -> FcpResult<serde_json::Value> {{
    serde_json::to_value(value).map_err(|e| FcpError::Internal {{
        message: format!("Failed to serialize response: {{e}}"),
    }})
}}

/// Handle a single FCP message.
async fn handle_message(connector: &mut {struct_name}Connector, message: &str) -> serde_json::Value {{
    let request: serde_json::Value = match serde_json::from_str(message) {{
        Ok(v) => v,
        Err(e) => {{
            return serde_json::json!({{
                "error": {{
                    "code": "FCP-1001",
                    "message": format!("Invalid JSON: {{e}}")
                }}
            }});
        }}
    }};

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({{}}));

    let result = match method {{
        "configure" => {{
            connector.configure(params).await?;
            Ok(serde_json::json!({{ "status": "configured" }}))
        }}
        "handshake" => {{
            let req: HandshakeRequest = serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {{
                code: 1003,
                message: format!("Invalid handshake request: {{e}}"),
            }})?;
            encode(&connector.handshake(req).await?)
        }}
        "health" => encode(&connector.health().await),
        "introspect" => encode(&connector.introspect()),
        "invoke" => {{
            let req: InvokeRequest = serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {{
                code: 1003,
                message: format!("Invalid invoke request: {{e}}"),
            }})?;
            encode(&connector.invoke(req).await?)
        }}
        "subscribe" => {{
            let req: SubscribeRequest = serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {{
                code: 1003,
                message: format!("Invalid subscribe request: {{e}}"),
            }})?;
            encode(&connector.subscribe(req).await?)
        }}
        "unsubscribe" => {{
            let req: UnsubscribeRequest = serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {{
                code: 1003,
                message: format!("Invalid unsubscribe request: {{e}}"),
            }})?;
            connector.unsubscribe(req).await?;
            Ok(serde_json::json!({{ "status": "unsubscribed" }}))
        }}
        "shutdown" => {{
            let req: ShutdownRequest = serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {{
                code: 1003,
                message: format!("Invalid shutdown request: {{e}}"),
            }})?;
            connector.shutdown(req).await?;
            Ok(serde_json::json!({{ "status": "shutdown_accepted" }}))
        }}
        _ => Err(FcpError::InvalidRequest {{
            code: 1002,
            message: format!("Unknown method: {{method}}"),
        }}),
    }};

    match result {{
        Ok(value) => {{
            let mut response = serde_json::json!({{
                "jsonrpc": "2.0",
                "result": value
            }});
            if let Some(id) = id {{
                response["id"] = id;
            }}
            response
        }}
        Err(e) => {{
            let err_response = e.to_response();
            let mut response = serde_json::json!({{
                "jsonrpc": "2.0",
                "error": err_response
            }});
            if let Some(id) = id {{
                response["id"] = id;
            }}
            response
        }}
    }}
}}
"#
    )
}

/// Generate lib.rs content.
fn generate_lib_rs(
    short_name: &str,
    include_api: bool,
    include_stream: bool,
    include_polling: bool,
) -> String {
    let struct_name = to_pascal_case(short_name);
    let api_module = if include_api { "pub mod api;\n" } else { "" };
    let stream_module = if include_stream {
        "pub mod stream;\n"
    } else {
        ""
    };
    let polling_module = if include_polling {
        "pub mod polling;\n"
    } else {
        ""
    };
    format!(
        r"//! Library exports for {struct_name} connector.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
{api_module}{stream_module}{polling_module}pub mod connector;
pub mod limits;
pub mod types;

pub use connector::{struct_name}Connector;
"
    )
}

/// Generate config.rs content.
fn generate_config_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);
    format!(
        r#"//! {struct_name} connector configuration.
//!
//! TODO: Define configuration fields for your connector.
//! NOTE: Never store secrets in config. Use capability tokens and host-provided secrets.

use fcp_sdk::prelude::{{FcpError, FcpResult}};
use serde::{{Deserialize, Serialize}};
use serde_json::Value;

/// Connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct {struct_name}Config {{
    // Example fields:
    // pub endpoint: String,
    // pub timeout_ms: u64,
}}

impl {struct_name}Config {{
    /// Parse and validate connector configuration from JSON.
    pub fn from_value(value: Value) -> FcpResult<Self> {{
        let config: Self = serde_json::from_value(value).map_err(|e| FcpError::InvalidRequest {{
            code: 1003,
            message: format!("Invalid config: {{e}}"),
        }})?;
        config.validate()?;
        Ok(config)
    }}

    /// Validate configuration invariants.
    pub fn validate(&self) -> FcpResult<()> {{
        // TODO: Add validation checks (required fields, bounds, etc.)
        Ok(())
    }}
}}
"#
    )
}

/// Generate error.rs content.
fn generate_error_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);
    format!(
        r#"//! {struct_name} connector error taxonomy.

use fcp_sdk::prelude::FcpError;

/// Connector-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum {struct_name}Error {{
    /// Configuration error.
    #[error("configuration error: {{0}}")]
    Config(String),

    /// External service error.
    #[error("external service error: {{0}}")]
    ExternalService(String),

    /// Rate limit error.
    #[error("rate limited: {{0}}")]
    RateLimited(String),
}}

impl {struct_name}Error {{
    /// Convert to a structured FCP error.
    pub fn to_fcp_error(&self) -> FcpError {{
        match self {{
            Self::Config(message) => FcpError::InvalidRequest {{
                code: 5001,
                message: message.clone(),
            }},
            Self::ExternalService(message) => FcpError::ExternalService {{
                code: 7001,
                message: message.clone(),
                retryable: true,
            }},
            Self::RateLimited(message) => FcpError::ExternalService {{
                code: 7002,
                message: message.clone(),
                retryable: true,
            }},
        }}
    }}
}}
"#
    )
}

/// Generate api.rs content (request-response connectors only).
fn generate_api_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);
    format!(
        r#"//! {struct_name} connector API client (request-response archetype).
//!
//! TODO: Implement HTTP calls and map failures to connector errors.

use std::future::Future;
use std::time::Duration;

use tokio::time::sleep;

use crate::error::{struct_name}Error;

/// API client configuration.
#[derive(Debug, Clone)]
pub struct ApiClient {{
    base_url: String,
    timeout: Duration,
}}

impl ApiClient {{
    /// Create a new API client.
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> Self {{
        Self {{
            base_url: base_url.into(),
            timeout,
        }}
    }}

    /// Execute a placeholder request.
    pub async fn request(
        &self,
        _path: &str,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, {struct_name}Error> {{
        let _ = &self.base_url;
        let _ = self.timeout;
        Err({struct_name}Error::ExternalService(
            "api client not implemented".to_string(),
        ))
    }}
}}

/// Retry helper with exponential backoff.
pub async fn retry<T, F, Fut>(
    mut attempts: usize,
    mut backoff: Duration,
    mut op: F,
) -> Result<T, {struct_name}Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, {struct_name}Error>>,
{{
    loop {{
        match op().await {{
            Ok(value) => return Ok(value),
            Err(err) => {{
                attempts = attempts.saturating_sub(1);
                if attempts == 0 {{
                    return Err(err);
                }}
                sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }}
        }}
    }}
}}
"#
    )
}

/// Generate stream.rs content (streaming/bidirectional archetypes).
fn generate_stream_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);
    format!(
        r"//! {struct_name} streaming supervisor scaffolding.
//!
//! TODO: Replace with a real stream supervisor tied to your transport layer.

use std::collections::HashSet;

use fcp_sdk::prelude::{{EventEnvelope, EventStream, FcpResult, SubscribeRequest}};
use tokio_stream::iter;

/// Supervisor for streaming subscriptions (placeholder).
#[derive(Debug, Default)]
pub struct StreamSupervisor {{
    topics: HashSet<String>,
    last_cursor: Option<String>,
}}

impl StreamSupervisor {{
    /// Create a new supervisor.
    pub fn new() -> Self {{
        Self::default()
    }}

    /// Record a subscription request.
    pub fn on_subscribe(&mut self, req: &SubscribeRequest) {{
        for topic in &req.topics {{
            self.topics.insert(topic.clone());
        }}
    }}

    /// Record a single topic subscription.
    pub fn on_subscribe_topic(&mut self, topic: &str) {{
        self.topics.insert(topic.to_string());
    }}

    /// Record unsubscription topics.
    pub fn on_unsubscribe(&mut self, topics: &[String]) {{
        for topic in topics {{
            self.topics.remove(topic);
        }}
    }}

    /// Record the last seen cursor.
    pub fn record_cursor(&mut self, cursor: impl Into<String>) {{
        self.last_cursor = Some(cursor.into());
    }}

    /// Access current topics (debugging).
    pub fn topics(&self) -> Vec<String> {{
        self.topics.iter().cloned().collect()
    }}
}}

/// Empty event stream placeholder.
pub fn empty_event_stream() -> EventStream {{
    Box::pin(iter(std::iter::empty::<FcpResult<EventEnvelope>>()))
}}
 "
    )
}

/// Generate polling.rs content (polling archetype).
fn generate_polling_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);
    format!(
        r"//! {struct_name} polling scaffolding (cursor + sequentialization hooks).
//!
//! TODO: Replace with real polling logic and durable cursor persistence.

use std::time::{{Duration, Instant}};

use fcp_sdk::prelude::CursorState;
use tokio_stream::iter;

/// Cursor wrapper with sequentialization hints.
#[derive(Debug, Clone)]
pub struct PollingCursor {{
    state: CursorState,
    last_polled_at: Option<Instant>,
}}

impl PollingCursor {{
    /// Create a fresh cursor (empty state).
    pub fn new() -> Self {{
        Self {{
            state: CursorState {{
                offset: None,
                last_seen_id: None,
                watermark: None,
            }},
            last_polled_at: None,
        }}
    }}

    /// Update cursor after a successful poll.
    pub fn advance(&mut self, next: CursorState) {{
        // TODO: Enforce monotonic cursor progression.
        self.state = next;
        self.last_polled_at = Some(Instant::now());
    }}

    /// Determine if it's time to poll again.
    pub fn should_poll(&self, interval: Duration) -> bool {{
        match self.last_polled_at {{
            Some(ts) => ts.elapsed() >= interval,
            None => true,
        }}
    }}

    /// Return the current cursor state.
    pub fn state(&self) -> &CursorState {{
        &self.state
    }}
}}

/// Polling supervisor (ensures sequential polling).
#[derive(Debug)]
pub struct PollingSupervisor {{
    cursor: PollingCursor,
    in_flight: bool,
}}

impl PollingSupervisor {{
    /// Create a new polling supervisor.
    pub fn new() -> Self {{
        Self {{
            cursor: PollingCursor::new(),
            in_flight: false,
        }}
    }}

    /// Begin a poll cycle. Returns false if a poll is already in flight.
    pub fn begin_poll(&mut self) -> bool {{
        if self.in_flight {{
            return false;
        }}
        self.in_flight = true;
        true
    }}

    /// Finish a poll cycle and update cursor.
    pub fn finish_poll(&mut self, next: Option<CursorState>) {{
        if let Some(state) = next {{
            self.cursor.advance(state);
        }}
        self.in_flight = false;
    }}

    /// Return the current cursor state.
    pub fn cursor(&self) -> &CursorState {{
        self.cursor.state()
    }}
}}

/// Empty event stream placeholder.
pub fn empty_event_stream() -> fcp_sdk::prelude::EventStream {{
    Box::pin(iter(std::iter::empty::<fcp_sdk::prelude::FcpResult<
        fcp_sdk::prelude::EventEnvelope,
    >>()))
}}
"
    )
}

/// Generate limits.rs content.
fn generate_limits_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);
    format!(
        r"//! {struct_name} connector API limits.
//!
//! TODO: Replace placeholders with the actual service limits before shipping.

#![allow(dead_code)]

/// Max length for message text payloads (chars).
pub const MAX_MESSAGE_CHARS: usize = 0;

/// Max payload size in bytes (serialized JSON).
pub const MAX_PAYLOAD_BYTES: usize = 0;

/// Max number of attachments per message.
pub const MAX_ATTACHMENTS: usize = 0;

/// Max size of a single attachment (bytes).
pub const MAX_ATTACHMENT_BYTES: usize = 0;

/// Max number of embeds/blocks per message.
pub const MAX_EMBEDS: usize = 0;

/// Max character length for titles/subject fields.
pub const MAX_TITLE_CHARS: usize = 0;
"
    )
}

/// Generate connector.rs content.
#[allow(clippy::too_many_lines)] // Template generation is inherently verbose
fn generate_connector_rs(
    connector_id: &str,
    short_name: &str,
    archetype: ConnectorArchetype,
) -> String {
    let struct_name = to_pascal_case(short_name);
    let include_stream = matches!(
        archetype,
        ConnectorArchetype::Streaming | ConnectorArchetype::Bidirectional
    );
    let include_polling = matches!(archetype, ConnectorArchetype::Polling);
    let include_bidirectional = matches!(archetype, ConnectorArchetype::Bidirectional);
    let needs_mutex = include_stream || include_polling;
    let mutex_import = if needs_mutex {
        "use std::sync::Mutex;\n"
    } else {
        ""
    };
    let stream_import = if include_stream {
        "use crate::stream::StreamSupervisor;\n"
    } else {
        ""
    };
    let polling_import = if include_polling {
        "use crate::polling::PollingSupervisor;\n"
    } else {
        ""
    };
    let stream_field = if include_stream {
        "    stream: Mutex<StreamSupervisor>,\n"
    } else {
        ""
    };
    let polling_field = if include_polling {
        "    polling: Mutex<PollingSupervisor>,\n"
    } else {
        ""
    };
    let stream_init = if include_stream {
        "            stream: Mutex::new(StreamSupervisor::new()),\n"
    } else {
        ""
    };
    let polling_init = if include_polling {
        "            polling: Mutex::new(PollingSupervisor::new()),\n"
    } else {
        ""
    };
    let stream_subscribe = if include_stream {
        "        if let Ok(mut stream) = self.stream.lock() {\n            stream.on_subscribe(&req);\n        }\n"
    } else {
        ""
    };
    let stream_unsubscribe = if include_stream {
        "        if let Ok(mut stream) = self.stream.lock() {\n            stream.on_unsubscribe(&req.topics);\n        }\n"
    } else {
        ""
    };
    let unsubscribe_param = if include_stream { "req" } else { "_req" };
    let streaming_impl = if include_stream {
        format!(
            r"
#[async_trait]
impl Streaming for {struct_name}Connector {{
    async fn stream_subscribe(&self, topic: &str) -> FcpResult<EventStream> {{
        if let Ok(mut stream) = self.stream.lock() {{
            stream.on_subscribe_topic(topic);
        }}
        Ok(crate::stream::empty_event_stream())
    }}

    fn events(&self) -> EventStream {{
        crate::stream::empty_event_stream()
    }}
}}
"
        )
    } else {
        String::new()
    };
    let polling_impl = if include_polling {
        format!(
            r#"
#[async_trait]
impl Polling for {struct_name}Connector {{
    async fn start_polling(
        &self,
        _target: &str,
        _interval: Option<std::time::Duration>,
        _token: &CapabilityToken,
    ) -> FcpResult<()> {{
        if let Ok(mut polling) = self.polling.lock() {{
            if !polling.begin_poll() {{
                return Err(FcpError::ConnectorUnavailable {{
                    code: 5003,
                    message: "poll already in flight".to_string(),
                }});
            }}
            polling.finish_poll(None);
        }}
        Ok(())
    }}

    async fn stop_polling(&self, _target: &str, _token: &CapabilityToken) -> FcpResult<()> {{
        Ok(())
    }}

    async fn poll_now(&self, _target: &str, _token: &CapabilityToken) -> FcpResult<usize> {{
        if let Ok(mut polling) = self.polling.lock() {{
            if !polling.begin_poll() {{
                return Err(FcpError::ConnectorUnavailable {{
                    code: 5003,
                    message: "poll already in flight".to_string(),
                }});
            }}
            // TODO: Execute poll, then update cursor via polling.finish_poll(Some(cursor))
            polling.finish_poll(None);
        }}
        Ok(0)
    }}

    fn events(&self) -> EventStream {{
        crate::polling::empty_event_stream()
    }}
}}
"#
        )
    } else {
        String::new()
    };
    let bidirectional_impl = if include_bidirectional {
        format!(
            r#"
#[async_trait]
impl Bidirectional for {struct_name}Connector {{
    async fn send(&self, message: serde_json::Value) -> FcpResult<()> {{
        let _ = message;
        Err(FcpError::ConnectorUnavailable {{
            code: 5002,
            message: "bidirectional send not implemented".to_string(),
        }})
    }}
}}
"#
        )
    } else {
        String::new()
    };
    let supports_streaming = matches!(
        archetype,
        ConnectorArchetype::Streaming
            | ConnectorArchetype::Bidirectional
            | ConnectorArchetype::Webhook
            | ConnectorArchetype::Queue
    );

    format!(
        r#"//! {struct_name} connector implementation.

use std::time::Instant;
{mutex_import}

use fcp_sdk::prelude::*;
use sha2::{{Digest, Sha256}};

use crate::config::{struct_name}Config;
use crate::limits;
{stream_import}{polling_import}

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_PLACEHOLDER: &str = "{short_name}.placeholder";
const CAP_PLACEHOLDER: &str = "{short_name}.placeholder";
const SUPPORTS_STREAMING: bool = {supports_streaming};

/// {struct_name} connector state.
#[derive(Debug)]
pub struct {struct_name}Connector {{
    base: BaseConnector,
    configured: bool,
    config: Option<{struct_name}Config>,
{stream_field}{polling_field}    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}}

impl {struct_name}Connector {{
    /// Create a new connector instance.
    pub fn new() -> Self {{
        Self {{
            base: BaseConnector::new(ConnectorId::from_static("{connector_id}")),
            configured: false,
            config: None,
{stream_init}{polling_init}            started_at: Instant::now(),
            verifier: None,
        }}
    }}

    fn manifest_hash() -> String {{
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{{}}", hex::encode(hasher.finalize()))
    }}

    fn enforce_limits(&self, input: &serde_json::Value) -> FcpResult<()> {{
        if limits::MAX_MESSAGE_CHARS > 0 {{
            if let Some(message) = input.get("message").and_then(|value| value.as_str()) {{
                if message.chars().count() > limits::MAX_MESSAGE_CHARS {{
                    return Err(FcpError::InvalidRequest {{
                        code: 1005,
                        message: "message exceeds MAX_MESSAGE_CHARS limit".to_string(),
                    }});
                }}
            }}
        }}

        if limits::MAX_PAYLOAD_BYTES > 0 && input.to_string().len() > limits::MAX_PAYLOAD_BYTES {{
            return Err(FcpError::InvalidRequest {{
                code: 1006,
                message: "payload exceeds MAX_PAYLOAD_BYTES limit".to_string(),
            }});
        }}

        Ok(())
    }}

    fn placeholder_operation(&self) -> OperationInfo {{
        OperationInfo {{
            id: OperationId::from_static(OP_PLACEHOLDER),
            summary: "Placeholder operation".to_string(),
            description: Some("TODO: Replace with real operation".to_string()),
            input_schema: serde_json::json!({{ "type": "object" }}),
            output_schema: serde_json::json!({{ "type": "object" }}),
            capability: CapabilityId::from_static(CAP_PLACEHOLDER),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {{
                when_to_use: "TODO: describe when to use".to_string(),
                common_mistakes: vec!["TODO: add common mistakes".to_string()],
                examples: Vec::new(),
                related: Vec::new(),
            }},
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        }}
    }}
}}

#[async_trait]
impl FcpConnector for {struct_name}Connector {{
    fn id(&self) -> &ConnectorId {{
        &self.base.id
    }}

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {{
        let config = {struct_name}Config::from_value(config)?;
        self.config = Some(config);
        self.configured = true;
        self.base.set_configured(true);
        Ok(())
    }}

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {{
        self.base.set_handshaken(true);

        // Initialize capability verifier with host key and zone
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {{
                capability: cap,
                operation: None,
            }})
            .collect();

        Ok(HandshakeResponse {{
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {{
                streaming: SUPPORTS_STREAMING,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }}),
            auth_caps: None,
            op_catalog_hash: None,
        }})
    }}

    async fn health(&self) -> HealthSnapshot {{
        let mut snapshot = if self.configured {{
            HealthSnapshot::ready()
        }} else {{
            HealthSnapshot::degraded("not configured")
        }};
        snapshot.uptime_ms = self.started_at.elapsed().as_millis() as u64;
        snapshot
    }}

    fn metrics(&self) -> ConnectorMetrics {{
        self.base.metrics()
    }}

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {{
        Ok(())
    }}

    fn introspect(&self) -> Introspection {{
        Introspection {{
            operations: vec![self.placeholder_operation()],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {{
                streaming: SUPPORTS_STREAMING,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }}),
        }}
    }}

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {{
        if req.operation.as_str() != OP_PLACEHOLDER {{
            return Err(FcpError::InvalidRequest {{
                code: 1004,
                message: format!("Unknown operation: {{}}", req.operation.as_str()),
            }});
        }}

        // Verify capability token
        if let Some(verifier) = &self.verifier {{
            // TODO: Pass actual resource URIs if the operation targets specific resources
            // TODO: Map operation to required capability dynamically
            let required_cap = CapabilityId::from_static(CAP_PLACEHOLDER);
            verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;
        }} else {{
            return Err(FcpError::NotConfigured);
        }}

        self.enforce_limits(&req.input)?;

        // TODO: Enforce network constraints, emit receipts.
        Ok(InvokeResponse::ok(
            req.id,
            serde_json::json!({{
                "status": "ok",
                "message": "Placeholder operation executed"
            }}),
        ))
    }}

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {{
        if !SUPPORTS_STREAMING {{
            return Err(FcpError::StreamingNotSupported);
        }}

{stream_subscribe}
        Ok(SubscribeResponse {{
            r#type: "response".into(),
            id: req.id,
            result: SubscribeResult {{
                confirmed_topics: req.topics,
                cursors: std::collections::HashMap::new(),
                replay_supported: false,
                buffer: None,
            }},
        }})
    }}

    async fn unsubscribe(&self, {unsubscribe_param}: UnsubscribeRequest) -> FcpResult<()> {{
{stream_unsubscribe}
        Ok(())
    }}
}}
{streaming_impl}{polling_impl}{bidirectional_impl}

impl Default for {struct_name}Connector {{
    fn default() -> Self {{
        Self::new()
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    fn base_handshake() -> HandshakeRequest {{
        HandshakeRequest {{
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_PLACEHOLDER)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }}
    }}

    fn base_invoke(connector_id: &ConnectorId, operation: &str) -> InvokeRequest {{
        InvokeRequest {{
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({{}}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }}
    }}

    #[tokio::test]
    async fn test_handshake() {{
        let mut connector = {struct_name}Connector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }}

    #[tokio::test]
    async fn test_invoke_placeholder() {{
        let mut connector = {struct_name}Connector::new();
        // Must handshake first to initialize verifier
        connector.handshake(base_handshake()).await.expect("handshake");
        
        let req = base_invoke(connector.id(), OP_PLACEHOLDER);
        let response = connector.invoke(req).await.expect("invoke");
        assert_eq!(response.status, InvokeStatus::Ok);
    }}
}}
"#
    )
}

/// Generate types.rs content.
fn generate_types_rs(short_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);

    format!(
        r"//! Request and response types for {struct_name} connector.

use serde::{{Deserialize, Serialize}};

// ─────────────────────────────────────────────────────────────────────────────
// Operation types
// ─────────────────────────────────────────────────────────────────────────────

/// Input for placeholder operation.
///
/// TODO: Define input types for each operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceholderInput {{
    // Example: pub query: String,
}}

/// Output for placeholder operation.
///
/// TODO: Define output types for each operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceholderOutput {{
    // Example: pub result: String,
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn config_serialization() {{
        // TODO: Add serialization tests for your types
    }}
}}
"
    )
}

/// Generate unit tests content.
fn generate_unit_tests_rs(short_name: &str, crate_ident: &str) -> String {
    let struct_name = to_pascal_case(short_name);

    format!(
        r#"//! Unit tests for {struct_name} connector.

use fcp_sdk::prelude::*;
use {crate_ident}::{struct_name}Connector;

const OP_PLACEHOLDER: &str = "{short_name}.placeholder";

fn base_invoke(connector_id: &ConnectorId, operation: &str) -> InvokeRequest {{
    InvokeRequest {{
        r#type: "invoke".into(),
        id: RequestId::new("req_1"),
        connector_id: connector_id.clone(),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input: serde_json::json!({{}}),
        capability_token: CapabilityToken::test_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }}
}}

// ─────────────────────────────────────────────────────────────────────────────
// Happy path tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_happy_path_placeholder() {{
    let mut connector = {struct_name}Connector::new();

    // Configure the connector
    connector
        .configure(serde_json::json!({{}}))
        .await
        .expect("configure");

    // Invoke placeholder operation
    let invoke_result = connector
        .invoke(base_invoke(connector.id(), OP_PLACEHOLDER))
        .await;
    assert!(invoke_result.is_ok(), "Placeholder operation should succeed");
}}

// ─────────────────────────────────────────────────────────────────────────────
// Capability denial tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_missing_capability_denied() {{
    // TODO: Test that operations fail without proper capability tokens
    // This verifies the default-deny security model
}}

// ─────────────────────────────────────────────────────────────────────────────
// Network constraint tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_network_constraints_enforced() {{
    // TODO: Test that network requests to non-allowed hosts are blocked
    // This verifies the default-deny NetworkConstraints
}}

// ─────────────────────────────────────────────────────────────────────────────
// Secret redaction tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_secrets_not_logged() {{
    // TODO: Verify that sensitive data is never logged
    // - Capture tracing output
    // - Perform operations with sensitive data
    // - Assert no sensitive values appear in logs

    // Example pattern:
    // let (subscriber, logs) = test_subscriber();
    // tracing::subscriber::with_default(subscriber, || {{
    //     // Perform operations...
    // }});
    // assert!(!logs.contains("secret_value"));
}}

// ─────────────────────────────────────────────────────────────────────────────
// Error taxonomy tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_error_codes_correct() {{
    let connector = {struct_name}Connector::new();

    // Test unknown operation returns correct error
    let result = connector
        .invoke(base_invoke(connector.id(), "unknown.operation"))
        .await;

    assert!(result.is_err());
    // TODO: Verify error code is in correct range (FCP-5xxx for connector errors)
}}
"#
    )
}

/// Generate E2E tests content.
#[allow(clippy::too_many_lines)]
fn generate_e2e_tests_rs(connector_id: &str, short_name: &str, crate_name: &str) -> String {
    let struct_name = to_pascal_case(short_name);

    format!(
        r#"//! E2E tests for {struct_name} connector.
//!
//! These tests verify the connector works correctly in a realistic environment:
//! - Protocol compliance
//! - DecisionReceipt emission
//! - AuditEvent shape
//! - Default-deny failure paths

use std::process::{{Command, Stdio}};
use std::io::{{BufRead, BufReader, Write}};
use assert_cmd::cargo::cargo_bin;

// ─────────────────────────────────────────────────────────────────────────────
// E2E test harness
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the connector binary and return handles for communication.
fn spawn_connector() -> std::io::Result<ConnectorProcess> {{
    let child = Command::new(cargo_bin("{crate_name}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(ConnectorProcess {{ child }})
}}

struct ConnectorProcess {{
    child: std::process::Child,
}}

impl ConnectorProcess {{
    fn send(&mut self, request: &serde_json::Value) -> std::io::Result<serde_json::Value> {{
        let stdin = self.child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{{}}", serde_json::to_string(request)?)?;
        stdin.flush()?;

        let stdout = self.child.stdout.as_mut().expect("stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line)?;

        Ok(serde_json::from_str(&line)?)
    }}
}}

impl Drop for ConnectorProcess {{
    fn drop(&mut self) {{
        let _ = self.child.kill();
    }}
}}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol compliance tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires built binary"]
fn test_e2e_handshake() {{
    let mut connector = spawn_connector().expect("spawn connector");

    let response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "handshake",
            "params": {{}}
        }}))
        .expect("handshake");

    assert!(response.get("result").is_some(), "Should have result");
    assert_eq!(
        response["result"]["connector_id"],
        "{connector_id}"
    );
}}

#[test]
#[ignore = "requires built binary"]
fn test_e2e_configure_and_invoke() {{
    let mut connector = spawn_connector().expect("spawn connector");

    // Configure
    let config_response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "configure",
            "params": {{}}
        }}))
        .expect("configure");
    assert!(config_response.get("result").is_some());

    // Invoke placeholder
    let invoke_response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "invoke",
            "params": {{
                "operation": "{short_name}.placeholder"
            }}
        }}))
        .expect("invoke");
    assert!(invoke_response.get("result").is_some());
}}

// ─────────────────────────────────────────────────────────────────────────────
// Default-deny tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires built binary"]
fn test_e2e_unknown_method_rejected() {{
    let mut connector = spawn_connector().expect("spawn connector");

    let response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "unknown_method",
            "params": {{}}
        }}))
        .expect("unknown method");

    assert!(response.get("error").is_some(), "Should return error");
}}

// ─────────────────────────────────────────────────────────────────────────────
// DecisionReceipt verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires integration environment"]
fn test_e2e_decision_receipt_shape() {{
    // TODO: Verify DecisionReceipt is emitted with correct fields:
    // - operation_id
    // - decision (allow/deny)
    // - policy_chain
    // - timestamp
}}

// ─────────────────────────────────────────────────────────────────────────────
// AuditEvent verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires integration environment"]
fn test_e2e_audit_event_shape() {{
    // TODO: Verify AuditEvent is emitted with correct fields:
    // - event_type
    // - connector_id
    // - correlation_id
    // - zone_id
    // - timestamp
}}
"#
    )
}

/// Run compliance prechecks on generated files.
#[allow(clippy::too_many_lines)]
fn run_prechecks(
    files: &[(String, String, String)],
    connector_id: &str,
    zone: &str,
) -> PrecheckResults {
    let mut checks = Vec::new();

    // Find manifest content
    let manifest_content = files
        .iter()
        .find(|(path, _, _)| path == "manifest.toml")
        .map(|(_, content, _)| content.as_str());

    let mut parsed_manifest: Option<ConnectorManifest> = None;

    // Check 1: Manifest passes FCP validation
    if let Some(content) = manifest_content {
        match ConnectorManifest::parse_str(content) {
            Ok(manifest) => {
                parsed_manifest = Some(manifest);
                checks.push(PrecheckItem {
                    id: "manifest.valid".to_string(),
                    description: "Manifest passes FCP validation".to_string(),
                    passed: true,
                    message: None,
                    severity: CheckSeverity::Error,
                });
                checks.push(PrecheckItem {
                    id: "manifest.capability_id_lint".to_string(),
                    description: "Capability IDs do not embed hostnames/ports/URLs".to_string(),
                    passed: true,
                    message: None,
                    severity: CheckSeverity::Error,
                });
            }
            Err(e) => {
                checks.push(PrecheckItem {
                    id: "manifest.valid".to_string(),
                    description: "Manifest passes FCP validation".to_string(),
                    passed: false,
                    message: Some(e.to_string()),
                    severity: CheckSeverity::Error,
                });
                if let Some(message) = capability_id_lint_message(&e) {
                    checks.push(PrecheckItem {
                        id: "manifest.capability_id_lint".to_string(),
                        description: "Capability IDs do not embed hostnames/ports/URLs".to_string(),
                        passed: false,
                        message: Some(message),
                        severity: CheckSeverity::Error,
                    });
                }
            }
        }
    } else {
        checks.push(PrecheckItem {
            id: "manifest.exists".to_string(),
            description: "Manifest file exists".to_string(),
            passed: false,
            message: Some("manifest.toml not found".to_string()),
            severity: CheckSeverity::Error,
        });
    }

    // Check 2: Single-zone binding
    let single_zone_ok = parsed_manifest.as_ref().is_some_and(|manifest| {
        let home = &manifest.zones.home;
        manifest.zones.allowed_sources.len() == 1
            && manifest.zones.allowed_targets.len() == 1
            && manifest.zones.allowed_sources[0] == *home
            && manifest.zones.allowed_targets[0] == *home
    });
    checks.push(PrecheckItem {
        id: "manifest.single_zone".to_string(),
        description: "Connector uses single-zone binding".to_string(),
        passed: single_zone_ok,
        message: Some(format!("Home zone: {zone}")),
        severity: CheckSeverity::Error,
    });

    // Check 3: Default-deny NetworkConstraints
    let mut missing_constraints = Vec::new();
    let mut weak_defaults = Vec::new();
    if let Some(manifest) = &parsed_manifest {
        for (op_id, op) in &manifest.provides.operations {
            match &op.network_constraints {
                Some(nc) => {
                    if nc.host_allow.is_empty() || nc.port_allow.is_empty() {
                        missing_constraints.push(op_id.clone());
                    }
                    if !(nc.deny_localhost
                        && nc.deny_private_ranges
                        && nc.deny_tailnet_ranges
                        && nc.deny_ip_literals)
                    {
                        weak_defaults.push(op_id.clone());
                    }
                }
                None => missing_constraints.push(op_id.clone()),
            }
        }
    }
    let network_ok = missing_constraints.is_empty() && weak_defaults.is_empty();
    checks.push(PrecheckItem {
        id: "manifest.network_default_deny".to_string(),
        description: "NetworkConstraints use default-deny".to_string(),
        passed: network_ok,
        message: if network_ok {
            Some("NetworkConstraints present with deny-by-default flags".to_string())
        } else {
            Some(format!(
                "Missing/weak constraints in ops: missing={missing_constraints:?} weak={weak_defaults:?}"
            ))
        },
        severity: CheckSeverity::Error,
    });

    // Check 4: Forbidden capabilities include system.exec
    let forbids_exec = parsed_manifest.as_ref().is_some_and(|manifest| {
        manifest
            .capabilities
            .forbidden
            .iter()
            .any(|cap| cap.as_str() == "system.exec")
    });
    checks.push(PrecheckItem {
        id: "manifest.forbidden_exec".to_string(),
        description: "system.exec is in forbidden capabilities".to_string(),
        passed: forbids_exec,
        message: None,
        severity: CheckSeverity::Error,
    });

    // Check 5: No secrets in generated files
    let has_secrets = files
        .iter()
        .any(|(_, content, _)| content.contains("password") || content.contains("api_key"));
    checks.push(PrecheckItem {
        id: "scaffold.no_secrets".to_string(),
        description: "No plaintext secrets in generated files".to_string(),
        passed: !has_secrets,
        message: if has_secrets {
            Some("Found potential secrets in generated files".to_string())
        } else {
            None
        },
        severity: CheckSeverity::Error,
    });

    // Check 6: Has #![forbid(unsafe_code)]
    let main_rs = files
        .iter()
        .find(|(path, _, _)| path == "src/main.rs")
        .map(|(_, content, _)| content.as_str());
    let lib_rs = files
        .iter()
        .find(|(path, _, _)| path == "src/lib.rs")
        .map(|(_, content, _)| content.as_str());
    let forbids_unsafe = main_rs.is_some_and(|c| c.contains("#![forbid(unsafe_code)]"))
        && lib_rs.is_some_and(|c| c.contains("#![forbid(unsafe_code)]"));
    checks.push(PrecheckItem {
        id: "code.forbid_unsafe".to_string(),
        description: "Code forbids unsafe Rust".to_string(),
        passed: forbids_unsafe,
        message: None,
        severity: CheckSeverity::Error,
    });

    // Check 7: Has unit tests
    let has_unit_tests = files
        .iter()
        .any(|(path, _, _)| path == "tests/unit_tests.rs");
    checks.push(PrecheckItem {
        id: "tests.unit_scaffold".to_string(),
        description: "Unit test scaffolding present".to_string(),
        passed: has_unit_tests,
        message: None,
        severity: CheckSeverity::Warning,
    });

    // Check 8: Connector ID format
    let valid_id = validate_connector_id(connector_id).is_ok();
    checks.push(PrecheckItem {
        id: "manifest.connector_id_format".to_string(),
        description: "Connector ID follows naming convention".to_string(),
        passed: valid_id,
        message: if valid_id {
            None
        } else {
            Some(format!("Invalid connector ID: {connector_id}"))
        },
        severity: CheckSeverity::Error,
    });

    PrecheckResults::passed(checks)
}

fn capability_id_lint_message(error: &ManifestError) -> Option<String> {
    match error {
        ManifestError::Invalid { field, message } if message.contains("network_constraints") => {
            Some(format!(
                "{message} (field: {field}). \
                 Move hostnames/ports into network_constraints and keep capability IDs abstract."
            ))
        }
        _ => None,
    }
}

/// Check an existing connector directory for compliance.
#[allow(clippy::too_many_lines)]
fn check_connector(path: &Path) -> Result<CheckResult> {
    let mut checks = Vec::new();
    let mut suggested_fixes = Vec::new();

    // Check directory exists
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }

    // Try to read manifest.toml
    let manifest_path = path.join("manifest.toml");
    let mut parsed_manifest: Option<ConnectorManifest> = None;
    let connector_id = if manifest_path.exists() {
        let content = fs::read_to_string(&manifest_path)?;

        match ConnectorManifest::parse_str(&content) {
            Ok(manifest) => {
                checks.push(PrecheckItem {
                    id: "manifest.valid".to_string(),
                    description: "Manifest passes FCP validation".to_string(),
                    passed: true,
                    message: None,
                    severity: CheckSeverity::Error,
                });
                let id = manifest.connector.id.to_string();
                parsed_manifest = Some(manifest);
                Some(id)
            }
            Err(e) => {
                checks.push(PrecheckItem {
                    id: "manifest.valid".to_string(),
                    description: "Manifest passes FCP validation".to_string(),
                    passed: false,
                    message: Some(e.to_string()),
                    severity: CheckSeverity::Error,
                });
                if let Some(message) = capability_id_lint_message(&e) {
                    checks.push(PrecheckItem {
                        id: "manifest.capability_id_lint".to_string(),
                        description: "Capability IDs do not embed hostnames/ports/URLs".to_string(),
                        passed: false,
                        message: Some(message),
                        severity: CheckSeverity::Error,
                    });
                    suggested_fixes.push(SuggestedFix {
                        check_id: "manifest.capability_id_lint".to_string(),
                        action: "Move host/port details into network_constraints and keep capability IDs abstract".to_string(),
                        file: Some("manifest.toml".to_string()),
                    });
                }
                suggested_fixes.push(SuggestedFix {
                    check_id: "manifest.valid".to_string(),
                    action: "Fix manifest validation errors".to_string(),
                    file: Some("manifest.toml".to_string()),
                });
                None
            }
        }
    } else {
        checks.push(PrecheckItem {
            id: "manifest.exists".to_string(),
            description: "Manifest file exists".to_string(),
            passed: false,
            message: Some("manifest.toml not found".to_string()),
            severity: CheckSeverity::Error,
        });
        suggested_fixes.push(SuggestedFix {
            check_id: "manifest.exists".to_string(),
            action: "Create manifest.toml with required FCP2 fields".to_string(),
            file: Some("manifest.toml".to_string()),
        });
        None
    };

    if parsed_manifest.is_some() {
        checks.push(PrecheckItem {
            id: "manifest.capability_id_lint".to_string(),
            description: "Capability IDs do not embed hostnames/ports/URLs".to_string(),
            passed: true,
            message: None,
            severity: CheckSeverity::Error,
        });
    }

    if let Some(id) = &connector_id {
        let valid = validate_connector_id(id).is_ok();
        checks.push(PrecheckItem {
            id: "manifest.connector_id_format".to_string(),
            description: "Connector ID follows naming convention".to_string(),
            passed: valid,
            message: if valid {
                None
            } else {
                Some(format!("Invalid connector ID: {id}"))
            },
            severity: CheckSeverity::Error,
        });
    }

    // Check single-zone binding
    let single_zone_ok = parsed_manifest.as_ref().is_some_and(|manifest| {
        let home = &manifest.zones.home;
        manifest.zones.allowed_sources.len() == 1
            && manifest.zones.allowed_targets.len() == 1
            && manifest.zones.allowed_sources[0] == *home
            && manifest.zones.allowed_targets[0] == *home
    });
    checks.push(PrecheckItem {
        id: "manifest.single_zone".to_string(),
        description: "Connector uses single-zone binding".to_string(),
        passed: single_zone_ok,
        message: None,
        severity: CheckSeverity::Error,
    });

    // Check default-deny NetworkConstraints
    let mut missing_constraints = Vec::new();
    let mut weak_defaults = Vec::new();
    if let Some(manifest) = &parsed_manifest {
        for (op_id, op) in &manifest.provides.operations {
            match &op.network_constraints {
                Some(nc) => {
                    if nc.host_allow.is_empty() || nc.port_allow.is_empty() {
                        missing_constraints.push(op_id.clone());
                    }
                    if !(nc.deny_localhost
                        && nc.deny_private_ranges
                        && nc.deny_tailnet_ranges
                        && nc.deny_ip_literals)
                    {
                        weak_defaults.push(op_id.clone());
                    }
                }
                None => missing_constraints.push(op_id.clone()),
            }
        }
    }
    let network_ok = missing_constraints.is_empty() && weak_defaults.is_empty();
    checks.push(PrecheckItem {
        id: "manifest.network_default_deny".to_string(),
        description: "NetworkConstraints use default-deny".to_string(),
        passed: network_ok,
        message: if network_ok {
            None
        } else {
            Some(format!(
                "Missing/weak constraints in ops: missing={missing_constraints:?} weak={weak_defaults:?}"
            ))
        },
        severity: CheckSeverity::Error,
    });

    // Check forbidden capabilities include system.exec
    let forbids_exec = parsed_manifest.as_ref().is_some_and(|manifest| {
        manifest
            .capabilities
            .forbidden
            .iter()
            .any(|cap| cap.as_str() == "system.exec")
    });
    checks.push(PrecheckItem {
        id: "manifest.forbidden_exec".to_string(),
        description: "system.exec is in forbidden capabilities".to_string(),
        passed: forbids_exec,
        message: None,
        severity: CheckSeverity::Error,
    });

    // Check for #![forbid(unsafe_code)] in main.rs and lib.rs
    let main_rs_path = path.join("src/main.rs");
    let lib_rs_path = path.join("src/lib.rs");
    let mut forbids_unsafe = true;

    if main_rs_path.exists() {
        let content = fs::read_to_string(&main_rs_path)?;
        if !content.contains("#![forbid(unsafe_code)]") {
            forbids_unsafe = false;
            suggested_fixes.push(SuggestedFix {
                check_id: "code.forbid_unsafe".to_string(),
                action: "Add #![forbid(unsafe_code)] at the top of main.rs".to_string(),
                file: Some("src/main.rs".to_string()),
            });
        }
    } else {
        forbids_unsafe = false;
    }

    if lib_rs_path.exists() {
        let content = fs::read_to_string(&lib_rs_path)?;
        if !content.contains("#![forbid(unsafe_code)]") {
            forbids_unsafe = false;
            suggested_fixes.push(SuggestedFix {
                check_id: "code.forbid_unsafe".to_string(),
                action: "Add #![forbid(unsafe_code)] at the top of lib.rs".to_string(),
                file: Some("src/lib.rs".to_string()),
            });
        }
    } else {
        forbids_unsafe = false;
    }

    checks.push(PrecheckItem {
        id: "code.forbid_unsafe".to_string(),
        description: "Code forbids unsafe Rust".to_string(),
        passed: forbids_unsafe,
        message: if forbids_unsafe {
            None
        } else {
            Some("Add #![forbid(unsafe_code)] to src/main.rs and src/lib.rs".to_string())
        },
        severity: CheckSeverity::Error,
    });

    // Check for test directory
    let tests_dir = path.join("tests");
    checks.push(PrecheckItem {
        id: "tests.directory".to_string(),
        description: "Tests directory exists".to_string(),
        passed: tests_dir.exists(),
        message: None,
        severity: CheckSeverity::Warning,
    });

    let prechecks = PrecheckResults::passed(checks);

    Ok(CheckResult {
        path: path.display().to_string(),
        connector_id,
        prechecks,
        suggested_fixes,
    })
}

/// Generate next steps for the developer.
fn generate_next_steps(
    connector_id: &str,
    crate_path: &str,
    archetype: ConnectorArchetype,
    no_e2e: bool,
) -> Vec<String> {
    let mut steps = vec![
        format!("cd {crate_path}"),
        "Fill in TODO placeholders in manifest.toml:".to_string(),
        "  - Update connector description".to_string(),
        "  - Define required capabilities".to_string(),
        "  - Configure network constraints for your API endpoints".to_string(),
        "Implement operations in src/connector.rs:".to_string(),
        "  - Replace placeholder_operation with real operations".to_string(),
        "  - Add capability verification".to_string(),
        "  - Implement error handling with FCP error taxonomy".to_string(),
    ];

    // Add archetype-specific hints
    match archetype {
        ConnectorArchetype::Streaming | ConnectorArchetype::Bidirectional => {
            steps.push("  - Implement event streaming logic".to_string());
        }
        ConnectorArchetype::Polling => {
            steps.push("  - Configure polling interval and backoff".to_string());
        }
        ConnectorArchetype::Webhook => {
            steps.push("  - Implement webhook signature verification".to_string());
        }
        _ => {}
    }

    steps.push("Update src/types.rs with your request/response types".to_string());
    steps.push("Run tests: cargo test".to_string());

    if !no_e2e {
        steps.push("Run E2E tests: cargo test --test e2e_tests -- --ignored".to_string());
    }

    steps.push(format!("Validate: fcp new --check {crate_path}"));
    let crate_slug = normalize_crate_slug(extract_short_name(connector_id));
    steps.push(format!("Build: cargo build -p fcp-{crate_slug}"));

    steps
}

/// Convert `snake_case` to `PascalCase`.
fn to_pascal_case(s: &str) -> String {
    s.split(['_', '-', '.'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(chars.flat_map(char::to_lowercase))
                    .collect()
            })
        })
        .collect()
}

/// Print scaffold result in human-readable format.
fn print_scaffold_result(result: &ScaffoldResult, dry_run: bool) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let cyan = "\x1b[36m";
    let dim = "\x1b[2m";

    println!();
    if dry_run {
        println!("{yellow}{bold}DRY RUN{reset} - No files written");
        println!();
    }
    println!(
        "{bold}Created connector:{reset} {cyan}{}{reset}",
        result.connector_id
    );
    println!("{bold}Path:{reset} {}", result.crate_path);
    println!();

    println!("{bold}Files:{reset}");
    for file in &result.files_created {
        println!(
            "  {green}+{reset} {:<30} {dim}({} bytes) - {}{reset}",
            file.path, file.size, file.purpose
        );
    }
    println!();

    print_precheck_results(&result.prechecks);

    println!("{bold}Next steps:{reset}");
    for (i, step) in result.next_steps.iter().enumerate() {
        if step.starts_with("  ") {
            println!("   {step}");
        } else {
            println!("{dim}{:2}.{reset} {step}", i + 1);
        }
    }
    println!();
}

/// Print check result in human-readable format.
fn print_check_result(result: &CheckResult) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let cyan = "\x1b[36m";

    println!();
    println!("{bold}Checking:{reset} {}", result.path);
    if let Some(id) = &result.connector_id {
        println!("{bold}Connector ID:{reset} {cyan}{id}{reset}");
    }
    println!();

    print_precheck_results(&result.prechecks);

    if !result.suggested_fixes.is_empty() {
        let yellow = "\x1b[33m";
        println!("{bold}Suggested fixes:{reset}");
        for fix in &result.suggested_fixes {
            print!("  {yellow}*{reset} {}", fix.action);
            if let Some(file) = &fix.file {
                print!(" ({file})");
            }
            println!();
        }
        println!();
    }
}

/// Print precheck results.
fn print_precheck_results(prechecks: &PrecheckResults) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let red = "\x1b[31m";
    let dim = "\x1b[2m";

    println!("{bold}Compliance Prechecks:{reset}");
    for check in &prechecks.checks {
        let (color, symbol) = if check.passed {
            (green, "✓")
        } else {
            match check.severity {
                CheckSeverity::Error => (red, "✗"),
                CheckSeverity::Warning => (yellow, "!"),
                CheckSeverity::Info => (dim, "·"),
            }
        };

        print!("  {color}{symbol}{reset} {}", check.description);
        if let Some(msg) = &check.message {
            print!(" {dim}({msg}){reset}");
        }
        println!();
    }
    println!();

    let summary = &prechecks.summary;
    let status_color = if prechecks.passed { green } else { red };
    let status_text = if prechecks.passed { "PASSED" } else { "FAILED" };
    println!(
        "{bold}Result:{reset} {status_color}{status_text}{reset} ({}/{} checks, {} warnings)",
        summary.passed, summary.total, summary.warnings
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_connector_id_valid() {
        assert!(validate_connector_id("fcp.myservice").is_ok());
        assert!(validate_connector_id("fcp.my_service").is_ok());
        assert!(validate_connector_id("fcp.my-service").is_ok());
        assert!(validate_connector_id("fcp.my.nested.service").is_ok());
    }

    #[test]
    fn validate_connector_id_invalid() {
        assert!(validate_connector_id("myservice").is_err());
        assert!(validate_connector_id("fcp.").is_err());
        assert!(validate_connector_id("fcp..service").is_err());
        assert!(validate_connector_id("fcp.MyService").is_err());
        assert!(validate_connector_id("fcp.my service").is_err());
    }

    #[test]
    fn extract_short_name_works() {
        assert_eq!(extract_short_name("fcp.myservice"), "myservice");
        assert_eq!(extract_short_name("fcp.my.nested"), "my.nested");
        assert_eq!(extract_short_name("myservice"), "myservice");
    }

    #[test]
    fn to_pascal_case_works() {
        assert_eq!(to_pascal_case("my_service"), "MyService");
        assert_eq!(to_pascal_case("myservice"), "Myservice");
        assert_eq!(to_pascal_case("my-service"), "MyService");
        assert_eq!(to_pascal_case("my.service"), "MyService");
        assert_eq!(to_pascal_case("MY_SERVICE"), "MyService");
    }

    #[test]
    fn scaffold_generates_all_files() {
        let result = scaffold_connector(
            "fcp.test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
            true, // dry run
        )
        .expect("scaffold should succeed");

        // Check expected files
        let file_paths: Vec<&str> = result
            .files_created
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert!(file_paths.contains(&"Cargo.toml"));
        assert!(file_paths.contains(&"manifest.toml"));
        assert!(file_paths.contains(&"src/main.rs"));
        assert!(file_paths.contains(&"src/lib.rs"));
        assert!(file_paths.contains(&"src/config.rs"));
        assert!(file_paths.contains(&"src/error.rs"));
        assert!(file_paths.contains(&"src/connector.rs"));
        assert!(file_paths.contains(&"src/api.rs"));
        assert!(file_paths.contains(&"src/types.rs"));
        assert!(file_paths.contains(&"src/limits.rs"));
        assert!(file_paths.contains(&"tests/unit_tests.rs"));
        assert!(file_paths.contains(&"tests/e2e_tests.rs"));

        let files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
        )
        .expect("generate files should succeed");
        let config = files
            .iter()
            .find(|(path, _, _)| path == "src/config.rs")
            .expect("config.rs present")
            .1
            .clone();
        let error = files
            .iter()
            .find(|(path, _, _)| path == "src/error.rs")
            .expect("error.rs present")
            .1
            .clone();
        let api = files
            .iter()
            .find(|(path, _, _)| path == "src/api.rs")
            .expect("api.rs present")
            .1
            .clone();
        let limits = files
            .iter()
            .find(|(path, _, _)| path == "src/limits.rs")
            .expect("limits.rs present")
            .1
            .clone();

        assert!(config.contains("Never store secrets"));
        assert!(error.contains("Connector-specific errors"));
        assert!(api.contains("Retry helper"));
        assert!(limits.contains("TODO: Replace placeholders"));
    }

    #[test]
    fn scaffold_archetype_file_matrix() {
        fn has_file(files: &[(String, String, String)], path: &str) -> bool {
            files.iter().any(|(p, _, _)| p == path)
        }

        let rr_files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
        )
        .expect("rr files");
        assert!(has_file(&rr_files, "src/api.rs"));
        assert!(!has_file(&rr_files, "src/stream.rs"));
        assert!(!has_file(&rr_files, "src/polling.rs"));

        let streaming_files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::Streaming,
            "z:project:test",
            false,
        )
        .expect("streaming files");
        assert!(has_file(&streaming_files, "src/stream.rs"));
        assert!(!has_file(&streaming_files, "src/api.rs"));
        assert!(!has_file(&streaming_files, "src/polling.rs"));

        let bidirectional_files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::Bidirectional,
            "z:project:test",
            false,
        )
        .expect("bidirectional files");
        assert!(has_file(&bidirectional_files, "src/stream.rs"));
        assert!(!has_file(&bidirectional_files, "src/api.rs"));
        assert!(!has_file(&bidirectional_files, "src/polling.rs"));

        let polling_files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::Polling,
            "z:project:test",
            false,
        )
        .expect("polling files");
        assert!(has_file(&polling_files, "src/polling.rs"));
        assert!(!has_file(&polling_files, "src/api.rs"));
        assert!(!has_file(&polling_files, "src/stream.rs"));
    }

    #[test]
    fn scaffold_no_e2e_skips_e2e() {
        let result = scaffold_connector(
            "fcp.test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            true, // no_e2e
            true, // dry run
        )
        .expect("scaffold should succeed");

        assert!(
            !result
                .files_created
                .iter()
                .any(|f| f.path.as_str() == "tests/e2e_tests.rs")
        );
    }

    #[test]
    fn prechecks_pass_for_valid_scaffold() {
        let result = scaffold_connector(
            "fcp.test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
            true, // dry run
        )
        .expect("scaffold should succeed");

        assert!(
            result.prechecks.passed,
            "Prechecks should pass for generated scaffold"
        );
    }
}
