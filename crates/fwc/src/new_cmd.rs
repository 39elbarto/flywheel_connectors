//! FCP connector scaffolding command.
//!
//! Scaffolds new V3-native connector crates with `ConnectorRuntime`,
//! `RetryLoop`, `ConnectorErrorMapping`, manifest boilerplate, and compliance
//! prechecks.
//!
//! # Usage
//!
//! ```text
//! # Create a new connector
//! fwc new fcp.myservice
//! fwc new fcp.myservice --archetype streaming
//! fwc new fcp.myservice --zone z:project:myapp
//!
//! # Preview without writing
//! fwc new fcp.myservice --dry-run
//!
//! # Check an existing connector
//! fwc new --check connectors/myservice
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use fcp_core::validate_canonical_id;
use fcp_manifest::ConnectorManifest;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Types (consolidated from types submodule)
// ─────────────────────────────────────────────────────────────────────────────

/// Archetype classification for connectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConnectorArchetype {
    /// Request-response pattern (most APIs).
    RequestResponse,
    /// Continuous data streaming (SSE, WebSocket).
    Streaming,
    /// Full-duplex real-time communication.
    Bidirectional,
    /// Periodic data fetch (getUpdates).
    Polling,
    /// Receives callbacks from external services.
    Webhook,
    /// Message queue integration (SQS, `RabbitMQ`).
    Queue,
    /// File/blob storage operations.
    File,
    /// Database read/write operations.
    Database,
    /// CLI or command execution wrapper.
    Cli,
    /// Browser automation or scraping.
    Browser,
}

impl std::fmt::Display for ConnectorArchetype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestResponse => write!(f, "request-response"),
            Self::Streaming => write!(f, "streaming"),
            Self::Bidirectional => write!(f, "bidirectional"),
            Self::Polling => write!(f, "polling"),
            Self::Webhook => write!(f, "webhook"),
            Self::Queue => write!(f, "queue"),
            Self::File => write!(f, "file"),
            Self::Database => write!(f, "database"),
            Self::Cli => write!(f, "cli"),
            Self::Browser => write!(f, "browser"),
        }
    }
}

impl std::str::FromStr for ConnectorArchetype {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "request-response" | "requestresponse" => Ok(Self::RequestResponse),
            "streaming" => Ok(Self::Streaming),
            "bidirectional" => Ok(Self::Bidirectional),
            "polling" => Ok(Self::Polling),
            "webhook" => Ok(Self::Webhook),
            "queue" => Ok(Self::Queue),
            "file" => Ok(Self::File),
            "database" => Ok(Self::Database),
            "cli" => Ok(Self::Cli),
            "browser" => Ok(Self::Browser),
            _ => Err(format!("unknown archetype: {s}")),
        }
    }
}

/// Result of scaffold generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScaffoldResult {
    /// Connector name/ID.
    connector_id: String,
    /// Path to generated crate.
    crate_path: String,
    /// Files created during scaffolding.
    files_created: Vec<CreatedFile>,
    /// Compliance precheck results.
    prechecks: PrecheckResults,
    /// Next steps for the developer.
    next_steps: Vec<String>,
}

/// A file created during scaffolding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreatedFile {
    /// Relative path from crate root.
    path: String,
    /// Purpose of this file.
    purpose: String,
    /// Size in bytes.
    size: usize,
}

/// Results of compliance prechecks.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrecheckResults {
    /// Overall pass/fail status.
    passed: bool,
    /// Individual check results.
    checks: Vec<PrecheckItem>,
    /// Summary counts.
    summary: PrecheckSummary,
}

impl PrecheckResults {
    /// Create a new passed precheck result.
    fn passed(checks: Vec<PrecheckItem>) -> Self {
        let passed = checks.iter().all(|c| c.passed);
        let summary = PrecheckSummary::from_checks(&checks);
        Self {
            passed,
            checks,
            summary,
        }
    }
}

/// A single compliance precheck.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrecheckItem {
    /// Check identifier.
    id: String,
    /// Human-readable description.
    description: String,
    /// Pass/fail status.
    passed: bool,
    /// Detailed message (especially for failures).
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Severity level.
    severity: CheckSeverity,
}

/// Severity level for precheck items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CheckSeverity {
    /// Must pass for compliance.
    Error,
    /// Should pass but not blocking.
    Warning,
    /// Informational only.
    Info,
}

/// Summary of precheck results.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrecheckSummary {
    /// Total checks run.
    total: usize,
    /// Checks that passed.
    passed: usize,
    /// Checks that failed.
    failed: usize,
    /// Checks with warnings.
    warnings: usize,
}

impl PrecheckSummary {
    /// Build summary from checks.
    fn from_checks(checks: &[PrecheckItem]) -> Self {
        let total = checks.len();
        let passed = checks.iter().filter(|c| c.passed).count();
        let failed = checks
            .iter()
            .filter(|c| !c.passed && c.severity == CheckSeverity::Error)
            .count();
        let warnings = checks
            .iter()
            .filter(|c| !c.passed && c.severity == CheckSeverity::Warning)
            .count();
        Self {
            total,
            passed,
            failed,
            warnings,
        }
    }
}

/// Result of running `fwc new --check` on an existing connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckResult {
    /// Connector directory checked.
    path: String,
    /// Connector ID from manifest (if found).
    connector_id: Option<String>,
    /// Compliance check results.
    prechecks: PrecheckResults,
    /// Suggested fixes for failed checks.
    suggested_fixes: Vec<SuggestedFix>,
}

/// A suggested fix for a failed check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SuggestedFix {
    /// Related check ID.
    check_id: String,
    /// What to do.
    action: String,
    /// File to modify (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Command arguments and entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `fwc new` command.
#[derive(Args, Debug)]
pub(crate) struct NewArgs {
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
pub(crate) enum ArchetypeArg {
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
pub(crate) fn run(args: &NewArgs) -> Result<()> {
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

// ─────────────────────────────────────────────────────────────────────────────
// Validation and helpers
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Scaffold generation
// ─────────────────────────────────────────────────────────────────────────────

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
            "Connector manifest".to_string(),
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
            generate_limits_rs(short_name, archetype),
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

// ─────────────────────────────────────────────────────────────────────────────
// File generators (Cargo.toml, manifest, main.rs, lib.rs, etc.)
// ─────────────────────────────────────────────────────────────────────────────

/// Generate Cargo.toml content.
fn generate_cargo_toml(crate_name: &str, short_name: &str) -> String {
    format!(
        r#"[package]
name = "{crate_name}"
description = "V3-native FCP connector for {short_name}"
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
futures-util.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
fcp-async-core = {{ path = "../../crates/fcp-async-core" }}
tracing.workspace = true
tracing-subscriber.workspace = true
uuid.workspace = true
sha2.workspace = true
hex.workspace = true

[dev-dependencies]
assert_cmd = "2.0"
wiremock.workspace = true
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
        r#"# Flywheel Connector Manifest
# Generated by `fwc new` - fill in placeholder values marked with TODO

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

# Signatures and supply chain metadata are added during `fwc install`
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
//! Generated entrypoint for a Flywheel connector scaffold.

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

    for line in stdin.lock().lines() {{
        let line = line?;
        if line.is_empty() {{
            continue;
        }}

        let response =
            fcp_async_core::runtime::block_on_sync(handle_message(&mut connector, &line))
                .unwrap_or_else(|e| {{
                    serde_json::json!({{
                        "jsonrpc": "2.0",
                        "error": {{
                            "code": "FCP-9001",
                            "message": format!("Runtime error: {{e}}")
                        }}
                    }})
                }});

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
        "doctor" => encode(&connector.doctor()),
        "self_check" => encode(&connector.self_check().await?),
        "introspect" => encode(&connector.introspect()),
        "invoke" => {{
            let req: InvokeRequest = serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {{
                code: 1003,
                message: format!("Invalid invoke request: {{e}}"),
            }})?;
            encode(&connector.invoke(req).await?)
        }}
        "simulate" => {{
            let req: SimulateRequest = serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {{
                code: 1003,
                message: format!("Invalid simulate request: {{e}}"),
            }})?;
            encode(&connector.simulate(req).await?)
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

use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::{{FcpError, FcpResult}};
use serde::{{Deserialize, Serialize}};
use serde_json::Value;

/// Connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct {struct_name}Config {{
    /// Default request timeout for invoke paths.
    pub request_timeout_ms: u64,
    /// Shared retry policy for outbound request helpers.
    pub retry: HttpRetryConfig,
}}

impl Default for {struct_name}Config {{
    fn default() -> Self {{
        Self {{
            request_timeout_ms: 30_000,
            retry: HttpRetryConfig::default(),
        }}
    }}
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
        if self.request_timeout_ms == 0 {{
            return Err(FcpError::InvalidRequest {{
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            }});
        }}
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

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_sdk::migration::ConnectorErrorMapping;
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
    #[error("rate limited, retry after {{retry_after_ms}}ms")]
    RateLimited {{ retry_after_ms: u64 }},

    /// Runtime / deadline error.
    #[error("runtime error: {{0}}")]
    Runtime(String),
}}

impl {struct_name}Error {{
    /// Whether this error should be retried.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {{
        matches!(self, Self::ExternalService(_) | Self::RateLimited {{ .. }})
    }}

    /// Suggested retry delay.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {{
        match self {{
            Self::RateLimited {{ retry_after_ms }} => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }}
    }}

    /// Convert to a structured FCP error.
    pub fn to_fcp_error(&self) -> FcpError {{
        match self {{
            Self::Config(message) => FcpError::InvalidRequest {{
                code: 5001,
                message: message.clone(),
            }},
            Self::ExternalService(message) => FcpError::External {{
                service: "{short_name}".into(),
                message: message.clone(),
                status_code: None,
                retryable: true,
                retry_after: None,
            }},
            Self::RateLimited {{ retry_after_ms }} => FcpError::RateLimited {{
                retry_after_ms: *retry_after_ms,
                violation: None,
            }},
            Self::Runtime(message) => FcpError::Internal {{
                message: message.clone(),
            }},
        }}
    }}
}}

impl ConnectorErrorMapping for {struct_name}Error {{
    fn from_async_error(error: AsyncError) -> Self {{
        match error {{
            AsyncError::Timeout {{ timeout_ms }} => Self::Runtime(format!(
                "request deadline exceeded after {{timeout_ms}}ms"
            )),
            AsyncError::Cancelled => Self::Runtime("request cancelled".into()),
            other => Self::Runtime(other.to_string()),
        }}
    }}

    fn to_fcp_error(&self) -> FcpError {{
        Self::to_fcp_error(self)
    }}

    fn is_retryable(&self) -> bool {{
        Self::is_retryable(self)
    }}

    fn retry_after(&self) -> Option<Duration> {{
        Self::retry_after(self)
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
//! TODO: Implement HTTP calls and wrap them with `ConnectorRuntime` +
//! `RetryLoop` at the real request boundary.

use std::time::Duration;

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
use futures_util::stream::iter;

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
use futures_util::stream::iter;

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

/// Generate limits.rs content tailored to the connector archetype.
fn generate_limits_rs(short_name: &str, archetype: ConnectorArchetype) -> String {
    let struct_name = to_pascal_case(short_name);
    let archetype_constants = match archetype {
        ConnectorArchetype::Streaming | ConnectorArchetype::Bidirectional => {
            r"
/// Max length for message text payloads (chars).
pub const MAX_MESSAGE_CHARS: usize = 0;

/// Max payload size in bytes (serialized JSON).
pub const MAX_PAYLOAD_BYTES: usize = 0;

/// Max items buffered before applying backpressure.
pub const MAX_BUFFER_ITEMS: usize = 0;

/// Max reconnection attempts before giving up.
pub const MAX_RECONNECT_ATTEMPTS: usize = 0;

/// Keepalive interval in seconds (0 = disabled).
pub const KEEPALIVE_INTERVAL_SECS: u64 = 0;
"
        }
        ConnectorArchetype::Webhook => {
            r"
/// Max webhook payload size in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 0;

/// Max registered webhooks per resource.
pub const MAX_WEBHOOKS_PER_RESOURCE: usize = 0;

/// Max event types per webhook subscription.
pub const MAX_EVENT_TYPES: usize = 0;

/// Max character length for webhook URL.
pub const MAX_URL_CHARS: usize = 0;
"
        }
        ConnectorArchetype::Polling => {
            r"
/// Max payload size in bytes (serialized JSON).
pub const MAX_PAYLOAD_BYTES: usize = 0;

/// Max items returned per poll request.
pub const MAX_ITEMS_PER_POLL: usize = 0;

/// Minimum poll interval in seconds.
pub const MIN_POLL_INTERVAL_SECS: u64 = 0;

/// Max offset/cursor value for pagination.
pub const MAX_OFFSET: usize = 0;
"
        }
        ConnectorArchetype::Queue => {
            r"
/// Max message body size in bytes.
pub const MAX_MESSAGE_BYTES: usize = 0;

/// Max messages per batch send/receive.
pub const MAX_BATCH_SIZE: usize = 0;

/// Max visibility timeout in seconds.
pub const MAX_VISIBILITY_TIMEOUT_SECS: u64 = 0;

/// Max message attributes per message.
pub const MAX_ATTRIBUTES: usize = 0;
"
        }
        ConnectorArchetype::File => {
            r"
/// Max file upload size in bytes.
pub const MAX_UPLOAD_BYTES: usize = 0;

/// Max file name length in chars.
pub const MAX_FILENAME_CHARS: usize = 0;

/// Max files per batch operation.
pub const MAX_BATCH_FILES: usize = 0;

/// Max path depth (nested folders).
pub const MAX_PATH_DEPTH: usize = 0;
"
        }
        ConnectorArchetype::Database => {
            r"
/// Max payload size in bytes (serialized JSON).
pub const MAX_PAYLOAD_BYTES: usize = 0;

/// Max rows per query result.
pub const MAX_ROWS_PER_QUERY: usize = 0;

/// Max query length in chars.
pub const MAX_QUERY_CHARS: usize = 0;

/// Max batch insert size (rows).
pub const MAX_BATCH_ROWS: usize = 0;
"
        }
        // RequestResponse, Cli, Browser all use the generic template
        _ => {
            r"
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
        }
    };
    format!(
        r"//! {struct_name} connector API limits.
//!
//! TODO: Replace placeholders with the actual service limits before shipping.

#![allow(dead_code)]
{archetype_constants}"
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
    let enforce_limits_body = match archetype {
        ConnectorArchetype::Queue => {
            r#"    fn enforce_limits(&self, input: &serde_json::Value) -> FcpResult<()> {{
        if limits::MAX_MESSAGE_BYTES > 0 && input.to_string().len() > limits::MAX_MESSAGE_BYTES {{
            return Err(FcpError::InvalidRequest {{
                code: 1006,
                message: "message exceeds MAX_MESSAGE_BYTES limit".to_string(),
            }});
        }}
        Ok(())
    }}"#
        }
        ConnectorArchetype::File => {
            r#"    fn enforce_limits(&self, input: &serde_json::Value) -> FcpResult<()> {{
        if limits::MAX_FILENAME_CHARS > 0 {{
            if let Some(name) = input.get("filename").and_then(|v| v.as_str()) {{
                if name.chars().count() > limits::MAX_FILENAME_CHARS {{
                    return Err(FcpError::InvalidRequest {{
                        code: 1005,
                        message: "filename exceeds MAX_FILENAME_CHARS limit".to_string(),
                    }});
                }}
            }}
        }}
        Ok(())
    }}"#
        }
        ConnectorArchetype::Webhook
        | ConnectorArchetype::Polling
        | ConnectorArchetype::Database => {
            r#"    fn enforce_limits(&self, input: &serde_json::Value) -> FcpResult<()> {{
        if limits::MAX_PAYLOAD_BYTES > 0 && input.to_string().len() > limits::MAX_PAYLOAD_BYTES {{
            return Err(FcpError::InvalidRequest {{
                code: 1006,
                message: "payload exceeds MAX_PAYLOAD_BYTES limit".to_string(),
            }});
        }}
        Ok(())
    }}"#
        }
        // RequestResponse, Streaming, Bidirectional, Cli, Browser
        _ => {
            r#"    fn enforce_limits(&self, input: &serde_json::Value) -> FcpResult<()> {{
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
    }}"#
        }
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

use std::time::{{Duration, Instant}};
{mutex_import}

use fcp_sdk::prelude::*;
use fcp_sdk::migration::{{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
}};
use sha2::{{Digest, Sha256}};

use crate::config::{struct_name}Config;
use crate::error::{struct_name}Error;
use crate::limits;
{stream_import}{polling_import}

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_PLACEHOLDER: &str = "{short_name}.placeholder";
const CAP_PLACEHOLDER: &str = "{short_name}.placeholder";
const SUPPORTS_STREAMING: bool = {supports_streaming};

// ─────────────────────────────────────────────────────────────────────────────
// Doctor types (connector-local diagnostics)
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a connector doctor check.
#[derive(Debug, Clone, serde::Serialize)]
struct DoctorResult {{
    passed: bool,
    checks: Vec<DoctorCheck>,
}}

/// A single diagnostic check within a doctor run.
#[derive(Debug, Clone, serde::Serialize)]
struct DoctorCheck {{
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}}

impl DoctorResult {{
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {{
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self {{ passed, checks }}
    }}
}}

/// {struct_name} connector state.
#[derive(Debug)]
pub struct {struct_name}Connector {{
    base: BaseConnector,
    configured: bool,
    config: Option<{struct_name}Config>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
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
            runtime: None,
            retry_config: HttpRetryConfig::default(),
{stream_init}{polling_init}            started_at: Instant::now(),
            verifier: None,
        }}
    }}

    fn manifest_hash() -> String {{
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{{}}", hex::encode(hasher.finalize()))
    }}

{enforce_limits_body}

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

    /// Run connector diagnostics (V3 doctor endpoint).
    ///
    /// Returns a structured readiness report without leaking secrets.
    pub fn doctor(&self) -> DoctorResult {{
        let mut checks = Vec::new();

        // Check 1: Configuration loaded
        let configured = self.config.is_some();
        checks.push(DoctorCheck {{
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {{
                "Configuration loaded".into()
            }} else {{
                "Not configured - run configure first".into()
            }}),
            critical: true,
        }});

        // Check 2: Runtime initialized
        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {{
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {{
                "ConnectorRuntime initialized".into()
            }} else {{
                "Runtime missing; re-run configure".into()
            }}),
            critical: true,
        }});

        // Check 3: Capability verifier
        let verifier_ok = self.verifier.is_some();
        checks.push(DoctorCheck {{
            name: "capability_verifier".into(),
            passed: verifier_ok,
            message: Some(if verifier_ok {{
                "Capability verifier initialized".into()
            }} else {{
                "Verifier missing; run handshake first".into()
            }}),
            critical: false,
        }});

        // TODO: Add connector-specific checks (API reachability, auth, etc.)

        DoctorResult::from_checks(checks)
    }}
}}

#[async_trait]
impl FcpConnector for {struct_name}Connector {{
    fn id(&self) -> &ConnectorId {{
        &self.base.id
    }}

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {{
        let config = {struct_name}Config::from_value(config)?;
        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));
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

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {{
        if !self.configured {{
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        }}

        // TODO: Replace with a real read-only API probe that validates
        //       credentials and reachability without side effects.
        Ok(SelfCheckReport::ok())
    }}

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {{
        // Default V3 simulate: check capability token and return allowed.
        // TODO: Add cost estimation, resource availability checks, etc.
        Ok(SimulateResponse::allowed(req.id))
    }}

    fn metrics(&self) -> ConnectorMetrics {{
        self.base.metrics()
    }}

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {{
        if let Some(runtime) = &self.runtime {{
            runtime.shutdown();
        }}
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
        let runtime = self.runtime.as_ref().ok_or(FcpError::NotConfigured)?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let output = RetryLoop::execute(&ctx, &policy, |attempt| async move {{
            debug!(attempt, operation = OP_PLACEHOLDER, "Executing placeholder V3 invoke path");
            AttemptOutcome::Success(json!({{
                "status": "ok",
                "message": "Placeholder operation executed"
            }}))
        }})
        .await
        .map_err(|error: {struct_name}Error| error.to_fcp_error())?;

        // TODO: Replace the placeholder branch with a real client call while
        // preserving the `ConnectorRuntime` + `RetryLoop` pattern.
        Ok(InvokeResponse::ok(req.id, output))
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

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {{
        let mut connector = {struct_name}Connector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }}

    #[fcp_async_core::runtime::test]
    async fn test_invoke_placeholder() {{
        let mut connector = {struct_name}Connector::new();
        connector
            .configure(serde_json::json!({{}}))
            .await
            .expect("configure");
        // Must handshake first to initialize verifier
        connector.handshake(base_handshake()).await.expect("handshake");

        let req = base_invoke(connector.id(), OP_PLACEHOLDER);
        let response = connector.invoke(req).await.expect("invoke");
        assert_eq!(response.status, InvokeStatus::Ok);
    }}

    #[test]
    fn test_doctor_before_configure() {{
        let connector = {struct_name}Connector::new();
        let report = connector.doctor();
        assert!(!report.passed, "doctor should fail before configure");
        assert!(report.checks.iter().any(|c| c.name == "configuration" && !c.passed));
    }}

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {{
        let mut connector = {struct_name}Connector::new();
        connector.configure(serde_json::json!({{}})).await.expect("configure");
        let report = connector.doctor();
        assert!(report.passed, "doctor should pass after configure");
        assert!(report.checks.iter().all(|c| !c.critical || c.passed));
    }}

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {{
        let connector = {struct_name}Connector::new();
        let report = connector.self_check().await.expect("self_check");
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }}

    #[fcp_async_core::runtime::test]
    async fn test_self_check_after_configure() {{
        let mut connector = {struct_name}Connector::new();
        connector.configure(serde_json::json!({{}})).await.expect("configure");
        let report = connector.self_check().await.expect("self_check");
        assert_eq!(report.status, SelfCheckStatus::Ok);
    }}

    #[fcp_async_core::runtime::test]
    async fn test_simulate_returns_allowed() {{
        let connector = {struct_name}Connector::new();
        let req = SimulateRequest {{
            r#type: "simulate".into(),
            id: RequestId::new("sim_1"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_PLACEHOLDER),
            zone_id: ZoneId::work(),
            input: serde_json::json!({{}}),
            capability_token: CapabilityToken::test_token(),
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        }};
        let response = connector.simulate(req).await.expect("simulate");
        assert!(response.would_succeed);
    }}

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation_rejected() {{
        let mut connector = {struct_name}Connector::new();
        connector.configure(serde_json::json!({{}})).await.expect("configure");
        connector.handshake(base_handshake()).await.expect("handshake");
        let req = base_invoke(connector.id(), "nonexistent.operation");
        let result = connector.invoke(req).await;
        assert!(result.is_err(), "unknown operation should be rejected");
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

fn base_handshake() -> HandshakeRequest {{
    HandshakeRequest {{
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: [0u8; 32],
        nonce: [0u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(OP_PLACEHOLDER)],
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

// ─────────────────────────────────────────────────────────────────────────────
// Happy path tests
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn test_happy_path_placeholder() {{
    let mut connector = {struct_name}Connector::new();

    // Configure the connector
    connector
        .configure(serde_json::json!({{}}))
        .await
        .expect("configure");

    connector
        .handshake(base_handshake())
        .await
        .expect("handshake");

    // Invoke placeholder operation
    let invoke_result = connector
        .invoke(base_invoke(connector.id(), OP_PLACEHOLDER))
        .await;
    assert!(invoke_result.is_ok(), "Placeholder operation should succeed");
}}

// ─────────────────────────────────────────────────────────────────────────────
// Capability denial tests
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn test_missing_capability_denied() {{
    // TODO: Test that operations fail without proper capability tokens
    // This verifies the default-deny security model
}}

// ─────────────────────────────────────────────────────────────────────────────
// Network constraint tests
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn test_network_constraints_enforced() {{
    // TODO: Test that network requests to non-allowed hosts are blocked
    // This verifies the default-deny NetworkConstraints
}}

// ─────────────────────────────────────────────────────────────────────────────
// Secret redaction tests
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
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

#[fcp_async_core::runtime::test]
async fn test_error_codes_correct() {{
    let connector = {struct_name}Connector::new();

    // Test unknown operation returns correct error
    let result = connector
        .invoke(base_invoke(connector.id(), "unknown.operation"))
        .await;

    assert!(result.is_err());
    // TODO: Verify error code is in correct range (FCP-5xxx for connector errors)
}}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorErrorMapping V3 contract tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_error_mapping_rate_limit() {{
    use crate::error::{struct_name}Error;
    use fcp_sdk::migration::ConnectorErrorMapping;

    let err = {struct_name}Error::RateLimited {{ retry_after_ms: 5000 }};
    assert!(err.is_retryable(), "rate limit should be retryable");
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_millis(5000)));

    let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
    assert!(matches!(fcp_err, FcpError::RateLimited {{ .. }}));
}}

#[test]
fn test_error_mapping_config() {{
    use crate::error::{struct_name}Error;
    use fcp_sdk::migration::ConnectorErrorMapping;

    let err = {struct_name}Error::Config("bad key".into());
    assert!(!err.is_retryable(), "config error should not be retryable");
    assert!(err.retry_after().is_none());

    let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
    assert!(matches!(fcp_err, FcpError::InvalidRequest {{ .. }}));
}}

#[test]
fn test_error_mapping_runtime() {{
    use crate::error::{struct_name}Error;
    use fcp_sdk::migration::ConnectorErrorMapping;

    let err = {struct_name}Error::Runtime("cancelled".into());
    assert!(!err.is_retryable(), "runtime error should not be retryable");

    let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
    assert!(matches!(fcp_err, FcpError::Internal {{ .. }}));
}}

#[test]
fn test_error_mapping_from_async_timeout() {{
    use crate::error::{struct_name}Error;
    use fcp_async_core::AsyncError;
    use fcp_sdk::migration::ConnectorErrorMapping;

    let async_err = AsyncError::Timeout {{ timeout_ms: 30000 }};
    let err = {struct_name}Error::from_async_error(async_err);
    assert!(matches!(err, {struct_name}Error::Runtime(_)));
}}

#[test]
fn test_error_mapping_from_async_cancelled() {{
    use crate::error::{struct_name}Error;
    use fcp_async_core::AsyncError;
    use fcp_sdk::migration::ConnectorErrorMapping;

    let async_err = AsyncError::Cancelled;
    let err = {struct_name}Error::from_async_error(async_err);
    assert!(matches!(err, {struct_name}Error::Runtime(_)));
}}

// ─────────────────────────────────────────────────────────────────────────────
// V3 diagnostic endpoint tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_doctor_reports_unconfigured() {{
    let connector = {struct_name}Connector::new();
    let report = connector.doctor();
    assert!(!report.passed, "doctor should fail before configure");
}}

#[fcp_async_core::runtime::test]
async fn test_doctor_reports_configured() {{
    let mut connector = {struct_name}Connector::new();
    connector.configure(serde_json::json!({{}})).await.expect("configure");
    let report = connector.doctor();
    assert!(report.passed, "doctor should pass after configure");
}}

#[fcp_async_core::runtime::test]
async fn test_self_check_degraded_before_configure() {{
    let connector = {struct_name}Connector::new();
    let report = connector.self_check().await.expect("self_check");
    assert_eq!(report.status, SelfCheckStatus::Degraded);
}}

#[fcp_async_core::runtime::test]
async fn test_self_check_ok_after_configure() {{
    let mut connector = {struct_name}Connector::new();
    connector.configure(serde_json::json!({{}})).await.expect("configure");
    let report = connector.self_check().await.expect("self_check");
    assert_eq!(report.status, SelfCheckStatus::Ok);
}}

#[fcp_async_core::runtime::test]
async fn test_simulate_allowed_by_default() {{
    let connector = {struct_name}Connector::new();
    let req = SimulateRequest {{
        r#type: "simulate".into(),
        id: RequestId::new("sim_1"),
        connector_id: connector.id().clone(),
        operation: OperationId::from_static(OP_PLACEHOLDER),
        zone_id: ZoneId::work(),
        input: serde_json::json!({{}}),
        capability_token: CapabilityToken::test_token(),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    }};
    let response = connector.simulate(req).await.expect("simulate");
    assert!(response.would_succeed);
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

// ─────────────────────────────────────────────────────────────────────────────
// V3 diagnostic endpoint tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires built binary"]
fn test_e2e_doctor() {{
    let mut connector = spawn_connector().expect("spawn connector");

    let response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "doctor",
            "params": {{}}
        }}))
        .expect("doctor");

    assert!(response.get("result").is_some(), "doctor should return result");
    let result = &response["result"];
    assert!(result.get("passed").is_some(), "doctor result should have passed field");
    assert!(result.get("checks").is_some(), "doctor result should have checks array");
}}

#[test]
#[ignore = "requires built binary"]
fn test_e2e_self_check() {{
    let mut connector = spawn_connector().expect("spawn connector");

    let response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "self_check",
            "params": {{}}
        }}))
        .expect("self_check");

    assert!(response.get("result").is_some(), "self_check should return result");
    let result = &response["result"];
    assert!(result.get("status").is_some(), "self_check should have status field");
}}

#[test]
#[ignore = "requires built binary"]
fn test_e2e_simulate() {{
    let mut connector = spawn_connector().expect("spawn connector");

    // Configure first
    connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "configure",
            "params": {{}}
        }}))
        .expect("configure");

    let response = connector
        .send(&serde_json::json!({{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "simulate",
            "params": {{
                "id": "sim_1",
                "operation": "{short_name}.placeholder",
                "input": {{}},
                "zone_id": "z:work",
                "capability_token": {{}}
            }}
        }}))
        .expect("simulate");

    assert!(response.get("result").is_some(), "simulate should return result");
}}
"#
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Prechecks and compliance validation
// ─────────────────────────────────────────────────────────────────────────────

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
                if let Some(message) = e.capability_id_lint_message() {
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

    // Check 9: V3 method completeness (doctor, self_check, simulate)
    let connector_rs = files
        .iter()
        .find(|(path, _, _)| path == "src/connector.rs")
        .map(|(_, content, _)| content.as_str());
    let v3_methods_ok = connector_rs.is_some_and(|c| {
        c.contains("fn doctor(") && c.contains("fn self_check(") && c.contains("fn simulate(")
    });
    checks.push(PrecheckItem {
        id: "code.v3_methods".to_string(),
        description: "V3 diagnostic methods present (doctor, self_check, simulate)".to_string(),
        passed: v3_methods_ok,
        message: if v3_methods_ok {
            None
        } else {
            Some("Missing V3 methods: doctor, self_check, or simulate".to_string())
        },
        severity: CheckSeverity::Error,
    });

    PrecheckResults::passed(checks)
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
                if let Some(message) = e.capability_id_lint_message() {
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

    // V3 method completeness check
    let connector_rs_path = path.join("src/connector.rs");
    let v3_methods_ok = if connector_rs_path.exists() {
        let content = fs::read_to_string(&connector_rs_path).unwrap_or_default();
        content.contains("fn doctor(")
            && (content.contains("fn self_check(") || content.contains("fn handle_self_check("))
            && (content.contains("fn simulate(") || content.contains("fn handle_simulate("))
    } else {
        false
    };
    checks.push(PrecheckItem {
        id: "code.v3_methods".to_string(),
        description: "V3 diagnostic methods present (doctor, self_check, simulate)".to_string(),
        passed: v3_methods_ok,
        message: if v3_methods_ok {
            None
        } else {
            Some("Add doctor(), self_check(), and simulate() methods".to_string())
        },
        severity: CheckSeverity::Warning,
    });
    if !v3_methods_ok {
        suggested_fixes.push(SuggestedFix {
            check_id: "code.v3_methods".to_string(),
            action: "Add V3 diagnostic methods: doctor() for diagnostics, self_check() for API reachability, simulate() for preflight checks".to_string(),
            file: Some("src/connector.rs".to_string()),
        });
    }

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

    // V3 verification guidance
    steps.push(
        "V3 Acceptance Contract verification (docs/V3_Connector_Acceptance_Contract.md):"
            .to_string(),
    );
    steps.push(
        "  - Ensure every OperationInfo has correct SafetyTier, RiskLevel, IdempotencyClass"
            .to_string(),
    );
    steps.push(
        "  - Verify ConnectorErrorMapping covers every error variant with truthful retryability"
            .to_string(),
    );
    steps.push("  - Confirm ConnectorRuntime.shutdown() is called in shutdown handler".to_string());
    steps.push("  - Confirm all HTTP calls use RetryLoop (no hand-rolled retry loops)".to_string());
    steps.push(
        "  - Confirm secrets are never logged (check Debug impls and error messages)".to_string(),
    );

    let crate_slug = normalize_crate_slug(extract_short_name(connector_id));
    steps.push(format!(
        "Run quality gates via rch: rch exec -- cargo clippy -p fcp-{crate_slug} --all-targets -- -D warnings"
    ));
    steps.push(format!(
        "Run tests via rch: rch exec -- cargo test -p fcp-{crate_slug}"
    ));

    if !no_e2e {
        steps.push(format!(
            "Run E2E tests: rch exec -- cargo test -p fcp-{crate_slug} --test e2e_tests -- --ignored"
        ));
    }

    steps.push(format!("Validate: fwc new --check {crate_path}"));
    steps.push(format!(
        "Build: rch exec -- cargo build -p fcp-{crate_slug}"
    ));

    steps
}

// ─────────────────────────────────────────────────────────────────────────────
// Display helpers
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ---- types tests (from types submodule) ----

    #[test]
    fn archetype_roundtrip() {
        for arch in [
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
            ConnectorArchetype::Queue,
            ConnectorArchetype::File,
            ConnectorArchetype::Database,
            ConnectorArchetype::Cli,
            ConnectorArchetype::Browser,
        ] {
            let s = arch.to_string();
            let parsed: ConnectorArchetype = s.parse().expect("should parse");
            assert_eq!(arch, parsed);
        }
    }

    #[test]
    fn precheck_summary_counts() {
        let checks = vec![
            PrecheckItem {
                id: "check1".to_string(),
                description: "Check 1".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Error,
            },
            PrecheckItem {
                id: "check2".to_string(),
                description: "Check 2".to_string(),
                passed: false,
                message: Some("Failed".to_string()),
                severity: CheckSeverity::Error,
            },
            PrecheckItem {
                id: "check3".to_string(),
                description: "Check 3".to_string(),
                passed: false,
                message: Some("Warning".to_string()),
                severity: CheckSeverity::Warning,
            },
        ];

        let summary = PrecheckSummary::from_checks(&checks);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.warnings, 1);
    }

    #[test]
    fn scaffold_result_serialization() {
        let result = ScaffoldResult {
            connector_id: "fcp.myservice".to_string(),
            crate_path: "connectors/myservice".to_string(),
            files_created: vec![CreatedFile {
                path: "Cargo.toml".to_string(),
                purpose: "Crate manifest".to_string(),
                size: 512,
            }],
            prechecks: PrecheckResults::passed(vec![PrecheckItem {
                id: "manifest.valid".to_string(),
                description: "Manifest is valid TOML".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Error,
            }]),
            next_steps: vec!["Fill in placeholder operations".to_string()],
        };

        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("fcp.myservice"));
        assert!(json.contains("Cargo.toml"));
    }

    // ---- validate_connector_id ----

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
        assert!(api.contains("RetryLoop"));
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
    fn limits_rs_is_archetype_specific() {
        fn get_limits(archetype: ConnectorArchetype) -> String {
            let files = generate_files(
                "fcp.test",
                "test",
                "fcp-test",
                archetype,
                "z:project:test",
                false,
            )
            .expect("generate files");
            files
                .iter()
                .find(|(p, _, _)| p == "src/limits.rs")
                .expect("limits.rs present")
                .1
                .clone()
        }

        let rr = get_limits(ConnectorArchetype::RequestResponse);
        assert!(rr.contains("MAX_MESSAGE_CHARS"));
        assert!(rr.contains("MAX_PAYLOAD_BYTES"));
        assert!(rr.contains("MAX_ATTACHMENTS"));

        let streaming = get_limits(ConnectorArchetype::Streaming);
        assert!(streaming.contains("MAX_BUFFER_ITEMS"));
        assert!(streaming.contains("MAX_RECONNECT_ATTEMPTS"));
        assert!(streaming.contains("KEEPALIVE_INTERVAL_SECS"));

        let webhook = get_limits(ConnectorArchetype::Webhook);
        assert!(webhook.contains("MAX_WEBHOOKS_PER_RESOURCE"));
        assert!(webhook.contains("MAX_EVENT_TYPES"));
        assert!(!webhook.contains("MAX_MESSAGE_CHARS"));

        let polling = get_limits(ConnectorArchetype::Polling);
        assert!(polling.contains("MAX_ITEMS_PER_POLL"));
        assert!(polling.contains("MIN_POLL_INTERVAL_SECS"));

        let queue = get_limits(ConnectorArchetype::Queue);
        assert!(queue.contains("MAX_MESSAGE_BYTES"));
        assert!(queue.contains("MAX_BATCH_SIZE"));
        assert!(queue.contains("MAX_VISIBILITY_TIMEOUT_SECS"));

        let file = get_limits(ConnectorArchetype::File);
        assert!(file.contains("MAX_UPLOAD_BYTES"));
        assert!(file.contains("MAX_FILENAME_CHARS"));
        assert!(file.contains("MAX_BATCH_FILES"));

        let db = get_limits(ConnectorArchetype::Database);
        assert!(db.contains("MAX_ROWS_PER_QUERY"));
        assert!(db.contains("MAX_QUERY_CHARS"));
        assert!(db.contains("MAX_BATCH_ROWS"));

        // All archetypes include the TODO marker
        for archetype in [
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Webhook,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Queue,
            ConnectorArchetype::File,
            ConnectorArchetype::Database,
        ] {
            let limits = get_limits(archetype);
            assert!(
                limits.contains("TODO: Replace placeholders"),
                "archetype {archetype} missing TODO marker"
            );
        }
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

    // ---- normalize_crate_slug ----

    #[test]
    fn normalize_crate_slug_simple() {
        assert_eq!(normalize_crate_slug("myservice"), "myservice");
    }

    #[test]
    fn normalize_crate_slug_with_dots() {
        assert_eq!(normalize_crate_slug("my.service"), "my-service");
    }

    #[test]
    fn normalize_crate_slug_with_underscores() {
        assert_eq!(normalize_crate_slug("my_service"), "my-service");
    }

    #[test]
    fn normalize_crate_slug_mixed_case() {
        assert_eq!(normalize_crate_slug("MyService"), "myservice");
    }

    #[test]
    fn normalize_crate_slug_consecutive_special() {
        // Consecutive non-alphanumeric should collapse to single dash
        assert_eq!(normalize_crate_slug("my..service"), "my-service");
    }

    #[test]
    fn normalize_crate_slug_leading_trailing_special() {
        assert_eq!(normalize_crate_slug(".myservice."), "myservice");
    }

    #[test]
    fn normalize_crate_slug_empty_input() {
        assert_eq!(normalize_crate_slug(""), "");
    }

    // ---- insert_workspace_member ----

    #[test]
    fn insert_workspace_member_basic() {
        let content = r#"[workspace]
members = [
    "crates/foo",
    "crates/bar",
]
"#;
        let result = insert_workspace_member(content, "connectors/test").unwrap();
        assert!(result.contains("\"connectors/test\""));
        // Should still contain existing members
        assert!(result.contains("\"crates/foo\""));
        assert!(result.contains("\"crates/bar\""));
    }

    #[test]
    fn insert_workspace_member_missing_members_fails() {
        let content = "[package]\nname = \"foo\"\n";
        let result = insert_workspace_member(content, "connectors/test");
        assert!(result.is_err());
    }

    // ---- manifest_archetype ----

    #[test]
    fn manifest_archetype_operational() {
        assert_eq!(
            manifest_archetype(ConnectorArchetype::RequestResponse),
            "operational"
        );
        assert_eq!(
            manifest_archetype(ConnectorArchetype::Polling),
            "operational"
        );
        assert_eq!(manifest_archetype(ConnectorArchetype::Cli), "operational");
        assert_eq!(
            manifest_archetype(ConnectorArchetype::Browser),
            "operational"
        );
    }

    #[test]
    fn manifest_archetype_streaming() {
        assert_eq!(
            manifest_archetype(ConnectorArchetype::Streaming),
            "streaming"
        );
        assert_eq!(manifest_archetype(ConnectorArchetype::Webhook), "streaming");
    }

    #[test]
    fn manifest_archetype_bidirectional() {
        assert_eq!(
            manifest_archetype(ConnectorArchetype::Bidirectional),
            "bidirectional"
        );
        assert_eq!(
            manifest_archetype(ConnectorArchetype::Queue),
            "bidirectional"
        );
    }

    #[test]
    fn manifest_archetype_storage() {
        assert_eq!(manifest_archetype(ConnectorArchetype::File), "storage");
        assert_eq!(manifest_archetype(ConnectorArchetype::Database), "storage");
    }

    // ---- archetype_arg_conversion ----

    #[test]
    fn archetype_arg_all_variants_convert() {
        let variants = [
            (
                ArchetypeArg::RequestResponse,
                ConnectorArchetype::RequestResponse,
            ),
            (ArchetypeArg::Streaming, ConnectorArchetype::Streaming),
            (
                ArchetypeArg::Bidirectional,
                ConnectorArchetype::Bidirectional,
            ),
            (ArchetypeArg::Polling, ConnectorArchetype::Polling),
            (ArchetypeArg::Webhook, ConnectorArchetype::Webhook),
            (ArchetypeArg::Queue, ConnectorArchetype::Queue),
            (ArchetypeArg::File, ConnectorArchetype::File),
            (ArchetypeArg::Database, ConnectorArchetype::Database),
            (ArchetypeArg::Cli, ConnectorArchetype::Cli),
            (ArchetypeArg::Browser, ConnectorArchetype::Browser),
        ];
        for (arg, expected) in variants {
            let result: ConnectorArchetype = arg.into();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn archetype_arg_default_is_request_response() {
        let default = ArchetypeArg::default();
        assert!(matches!(default, ArchetypeArg::RequestResponse));
    }

    // ---- generate_cargo_toml ----

    #[test]
    fn generate_cargo_toml_contains_crate_name() {
        let output = generate_cargo_toml("fcp-myservice", "myservice");
        assert!(output.contains("name = \"fcp-myservice\""));
        assert!(output.contains("description = \"V3-native FCP connector for myservice\""));
        assert!(output.contains("fcp-sdk"));
    }

    #[test]
    fn generate_cargo_toml_has_workspace_version() {
        let output = generate_cargo_toml("fcp-test", "test");
        assert!(output.contains("version.workspace = true"));
        assert!(output.contains("edition.workspace = true"));
    }

    // ---- generate_lib_rs ----

    #[test]
    fn generate_lib_rs_request_response_has_api() {
        let output = generate_lib_rs("test", true, false, false);
        assert!(output.contains("pub mod api;"));
        assert!(!output.contains("pub mod stream;"));
        assert!(!output.contains("pub mod polling;"));
    }

    #[test]
    fn generate_lib_rs_streaming_has_stream() {
        let output = generate_lib_rs("test", false, true, false);
        assert!(output.contains("pub mod stream;"));
        assert!(!output.contains("pub mod api;"));
    }

    #[test]
    fn generate_lib_rs_polling_has_polling() {
        let output = generate_lib_rs("test", false, false, true);
        assert!(output.contains("pub mod polling;"));
        assert!(!output.contains("pub mod api;"));
        assert!(!output.contains("pub mod stream;"));
    }

    #[test]
    fn generate_lib_rs_forbids_unsafe() {
        let output = generate_lib_rs("test", false, false, false);
        assert!(output.contains("#![forbid(unsafe_code)]"));
    }

    // ---- generate_config_rs ----

    #[test]
    fn generate_config_rs_has_struct() {
        let output = generate_config_rs("my_service");
        assert!(output.contains("pub struct MyServiceConfig"));
        assert!(output.contains("Never store secrets"));
        assert!(output.contains("request_timeout_ms"));
        assert!(output.contains("HttpRetryConfig"));
    }

    // ---- generate_error_rs ----

    #[test]
    fn generate_error_rs_has_taxonomy() {
        let output = generate_error_rs("my_service");
        assert!(output.contains("pub enum MyServiceError"));
        assert!(output.contains("Config(String)"));
        assert!(output.contains("ExternalService(String)"));
        assert!(output.contains("RateLimited { retry_after_ms: u64 }"));
        assert!(output.contains("Runtime(String)"));
    }

    #[test]
    fn generate_error_rs_has_fcp_conversion() {
        let output = generate_error_rs("test");
        assert!(output.contains("to_fcp_error"));
        assert!(output.contains("5001"));
        assert!(output.contains("FcpError::External"));
        assert!(output.contains("FcpError::RateLimited"));
        assert!(output.contains("ConnectorErrorMapping"));
    }

    // ---- generate_limits_rs ----

    #[test]
    fn generate_limits_rs_has_constants() {
        let output = generate_limits_rs("test", ConnectorArchetype::RequestResponse);
        assert!(output.contains("MAX_MESSAGE_CHARS"));
        assert!(output.contains("MAX_PAYLOAD_BYTES"));
        assert!(output.contains("MAX_ATTACHMENTS"));
        assert!(output.contains("MAX_ATTACHMENT_BYTES"));
        assert!(output.contains("MAX_EMBEDS"));
        assert!(output.contains("MAX_TITLE_CHARS"));
    }

    // ---- generate_types_rs ----

    #[test]
    fn generate_types_rs_has_placeholder_types() {
        let output = generate_types_rs("test");
        assert!(output.contains("PlaceholderInput"));
        assert!(output.contains("PlaceholderOutput"));
    }

    // ---- generate_next_steps ----

    #[test]
    fn generate_next_steps_includes_build_and_validate() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::RequestResponse,
            false,
        );
        assert!(steps.iter().any(|s| s.contains("cd connectors/test")));
        assert!(steps.iter().any(|s| s.contains("cargo test")));
        assert!(steps.iter().any(|s| s.contains("fwc new --check")));
        assert!(steps.iter().any(|s| s.contains("cargo build")));
    }

    #[test]
    fn generate_next_steps_streaming_includes_event_hint() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::Streaming,
            false,
        );
        assert!(steps.iter().any(|s| s.contains("event streaming")));
    }

    #[test]
    fn generate_next_steps_polling_includes_interval_hint() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::Polling,
            false,
        );
        assert!(steps.iter().any(|s| s.contains("polling interval")));
    }

    #[test]
    fn generate_next_steps_webhook_includes_signature_hint() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::Webhook,
            false,
        );
        assert!(steps.iter().any(|s| s.contains("webhook signature")));
    }

    #[test]
    fn generate_next_steps_no_e2e_excludes_e2e_step() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::RequestResponse,
            true,
        );
        assert!(!steps.iter().any(|s| s.contains("e2e_tests")));
    }

    #[test]
    fn generate_next_steps_with_e2e_includes_e2e_step() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::RequestResponse,
            false,
        );
        assert!(steps.iter().any(|s| s.contains("e2e_tests")));
    }

    #[test]
    fn generate_next_steps_includes_v3_contract_guidance() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::RequestResponse,
            false,
        );
        assert!(
            steps.iter().any(|s| s.contains("V3 Acceptance Contract")),
            "next steps should reference V3 acceptance contract"
        );
        assert!(
            steps.iter().any(|s| s.contains("ConnectorErrorMapping")),
            "next steps should mention ConnectorErrorMapping verification"
        );
        assert!(
            steps.iter().any(|s| s.contains("OperationInfo")),
            "next steps should mention OperationInfo verification"
        );
        assert!(
            steps.iter().any(|s| s.contains("rch exec")),
            "next steps should use rch for build commands"
        );
    }

    // ---- to_pascal_case edge cases ----

    #[test]
    fn to_pascal_case_empty_string() {
        assert_eq!(to_pascal_case(""), "");
    }

    #[test]
    fn to_pascal_case_single_char() {
        assert_eq!(to_pascal_case("a"), "A");
    }

    #[test]
    fn to_pascal_case_with_dots() {
        assert_eq!(to_pascal_case("a.b.c"), "ABC");
    }

    #[test]
    fn to_pascal_case_mixed_delimiters() {
        assert_eq!(to_pascal_case("my_service-v2.beta"), "MyServiceV2Beta");
    }

    // ---- validate_connector_id edge cases ----

    #[test]
    fn validate_connector_id_with_numbers() {
        assert!(validate_connector_id("fcp.service2").is_ok());
    }

    #[test]
    fn validate_connector_id_deeply_nested() {
        assert!(validate_connector_id("fcp.a.b.c.d").is_ok());
    }

    // ---- generate_manifest_toml ----

    #[test]
    fn generate_manifest_toml_valid() {
        let result = generate_manifest_toml(
            "fcp.test",
            "test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
        );
        assert!(result.is_ok());
        let content = result.unwrap();
        assert!(content.contains("fcp.test"));
        assert!(content.contains("z:project:test"));
        assert!(!content.contains(INTERFACE_HASH_PLACEHOLDER));
    }

    #[test]
    fn generate_manifest_toml_storage_archetype() {
        let result = generate_manifest_toml(
            "fcp.filestore",
            "filestore",
            ConnectorArchetype::File,
            "z:project:files",
        );
        assert!(result.is_ok());
        let content = result.unwrap();
        assert!(content.contains("\"storage\""));
    }

    // ---- scaffold_connector edge cases ----

    #[test]
    fn scaffold_all_archetypes_pass_prechecks() {
        let archetypes = [
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
            ConnectorArchetype::Queue,
            ConnectorArchetype::File,
            ConnectorArchetype::Database,
            ConnectorArchetype::Cli,
            ConnectorArchetype::Browser,
        ];
        for archetype in archetypes {
            let result = scaffold_connector(
                "fcp.test",
                archetype,
                "z:project:test",
                true, // no_e2e (faster)
                true, // dry_run
            )
            .unwrap_or_else(|e| panic!("scaffold failed for {archetype:?}: {e}"));
            assert!(
                result.prechecks.passed,
                "Prechecks failed for archetype {archetype:?}: {:?}",
                result
                    .prechecks
                    .checks
                    .iter()
                    .filter(|c| !c.passed)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn scaffold_connector_id_in_result() {
        let result = scaffold_connector(
            "fcp.myservice",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            true,
            true,
        )
        .unwrap();
        assert_eq!(result.connector_id, "fcp.myservice");
        assert_eq!(result.crate_path, "connectors/myservice");
    }

    // ---- generate_main_rs ----

    #[test]
    fn generate_main_rs_has_protocol_loop() {
        let output = generate_main_rs("test", "fcp_test");
        assert!(output.contains("run_fcp_loop"));
        assert!(output.contains("fcp_test::TestConnector"));
        assert!(output.contains("#![forbid(unsafe_code)]"));
    }

    #[test]
    fn generate_main_rs_handles_all_methods() {
        let output = generate_main_rs("test", "fcp_test");
        assert!(output.contains("\"configure\""));
        assert!(output.contains("\"handshake\""));
        assert!(output.contains("\"health\""));
        assert!(output.contains("\"introspect\""));
        assert!(output.contains("\"invoke\""));
        assert!(output.contains("\"subscribe\""));
        assert!(output.contains("\"unsubscribe\""));
        assert!(output.contains("\"shutdown\""));
    }

    // ---- generate_connector_rs ----

    #[test]
    fn generate_connector_rs_has_basic_structure() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::RequestResponse);
        assert!(output.contains("pub struct TestConnector"));
        assert!(output.contains("impl FcpConnector for TestConnector"));
        assert!(output.contains("MANIFEST_TOML"));
        assert!(output.contains("test.placeholder"));
        assert!(output.contains("runtime: Option<ConnectorRuntime>"));
        assert!(output.contains("RetryLoop::execute"));
        assert!(output.contains("runtime.request_context()"));
    }

    #[test]
    fn generate_connector_rs_streaming_has_stream_field() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::Streaming);
        assert!(output.contains("stream: Mutex<StreamSupervisor>"));
        assert!(output.contains("impl Streaming for TestConnector"));
    }

    #[test]
    fn generate_connector_rs_polling_has_polling_field() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::Polling);
        assert!(output.contains("polling: Mutex<PollingSupervisor>"));
        assert!(output.contains("impl Polling for TestConnector"));
    }

    #[test]
    fn generate_connector_rs_bidirectional_has_send() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::Bidirectional);
        assert!(output.contains("impl Bidirectional for TestConnector"));
        assert!(output.contains("impl Streaming for TestConnector"));
    }

    // ---- generate_e2e_tests_rs ----

    #[test]
    fn generate_e2e_tests_rs_has_harness() {
        let output = generate_e2e_tests_rs("fcp.test", "test", "fcp-test");
        assert!(output.contains("spawn_connector"));
        assert!(output.contains("ConnectorProcess"));
        assert!(output.contains("#[ignore"));
        assert!(output.contains("cargo_bin(\"fcp-test\")"));
    }

    // ---- run_prechecks ----

    #[test]
    fn prechecks_fail_without_manifest() {
        let files: Vec<(String, String, String)> = vec![(
            "src/main.rs".to_string(),
            "fn main() {}".to_string(),
            "Main".to_string(),
        )];
        let result = run_prechecks(&files, "fcp.test", "z:project:test");
        assert!(!result.passed);
    }

    #[test]
    fn prechecks_check_unsafe_code_forbid() {
        let files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            true,
        )
        .unwrap();
        let result = run_prechecks(&files, "fcp.test", "z:project:test");
        let unsafe_check = result
            .checks
            .iter()
            .find(|c| c.id == "code.forbid_unsafe")
            .expect("should have forbid_unsafe check");
        assert!(unsafe_check.passed);
    }

    #[test]
    fn prechecks_check_no_secrets() {
        let files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            true,
        )
        .unwrap();
        let result = run_prechecks(&files, "fcp.test", "z:project:test");
        let secrets_check = result
            .checks
            .iter()
            .find(|c| c.id == "scaffold.no_secrets")
            .expect("should have no_secrets check");
        assert!(secrets_check.passed);
    }

    // ---- generate_api_rs ----

    #[test]
    fn generate_api_rs_has_client_without_manual_retry_helper() {
        let output = generate_api_rs("test");
        assert!(output.contains("pub struct ApiClient"));
        assert!(output.contains("ConnectorRuntime"));
        assert!(!output.contains("pub async fn retry"));
        assert!(!output.contains("sleep(backoff).await"));
    }

    // ---- generate_stream_rs ----

    #[test]
    fn generate_stream_rs_has_supervisor() {
        let output = generate_stream_rs("test");
        assert!(output.contains("pub struct StreamSupervisor"));
        assert!(output.contains("on_subscribe"));
        assert!(output.contains("on_unsubscribe"));
        assert!(output.contains("empty_event_stream"));
    }

    // ---- generate_polling_rs ----

    #[test]
    fn generate_polling_rs_has_cursor_and_supervisor() {
        let output = generate_polling_rs("test");
        assert!(output.contains("pub struct PollingCursor"));
        assert!(output.contains("pub struct PollingSupervisor"));
        assert!(output.contains("should_poll"));
        assert!(output.contains("begin_poll"));
        assert!(output.contains("finish_poll"));
    }

    // ---- generate_unit_tests_rs ----

    #[test]
    fn generate_unit_tests_rs_has_test_scaffolds() {
        let output = generate_unit_tests_rs("test", "fcp_test");
        assert!(output.contains("test_happy_path_placeholder"));
        assert!(output.contains("test_missing_capability_denied"));
        assert!(output.contains("test_error_codes_correct"));
    }

    // ════════════════════════════════════════════════════════════════
    // Expanded coverage below
    // ════════════════════════════════════════════════════════════════

    // ---- ConnectorArchetype serde roundtrip ----

    #[test]
    fn archetype_serde_roundtrip_all() {
        for arch in [
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
            ConnectorArchetype::Queue,
            ConnectorArchetype::File,
            ConnectorArchetype::Database,
            ConnectorArchetype::Cli,
            ConnectorArchetype::Browser,
        ] {
            let json = serde_json::to_string(&arch).unwrap();
            let parsed: ConnectorArchetype = serde_json::from_str(&json).unwrap();
            assert_eq!(arch, parsed, "serde roundtrip failed for {arch:?}");
        }
    }

    #[test]
    fn archetype_kebab_case_serialization() {
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::RequestResponse).unwrap(),
            "\"request-response\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Streaming).unwrap(),
            "\"streaming\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Bidirectional).unwrap(),
            "\"bidirectional\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Polling).unwrap(),
            "\"polling\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Webhook).unwrap(),
            "\"webhook\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Queue).unwrap(),
            "\"queue\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::File).unwrap(),
            "\"file\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Database).unwrap(),
            "\"database\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Cli).unwrap(),
            "\"cli\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Browser).unwrap(),
            "\"browser\""
        );
    }

    #[test]
    fn archetype_from_str_case_insensitive() {
        assert_eq!(
            "STREAMING".parse::<ConnectorArchetype>().unwrap(),
            ConnectorArchetype::Streaming
        );
        assert_eq!(
            "Polling".parse::<ConnectorArchetype>().unwrap(),
            ConnectorArchetype::Polling
        );
        assert_eq!(
            "REQUEST-RESPONSE".parse::<ConnectorArchetype>().unwrap(),
            ConnectorArchetype::RequestResponse
        );
        assert_eq!(
            "REQUESTRESPONSE".parse::<ConnectorArchetype>().unwrap(),
            ConnectorArchetype::RequestResponse
        );
    }

    #[test]
    fn archetype_from_str_unknown_gives_error() {
        let err = "foobar".parse::<ConnectorArchetype>().unwrap_err();
        assert!(err.contains("unknown archetype"));
        assert!(err.contains("foobar"));
    }

    #[test]
    fn archetype_display_all_variants() {
        assert_eq!(
            ConnectorArchetype::RequestResponse.to_string(),
            "request-response"
        );
        assert_eq!(ConnectorArchetype::Streaming.to_string(), "streaming");
        assert_eq!(
            ConnectorArchetype::Bidirectional.to_string(),
            "bidirectional"
        );
        assert_eq!(ConnectorArchetype::Polling.to_string(), "polling");
        assert_eq!(ConnectorArchetype::Webhook.to_string(), "webhook");
        assert_eq!(ConnectorArchetype::Queue.to_string(), "queue");
        assert_eq!(ConnectorArchetype::File.to_string(), "file");
        assert_eq!(ConnectorArchetype::Database.to_string(), "database");
        assert_eq!(ConnectorArchetype::Cli.to_string(), "cli");
        assert_eq!(ConnectorArchetype::Browser.to_string(), "browser");
    }

    #[allow(clippy::clone_on_copy)]
    #[test]
    fn archetype_clone_copy() {
        let a = ConnectorArchetype::Queue;
        let b = a;
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn archetype_debug() {
        let debug = format!("{:?}", ConnectorArchetype::Browser);
        assert!(debug.contains("Browser"));
    }

    // ---- ScaffoldResult serde ----

    #[test]
    fn scaffold_result_serde_roundtrip() {
        let result = ScaffoldResult {
            connector_id: "fcp.example".to_string(),
            crate_path: "connectors/example".to_string(),
            files_created: vec![
                CreatedFile {
                    path: "Cargo.toml".to_string(),
                    purpose: "Manifest".to_string(),
                    size: 100,
                },
                CreatedFile {
                    path: "src/main.rs".to_string(),
                    purpose: "Entry".to_string(),
                    size: 200,
                },
            ],
            prechecks: PrecheckResults::passed(vec![]),
            next_steps: vec!["step1".to_string(), "step2".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ScaffoldResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "fcp.example");
        assert_eq!(parsed.files_created.len(), 2);
        assert_eq!(parsed.next_steps.len(), 2);
    }

    #[test]
    fn scaffold_result_empty_files() {
        let result = ScaffoldResult {
            connector_id: "fcp.empty".to_string(),
            crate_path: "connectors/empty".to_string(),
            files_created: vec![],
            prechecks: PrecheckResults::passed(vec![]),
            next_steps: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["files_created"].as_array().unwrap().is_empty());
        assert!(json["next_steps"].as_array().unwrap().is_empty());
    }

    // ---- CreatedFile serde ----

    #[test]
    fn created_file_serde_roundtrip() {
        let file = CreatedFile {
            path: "src/lib.rs".to_string(),
            purpose: "Library".to_string(),
            size: 42,
        };
        let json = serde_json::to_string(&file).unwrap();
        let parsed: CreatedFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path, "src/lib.rs");
        assert_eq!(parsed.purpose, "Library");
        assert_eq!(parsed.size, 42);
    }

    #[test]
    fn created_file_zero_size() {
        let file = CreatedFile {
            path: "empty.txt".to_string(),
            purpose: "Placeholder".to_string(),
            size: 0,
        };
        let json = serde_json::to_value(&file).unwrap();
        assert_eq!(json["size"], 0);
    }

    // ---- PrecheckResults ----

    #[test]
    fn precheck_results_all_passed() {
        let checks = vec![
            PrecheckItem {
                id: "a".to_string(),
                description: "A".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Error,
            },
            PrecheckItem {
                id: "b".to_string(),
                description: "B".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Warning,
            },
        ];
        let result = PrecheckResults::passed(checks);
        assert!(result.passed);
        assert_eq!(result.summary.total, 2);
        assert_eq!(result.summary.passed, 2);
        assert_eq!(result.summary.failed, 0);
        assert_eq!(result.summary.warnings, 0);
    }

    #[test]
    fn precheck_results_some_failed() {
        let checks = vec![
            PrecheckItem {
                id: "a".to_string(),
                description: "A".to_string(),
                passed: true,
                message: None,
                severity: CheckSeverity::Error,
            },
            PrecheckItem {
                id: "b".to_string(),
                description: "B".to_string(),
                passed: false,
                message: Some("fail".to_string()),
                severity: CheckSeverity::Error,
            },
        ];
        let result = PrecheckResults::passed(checks);
        assert!(!result.passed);
        assert_eq!(result.summary.failed, 1);
    }

    #[test]
    fn precheck_results_empty_checks() {
        let result = PrecheckResults::passed(vec![]);
        assert!(result.passed);
        assert_eq!(result.summary.total, 0);
        assert_eq!(result.summary.passed, 0);
        assert_eq!(result.summary.failed, 0);
    }

    #[test]
    fn precheck_results_serde_roundtrip() {
        let checks = vec![PrecheckItem {
            id: "test".to_string(),
            description: "Test check".to_string(),
            passed: true,
            message: Some("ok".to_string()),
            severity: CheckSeverity::Info,
        }];
        let result = PrecheckResults::passed(checks);
        let json = serde_json::to_string(&result).unwrap();
        let parsed: PrecheckResults = serde_json::from_str(&json).unwrap();
        assert!(parsed.passed);
        assert_eq!(parsed.checks.len(), 1);
        assert_eq!(parsed.checks[0].id, "test");
    }

    #[test]
    fn precheck_results_warning_only_still_passes() {
        let checks = vec![PrecheckItem {
            id: "w".to_string(),
            description: "Warn".to_string(),
            passed: false,
            message: None,
            severity: CheckSeverity::Warning,
        }];
        let result = PrecheckResults::passed(checks);
        // The `passed` field is computed from all checks passing, so this fails
        assert!(!result.passed);
        assert_eq!(result.summary.warnings, 1);
        assert_eq!(result.summary.failed, 0);
    }

    // ---- PrecheckItem serde ----

    #[test]
    fn precheck_item_skips_none_message() {
        let item = PrecheckItem {
            id: "test".to_string(),
            description: "Desc".to_string(),
            passed: true,
            message: None,
            severity: CheckSeverity::Info,
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn precheck_item_includes_some_message() {
        let item = PrecheckItem {
            id: "test".to_string(),
            description: "Desc".to_string(),
            passed: false,
            message: Some("bad stuff".to_string()),
            severity: CheckSeverity::Error,
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("bad stuff"));
    }

    // ---- CheckSeverity serde ----

    #[test]
    fn check_severity_serde_roundtrip() {
        for sev in [
            CheckSeverity::Error,
            CheckSeverity::Warning,
            CheckSeverity::Info,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let parsed: CheckSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, parsed);
        }
    }

    #[test]
    fn check_severity_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Info).unwrap(),
            "\"info\""
        );
    }

    // ---- PrecheckSummary ----

    #[test]
    fn precheck_summary_all_passed() {
        let checks = vec![
            PrecheckItem {
                id: "a".into(),
                description: "A".into(),
                passed: true,
                message: None,
                severity: CheckSeverity::Error,
            },
            PrecheckItem {
                id: "b".into(),
                description: "B".into(),
                passed: true,
                message: None,
                severity: CheckSeverity::Warning,
            },
        ];
        let summary = PrecheckSummary::from_checks(&checks);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.warnings, 0);
    }

    #[test]
    fn precheck_summary_empty() {
        let summary = PrecheckSummary::from_checks(&[]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.warnings, 0);
    }

    #[test]
    fn precheck_summary_serde_roundtrip() {
        let summary = PrecheckSummary {
            total: 5,
            passed: 3,
            failed: 1,
            warnings: 1,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: PrecheckSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total, 5);
        assert_eq!(parsed.passed, 3);
        assert_eq!(parsed.failed, 1);
        assert_eq!(parsed.warnings, 1);
    }

    #[test]
    fn precheck_summary_info_failures_not_counted() {
        let checks = vec![PrecheckItem {
            id: "i".into(),
            description: "I".into(),
            passed: false,
            message: None,
            severity: CheckSeverity::Info,
        }];
        let summary = PrecheckSummary::from_checks(&checks);
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.warnings, 0);
    }

    // ---- CheckResult serde ----

    #[test]
    fn check_result_serde_roundtrip() {
        let result = CheckResult {
            path: "/tmp/test".to_string(),
            connector_id: Some("fcp.test".to_string()),
            prechecks: PrecheckResults::passed(vec![]),
            suggested_fixes: vec![SuggestedFix {
                check_id: "manifest.valid".to_string(),
                action: "Fix it".to_string(),
                file: Some("manifest.toml".to_string()),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: CheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path, "/tmp/test");
        assert_eq!(parsed.connector_id, Some("fcp.test".to_string()));
        assert_eq!(parsed.suggested_fixes.len(), 1);
    }

    #[test]
    fn check_result_no_connector_id() {
        let result = CheckResult {
            path: "/tmp/test".to_string(),
            connector_id: None,
            prechecks: PrecheckResults::passed(vec![]),
            suggested_fixes: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["connector_id"].is_null());
    }

    // ---- SuggestedFix serde ----

    #[test]
    fn suggested_fix_serde_roundtrip() {
        let fix = SuggestedFix {
            check_id: "test.check".to_string(),
            action: "Do something".to_string(),
            file: Some("src/main.rs".to_string()),
        };
        let json = serde_json::to_string(&fix).unwrap();
        let parsed: SuggestedFix = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.check_id, "test.check");
        assert_eq!(parsed.file, Some("src/main.rs".to_string()));
    }

    #[test]
    fn suggested_fix_no_file_skips_field() {
        let fix = SuggestedFix {
            check_id: "x".to_string(),
            action: "Do it".to_string(),
            file: None,
        };
        let json = serde_json::to_string(&fix).unwrap();
        assert!(!json.contains("file"));
    }

    // ---- validate_connector_id expanded ----

    #[test]
    fn validate_connector_id_just_fcp_dot() {
        assert!(validate_connector_id("fcp.").is_err());
    }

    #[test]
    fn validate_connector_id_consecutive_dots() {
        assert!(validate_connector_id("fcp..test").is_err());
    }

    #[test]
    fn validate_connector_id_triple_dots() {
        assert!(validate_connector_id("fcp...test").is_err());
    }

    #[test]
    fn validate_connector_id_no_prefix() {
        let err = validate_connector_id("nofcp").unwrap_err();
        assert!(err.to_string().contains("fcp."));
    }

    #[test]
    fn validate_connector_id_uppercase_rejected() {
        assert!(validate_connector_id("fcp.MyService").is_err());
    }

    #[test]
    fn validate_connector_id_with_spaces() {
        assert!(validate_connector_id("fcp.my service").is_err());
    }

    #[test]
    fn validate_connector_id_single_char_suffix() {
        assert!(validate_connector_id("fcp.a").is_ok());
    }

    #[test]
    fn validate_connector_id_with_underscores() {
        assert!(validate_connector_id("fcp.my_service").is_ok());
    }

    #[test]
    fn validate_connector_id_with_hyphens() {
        assert!(validate_connector_id("fcp.my-service").is_ok());
    }

    // ---- extract_short_name expanded ----

    #[test]
    fn extract_short_name_no_prefix() {
        assert_eq!(extract_short_name("noprefixhere"), "noprefixhere");
    }

    #[test]
    fn extract_short_name_empty() {
        assert_eq!(extract_short_name(""), "");
    }

    #[test]
    fn extract_short_name_just_prefix() {
        assert_eq!(extract_short_name("fcp."), "");
    }

    // ---- normalize_crate_slug expanded ----

    #[test]
    fn normalize_crate_slug_all_special_chars() {
        assert_eq!(normalize_crate_slug("..."), "");
    }

    #[test]
    fn normalize_crate_slug_numbers() {
        assert_eq!(normalize_crate_slug("service123"), "service123");
    }

    #[test]
    fn normalize_crate_slug_unicode() {
        // Non-ascii is replaced with dash
        assert_eq!(normalize_crate_slug("abc\u{00e9}def"), "abc-def");
    }

    #[test]
    fn normalize_crate_slug_mixed_special() {
        assert_eq!(normalize_crate_slug("a.b_c-d"), "a-b-c-d");
    }

    // ---- to_pascal_case expanded ----

    #[test]
    fn to_pascal_case_consecutive_underscores() {
        assert_eq!(to_pascal_case("a__b"), "AB");
    }

    #[test]
    fn to_pascal_case_all_uppercase() {
        assert_eq!(to_pascal_case("ABC"), "Abc");
    }

    #[test]
    fn to_pascal_case_numeric_parts() {
        assert_eq!(to_pascal_case("v2_beta"), "V2Beta");
    }

    // ---- insert_workspace_member expanded ----

    #[test]
    fn insert_workspace_member_multiple_sections() {
        let content = r#"[package]
name = "root"

[workspace]
members = [
    "crates/alpha",
]

[dependencies]
serde = "1"
"#;
        let result = insert_workspace_member(content, "connectors/new").unwrap();
        assert!(result.contains("\"connectors/new\""));
        assert!(result.contains("\"crates/alpha\""));
    }

    #[test]
    fn insert_workspace_member_empty_list() {
        let content = "[workspace]\nmembers = [\n]\n";
        let result = insert_workspace_member(content, "connectors/first").unwrap();
        assert!(result.contains("\"connectors/first\""));
    }

    // ---- generate_next_steps expanded ----

    #[test]
    fn generate_next_steps_bidirectional_has_event_hint() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::Bidirectional,
            false,
        );
        assert!(steps.iter().any(|s| s.contains("event streaming")));
    }

    #[test]
    fn generate_next_steps_queue_no_specific_hint() {
        let steps = generate_next_steps(
            "fcp.test",
            "connectors/test",
            ConnectorArchetype::Queue,
            false,
        );
        // Queue doesn't have a special archetype hint
        assert!(!steps.iter().any(|s| s.contains("event streaming")));
        assert!(!steps.iter().any(|s| s.contains("polling interval")));
        assert!(!steps.iter().any(|s| s.contains("webhook signature")));
    }

    #[test]
    fn generate_next_steps_always_has_cd_and_build() {
        for archetype in [
            ConnectorArchetype::File,
            ConnectorArchetype::Database,
            ConnectorArchetype::Cli,
            ConnectorArchetype::Browser,
        ] {
            let steps = generate_next_steps("fcp.x", "connectors/x", archetype, false);
            assert!(steps.iter().any(|s| s.contains("cd connectors/x")));
            assert!(steps.iter().any(|s| s.contains("cargo build")));
        }
    }

    // ---- manifest_archetype expanded ----

    #[test]
    fn manifest_archetype_all_variants_non_empty() {
        for arch in [
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
            ConnectorArchetype::Queue,
            ConnectorArchetype::File,
            ConnectorArchetype::Database,
            ConnectorArchetype::Cli,
            ConnectorArchetype::Browser,
        ] {
            assert!(
                !manifest_archetype(arch).is_empty(),
                "archetype {arch:?} had empty manifest label"
            );
        }
    }

    // ---- generate_manifest_toml expanded ----

    #[test]
    fn generate_manifest_toml_streaming() {
        let result = generate_manifest_toml(
            "fcp.stream",
            "stream",
            ConnectorArchetype::Streaming,
            "z:project:stream",
        );
        assert!(result.is_ok());
        let content = result.unwrap();
        assert!(content.contains("\"streaming\""));
        assert!(content.contains("z:project:stream"));
    }

    #[test]
    fn generate_manifest_toml_bidirectional() {
        let result = generate_manifest_toml(
            "fcp.bidir",
            "bidir",
            ConnectorArchetype::Bidirectional,
            "z:project:bidir",
        );
        assert!(result.is_ok());
        let content = result.unwrap();
        assert!(content.contains("\"bidirectional\""));
    }

    #[test]
    fn generate_manifest_toml_replaces_placeholder_hash() {
        let content = generate_manifest_toml(
            "fcp.test",
            "test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
        )
        .unwrap();
        // The INTERFACE_HASH_PLACEHOLDER should not appear in the final output
        assert!(!content.contains("0000000000000000000000000000000000000000"));
    }

    #[test]
    fn generate_manifest_toml_contains_default_deny() {
        let content = generate_manifest_toml(
            "fcp.test",
            "test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
        )
        .unwrap();
        assert!(content.contains("deny_localhost = true"));
        assert!(content.contains("deny_private_ranges = true"));
        assert!(content.contains("deny_ip_literals = true"));
    }

    // ---- scaffold_connector expanded ----

    #[test]
    fn scaffold_connector_next_steps_not_empty() {
        let result = scaffold_connector(
            "fcp.test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
            true,
        )
        .unwrap();
        assert!(!result.next_steps.is_empty());
    }

    #[test]
    fn scaffold_connector_crate_path_matches() {
        let result = scaffold_connector(
            "fcp.my-svc",
            ConnectorArchetype::Database,
            "z:project:db",
            true,
            true,
        )
        .unwrap();
        assert_eq!(result.crate_path, "connectors/my-svc");
    }

    #[test]
    fn scaffold_connector_nested_id() {
        let result = scaffold_connector(
            "fcp.a.b.c",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            true,
            true,
        )
        .unwrap();
        assert_eq!(result.connector_id, "fcp.a.b.c");
        assert_eq!(result.crate_path, "connectors/a-b-c");
    }

    // ---- generate_files expanded ----

    #[test]
    fn generate_files_webhook_no_api_no_stream_no_polling() {
        let files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::Webhook,
            "z:project:test",
            true,
        )
        .unwrap();
        let paths: Vec<&str> = files.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(!paths.contains(&"src/api.rs"));
        assert!(!paths.contains(&"src/stream.rs"));
        assert!(!paths.contains(&"src/polling.rs"));
        assert!(!paths.contains(&"tests/e2e_tests.rs"));
    }

    #[test]
    fn generate_files_database_no_api() {
        let files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::Database,
            "z:project:test",
            false,
        )
        .unwrap();
        let paths: Vec<&str> = files.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(!paths.contains(&"src/api.rs"));
        assert!(paths.contains(&"tests/e2e_tests.rs"));
    }

    #[test]
    fn generate_files_cli_archetype() {
        let files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::Cli,
            "z:project:test",
            true,
        )
        .unwrap();
        let paths: Vec<&str> = files.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(!paths.contains(&"src/api.rs"));
        assert!(!paths.contains(&"src/stream.rs"));
    }

    #[test]
    fn generate_files_all_have_nonzero_content() {
        let files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
        )
        .unwrap();
        for (path, content, _) in &files {
            assert!(!content.is_empty(), "file {path} has empty content");
        }
    }

    #[test]
    fn generate_files_scaffolded_connector_uses_limits_in_validation() {
        fn generated_file(files: &[(String, String, String)], path: &str) -> String {
            files
                .iter()
                .find(|(file_path, _, _)| file_path == path)
                .unwrap_or_else(|| panic!("expected {path} to be generated"))
                .1
                .clone()
        }

        let request_response_files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::RequestResponse,
            "z:project:test",
            false,
        )
        .expect("request-response files");
        let request_response_connector =
            generated_file(&request_response_files, "src/connector.rs");
        assert!(request_response_connector.contains("use crate::limits;"));
        assert!(request_response_connector.contains("limits::MAX_MESSAGE_CHARS"));
        assert!(request_response_connector.contains("limits::MAX_PAYLOAD_BYTES"));

        let queue_files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::Queue,
            "z:project:test",
            false,
        )
        .expect("queue files");
        let queue_connector = generated_file(&queue_files, "src/connector.rs");
        assert!(queue_connector.contains("use crate::limits;"));
        assert!(queue_connector.contains("limits::MAX_MESSAGE_BYTES"));

        let file_files = generate_files(
            "fcp.test",
            "test",
            "fcp-test",
            ConnectorArchetype::File,
            "z:project:test",
            false,
        )
        .expect("file files");
        let file_connector = generated_file(&file_files, "src/connector.rs");
        assert!(file_connector.contains("use crate::limits;"));
        assert!(file_connector.contains("limits::MAX_FILENAME_CHARS"));
    }

    // ---- generate_connector_rs expanded ----

    #[test]
    fn generate_connector_rs_queue_has_enforce_limits() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::Queue);
        assert!(output.contains("use crate::limits;"));
        assert!(output.contains("MAX_MESSAGE_BYTES"));
        assert!(output.contains("enforce_limits"));
    }

    #[test]
    fn generate_connector_rs_file_has_filename_check() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::File);
        assert!(output.contains("use crate::limits;"));
        assert!(output.contains("MAX_FILENAME_CHARS"));
    }

    #[test]
    fn generate_connector_rs_database_enforce_limits() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::Database);
        assert!(output.contains("use crate::limits;"));
        assert!(output.contains("MAX_PAYLOAD_BYTES"));
    }

    #[test]
    fn generate_connector_rs_generic_archetypes_use_limits_in_validation() {
        for archetype in [
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Cli,
            ConnectorArchetype::Browser,
        ] {
            let output = generate_connector_rs("fcp.test", "test", archetype);
            assert!(output.contains("use crate::limits;"));
            assert!(output.contains("limits::MAX_MESSAGE_CHARS"));
            assert!(output.contains("limits::MAX_PAYLOAD_BYTES"));
        }
    }

    #[test]
    fn generate_connector_rs_payload_archetypes_use_named_payload_limits() {
        for archetype in [
            ConnectorArchetype::Webhook,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Database,
        ] {
            let output = generate_connector_rs("fcp.test", "test", archetype);
            assert!(output.contains("use crate::limits;"));
            assert!(output.contains("limits::MAX_PAYLOAD_BYTES"));
        }
    }

    #[test]
    fn generate_connector_rs_has_default_impl() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::RequestResponse);
        assert!(output.contains("impl Default for TestConnector"));
    }

    #[test]
    fn generate_connector_rs_cli_no_stream_or_polling() {
        let output = generate_connector_rs("fcp.test", "test", ConnectorArchetype::Cli);
        assert!(!output.contains("StreamSupervisor"));
        assert!(!output.contains("PollingSupervisor"));
    }

    // ---- generate_limits_rs expanded ----

    #[test]
    fn generate_limits_rs_cli_uses_generic_template() {
        let output = generate_limits_rs("test", ConnectorArchetype::Cli);
        assert!(output.contains("MAX_MESSAGE_CHARS"));
        assert!(output.contains("MAX_ATTACHMENTS"));
    }

    #[test]
    fn generate_limits_rs_browser_uses_generic_template() {
        let output = generate_limits_rs("test", ConnectorArchetype::Browser);
        assert!(output.contains("MAX_MESSAGE_CHARS"));
    }

    #[test]
    fn generate_limits_rs_bidirectional_same_as_streaming() {
        let streaming = generate_limits_rs("test", ConnectorArchetype::Streaming);
        let bidir = generate_limits_rs("test", ConnectorArchetype::Bidirectional);
        assert!(streaming.contains("MAX_BUFFER_ITEMS"));
        assert!(bidir.contains("MAX_BUFFER_ITEMS"));
    }

    // ---- prechecks expanded ----

    #[test]
    fn prechecks_detect_secrets_in_files() {
        let files: Vec<(String, String, String)> = vec![
            (
                "manifest.toml".to_string(),
                "placeholder".to_string(),
                "Manifest".to_string(),
            ),
            (
                "src/config.rs".to_string(),
                "let password = \"secret\";".to_string(),
                "Config".to_string(),
            ),
        ];
        let result = run_prechecks(&files, "fcp.test", "z:project:test");
        let secrets_check = result.checks.iter().find(|c| c.id == "scaffold.no_secrets");
        assert!(secrets_check.is_some());
        assert!(!secrets_check.unwrap().passed);
    }

    #[test]
    fn prechecks_detect_api_key_in_files() {
        let files: Vec<(String, String, String)> = vec![
            (
                "manifest.toml".to_string(),
                "placeholder".to_string(),
                "Manifest".to_string(),
            ),
            (
                "src/main.rs".to_string(),
                "let api_key = \"abc\";".to_string(),
                "Main".to_string(),
            ),
        ];
        let result = run_prechecks(&files, "fcp.test", "z:project:test");
        let secrets_check = result
            .checks
            .iter()
            .find(|c| c.id == "scaffold.no_secrets")
            .unwrap();
        assert!(!secrets_check.passed);
    }

    // ---- generate_e2e_tests_rs expanded ----

    #[test]
    fn generate_e2e_tests_rs_references_connector_id() {
        let output = generate_e2e_tests_rs("fcp.github", "github", "fcp-github");
        assert!(output.contains("fcp.github"));
        assert!(output.contains("cargo_bin(\"fcp-github\")"));
        assert!(output.contains("github.placeholder"));
    }

    // ---- generate_config_rs expanded ----

    #[test]
    fn generate_config_rs_pascal_case_name() {
        let output = generate_config_rs("my_complex_service");
        assert!(output.contains("MyComplexServiceConfig"));
    }

    // ---- generate_error_rs expanded ----

    #[test]
    fn generate_error_rs_pascal_case_name() {
        let output = generate_error_rs("my_complex_service");
        assert!(output.contains("MyComplexServiceError"));
    }

    // ---- ArchetypeArg ----

    #[test]
    fn archetype_arg_debug_all() {
        for arg in [
            ArchetypeArg::RequestResponse,
            ArchetypeArg::Streaming,
            ArchetypeArg::Bidirectional,
            ArchetypeArg::Polling,
            ArchetypeArg::Webhook,
            ArchetypeArg::Queue,
            ArchetypeArg::File,
            ArchetypeArg::Database,
            ArchetypeArg::Cli,
            ArchetypeArg::Browser,
        ] {
            let debug = format!("{arg:?}");
            assert!(!debug.is_empty());
        }
    }

    // ---- generate_lib_rs expanded ----

    #[test]
    fn generate_lib_rs_all_modules_off() {
        let output = generate_lib_rs("test", false, false, false);
        assert!(!output.contains("pub mod api;"));
        assert!(!output.contains("pub mod stream;"));
        assert!(!output.contains("pub mod polling;"));
        assert!(output.contains("pub mod connector;"));
        assert!(output.contains("pub mod config;"));
        assert!(output.contains("pub mod error;"));
    }

    #[test]
    fn generate_lib_rs_all_modules_on() {
        let output = generate_lib_rs("test", true, true, true);
        assert!(output.contains("pub mod api;"));
        assert!(output.contains("pub mod stream;"));
        assert!(output.contains("pub mod polling;"));
    }

    #[test]
    fn generate_lib_rs_re_exports_connector() {
        let output = generate_lib_rs("my_svc", false, false, false);
        assert!(output.contains("pub use connector::MySvcConnector;"));
    }

    // ---- generate_main_rs expanded ----

    #[test]
    fn generate_main_rs_uses_correct_crate_ident() {
        let output = generate_main_rs("my_svc", "fcp_my_svc");
        assert!(output.contains("fcp_my_svc::MySvcConnector"));
    }

    #[test]
    fn generate_main_rs_forbids_unsafe() {
        let output = generate_main_rs("test", "fcp_test");
        assert!(output.contains("#![forbid(unsafe_code)]"));
    }

    // ---- generate_cargo_toml expanded ----

    #[test]
    fn generate_cargo_toml_has_dev_deps() {
        let output = generate_cargo_toml("fcp-test", "test");
        assert!(output.contains("[dev-dependencies]"));
        assert!(output.contains("wiremock"));
        assert!(output.contains("assert_cmd"));
    }

    #[test]
    fn generate_cargo_toml_has_bin_section() {
        let output = generate_cargo_toml("fcp-myservice", "myservice");
        assert!(output.contains("[[bin]]"));
        assert!(output.contains("name = \"fcp-myservice\""));
    }

    // ---- generate_types_rs expanded ----

    #[test]
    fn generate_types_rs_has_serde_derives() {
        let output = generate_types_rs("test");
        assert!(output.contains("Serialize, Deserialize"));
    }

    #[test]
    fn generate_types_rs_has_test_module() {
        let output = generate_types_rs("test");
        assert!(output.contains("#[cfg(test)]"));
        assert!(output.contains("mod tests"));
    }

    // ---- generate_stream_rs expanded ----

    #[test]
    fn generate_stream_rs_has_topics_tracking() {
        let output = generate_stream_rs("test");
        assert!(output.contains("topics"));
        assert!(output.contains("on_subscribe_topic"));
        assert!(output.contains("record_cursor"));
    }

    // ---- generate_polling_rs expanded ----

    #[test]
    fn generate_polling_rs_has_should_poll() {
        let output = generate_polling_rs("test");
        assert!(output.contains("should_poll"));
        assert!(output.contains("CursorState"));
        assert!(output.contains("advance"));
    }

    // ---- generate_api_rs expanded ----

    #[test]
    fn generate_api_rs_uses_correct_error_type() {
        let output = generate_api_rs("my_svc");
        assert!(output.contains("MySvcError"));
    }
}
