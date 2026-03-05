//! `fcp policy` command implementation.
//!
//! Provides a policy simulation CLI for `DecisionReceipt` previews.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use fcp_cbor::SchemaId;
use fcp_core::{
    CapabilityObject, DecisionReceipt, DecisionReceiptPolicy, InvokeRequest, ObjectId,
    POLICY_BUNDLE_SIGNED_FIELDS, PolicyBundle, PolicyBundleObject, PolicyBundlePolicyRef,
    PolicyBundleResolved, PolicyBundleSignature, PolicyPreviewSample, PolicySimulationError,
    PolicySimulationInput, Provenance, ResourceObject, RoleObject, ZoneDefinitionObject, ZoneId,
    ZonePolicyObject, compute_policy_bundle_hash, diff_policy_bundles, preview_policy_bundles,
};
use fcp_crypto::ed25519::{Ed25519SigningKey, SECRET_KEY_SIZE};
use hex::decode as hex_decode;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Arguments for the `fcp policy` command.
#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommands,
}

/// Policy subcommands.
#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Simulate a policy decision for an invoke request.
    Simulate(SimulateArgs),
    /// Diff two zone policy or definition objects.
    Diff(DiffArgs),
    /// Generate a rollback plan between two policy objects.
    Rollback(RollbackArgs),
    /// Policy bundle workflows.
    Bundle(BundleArgs),
}

/// Arguments for `fcp policy simulate`.
#[derive(Args, Debug)]
pub struct SimulateArgs {
    /// Policy simulation input (JSON). Use "-" for stdin.
    ///
    /// Accepts either:
    /// 1) `PolicySimulationInput` JSON (with `zone_policy` + `invoke_request`)
    /// 2) `InvokeRequest` JSON (a permissive zone policy is synthesized)
    #[arg(long)]
    pub input: PathBuf,

    /// Output JSON (`DecisionReceipt`). Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy diff`.
#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Path to the "before" policy object (JSON).
    #[arg(long)]
    pub before: PathBuf,

    /// Path to the "after" policy object (JSON).
    #[arg(long)]
    pub after: PathBuf,

    /// Output JSON diff. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy rollback`.
#[derive(Args, Debug)]
pub struct RollbackArgs {
    /// Path to the current policy object (JSON).
    #[arg(long)]
    pub current: PathBuf,

    /// Path to the previous policy object (JSON).
    #[arg(long)]
    pub previous: PathBuf,

    /// Emit a rollback plan without executing it.
    #[arg(long, default_value_t = false)]
    pub plan: bool,

    /// Output JSON rollback plan. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for policy bundle workflows.
#[derive(Args, Debug)]
pub struct BundleArgs {
    #[command(subcommand)]
    pub command: BundleCommands,
}

/// Policy bundle subcommands.
#[derive(Subcommand, Debug)]
pub enum BundleCommands {
    /// Create a new policy bundle.
    Create(BundleCreateArgs),
    /// Diff two policy bundles (resolved objects required).
    Diff(BundleDiffArgs),
    /// Preview policy changes for a bundle diff with sample invocations.
    Preview(BundlePreviewArgs),
    /// Apply a policy bundle to a state file.
    Apply(BundleApplyArgs),
    /// Roll back policy state to a previous bundle.
    Rollback(BundleRollbackArgs),
}

/// Arguments for `fcp policy bundle diff`.
#[derive(Args, Debug)]
pub struct BundleDiffArgs {
    /// Path to the "before" bundle JSON.
    #[arg(long)]
    pub before: PathBuf,

    /// Path to the "after" bundle JSON.
    #[arg(long)]
    pub after: PathBuf,

    /// JSON map of `object_id` -> policy object for the "before" bundle.
    #[arg(long)]
    pub objects_before: PathBuf,

    /// JSON map of `object_id` -> policy object for the "after" bundle.
    #[arg(long)]
    pub objects_after: PathBuf,

    /// Output JSON diff. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy bundle create`.
#[derive(Args, Debug)]
pub struct BundleCreateArgs {
    /// Bundle identifier.
    #[arg(long)]
    pub bundle_id: String,

    /// Zone identifier (e.g. z:work).
    #[arg(long)]
    pub zone: String,

    /// Monotonic policy sequence number.
    #[arg(long)]
    pub policy_seq: u64,

    /// Path to policy reference list (JSON array).
    #[arg(long)]
    pub policies: PathBuf,

    /// Previous bundle id (optional).
    #[arg(long)]
    pub previous_bundle: Option<String>,

    /// Creation timestamp (RFC3339). Defaults to now.
    #[arg(long)]
    pub created_at: Option<String>,

    /// Signing key id for the bundle signature.
    #[arg(long)]
    pub key_id: String,

    /// Signing key seed as hex (32 bytes).
    #[arg(long, conflicts_with = "signing_key_file")]
    pub signing_key_hex: Option<String>,

    /// Path to signing key seed hex (32 bytes).
    #[arg(long, conflicts_with = "signing_key_hex")]
    pub signing_key_file: Option<PathBuf>,

    /// Output path for the bundle JSON (stdout if omitted).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// Arguments for `fcp policy bundle preview`.
#[derive(Args, Debug)]
pub struct BundlePreviewArgs {
    /// Path to the "before" bundle JSON.
    #[arg(long)]
    pub before: PathBuf,

    /// Path to the "after" bundle JSON.
    #[arg(long)]
    pub after: PathBuf,

    /// JSON map of `object_id` -> policy object for the "before" bundle.
    #[arg(long)]
    pub objects_before: PathBuf,

    /// JSON map of `object_id` -> policy object for the "after" bundle.
    #[arg(long)]
    pub objects_after: PathBuf,

    /// Preview samples (JSON array or object with `samples` field).
    #[arg(long)]
    pub samples: PathBuf,

    /// Output JSON report. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy bundle apply`.
#[derive(Args, Debug)]
pub struct BundleApplyArgs {
    /// Bundle JSON to apply.
    #[arg(long)]
    pub bundle: PathBuf,

    /// Policy bundle state file to write.
    #[arg(long)]
    pub state: PathBuf,

    /// Emit a plan only (do not write state).
    #[arg(long, default_value_t = false)]
    pub plan: bool,

    /// Output JSON. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy bundle rollback`.
#[derive(Args, Debug)]
pub struct BundleRollbackArgs {
    /// Bundle JSON to roll back to.
    #[arg(long)]
    pub to: PathBuf,

    /// Policy bundle state file to write.
    #[arg(long)]
    pub state: PathBuf,

    /// Emit a plan only (do not write state).
    #[arg(long, default_value_t = false)]
    pub plan: bool,

    /// Output JSON. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Run the policy command.
pub fn run(args: &PolicyArgs) -> Result<()> {
    match &args.command {
        PolicyCommands::Simulate(sim_args) => run_simulate(sim_args),
        PolicyCommands::Diff(diff_args) => run_diff(diff_args),
        PolicyCommands::Rollback(rollback_args) => run_rollback(rollback_args),
        PolicyCommands::Bundle(bundle_args) => run_bundle(bundle_args),
    }
}

fn run_simulate(args: &SimulateArgs) -> Result<()> {
    let raw = read_input(&args.input)?;
    let input = parse_simulation_input(&raw)?;
    match fcp_core::simulate_policy_decision(&input) {
        Ok(receipt) => output_receipt(&receipt, args.json),
        Err(err) => output_error(&err, args.json),
    }
}

fn run_bundle(args: &BundleArgs) -> Result<()> {
    match &args.command {
        BundleCommands::Create(create_args) => run_bundle_create(create_args),
        BundleCommands::Diff(diff_args) => run_bundle_diff(diff_args),
        BundleCommands::Preview(preview_args) => run_bundle_preview(preview_args),
        BundleCommands::Apply(apply_args) => run_bundle_apply(apply_args),
        BundleCommands::Rollback(rollback_args) => run_bundle_rollback(rollback_args),
    }
}

fn read_input(path: &PathBuf) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read stdin")?;
        return Ok(buf);
    }

    fs::read_to_string(path).with_context(|| format!("failed to read input {}", path.display()))
}

fn run_bundle_diff(args: &BundleDiffArgs) -> Result<()> {
    let before_bundle = load_policy_bundle(&args.before)?;
    let after_bundle = load_policy_bundle(&args.after)?;
    let before_objects_raw = load_object_map(&args.objects_before)?;
    let after_objects_raw = load_object_map(&args.objects_after)?;

    let before_objects = resolve_bundle_objects(&before_bundle, &before_objects_raw)?;
    let after_objects = resolve_bundle_objects(&after_bundle, &after_objects_raw)?;

    let before_resolved = PolicyBundleResolved::new(before_bundle, before_objects);
    let after_resolved = PolicyBundleResolved::new(after_bundle, after_objects);

    let diff = diff_policy_bundles(&before_resolved, &after_resolved)
        .map_err(|err| anyhow::anyhow!("policy bundle diff failed: {err}"))?;

    output_json_or_human(&diff, args.json)
}

fn run_bundle_create(args: &BundleCreateArgs) -> Result<()> {
    let zone_id: ZoneId = args
        .zone
        .parse()
        .with_context(|| format!("invalid zone id '{}'", args.zone))?;
    let created_at = parse_created_at(args.created_at.as_deref())?;
    let policies = load_policy_refs(&args.policies)?;

    let bundle_hash = compute_policy_bundle_hash(
        &args.bundle_id,
        &zone_id,
        args.policy_seq,
        created_at,
        args.previous_bundle.as_deref(),
        &policies,
    )
    .map_err(|err| anyhow::anyhow!("failed to compute bundle hash: {err}"))?;

    let signing_key = load_signing_key(args)?;
    let signed_fields = POLICY_BUNDLE_SIGNED_FIELDS
        .iter()
        .map(|field| (*field).to_string())
        .collect::<Vec<_>>();

    let placeholder_signature =
        PolicyBundleSignature::new(args.key_id.clone(), "pending", signed_fields.clone());

    let mut builder = PolicyBundle::builder(&args.bundle_id, zone_id, args.policy_seq)
        .bundle_hash(bundle_hash)
        .policies(policies)
        .signature(placeholder_signature);
    if let Some(created_at) = created_at {
        builder = builder.created_at(created_at);
    }
    if let Some(previous) = &args.previous_bundle {
        builder = builder.previous_bundle(previous.clone());
    }

    let mut bundle = builder
        .build()
        .map_err(|err| anyhow::anyhow!("policy bundle build failed: {err}"))?;

    let signing_bytes = bundle
        .signing_bytes()
        .map_err(|err| anyhow::anyhow!("failed to compute signing bytes: {err}"))?;
    let signature = signing_key.sign(&signing_bytes);
    let signature_b64 = BASE64_STANDARD.encode(signature.to_bytes());
    bundle.signature =
        PolicyBundleSignature::new(args.key_id.clone(), signature_b64, signed_fields);
    bundle
        .validate()
        .map_err(|err| anyhow::anyhow!("policy bundle validation failed: {err}"))?;

    write_bundle_output(&bundle, args.out.as_ref())
}

fn run_bundle_preview(args: &BundlePreviewArgs) -> Result<()> {
    let before_bundle = load_policy_bundle(&args.before)?;
    let after_bundle = load_policy_bundle(&args.after)?;
    let before_objects_raw = load_object_map(&args.objects_before)?;
    let after_objects_raw = load_object_map(&args.objects_after)?;
    let samples = load_preview_samples(&args.samples)?;

    let before_objects = resolve_bundle_objects(&before_bundle, &before_objects_raw)?;
    let after_objects = resolve_bundle_objects(&after_bundle, &after_objects_raw)?;

    let before_resolved = PolicyBundleResolved::new(before_bundle, before_objects);
    let after_resolved = PolicyBundleResolved::new(after_bundle, after_objects);

    let report = preview_policy_bundles(&before_resolved, &after_resolved, &samples)
        .map_err(|err| anyhow::anyhow!("policy bundle preview failed: {err}"))?;

    output_json_or_human(&report, args.json)
}

#[derive(Debug, Serialize)]
struct BundleApplyPlan {
    plan_type: String,
    zone_id: String,
    bundle_id: String,
    state_path: String,
}

fn run_bundle_apply(args: &BundleApplyArgs) -> Result<()> {
    if !args.plan {
        anyhow::bail!("bundle apply requires --plan (execution is not supported yet)");
    }

    let bundle = load_policy_bundle(&args.bundle)?;
    let zone_id = bundle.zone_id.to_string();
    let bundle_id = bundle.bundle_id;
    let plan = BundleApplyPlan {
        plan_type: "bundle_apply".to_string(),
        zone_id,
        bundle_id,
        state_path: args.state.display().to_string(),
    };

    output_json_or_human(&plan, args.json)
}

#[derive(Debug, Serialize)]
struct BundleRollbackPlan {
    plan_type: String,
    zone_id: String,
    target_bundle_id: String,
    state_path: String,
}

fn run_bundle_rollback(args: &BundleRollbackArgs) -> Result<()> {
    if !args.plan {
        anyhow::bail!("bundle rollback requires --plan (execution is not supported yet)");
    }

    let bundle = load_policy_bundle(&args.to)?;
    let zone_id = bundle.zone_id.to_string();
    let target_bundle_id = bundle.bundle_id;
    let plan = BundleRollbackPlan {
        plan_type: "bundle_rollback".to_string(),
        zone_id,
        target_bundle_id,
        state_path: args.state.display().to_string(),
    };

    output_json_or_human(&plan, args.json)
}

fn load_policy_bundle(path: &PathBuf) -> Result<PolicyBundle> {
    let raw = read_input(path)?;
    let bundle: PolicyBundle = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy bundle {}", path.display()))?;
    bundle
        .validate()
        .map_err(|err| anyhow::anyhow!("invalid policy bundle {}: {err}", path.display()))?;
    Ok(bundle)
}

fn load_object_map(path: &PathBuf) -> Result<BTreeMap<String, Value>> {
    let raw = read_input(path)?;
    let map: BTreeMap<String, Value> = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse object map {}", path.display()))?;
    Ok(map)
}

fn load_policy_refs(path: &PathBuf) -> Result<Vec<PolicyBundlePolicyRef>> {
    let raw = read_input(path)?;
    let refs: Vec<PolicyBundlePolicyRef> = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy refs {}", path.display()))?;
    if refs.is_empty() {
        anyhow::bail!("policy refs list is empty");
    }
    for (idx, policy_ref) in refs.iter().enumerate() {
        policy_ref
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid policy ref at index {idx}: {err}"))?;
    }
    Ok(refs)
}

#[derive(Debug, Deserialize)]
struct PreviewSamplesFile {
    samples: Vec<PolicyPreviewSample>,
}

fn load_preview_samples(path: &PathBuf) -> Result<Vec<PolicyPreviewSample>> {
    let raw = read_input(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("preview samples input is empty");
    }
    if let Ok(samples) = serde_json::from_str::<Vec<PolicyPreviewSample>>(trimmed) {
        return Ok(samples);
    }
    if let Ok(wrapper) = serde_json::from_str::<PreviewSamplesFile>(trimmed) {
        return Ok(wrapper.samples);
    }
    anyhow::bail!("failed to parse preview samples as array or object with 'samples'")
}

fn parse_created_at(value: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("invalid RFC3339 timestamp '{raw}'"))?;
    Ok(Some(parsed.with_timezone(&Utc)))
}

fn load_signing_key(args: &BundleCreateArgs) -> Result<Ed25519SigningKey> {
    let key_hex = if let Some(hex) = &args.signing_key_hex {
        hex.clone()
    } else if let Some(path) = &args.signing_key_file {
        fs::read_to_string(path)
            .with_context(|| format!("failed to read signing key {}", path.display()))?
    } else {
        anyhow::bail!("signing key is required (--signing-key-hex or --signing-key-file)");
    };

    let key_hex = key_hex.trim();
    let bytes = hex_decode(key_hex).context("failed to decode signing key hex")?;
    if bytes.len() != SECRET_KEY_SIZE {
        anyhow::bail!(
            "signing key must be {SECRET_KEY_SIZE} bytes, got {}",
            bytes.len()
        );
    }
    let mut arr = [0u8; SECRET_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ed25519SigningKey::from_bytes(&arr)
        .map_err(|err| anyhow::anyhow!("failed to load signing key: {err}"))
}

fn write_bundle_output(bundle: &PolicyBundle, out: Option<&PathBuf>) -> Result<()> {
    let json = serde_json::to_string_pretty(bundle)?;
    if let Some(path) = out {
        fs::write(path, json)
            .with_context(|| format!("failed to write bundle {}", path.display()))?;
        return Ok(());
    }

    println!("{json}");
    Ok(())
}

fn resolve_bundle_objects(
    bundle: &PolicyBundle,
    raw_objects: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, PolicyBundleObject>> {
    let mut resolved = BTreeMap::new();
    for policy_ref in &bundle.policies {
        let Some(value) = raw_objects.get(&policy_ref.object_id) else {
            continue;
        };
        let object = parse_bundle_object(&policy_ref.schema_id, value)
            .with_context(|| format!("object_id {}", policy_ref.object_id))?;
        resolved.insert(policy_ref.object_id.clone(), object);
    }
    Ok(resolved)
}

fn parse_bundle_object(schema_id: &str, value: &Value) -> Result<PolicyBundleObject> {
    if schema_id.starts_with("fcp.core:ZonePolicy@") {
        let policy: ZonePolicyObject =
            serde_json::from_value(value.clone()).context("failed to parse ZonePolicy object")?;
        return Ok(PolicyBundleObject::ZonePolicy(policy));
    }
    if schema_id.starts_with("fcp.core:ZoneDefinition@") {
        let definition: ZoneDefinitionObject = serde_json::from_value(value.clone())
            .context("failed to parse ZoneDefinition object")?;
        return Ok(PolicyBundleObject::ZoneDefinition(definition));
    }
    if schema_id.starts_with("fcp.core:RoleObject@") {
        let role: RoleObject =
            serde_json::from_value(value.clone()).context("failed to parse RoleObject")?;
        return Ok(PolicyBundleObject::Role(role));
    }
    if schema_id.starts_with("fcp.core:ResourceObject@") {
        let resource: ResourceObject =
            serde_json::from_value(value.clone()).context("failed to parse ResourceObject")?;
        return Ok(PolicyBundleObject::Resource(resource));
    }
    if schema_id.starts_with("fcp.core:CapabilityObject@") {
        let capability: CapabilityObject =
            serde_json::from_value(value.clone()).context("failed to parse CapabilityObject")?;
        return Ok(PolicyBundleObject::Capability(capability));
    }

    Err(anyhow::anyhow!(
        "unsupported policy bundle schema_id {schema_id}"
    ))
}

fn parse_simulation_input(raw: &str) -> Result<PolicySimulationInput> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("policy simulation input is empty");
    }

    if let Ok(input) = serde_json::from_str::<PolicySimulationInput>(trimmed) {
        return Ok(input);
    }

    let invoke = serde_json::from_str::<InvokeRequest>(trimmed)
        .context("failed to parse input as PolicySimulationInput or InvokeRequest")?;
    let zone_policy = default_zone_policy(&invoke);

    Ok(PolicySimulationInput {
        zone_policy,
        invoke_request: invoke,
        transport: fcp_core::TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: None,
        safety_tier: fcp_core::SafetyTier::Safe,
        principal: None,
        capability_id: None,
        provenance_record: None,
        now_ms: None,
        posture_attestation: None,
    })
}

#[derive(Debug)]
enum PolicyDocument {
    ZonePolicy(ZonePolicyObject),
    ZoneDefinition(ZoneDefinitionObject),
}

impl PolicyDocument {
    const fn zone_id(&self) -> &fcp_core::ZoneId {
        match self {
            Self::ZonePolicy(policy) => &policy.zone_id,
            Self::ZoneDefinition(definition) => &definition.zone_id,
        }
    }

    const fn policy_type(&self) -> &'static str {
        match self {
            Self::ZonePolicy(_) => "zone_policy",
            Self::ZoneDefinition(_) => "zone_definition",
        }
    }
}

#[derive(Debug, Serialize, Default)]
struct PolicyListDiff {
    principal_allow: Vec<String>,
    principal_deny: Vec<String>,
    connector_allow: Vec<String>,
    connector_deny: Vec<String>,
    capability_allow: Vec<String>,
    capability_deny: Vec<String>,
    capability_ceiling: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Change<T> {
    before: T,
    after: T,
}

#[derive(Debug, Serialize)]
struct TransportPolicyChange {
    before: fcp_core::ZoneTransportPolicy,
    after: fcp_core::ZoneTransportPolicy,
}

#[derive(Debug, Serialize, Default)]
struct PolicyChangedFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    transport_policy: Option<TransportPolicyChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_receipts: Option<Change<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_posture: Option<Change<Value>>,
}

#[derive(Debug, Serialize)]
struct PolicyDiffOutput {
    policy_type: String,
    zone_id: String,
    previous_policy_id: String,
    current_policy_id: String,
    added: Value,
    removed: Value,
    changed: Value,
    risk_flags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RollbackPlan {
    policy_type: String,
    zone_id: String,
    current_policy_id: String,
    previous_policy_id: String,
    plan_type: String,
}

#[derive(Debug, Serialize)]
struct JsonDiff {
    added: BTreeMap<String, Value>,
    removed: BTreeMap<String, Value>,
    changed: BTreeMap<String, Change<Value>>,
}

fn run_diff(args: &DiffArgs) -> Result<()> {
    let before = load_policy_document(&args.before)?;
    let after = load_policy_document(&args.after)?;

    if before.policy_type() != after.policy_type() {
        anyhow::bail!(
            "policy types do not match: {} vs {}",
            before.policy_type(),
            after.policy_type()
        );
    }
    if before.zone_id() != after.zone_id() {
        anyhow::bail!(
            "zone_id mismatch: {} vs {}",
            before.zone_id(),
            after.zone_id()
        );
    }

    let diff = match (&before, &after) {
        (PolicyDocument::ZonePolicy(prev), PolicyDocument::ZonePolicy(curr)) => {
            diff_zone_policy(prev, curr)?
        }
        (PolicyDocument::ZoneDefinition(prev), PolicyDocument::ZoneDefinition(curr)) => {
            diff_zone_definition(prev, curr)?
        }
        _ => anyhow::bail!("unsupported policy comparison"),
    };

    output_json_or_human(&diff, args.json)
}

fn run_rollback(args: &RollbackArgs) -> Result<()> {
    if !args.plan {
        anyhow::bail!("rollback requires --plan (execution is not supported yet)");
    }

    let current = load_policy_document(&args.current)?;
    let previous = load_policy_document(&args.previous)?;

    if current.policy_type() != previous.policy_type() {
        anyhow::bail!(
            "policy types do not match: {} vs {}",
            current.policy_type(),
            previous.policy_type()
        );
    }
    if current.zone_id() != previous.zone_id() {
        anyhow::bail!(
            "zone_id mismatch: {} vs {}",
            current.zone_id(),
            previous.zone_id()
        );
    }

    let plan = RollbackPlan {
        policy_type: current.policy_type().to_string(),
        zone_id: current.zone_id().to_string(),
        current_policy_id: unscoped_policy_id(&current)?.to_string(),
        previous_policy_id: unscoped_policy_id(&previous)?.to_string(),
        plan_type: "rollback".to_string(),
    };

    output_json_or_human(&plan, args.json)
}

fn load_policy_document(path: &PathBuf) -> Result<PolicyDocument> {
    let raw = read_input(path)?;
    parse_policy_document(&raw)
}

fn parse_policy_document(raw: &str) -> Result<PolicyDocument> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("policy input is empty");
    }

    if let Ok(policy) = serde_json::from_str::<ZonePolicyObject>(trimmed) {
        return Ok(PolicyDocument::ZonePolicy(policy));
    }
    if let Ok(definition) = serde_json::from_str::<ZoneDefinitionObject>(trimmed) {
        return Ok(PolicyDocument::ZoneDefinition(definition));
    }

    anyhow::bail!("failed to parse policy input as ZonePolicyObject or ZoneDefinitionObject");
}

fn unscoped_policy_id(policy: &PolicyDocument) -> Result<ObjectId> {
    let value = match policy {
        PolicyDocument::ZonePolicy(doc) => serde_json::to_value(doc)?,
        PolicyDocument::ZoneDefinition(doc) => serde_json::to_value(doc)?,
    };
    let bytes = fcp_cbor::to_canonical_cbor(&value)?;
    Ok(ObjectId::from_unscoped_bytes(&bytes))
}

fn diff_zone_policy(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> Result<PolicyDiffOutput> {
    let (added, removed) = diff_policy_lists(before, after);
    let changed = diff_policy_changed(before, after)?;
    let risk_flags = compute_risk_flags(&added, &changed);

    let output = PolicyDiffOutput {
        policy_type: "zone_policy".to_string(),
        zone_id: before.zone_id.to_string(),
        previous_policy_id: ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(before)?)
            .to_string(),
        current_policy_id: ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(after)?)
            .to_string(),
        added: serde_json::to_value(&added)?,
        removed: serde_json::to_value(&removed)?,
        changed: serde_json::to_value(&changed)?,
        risk_flags,
    };

    Ok(output)
}

fn diff_zone_definition(
    before: &ZoneDefinitionObject,
    after: &ZoneDefinitionObject,
) -> Result<PolicyDiffOutput> {
    let before_json = serde_json::to_value(before)?;
    let after_json = serde_json::to_value(after)?;
    let diff = diff_json_objects(&before_json, &after_json)?;

    Ok(PolicyDiffOutput {
        policy_type: "zone_definition".to_string(),
        zone_id: before.zone_id.to_string(),
        previous_policy_id: ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(
            &before_json,
        )?)
        .to_string(),
        current_policy_id: ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(
            &after_json,
        )?)
        .to_string(),
        added: serde_json::to_value(&diff.added)?,
        removed: serde_json::to_value(&diff.removed)?,
        changed: serde_json::to_value(&diff.changed)?,
        risk_flags: Vec::new(),
    })
}

fn diff_policy_lists(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> (PolicyListDiff, PolicyListDiff) {
    let (principal_allow_added, principal_allow_removed) =
        diff_patterns(&before.principal_allow, &after.principal_allow);
    let (principal_deny_added, principal_deny_removed) =
        diff_patterns(&before.principal_deny, &after.principal_deny);
    let (connector_allow_added, connector_allow_removed) =
        diff_patterns(&before.connector_allow, &after.connector_allow);
    let (connector_deny_added, connector_deny_removed) =
        diff_patterns(&before.connector_deny, &after.connector_deny);
    let (capability_allow_added, capability_allow_removed) =
        diff_patterns(&before.capability_allow, &after.capability_allow);
    let (capability_deny_added, capability_deny_removed) =
        diff_patterns(&before.capability_deny, &after.capability_deny);
    let (capability_ceiling_added, capability_ceiling_removed) =
        diff_capability_ids(&before.capability_ceiling, &after.capability_ceiling);

    let added = PolicyListDiff {
        principal_allow: principal_allow_added,
        principal_deny: principal_deny_added,
        connector_allow: connector_allow_added,
        connector_deny: connector_deny_added,
        capability_allow: capability_allow_added,
        capability_deny: capability_deny_added,
        capability_ceiling: capability_ceiling_added,
    };
    let removed = PolicyListDiff {
        principal_allow: principal_allow_removed,
        principal_deny: principal_deny_removed,
        connector_allow: connector_allow_removed,
        connector_deny: connector_deny_removed,
        capability_allow: capability_allow_removed,
        capability_deny: capability_deny_removed,
        capability_ceiling: capability_ceiling_removed,
    };

    (added, removed)
}

fn diff_policy_changed(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> Result<PolicyChangedFields> {
    let mut changed = PolicyChangedFields::default();

    if transport_policy_changed(&before.transport_policy, &after.transport_policy) {
        changed.transport_policy = Some(TransportPolicyChange {
            before: before.transport_policy.clone(),
            after: after.transport_policy.clone(),
        });
    }

    let decision_before = serde_json::to_value(&before.decision_receipts)?;
    let decision_after = serde_json::to_value(&after.decision_receipts)?;
    if decision_before != decision_after {
        changed.decision_receipts = Some(Change {
            before: decision_before,
            after: decision_after,
        });
    }

    let posture_before = serde_json::to_value(&before.requires_posture)?;
    let posture_after = serde_json::to_value(&after.requires_posture)?;
    if posture_before != posture_after {
        changed.requires_posture = Some(Change {
            before: posture_before,
            after: posture_after,
        });
    }

    Ok(changed)
}

fn compute_risk_flags(added: &PolicyListDiff, changed: &PolicyChangedFields) -> Vec<String> {
    let mut flags = Vec::new();

    if !added.principal_allow.is_empty() {
        flags.push("principal_allow_expanded".to_string());
    }
    if !added.connector_allow.is_empty() {
        flags.push("connector_allow_expanded".to_string());
    }
    if !added.capability_allow.is_empty() {
        flags.push("capability_allow_expanded".to_string());
    }

    if let Some(ref transport) = changed.transport_policy {
        if !transport.before.allow_derp && transport.after.allow_derp {
            flags.push("transport_derp_enabled".to_string());
        }
        if !transport.before.allow_funnel && transport.after.allow_funnel {
            flags.push("transport_funnel_enabled".to_string());
        }
        if !transport.before.allow_lan && transport.after.allow_lan {
            flags.push("transport_lan_enabled".to_string());
        }
    }

    flags
}

fn diff_json_objects(before: &Value, after: &Value) -> Result<JsonDiff> {
    let before_obj = before
        .as_object()
        .context("before policy is not a JSON object")?;
    let after_obj = after
        .as_object()
        .context("after policy is not a JSON object")?;

    let mut added = BTreeMap::new();
    let mut removed = BTreeMap::new();
    let mut changed = BTreeMap::new();

    for (key, value) in before_obj {
        if !after_obj.contains_key(key) {
            removed.insert(key.clone(), value.clone());
        } else if let Some(after_value) = after_obj.get(key) {
            if after_value != value {
                changed.insert(
                    key.clone(),
                    Change {
                        before: value.clone(),
                        after: after_value.clone(),
                    },
                );
            }
        }
    }

    for (key, value) in after_obj {
        if !before_obj.contains_key(key) {
            added.insert(key.clone(), value.clone());
        }
    }

    Ok(JsonDiff {
        added,
        removed,
        changed,
    })
}

fn diff_patterns(
    before: &[fcp_core::PolicyPattern],
    after: &[fcp_core::PolicyPattern],
) -> (Vec<String>, Vec<String>) {
    let before_set: BTreeSet<String> = before.iter().map(|p| p.pattern.clone()).collect();
    let after_set: BTreeSet<String> = after.iter().map(|p| p.pattern.clone()).collect();

    let added = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_set
        .difference(&after_set)
        .cloned()
        .collect::<Vec<_>>();

    (added, removed)
}

fn diff_capability_ids(
    before: &[fcp_core::CapabilityId],
    after: &[fcp_core::CapabilityId],
) -> (Vec<String>, Vec<String>) {
    let before_set: BTreeSet<String> = before.iter().map(|c| c.as_str().to_string()).collect();
    let after_set: BTreeSet<String> = after.iter().map(|c| c.as_str().to_string()).collect();

    let added = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_set
        .difference(&after_set)
        .cloned()
        .collect::<Vec<_>>();

    (added, removed)
}

const fn transport_policy_changed(
    before: &fcp_core::ZoneTransportPolicy,
    after: &fcp_core::ZoneTransportPolicy,
) -> bool {
    before.allow_lan != after.allow_lan
        || before.allow_derp != after.allow_derp
        || before.allow_funnel != after.allow_funnel
}

fn output_json_or_human<T: Serialize>(payload: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(payload)?);
        return Ok(());
    }

    let pretty = serde_json::to_string_pretty(payload)?;
    println!("{pretty}");
    Ok(())
}

fn default_zone_policy(invoke: &InvokeRequest) -> ZonePolicyObject {
    let schema = SchemaId::new("fcp.core", "ZonePolicy", Version::new(1, 0, 0));
    let header = fcp_core::ObjectHeader {
        schema,
        zone_id: invoke.zone_id.clone(),
        created_at: u64::try_from(fcp_core::Utc::now().timestamp()).unwrap_or(0),
        provenance: Provenance::new(invoke.zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    };

    ZonePolicyObject {
        header,
        zone_id: invoke.zone_id.clone(),
        principal_allow: Vec::new(),
        principal_deny: Vec::new(),
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: fcp_core::ZoneTransportPolicy::default(),
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn output_receipt(receipt: &DecisionReceipt, json: bool) -> Result<()> {
    if json {
        let payload =
            serde_json::to_string_pretty(receipt).context("failed to serialize DecisionReceipt")?;
        println!("{payload}");
        return Ok(());
    }

    println!();
    println!("Decision: {:?}", receipt.decision);
    println!("Reason: {}", receipt.reason_code);
    if !receipt.evidence.is_empty() {
        println!("Evidence:");
        for id in &receipt.evidence {
            println!("  - {id}");
        }
    }
    if let Some(ref explanation) = receipt.explanation {
        println!("Explanation: {explanation}");
    }
    println!();
    Ok(())
}

fn output_error(err: &PolicySimulationError, json: bool) -> Result<()> {
    if json {
        let payload = serde_json::json!({
            "error": err.to_string(),
            "code": "policy.simulation_failed",
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    Err(anyhow::anyhow!(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::PolicyPattern;

    #[test]
    fn parse_policy_simulation_input_direct() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: fcp_core::ZoneId::work(),
            input: serde_json::json!({"k": "v"}),
            capability_token: fcp_core::CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let raw = serde_json::to_string(&invoke).unwrap();
        let input = parse_simulation_input(&raw).unwrap();
        assert_eq!(input.invoke_request.zone_id, fcp_core::ZoneId::work());
    }

    fn base_policy(zone: fcp_core::ZoneId) -> ZonePolicyObject {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: zone,
            input: serde_json::json!({"k": "v"}),
            capability_token: fcp_core::CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        default_zone_policy(&invoke)
    }

    #[test]
    fn policy_diff_detects_added_connector_and_transport_risk() {
        let zone = fcp_core::ZoneId::work();
        let before = base_policy(zone.clone());
        let mut after = base_policy(zone);

        after.connector_allow.push(PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        });
        after.transport_policy.allow_derp = true;

        let diff = diff_zone_policy(&before, &after).expect("diff zone policy");
        let added = diff.added.as_object().expect("added object");
        let connector_allow = added
            .get("connector_allow")
            .and_then(Value::as_array)
            .expect("connector_allow array");

        assert!(
            connector_allow
                .iter()
                .any(|v| v.as_str() == Some("fcp.test:*"))
        );
        assert!(
            diff.risk_flags
                .iter()
                .any(|flag| flag == "transport_derp_enabled")
        );
    }

    // ---- parse_simulation_input ----

    #[test]
    fn parse_simulation_input_empty() {
        assert!(parse_simulation_input("").is_err());
    }

    #[test]
    fn parse_simulation_input_whitespace_only() {
        assert!(parse_simulation_input("   \n\t  ").is_err());
    }

    #[test]
    fn parse_simulation_input_invalid_json() {
        assert!(parse_simulation_input("{not valid}").is_err());
    }

    // ---- parse_created_at ----

    #[test]
    fn parse_created_at_none() {
        assert!(parse_created_at(None).unwrap().is_none());
    }

    #[test]
    fn parse_created_at_valid_rfc3339() {
        let dt = parse_created_at(Some("2026-03-01T12:00:00Z"))
            .unwrap()
            .unwrap();
        assert!(dt.to_rfc3339().contains("2026-03-01"));
    }

    #[test]
    fn parse_created_at_invalid() {
        assert!(parse_created_at(Some("not-a-date")).is_err());
    }

    #[test]
    fn parse_created_at_with_offset() {
        let dt = parse_created_at(Some("2026-03-01T12:00:00+05:00"))
            .unwrap()
            .unwrap();
        // Converted to UTC: 12:00 +05:00 = 07:00 UTC
        assert!(dt.to_rfc3339().contains("07:00:00"));
    }

    // ---- diff_patterns ----

    #[test]
    fn diff_patterns_both_empty() {
        let (added, removed) = diff_patterns(&[], &[]);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_patterns_identical() {
        let patterns = vec![PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        }];
        let (added, removed) = diff_patterns(&patterns, &patterns);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_patterns_added() {
        let before = vec![];
        let after = vec![PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        }];
        let (added, removed) = diff_patterns(&before, &after);
        assert_eq!(added, vec!["fcp.test:*"]);
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_patterns_removed() {
        let before = vec![PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        }];
        let after = vec![];
        let (added, removed) = diff_patterns(&before, &after);
        assert!(added.is_empty());
        assert_eq!(removed, vec!["fcp.test:*"]);
    }

    #[test]
    fn diff_patterns_mixed() {
        let before = vec![
            PolicyPattern {
                pattern: "a".to_string(),
            },
            PolicyPattern {
                pattern: "b".to_string(),
            },
        ];
        let after = vec![
            PolicyPattern {
                pattern: "b".to_string(),
            },
            PolicyPattern {
                pattern: "c".to_string(),
            },
        ];
        let (added, removed) = diff_patterns(&before, &after);
        assert_eq!(added, vec!["c"]);
        assert_eq!(removed, vec!["a"]);
    }

    // ---- diff_capability_ids ----

    #[test]
    fn diff_capability_ids_empty() {
        let (added, removed) = diff_capability_ids(&[], &[]);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_capability_ids_added_and_removed() {
        let before = vec!["cap.read".parse().unwrap()];
        let after = vec!["cap.write".parse().unwrap()];
        let (added, removed) = diff_capability_ids(&before, &after);
        assert_eq!(added, vec!["cap.write"]);
        assert_eq!(removed, vec!["cap.read"]);
    }

    // ---- transport_policy_changed ----

    #[test]
    fn transport_policy_unchanged() {
        let policy = fcp_core::ZoneTransportPolicy::default();
        assert!(!transport_policy_changed(&policy, &policy));
    }

    #[test]
    fn transport_policy_lan_changed() {
        let before = fcp_core::ZoneTransportPolicy::default();
        let mut after = before.clone();
        after.allow_lan = !before.allow_lan;
        assert!(transport_policy_changed(&before, &after));
    }

    #[test]
    fn transport_policy_derp_changed() {
        let before = fcp_core::ZoneTransportPolicy::default();
        let mut after = before.clone();
        after.allow_derp = !before.allow_derp;
        assert!(transport_policy_changed(&before, &after));
    }

    #[test]
    fn transport_policy_funnel_changed() {
        let before = fcp_core::ZoneTransportPolicy::default();
        let mut after = before.clone();
        after.allow_funnel = !before.allow_funnel;
        assert!(transport_policy_changed(&before, &after));
    }

    // ---- compute_risk_flags ----

    #[test]
    fn risk_flags_empty_when_no_changes() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &changed);
        assert!(flags.is_empty());
    }

    #[test]
    fn risk_flags_principal_allow_expanded() {
        let added = PolicyListDiff {
            principal_allow: vec!["user:*".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &changed);
        assert!(flags.contains(&"principal_allow_expanded".to_string()));
    }

    #[test]
    fn risk_flags_connector_allow_expanded() {
        let added = PolicyListDiff {
            connector_allow: vec!["fcp.*".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &changed);
        assert!(flags.contains(&"connector_allow_expanded".to_string()));
    }

    #[test]
    fn risk_flags_capability_allow_expanded() {
        let added = PolicyListDiff {
            capability_allow: vec!["cap.*".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &changed);
        assert!(flags.contains(&"capability_allow_expanded".to_string()));
    }

    #[test]
    fn risk_flags_transport_derp_enabled() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields {
            transport_policy: Some(TransportPolicyChange {
                before: fcp_core::ZoneTransportPolicy {
                    allow_derp: false,
                    ..Default::default()
                },
                after: fcp_core::ZoneTransportPolicy {
                    allow_derp: true,
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let flags = compute_risk_flags(&added, &changed);
        assert!(flags.contains(&"transport_derp_enabled".to_string()));
    }

    #[test]
    fn risk_flags_transport_funnel_enabled() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields {
            transport_policy: Some(TransportPolicyChange {
                before: fcp_core::ZoneTransportPolicy {
                    allow_funnel: false,
                    ..Default::default()
                },
                after: fcp_core::ZoneTransportPolicy {
                    allow_funnel: true,
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let flags = compute_risk_flags(&added, &changed);
        assert!(flags.contains(&"transport_funnel_enabled".to_string()));
    }

    #[test]
    fn risk_flags_multiple_risks() {
        let added = PolicyListDiff {
            principal_allow: vec!["user:*".to_string()],
            connector_allow: vec!["fcp.*".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &changed);
        assert_eq!(flags.len(), 2);
    }

    // ---- diff_json_objects ----

    #[test]
    fn diff_json_objects_identical() {
        let obj = serde_json::json!({"a": 1, "b": "hello"});
        let diff = diff_json_objects(&obj, &obj).unwrap();
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_json_objects_added_key() {
        let before = serde_json::json!({"a": 1});
        let after = serde_json::json!({"a": 1, "b": 2});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert_eq!(diff.added.len(), 1);
        assert!(diff.added.contains_key("b"));
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_json_objects_removed_key() {
        let before = serde_json::json!({"a": 1, "b": 2});
        let after = serde_json::json!({"a": 1});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed.len(), 1);
        assert!(diff.removed.contains_key("b"));
    }

    #[test]
    fn diff_json_objects_changed_value() {
        let before = serde_json::json!({"a": 1});
        let after = serde_json::json!({"a": 2});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed.contains_key("a"));
    }

    #[test]
    fn diff_json_objects_not_object_fails() {
        let before = serde_json::json!([1, 2]);
        let after = serde_json::json!({"a": 1});
        assert!(diff_json_objects(&before, &after).is_err());
    }

    // ---- parse_policy_document ----

    #[test]
    fn parse_policy_document_empty() {
        assert!(parse_policy_document("").is_err());
    }

    #[test]
    fn parse_policy_document_invalid_json() {
        assert!(parse_policy_document("{bad json}").is_err());
    }

    // ---- parse_bundle_object ----

    #[test]
    fn parse_bundle_object_unsupported_schema() {
        let value = serde_json::json!({"some": "data"});
        assert!(parse_bundle_object("fcp.core:Unknown@1.0.0", &value).is_err());
    }

    // ---- default_zone_policy ----

    #[test]
    fn default_zone_policy_structure() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: fcp_core::ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: fcp_core::CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let policy = default_zone_policy(&invoke);
        assert_eq!(policy.zone_id, fcp_core::ZoneId::work());
        assert!(policy.principal_allow.is_empty());
        assert!(policy.principal_deny.is_empty());
        assert!(policy.connector_allow.is_empty());
        assert!(policy.connector_deny.is_empty());
        assert!(policy.capability_allow.is_empty());
        assert!(policy.capability_deny.is_empty());
        assert!(policy.capability_ceiling.is_empty());
        assert!(policy.usage_budget.is_none());
        assert!(policy.requires_posture.is_none());
    }

    // ---- PolicyListDiff default ----

    #[test]
    fn policy_list_diff_default_empty() {
        let d = PolicyListDiff::default();
        assert!(d.principal_allow.is_empty());
        assert!(d.principal_deny.is_empty());
        assert!(d.connector_allow.is_empty());
        assert!(d.connector_deny.is_empty());
        assert!(d.capability_allow.is_empty());
        assert!(d.capability_deny.is_empty());
        assert!(d.capability_ceiling.is_empty());
    }

    // ---- PolicyChangedFields default ----

    #[test]
    fn policy_changed_fields_default_all_none() {
        let d = PolicyChangedFields::default();
        assert!(d.transport_policy.is_none());
        assert!(d.decision_receipts.is_none());
        assert!(d.requires_posture.is_none());
    }

    // ---- BundleApplyPlan serde ----

    #[test]
    fn bundle_apply_plan_serializes() {
        let plan = BundleApplyPlan {
            plan_type: "bundle_apply".to_string(),
            zone_id: "z:work".to_string(),
            bundle_id: "bundle-1".to_string(),
            state_path: "/tmp/state.json".to_string(),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"plan_type\":\"bundle_apply\""));
        assert!(json.contains("\"bundle_id\":\"bundle-1\""));
    }

    // ---- BundleRollbackPlan serde ----

    #[test]
    fn bundle_rollback_plan_serializes() {
        let plan = BundleRollbackPlan {
            plan_type: "bundle_rollback".to_string(),
            zone_id: "z:work".to_string(),
            target_bundle_id: "bundle-prev".to_string(),
            state_path: "/tmp/state.json".to_string(),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"plan_type\":\"bundle_rollback\""));
        assert!(json.contains("\"target_bundle_id\":\"bundle-prev\""));
    }

    // ---- RollbackPlan serde ----

    #[test]
    fn rollback_plan_serializes() {
        let plan = RollbackPlan {
            policy_type: "zone_policy".to_string(),
            zone_id: "z:work".to_string(),
            current_policy_id: "oid-1".to_string(),
            previous_policy_id: "oid-2".to_string(),
            plan_type: "rollback".to_string(),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"plan_type\":\"rollback\""));
        assert!(json.contains("\"zone_id\":\"z:work\""));
    }

    // ---- PolicyDiffOutput serde ----

    #[test]
    fn policy_diff_output_serializes() {
        let output = PolicyDiffOutput {
            policy_type: "zone_policy".to_string(),
            zone_id: "z:work".to_string(),
            previous_policy_id: "prev-id".to_string(),
            current_policy_id: "curr-id".to_string(),
            added: serde_json::json!({}),
            removed: serde_json::json!({}),
            changed: serde_json::json!({}),
            risk_flags: vec!["transport_derp_enabled".to_string()],
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"risk_flags\""));
        assert!(json.contains("transport_derp_enabled"));
    }

    // ---- PolicyDocument methods ----

    #[test]
    fn policy_document_zone_policy_type() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: fcp_core::ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: fcp_core::CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let doc = PolicyDocument::ZonePolicy(default_zone_policy(&invoke));
        assert_eq!(doc.policy_type(), "zone_policy");
        assert_eq!(*doc.zone_id(), fcp_core::ZoneId::work());
    }

    // ---- diff_zone_policy no changes ----

    #[test]
    fn diff_zone_policy_identical() {
        let zone = fcp_core::ZoneId::work();
        let policy = base_policy(zone);
        let diff = diff_zone_policy(&policy, &policy).unwrap();
        assert!(diff.risk_flags.is_empty());
    }
}
