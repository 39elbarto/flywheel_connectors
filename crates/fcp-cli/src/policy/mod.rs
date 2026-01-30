//! `fcp policy` command implementation.
//!
//! Provides a policy simulation CLI for `DecisionReceipt` previews.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use fcp_cbor::SchemaId;
use fcp_core::{
    DecisionReceipt, DecisionReceiptPolicy, InvokeRequest, ObjectId, PolicySimulationError,
    PolicySimulationInput, Provenance, ZoneDefinitionObject, ZonePolicyObject,
};
use semver::Version;
use serde::Serialize;
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

/// Run the policy command.
pub fn run(args: &PolicyArgs) -> Result<()> {
    match &args.command {
        PolicyCommands::Simulate(sim_args) => run_simulate(sim_args),
        PolicyCommands::Diff(diff_args) => run_diff(diff_args),
        PolicyCommands::Rollback(rollback_args) => run_rollback(rollback_args),
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
    fn zone_id(&self) -> &fcp_core::ZoneId {
        match self {
            Self::ZonePolicy(policy) => &policy.zone_id,
            Self::ZoneDefinition(definition) => &definition.zone_id,
        }
    }

    fn policy_type(&self) -> &'static str {
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
    let (added, removed, changed) = diff_json_objects(&before_json, &after_json)?;

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
        added: serde_json::to_value(&added)?,
        removed: serde_json::to_value(&removed)?,
        changed: serde_json::to_value(&changed)?,
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

fn diff_json_objects(
    before: &Value,
    after: &Value,
) -> Result<(
    BTreeMap<String, Value>,
    BTreeMap<String, Value>,
    BTreeMap<String, Change<Value>>,
)> {
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

    Ok((added, removed, changed))
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

fn transport_policy_changed(
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
}
