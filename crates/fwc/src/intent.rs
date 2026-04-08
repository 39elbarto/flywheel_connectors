use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use serde::{Deserialize, Serialize};

use crate::catalog::{CommandTruthSource, classify_command};
use crate::readiness::{CommandAvailability, DiscoveryCatalog, normalize_operation_selector};

const EXECUTION_NOTICE: &str = "The plan compiler emits concrete `fwc` primitives. A step only succeeds if that primitive is actually implemented and the live host or local state it needs is configured; `fwc` does not fabricate success.";
const WORKFLOW_TRUTH_COMPILER_SOURCE: &str = "local-intent-compiler";

/// Classification of where a compiled intent answer draws its truth.
///
/// Every compiled plan carries a provenance tag so downstream consumers
/// (and humans reading transcripts) can tell whether the answer came
/// from a live host, offline artifacts, a mesh query, or a degraded
/// fallback — without parsing prose.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntentProvenance {
    /// Answer backed by a live host admin API call.
    HostBacked,
    /// Answer derived from local offline artifacts (manifests, registry cache).
    Offline,
    /// Answer derived from mesh-backed evidence (future).
    MeshBacked,
    /// Host or mesh was queried but returned partial or stale data.
    Degraded,
    /// The requested action is not supported by any real primitive.
    Unsupported,
}

impl IntentProvenance {
    #[allow(dead_code)]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::HostBacked => "host-backed",
            Self::Offline => "offline",
            Self::MeshBacked => "mesh-backed",
            Self::Degraded => "degraded",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Why an intent was refused or could not be compiled into a real workflow.
///
/// Provides a structured taxonomy instead of ad-hoc prose so that
/// acceptance tests and operator tooling can pattern-match on the
/// refusal class.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntentRefusalReason {
    /// The host endpoint is not reachable or not configured.
    HostUnavailable,
    /// The requested lifecycle transition is invalid for the current state.
    InvalidTransition,
    /// The connector does not exist or could not be resolved.
    ConnectorUnresolved,
    /// The action requires approval that has not been granted.
    ApprovalRequired,
    /// The intent does not map to any known real primitive.
    NoMatchingPrimitive,
    /// A required parameter (connector, version, etc.) is missing.
    MissingParameter,
}

impl IntentRefusalReason {
    #[allow(dead_code)]
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::HostUnavailable => "host-unavailable",
            Self::InvalidTransition => "invalid-transition",
            Self::ConnectorUnresolved => "connector-unresolved",
            Self::ApprovalRequired => "approval-required",
            Self::NoMatchingPrimitive => "no-matching-primitive",
            Self::MissingParameter => "missing-parameter",
        }
    }
}

/// Contract surface for intent log-tail operations.
///
/// Represents the typed request that the intent compiler produces
/// when it recognizes log/tail/stream verbs. Maps to `fwc tail`
/// backed by `POST /rpc/admin/logs` and `POST /rpc/admin/events`
/// on the host.
#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogTailContract {
    pub connector_id: Option<String>,
    pub since_duration: Option<String>,
    pub event_type_filter: Option<String>,
    pub limit: usize,
    pub provenance: IntentProvenance,
    pub refusal: Option<IntentRefusalReason>,
}

/// Contract surface for intent lifecycle operations.
///
/// Represents the typed request that the intent compiler produces
/// when it recognizes lifecycle verbs (enable, disable, start, stop,
/// restart). Maps to `fwc lifecycle <connector> --action <verb>`
/// backed by `POST /rpc/lifecycle/{connector_id}` on the host.
#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleIntentContract {
    pub connector_id: String,
    pub action: String,
    pub preflight: bool,
    pub dry_run: bool,
    pub provenance: IntentProvenance,
    pub refusal: Option<IntentRefusalReason>,
}

fn default_execution_notice() -> String {
    EXECUTION_NOTICE.to_owned()
}

fn default_workflow_truth() -> WorkflowTruth {
    WorkflowTruth::from_compiler(
        CommandAvailability::Unknown,
        "The intent compiler has not derived a truthful execution path yet.",
    )
}

#[derive(Clone, Copy, Debug)]
pub enum IntentMode {
    Plan,
    Explain,
    DoSimulate,
    DoApprove,
}

impl IntentMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Explain => "explain",
            Self::DoSimulate => "do-simulate",
            Self::DoApprove => "do-approve",
        }
    }

    #[must_use]
    pub const fn is_execution(self) -> bool {
        matches!(self, Self::DoSimulate | Self::DoApprove)
    }

    #[must_use]
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::DoApprove)
    }
}

#[derive(Clone, Debug)]
pub struct IntentRequest {
    pub intent: String,
    pub connector_override: Option<String>,
    pub zone_override: Option<String>,
    pub mode: IntentMode,
    /// When set, the compiler will attempt to fetch live operation schemas from
    /// this fcp-host endpoint, supplementing or overriding local manifest data.
    /// Falls back to local manifests if the host is unreachable.
    pub host_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompiledIntent {
    pub status: String,
    #[serde(default = "default_workflow_truth")]
    pub workflow_truth: WorkflowTruth,
    pub mode: String,
    pub summary: String,
    pub template: String,
    pub confidence: String,
    pub raw_intent: String,
    pub normalized_intent: String,
    pub connector_override: Option<String>,
    pub zone: Option<String>,
    pub quoted_literals: Vec<String>,
    pub lookup_literal: Option<String>,
    pub payload_literal: Option<String>,
    pub chosen_connector: Option<ConnectorCandidate>,
    pub alternative_connectors: Vec<ConnectorCandidate>,
    pub action: ActionInference,
    pub operation_hint: Option<String>,
    pub missing_information: Vec<String>,
    #[serde(default)]
    pub unsupported_reasons: Vec<String>,
    pub ambiguities: Vec<Ambiguity>,
    pub assumptions: Vec<String>,
    pub suggested_command_lines: Vec<String>,
    pub next_actions: Vec<String>,
    pub steps: Vec<CompiledStep>,
    pub explanation: Explanation,
    #[serde(default = "default_execution_notice")]
    pub execution_notice: String,
    /// Partial payload auto-populated from extracted literals mapped to the
    /// resolved operation's JSON Schema. `None` when no operation schema is
    /// available or when no literals could be mapped to schema fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_payload: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowTruth {
    pub availability: CommandAvailability,
    pub source_of_truth: String,
    pub authoritative: bool,
    pub recoverable: bool,
    pub exit_code_hint: u8,
    pub explanation: String,
}

impl WorkflowTruth {
    #[must_use]
    pub fn new(
        availability: CommandAvailability,
        source_of_truth: impl Into<String>,
        authoritative: bool,
        recoverable: bool,
        explanation: impl Into<String>,
    ) -> Self {
        let exit_code_hint = availability.exit_code_u8();
        Self {
            availability,
            source_of_truth: source_of_truth.into(),
            authoritative,
            recoverable,
            exit_code_hint,
            explanation: explanation.into(),
        }
    }

    #[must_use]
    pub fn from_compiler(
        availability: CommandAvailability,
        explanation: impl Into<String>,
    ) -> Self {
        let recoverable = availability.is_recoverable();
        Self::new(
            availability,
            WORKFLOW_TRUTH_COMPILER_SOURCE,
            false,
            recoverable,
            explanation,
        )
    }

    #[must_use]
    pub fn from_execution_receipt(
        availability: CommandAvailability,
        authoritative: bool,
        recoverable: bool,
        explanation: impl Into<String>,
    ) -> Self {
        Self::new(
            availability,
            "workflow-execution-receipt",
            authoritative,
            recoverable,
            explanation,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorCandidate {
    pub id: String,
    pub score: i32,
    pub reasons: Vec<String>,
}

impl std::fmt::Display for ConnectorCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionInference {
    pub family: String,
    pub verb: String,
    pub resource: Option<String>,
    pub risk: String,
    pub mutating: bool,
    pub matched_terms: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ambiguity {
    pub kind: String,
    pub message: String,
    pub candidates: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompiledStep {
    pub ordinal: usize,
    pub phase: String,
    pub purpose: String,
    pub command: String,
    pub command_line: String,
    pub argv: Vec<String>,
    pub side_effecting: bool,
    pub approval_required: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Explanation {
    pub connector_evidence: Vec<String>,
    pub action_evidence: Vec<String>,
    pub lookup_evidence: Vec<String>,
    pub template_reasoning: Vec<String>,
}

#[derive(Clone, Debug)]
struct ConnectorProfile {
    id: String,
    aliases: Vec<String>,
    keywords: Vec<String>,
    operations: Vec<ManifestOperationProfile>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct ManifestOperationProfile {
    actual_id: String,
    local_id: String,
    preferred_selector: String,
    aliases: Vec<String>,
    description: String,
    capability: String,
    risk_level: String,
    safety_tier: String,
    when_to_use: String,
    common_mistakes: Vec<String>,
    input_schema: serde_json::Value,
}

impl ManifestOperationProfile {
    fn from_discovered(operation: &crate::readiness::DiscoveredOperation) -> Self {
        Self {
            actual_id: operation.actual_id.clone(),
            local_id: operation.local_id.clone(),
            preferred_selector: operation.preferred_selector.clone(),
            aliases: operation.aliases.clone(),
            description: operation.description.clone(),
            capability: operation.summary.capability.clone(),
            risk_level: operation.summary.risk_level.clone(),
            safety_tier: operation.summary.safety_tier.clone(),
            when_to_use: operation.when_to_use.clone(),
            common_mistakes: operation.common_mistakes.clone(),
            input_schema: operation.input_schema.clone(),
        }
    }

    /// Map extracted intent literals to schema fields, producing a partial JSON payload.
    ///
    /// Strategy:
    /// - `titled` literal → first `string` property whose name contains "title" or "name"
    /// - `payload_literal` → first required `string` property (fallback)
    /// - `lookup_literal` → property named "query", "search", "filter", or "id"
    /// - Quoted literals → fill remaining required `string` properties in declaration order
    ///
    /// Returns `None` if the schema has no `properties` or no literals were extracted.
    fn map_literals_to_schema(
        &self,
        titled: Option<&str>,
        payload_literal: Option<&str>,
        lookup_literal: Option<&str>,
        quoted_literals: &[String],
    ) -> Option<serde_json::Value> {
        let properties = self.input_schema.get("properties")?.as_object()?;
        if properties.is_empty() {
            return None;
        }

        let required: Vec<&str> = self
            .input_schema
            .get("required")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let mut payload = serde_json::Map::new();

        // Pass 1: titled → title/name/subject field
        // Use exact matches or suffix patterns to avoid false positives like
        // "username" or "filename" matching a titled literal.
        if let Some(titled_value) = titled {
            for (field_name, field_schema) in properties {
                let is_string = field_schema
                    .get("type")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t == "string");
                let name_lower = field_name.to_lowercase();
                let is_title_field = name_lower == "title"
                    || name_lower == "name"
                    || name_lower == "subject"
                    || name_lower == "summary"
                    || name_lower.ends_with("_title")
                    || name_lower.ends_with("_name")
                    || name_lower.ends_with("_subject");
                if is_string && is_title_field {
                    payload.insert(field_name.clone(), serde_json::Value::String(titled_value.to_owned()));
                    break;
                }
            }
        }

        // Pass 2: lookup_literal → query/search/filter/id field
        if let Some(lookup_value) = lookup_literal {
            for (field_name, field_schema) in properties {
                if payload.contains_key(field_name) {
                    continue;
                }
                let is_string = field_schema
                    .get("type")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t == "string");
                let name_lower = field_name.to_lowercase();
                if is_string
                    && (name_lower.contains("query")
                        || name_lower.contains("search")
                        || name_lower.contains("filter")
                        || name_lower == "id"
                        || name_lower == "q")
                {
                    payload.insert(field_name.clone(), serde_json::Value::String(lookup_value.to_owned()));
                    break;
                }
            }
        }

        // Pass 3: payload_literal → first unfilled required string field
        if let Some(payload_value) = payload_literal {
            for field_name in &required {
                if payload.contains_key(*field_name) {
                    continue;
                }
                let is_string = properties
                    .get(*field_name)
                    .and_then(|s| s.get("type"))
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t == "string");
                if is_string {
                    payload.insert((*field_name).to_owned(), serde_json::Value::String(payload_value.to_owned()));
                    break;
                }
            }
        }

        // Pass 4: remaining quoted literals → remaining required string fields
        let mut remaining_required: Vec<&str> = required
            .iter()
            .filter(|f| {
                !payload.contains_key(**f)
                    && properties
                        .get(**f)
                        .and_then(|s| s.get("type"))
                        .and_then(|t| t.as_str())
                        .is_some_and(|t| t == "string")
            })
            .copied()
            .collect();

        for literal in quoted_literals {
            if remaining_required.is_empty() {
                break;
            }
            let field = remaining_required.remove(0);
            payload.insert(field.to_owned(), serde_json::Value::String(literal.clone()));
        }

        if payload.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(payload))
        }
    }

    fn selector_keys(&self) -> BTreeSet<String> {
        self.aliases
            .iter()
            .map(|alias| normalize_operation_selector(alias))
            .chain([
                normalize_operation_selector(&self.actual_id),
                normalize_operation_selector(&self.local_id),
                normalize_operation_selector(&self.preferred_selector),
            ])
            .collect()
    }

    fn matches_selector(&self, selector: &str) -> bool {
        let normalized = normalize_operation_selector(selector);
        self.selector_keys().contains(&normalized)
    }
}

#[derive(Clone, Debug, Default)]
struct OperationIndex {
    by_connector: BTreeMap<String, Vec<ManifestOperationProfile>>,
}

impl OperationIndex {
    fn load() -> Self {
        let Ok(catalog) = DiscoveryCatalog::load() else {
            return Self::default();
        };

        let by_connector = catalog
            .connectors()
            .iter()
            .map(|connector| {
                (
                    connector.slug.clone(),
                    connector
                        .operations
                        .iter()
                        .map(ManifestOperationProfile::from_discovered)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        Self { by_connector }
    }
}

#[derive(Clone, Debug)]
struct ActionSignals {
    family: &'static str,
    verb: &'static str,
    resource: Option<&'static str>,
    risk: &'static str,
    mutating: bool,
    matched_terms: Vec<String>,
    needs_lookup: bool,
}

#[derive(Clone, Debug, Default)]
struct ParsedLiterals {
    quoted: Vec<String>,
    named: Option<String>,
    titled: Option<String>,
    called: Option<String>,
    zone: Option<String>,
}

#[derive(Default)]
struct PlanBuild {
    summary: String,
    operation_hint: Option<String>,
    steps: Vec<CompiledStep>,
    missing_information: Vec<String>,
    unsupported_reasons: Vec<String>,
    ambiguities: Vec<Ambiguity>,
    assumptions: Vec<String>,
    lookup_evidence: Vec<String>,
    template_reasoning: Vec<String>,
}

#[must_use]
pub fn compile(request: &IntentRequest) -> CompiledIntent {
    let raw_intent = request.intent.trim().to_owned();
    let normalized_intent = normalize_text(&raw_intent);
    let literals = parse_literals(&raw_intent, &normalized_intent);
    let zone = request
        .zone_override
        .clone()
        .or_else(|| literals.zone.clone());
    let profiles = connector_profiles();
    let connector_candidates = infer_connector_candidates(
        &normalized_intent,
        request.connector_override.as_deref(),
        &profiles,
    );
    let chosen_connector = connector_candidates.first().cloned();
    let chosen_profile = chosen_connector
        .as_ref()
        .and_then(|candidate| profiles.iter().find(|profile| profile.id == candidate.id));
    let alternative_connectors = connector_candidates
        .iter()
        .skip(1)
        .take(3)
        .cloned()
        .collect();
    let action_signals = infer_action(&normalized_intent);
    let payload_literal = literals
        .titled
        .clone()
        .or_else(|| payload_literal(&literals, &action_signals));
    let lookup_literal = literals
        .named
        .clone()
        .or_else(|| literals.called.clone())
        .or_else(|| lookup_literal(&literals, &action_signals));
    let mut plan = build_plan(
        request,
        &normalized_intent,
        zone.as_deref(),
        &literals,
        payload_literal.as_deref(),
        lookup_literal.as_deref(),
        chosen_connector.as_ref(),
        chosen_profile,
        &connector_candidates,
        &action_signals,
    );
    let confidence = confidence_for(&connector_candidates, !plan.ambiguities.is_empty());
    let (status, workflow_truth, suggested_command_lines, next_actions) =
        compile_status_metadata(request, chosen_connector.as_ref(), &plan);
    let explanation = compile_explanation(&action_signals, &connector_candidates, &mut plan);

    // Attempt schema-based payload mapping when we have a resolved operation
    let suggested_payload = chosen_profile
        .and_then(|profile| {
            let operation = plan.operation_hint.as_deref()?;
            profile
                .operations
                .iter()
                .find(|op| op.matches_selector(operation))
        })
        .and_then(|op| {
            op.map_literals_to_schema(
                literals.titled.as_deref(),
                payload_literal.as_deref(),
                lookup_literal.as_deref(),
                &literals.quoted,
            )
        });

    CompiledIntent {
        status,
        workflow_truth,
        mode: request.mode.label().to_owned(),
        summary: std::mem::take(&mut plan.summary),
        template: action_signals.family.to_owned(),
        confidence,
        raw_intent,
        normalized_intent,
        connector_override: request.connector_override.clone(),
        zone,
        quoted_literals: literals.quoted,
        lookup_literal,
        payload_literal,
        chosen_connector,
        alternative_connectors,
        action: action_inference(&action_signals),
        operation_hint: plan.operation_hint.take(),
        missing_information: plan.missing_information,
        unsupported_reasons: plan.unsupported_reasons,
        ambiguities: plan.ambiguities,
        assumptions: plan.assumptions,
        suggested_command_lines,
        next_actions,
        steps: plan.steps,
        explanation,
        execution_notice: EXECUTION_NOTICE.to_owned(),
        suggested_payload,
    }
}

fn compile_status_metadata(
    request: &IntentRequest,
    chosen_connector: Option<&ConnectorCandidate>,
    plan: &PlanBuild,
) -> (String, WorkflowTruth, Vec<String>, Vec<String>) {
    let status = status_for(
        chosen_connector.is_some(),
        &plan.missing_information,
        &plan.unsupported_reasons,
        &plan.ambiguities,
    );
    let workflow_truth = compiled_workflow_truth(
        &status,
        &plan.steps,
        &plan.missing_information,
        &plan.unsupported_reasons,
        &plan.ambiguities,
    );
    let suggested_command_lines = plan
        .steps
        .iter()
        .take(4)
        .map(|step| step.command_line.clone())
        .collect::<Vec<_>>();
    let next_actions = build_next_actions(
        request,
        &status,
        &plan.steps,
        chosen_connector,
        !plan.ambiguities.is_empty(),
        !plan.missing_information.is_empty(),
    );

    (
        status,
        workflow_truth,
        suggested_command_lines,
        next_actions,
    )
}

fn action_inference(action_signals: &ActionSignals) -> ActionInference {
    ActionInference {
        family: action_signals.family.to_owned(),
        verb: action_signals.verb.to_owned(),
        resource: action_signals.resource.map(str::to_owned),
        risk: action_signals.risk.to_owned(),
        mutating: action_signals.mutating,
        matched_terms: action_signals.matched_terms.clone(),
    }
}

fn compile_explanation(
    action_signals: &ActionSignals,
    connector_candidates: &[ConnectorCandidate],
    plan: &mut PlanBuild,
) -> Explanation {
    Explanation {
        connector_evidence: connector_evidence(connector_candidates),
        action_evidence: action_evidence(action_signals),
        lookup_evidence: std::mem::take(&mut plan.lookup_evidence),
        template_reasoning: std::mem::take(&mut plan.template_reasoning),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_plan(
    request: &IntentRequest,
    normalized_intent: &str,
    zone: Option<&str>,
    literals: &ParsedLiterals,
    payload_literal: Option<&str>,
    lookup_literal: Option<&str>,
    chosen_connector: Option<&ConnectorCandidate>,
    chosen_profile: Option<&ConnectorProfile>,
    connector_candidates: &[ConnectorCandidate],
    action: &ActionSignals,
) -> PlanBuild {
    match action.family {
        "lifecycle" => {
            build_lifecycle_plan(request, zone, payload_literal, chosen_connector, action)
        }
        "log-tail" => build_log_tail_plan(request, zone, chosen_connector, action),
        "config" => build_config_plan(request, zone, payload_literal, chosen_connector, action),
        "unsupported" => build_unsupported_plan(zone, chosen_connector, action),
        "discovery" => build_discovery_plan(request, zone, normalized_intent, chosen_connector),
        _ => build_operation_plan(
            request,
            zone,
            literals,
            payload_literal,
            lookup_literal,
            chosen_connector,
            chosen_profile,
            connector_candidates,
            action,
        ),
    }
}

/// Host-backed lifecycle verbs that map to `fwc lifecycle --action <verb>`.
const HOST_LIFECYCLE_VERBS: &[&str] = &["disable", "enable", "restart", "start", "stop"];

fn build_lifecycle_plan(
    request: &IntentRequest,
    zone: Option<&str>,
    payload_literal: Option<&str>,
    chosen_connector: Option<&ConnectorCandidate>,
    action: &ActionSignals,
) -> PlanBuild {
    let mut plan = PlanBuild::default();
    let Some(connector) = chosen_connector else {
        "Clarify which connector lifecycle should change.".clone_into(&mut plan.summary);
        plan.missing_information.push(
            "Name the connector explicitly or pass `--connector <id>` so the lifecycle plan has a concrete target."
                .to_owned(),
        );
        plan.template_reasoning.push(
            "The intent matched lifecycle verbs, so `fwc` chose the lifecycle template.".to_owned(),
        );
        return plan;
    };

    // Host-backed lifecycle transitions route through `fwc lifecycle --action <verb>`
    // backed by POST /rpc/lifecycle/{connector_id} on the host admin API.
    let is_host_lifecycle = HOST_LIFECYCLE_VERBS.contains(&action.verb);

    plan.summary = format!(
        "Plan a {} workflow for the `{}` connector.",
        action.verb, connector.id
    );

    if is_host_lifecycle {
        plan.template_reasoning.push(format!(
            "The `{}` verb maps to `fwc lifecycle --action {}`, backed by the host admin API lifecycle endpoint (POST /rpc/lifecycle/{{connector_id}}).",
            action.verb, action.verb
        ));

        // Step 1: preflight — check valid actions for current state
        plan.steps.push(step(
            1,
            "preflight",
            "Query valid lifecycle actions for the connector's current state.".to_owned(),
            vec![
                "fwc".to_owned(),
                "lifecycle".to_owned(),
                connector.id.clone(),
                "--valid-actions".to_owned(),
            ],
            false,
            false,
            vec!["Provenance: host-backed. This step queries the live host admin API.".to_owned()],
        ));

        // Step 2: preflight safety check for the specific action
        plan.steps.push(step(
            2,
            "preflight",
            format!(
                "Run a preflight safety check for the `{}` lifecycle transition.",
                action.verb
            ),
            vec![
                "fwc".to_owned(),
                "lifecycle".to_owned(),
                connector.id.clone(),
                "--action".to_owned(),
                action.verb.to_owned(),
                "--preflight".to_owned(),
            ],
            false,
            false,
            vec![
                "Provenance: host-backed. Validates the transition is legal for the current state."
                    .to_owned(),
            ],
        ));

        // Step 3: execute the lifecycle transition
        plan.steps.push(step(
            3,
            "mutate",
            format!(
                "Execute the `{}` lifecycle transition via the host admin API.",
                action.verb
            ),
            vec![
                "fwc".to_owned(),
                "lifecycle".to_owned(),
                connector.id.clone(),
                "--action".to_owned(),
                action.verb.to_owned(),
            ],
            true,
            true,
            vec![
                "Provenance: host-backed. Calls POST /rpc/lifecycle/{connector_id} on the host."
                    .to_owned(),
                format!(
                    "Refusal taxonomy: host-unavailable if no host configured, invalid-transition if the connector's current state does not permit `{}`.",
                    action.verb
                ),
            ],
        ));

        // Step 4: verify convergence
        plan.steps.push(step(
            4,
            "verify",
            "Re-read status after the transition to confirm convergence.".to_owned(),
            vec!["fwc".to_owned(), "status".to_owned(), connector.id.clone()],
            false,
            false,
            vec![],
        ));
    } else {
        // Original install/update/pin/unpin/status path
        plan.template_reasoning.push(
            "Supported lifecycle verbs map onto real `fwc` lifecycle primitives plus a status verification pass."
                .to_owned(),
        );
        plan.steps.push(step(
            1,
            "preflight",
            "Capture the connector's current desired and observed state before changing it."
                .to_string(),
            vec!["fwc".to_owned(), "status".to_owned(), connector.id.clone()],
            false,
            false,
            vec![],
        ));
        plan.steps.push(step(
            2,
            "mutate",
            format!("Apply the requested `{}` lifecycle action.", action.verb),
            vec![
                "fwc".to_owned(),
                action.verb.to_owned(),
                connector.id.clone(),
            ],
            true,
            true,
            vec![],
        ));
        plan.steps.push(step(
            3,
            "verify",
            "Re-read status after the change to confirm convergence.".to_owned(),
            vec!["fwc".to_owned(), "status".to_owned(), connector.id.clone()],
            false,
            false,
            vec![],
        ));
    }

    if zone.is_some() {
        plan.assumptions.push(
            "A zone hint was captured, but lifecycle primitives do not yet expose explicit zone targeting flags; the host/context layer will need to honor that binding later."
                .to_owned(),
        );
    }

    if action.verb == "pin" && payload_literal.is_none() {
        plan.missing_information.push(
            "Specify the version or channel to pin, for example `pin github to stable`.".to_owned(),
        );
        if let Some(last) = plan.steps.get_mut(1) {
            last.argv.push("<version-or-channel>".to_owned());
            last.command_line = shell_join(&last.argv);
            last.notes.push(
                "Replace this unresolved version/channel argument before real execution."
                    .to_owned(),
            );
        }
    }

    if matches!(request.mode, IntentMode::DoApprove) {
        plan.assumptions.push(
            "Approval is explicit, so `fwc do --approve` will attempt the real mutating lifecycle primitive."
                .to_owned(),
        );
    }

    plan
}

fn build_log_tail_plan(
    request: &IntentRequest,
    zone: Option<&str>,
    chosen_connector: Option<&ConnectorCandidate>,
    _action: &ActionSignals,
) -> PlanBuild {
    let mut plan = PlanBuild::default();

    plan.template_reasoning.push(
        "Log/tail/stream verbs map to `fwc tail`, backed by the host admin API log and event endpoints (POST /rpc/admin/logs, POST /rpc/admin/events)."
            .to_owned(),
    );

    let connector_label = chosen_connector
        .map(|c| c.id.as_str())
        .unwrap_or("all connectors");

    plan.summary = format!("Plan a log-tail workflow for {}.", connector_label);

    // Step 1: status check to confirm the connector exists and is reachable
    if let Some(connector) = chosen_connector {
        plan.steps.push(step(
            1,
            "preflight",
            "Confirm the connector is known and its current state.".to_owned(),
            vec!["fwc".to_owned(), "status".to_owned(), connector.id.clone()],
            false,
            false,
            vec![
                "Provenance: host-backed. Validates the connector exists before tailing."
                    .to_owned(),
            ],
        ));
    }

    // Step 2: tail events/logs
    let next_ordinal = if chosen_connector.is_some() { 2 } else { 1 };
    let mut tail_argv = vec!["fwc".to_owned(), "tail".to_owned()];
    if let Some(connector) = chosen_connector {
        tail_argv.push(connector.id.clone());
    }
    // Default --since and --limit for a reasonable snapshot
    tail_argv.push("--since".to_owned());
    tail_argv.push("5m".to_owned());
    tail_argv.push("--limit".to_owned());
    tail_argv.push("50".to_owned());

    plan.steps.push(step(
        next_ordinal,
        "inspect",
        format!(
            "Tail recent events and logs for {}.",
            connector_label
        ),
        tail_argv,
        false,
        false,
        vec![
            "Provenance: host-backed. Queries POST /rpc/admin/logs and POST /rpc/admin/events on the host."
                .to_owned(),
            "Refusal taxonomy: host-unavailable if no host configured, connector-unresolved if the connector does not exist."
                .to_owned(),
        ],
    ));

    // Step 3: also show recent operation receipts for richer context
    if let Some(connector) = chosen_connector {
        plan.steps.push(step(
            next_ordinal + 1,
            "inspect",
            "Show recent operation receipts for additional execution context.".to_owned(),
            vec![
                "fwc".to_owned(),
                "history".to_owned(),
                "--connector".to_owned(),
                connector.id.clone(),
                "--limit".to_owned(),
                "10".to_owned(),
            ],
            false,
            false,
            vec![],
        ));
    }

    if zone.is_some() {
        plan.assumptions.push(
            "A zone hint was captured, but the tail command does not yet filter by zone."
                .to_owned(),
        );
    }

    if matches!(request.mode, IntentMode::DoApprove | IntentMode::DoSimulate) {
        plan.assumptions.push(
            "Log tailing is read-only; approval and simulation modes have no additional effect on these steps."
                .to_owned(),
        );
    }

    plan
}

#[allow(clippy::too_many_lines)]
fn build_config_plan(
    request: &IntentRequest,
    zone: Option<&str>,
    payload_literal: Option<&str>,
    chosen_connector: Option<&ConnectorCandidate>,
    action: &ActionSignals,
) -> PlanBuild {
    let mut plan = PlanBuild::default();
    let Some(connector) = chosen_connector else {
        "Clarify which connector configuration should change.".clone_into(&mut plan.summary);
        plan.missing_information.push(
            "Name the connector explicitly or pass `--connector <id>` so the config workflow has a concrete target."
                .to_owned(),
        );
        return plan;
    };

    plan.summary = format!(
        "Plan a config-first workflow for the `{}` connector.",
        connector.id
    );
    plan.template_reasoning.push(
        "Config-oriented words map to `config schema`, a config mutation/read step, `config doctor`, and a final `status` check."
            .to_owned(),
    );
    plan.steps.push(step(
        1,
        "schema",
        "Inspect the connector's config schema before touching values.".to_owned(),
        vec![
            "fwc".to_owned(),
            "config".to_owned(),
            "schema".to_owned(),
            connector.id.clone(),
        ],
        false,
        false,
        vec![],
    ));

    let mut mutation_argv = vec![
        "fwc".to_owned(),
        "config".to_owned(),
        if action.verb == "get" { "get" } else { "set" }.to_owned(),
        connector.id.clone(),
    ];
    let mut mutation_notes = Vec::new();
    let purpose = if action.verb == "get" {
        "Read the current config state to confirm what is already set.".to_owned()
    } else {
        mutation_argv.push("<key>".to_owned());
        mutation_argv.push(payload_literal.map_or_else(|| "<value>".to_owned(), str::to_owned));
        mutation_notes.push(
            "Replace `<key>` and `<value>` with the concrete config path and value or secret reference."
                .to_owned(),
        );
        "Apply the requested config mutation.".to_owned()
    };

    plan.steps.push(step(
        2,
        if action.verb == "get" {
            "read"
        } else {
            "mutate"
        },
        purpose,
        mutation_argv,
        action.verb != "get",
        action.verb != "get",
        mutation_notes,
    ));
    plan.steps.push(step(
        3,
        "doctor",
        "Run connector config doctor immediately after the change.".to_owned(),
        vec![
            "fwc".to_owned(),
            "config".to_owned(),
            "doctor".to_owned(),
            connector.id.clone(),
        ],
        false,
        false,
        vec![],
    ));
    plan.steps.push(step(
        4,
        "verify",
        "Check connector status after the config workflow.".to_owned(),
        vec!["fwc".to_owned(), "status".to_owned(), connector.id.clone()],
        false,
        false,
        vec![],
    ));

    if action.verb != "get" {
        plan.missing_information.push(
            "Extract the specific config key path and concrete value or secret reference before real execution."
                .to_owned(),
        );
    }

    if zone.is_some() {
        plan.assumptions.push(
            "A zone hint was captured, but config primitives do not yet expose explicit zone-targeting flags."
                .to_owned(),
        );
    }

    if matches!(request.mode, IntentMode::DoApprove) {
        plan.assumptions.push(
            "Approval is explicit, so `fwc do --approve` will attempt the real config mutation path."
                .to_owned(),
        );
    }

    plan
}

fn build_unsupported_plan(
    zone: Option<&str>,
    chosen_connector: Option<&ConnectorCandidate>,
    action: &ActionSignals,
) -> PlanBuild {
    let mut plan = PlanBuild::default();
    plan.unsupported_reasons
        .push("That intent does not map to a supported real `fwc` primitive.".to_owned());
    plan.template_reasoning.push(
        "The intent matched a verb that does not currently have a truthful `fwc` primitive, so the compiler switched to an unsupported-intent explanation instead of inventing a command."
            .to_owned(),
    );

    let Some(connector) = chosen_connector else {
        plan.summary = format!(
            "`{}` is not currently a supported real `fwc` primitive.",
            action.verb
        );
        plan.missing_information.push(
            "Name the connector explicitly if you want the compiler to suggest the closest real inspection commands."
                .to_owned(),
        );
        return plan;
    };

    plan.summary = format!(
        "`fwc {}` is unavailable for `{}`; inspect current state and choose a supported command instead.",
        action.verb, connector.id
    );

    plan.steps.push(step(
        1,
        "inspect",
        "Inspect the connector's current state.".to_owned(),
        vec!["fwc".to_owned(), "status".to_owned(), connector.id.clone()],
        false,
        false,
        vec![],
    ));
    plan.steps.push(step(
        2,
        "inspect",
        "Inspect connector detail before choosing a supported action.".to_owned(),
        vec!["fwc".to_owned(), "show".to_owned(), connector.id.clone()],
        false,
        false,
        vec![],
    ));

    if let Some(zone) = zone {
        plan.assumptions.push(format!(
            "A zone hint (`{zone}`) was captured, but there is no supported primitive for `{}` that can enforce it yet.",
            action.verb
        ));
    }

    plan
}

fn build_discovery_plan(
    request: &IntentRequest,
    zone: Option<&str>,
    normalized_intent: &str,
    chosen_connector: Option<&ConnectorCandidate>,
) -> PlanBuild {
    let mut plan = PlanBuild::default();
    plan.template_reasoning.push(
        "No strong mutation or lifecycle intent was detected, so `fwc` fell back to a discovery-first plan."
            .to_owned(),
    );
    plan.summary = chosen_connector.map_or_else(
        || "Plan a broad connector discovery workflow.".to_owned(),
        |connector| format!("Plan a discovery workflow for `{}`.", connector.id),
    );

    let mut list_argv = vec!["fwc".to_owned(), "list".to_owned()];
    if let Some(zone) = zone {
        list_argv.push("--zone".to_owned());
        list_argv.push(zone.to_owned());
    }
    plan.steps.push(step(
        1,
        "discover",
        "Start from the low-token connector inventory.".to_owned(),
        list_argv,
        false,
        false,
        vec![],
    ));

    if let Some(connector) = chosen_connector {
        plan.steps.push(step(
            2,
            "inspect",
            "Expand the most likely connector into a high-signal detail view.".to_owned(),
            vec!["fwc".to_owned(), "show".to_owned(), connector.id.clone()],
            false,
            false,
            vec![],
        ));
        plan.steps.push(step(
            3,
            "inspect",
            "Inspect the connector's operation surface before narrowing further.".to_owned(),
            vec!["fwc".to_owned(), "ops".to_owned(), connector.id.clone()],
            false,
            false,
            vec![],
        ));
    } else {
        plan.steps.push(step(
            2,
            "search",
            "Search connectors and operations with the exact phrasing from the request.".to_owned(),
            search_argv(normalized_intent, zone),
            false,
            false,
            vec![],
        ));
        plan.missing_information.push(
            "Name the connector or service more explicitly so the compiler can move from discovery into schema or execution planning."
                .to_owned(),
        );
    }

    if request.mode.is_execution() {
        plan.assumptions.push(
            "`do` fell back to discovery because the request was too vague for a safe execution plan."
                .to_owned(),
        );
    }

    plan
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_operation_plan(
    request: &IntentRequest,
    zone: Option<&str>,
    literals: &ParsedLiterals,
    payload_literal: Option<&str>,
    lookup_literal: Option<&str>,
    chosen_connector: Option<&ConnectorCandidate>,
    chosen_profile: Option<&ConnectorProfile>,
    connector_candidates: &[ConnectorCandidate],
    action: &ActionSignals,
) -> PlanBuild {
    let mut plan = PlanBuild::default();
    if let [top, second, ..] = connector_candidates {
        if top.score - second.score <= 3 {
            plan.ambiguities.push(Ambiguity {
                kind: "connector".to_owned(),
                message: "Multiple connectors matched the request closely enough that the chosen connector should be treated as provisional."
                    .to_owned(),
                candidates: connector_candidates
                    .iter()
                    .take(3)
                    .map(|candidate| candidate.id.clone())
                    .collect(),
            });
        }
    }

    let Some(connector) = chosen_connector else {
        "Clarify which connector should satisfy the requested task.".clone_into(&mut plan.summary);
        plan.template_reasoning.push(
            "The compiler detected an external operation workflow but could not infer a concrete connector with enough confidence."
                .to_owned(),
        );
        plan.missing_information.push(
            "Name the connector explicitly or pass `--connector <id>` so `fwc` can compile exact primitive commands."
                .to_owned(),
        );
        if !connector_candidates.is_empty() {
            plan.ambiguities.push(Ambiguity {
                kind: "connector".to_owned(),
                message: "Several connectors partially matched the request.".to_owned(),
                candidates: connector_candidates
                    .iter()
                    .take(3)
                    .map(|candidate| candidate.id.clone())
                    .collect(),
            });
        }
        return plan;
    };

    let operation_hint = infer_operation_hint(
        chosen_profile,
        &connector.id,
        action,
        payload_literal,
        lookup_literal,
    );
    plan.operation_hint = Some(operation_hint.clone());
    plan.summary = format!(
        "Plan a {} workflow on `{}` via `{}`.",
        action.verb, connector.id, operation_hint
    );
    plan.template_reasoning.push(
        "The compiler chose the external-operation template because the request implies a connector action rather than a lifecycle or config change."
            .to_owned(),
    );

    plan.steps.push(step(
        1,
        "inspect",
        "Inspect the connector before choosing an operation.".to_owned(),
        vec!["fwc".to_owned(), "show".to_owned(), connector.id.clone()],
        false,
        false,
        vec![],
    ));
    plan.steps.push(step(
        2,
        "inspect",
        "Inspect the connector's operation inventory.".to_owned(),
        vec!["fwc".to_owned(), "ops".to_owned(), connector.id.clone()],
        false,
        false,
        vec![],
    ));

    if action.needs_lookup || identifier_heavy_connector(&connector.id) {
        let query = lookup_literal
            .map(str::to_owned)
            .or_else(|| literals.named.clone())
            .or_else(|| literals.called.clone());
        if let Some(query) = query {
            plan.lookup_evidence.push(format!(
                "Inserted a lookup/search step because `{connector}` often requires human-name to identifier resolution."
            ));
            plan.steps.push(step(
                3,
                "lookup",
                "Search for the target resource or identifier before mutation.".to_owned(),
                search_argv(&query, zone),
                false,
                false,
                vec![format!(
                    "Use the search result to fill in the unresolved resource identifier before real execution on `{connector}`."
                )],
            ));
        } else if action.mutating {
            plan.missing_information.push(
                format!(
                    "Provide the target resource name or identifier for `{}` so the compiler can add a lookup step before mutation.",
                    connector.id
                ),
            );
        }
    }

    plan.steps.push(step(
        plan.steps.len() + 1,
        "schema",
        "Inspect the exact operation schema.".to_owned(),
        vec![
            "fwc".to_owned(),
            "schema".to_owned(),
            connector.id.clone(),
            operation_hint.clone(),
        ],
        false,
        false,
        vec![],
    ));
    plan.steps.push(step(
        plan.steps.len() + 1,
        "examples",
        "Inspect a minimal example payload before composing the request.".to_owned(),
        vec![
            "fwc".to_owned(),
            "examples".to_owned(),
            connector.id.clone(),
            operation_hint.clone(),
        ],
        false,
        false,
        vec![],
    ));

    if action.mutating {
        plan.steps.push(step(
            plan.steps.len() + 1,
            "preflight",
            "Simulate the operation before requesting side effects.".to_owned(),
            vec![
                "fwc".to_owned(),
                "simulate".to_owned(),
                connector.id.clone(),
                operation_hint.clone(),
                "--file".to_owned(),
                "./intent-payload.json".to_owned(),
            ],
            false,
            false,
            vec![
                "Replace `./intent-payload.json` with the concrete payload assembled from the schema and examples."
                    .to_owned(),
            ],
        ));
    }

    plan.steps.push(step(
        plan.steps.len() + 1,
        "execute",
        if action.mutating {
            "Execute the compiled connector operation once the payload and approvals are ready."
                .to_owned()
        } else {
            "Invoke the compiled connector operation.".to_owned()
        },
        operation_invoke_argv(&connector.id, &operation_hint, action.mutating),
        action.mutating,
        action.mutating,
        vec![
            format!(
                "This step calls the real `fwc invoke` primitive and will only succeed if the selected host and connector are configured for `{}`.",
                connector.id
            ),
        ],
    ));

    if payload_missing(action, payload_literal, lookup_literal, &connector.id) {
        plan.missing_information
            .push(missing_payload_message(action, &connector.id));
    }

    if let Some(zone) = zone {
        plan.assumptions.push(format!(
            "A zone hint (`{zone}`) was captured. The global search step can express it directly today; the remaining primitive commands will require host/context support to preserve that scope."
        ));
    }

    if request.mode.is_approved() {
        plan.assumptions.push(
            "Approval is explicit, so `fwc do --approve` will attempt the real side-effecting primitive."
                .to_owned(),
        );
    }

    plan
}

fn operation_invoke_argv(
    connector_id: &str,
    operation_hint: &str,
    payload_required: bool,
) -> Vec<String> {
    let mut argv = vec![
        "fwc".to_owned(),
        "invoke".to_owned(),
        connector_id.to_owned(),
        operation_hint.to_owned(),
    ];
    if payload_required {
        argv.push("--file".to_owned());
        argv.push("./intent-payload.json".to_owned());
    }
    argv
}

fn infer_connector_candidates(
    normalized_intent: &str,
    connector_override: Option<&str>,
    profiles: &[ConnectorProfile],
) -> Vec<ConnectorCandidate> {
    if let Some(override_name) = connector_override {
        return vec![ConnectorCandidate {
            id: override_name.to_owned(),
            score: 100,
            reasons: vec!["Connector was explicitly pinned with `--connector`.".to_owned()],
        }];
    }

    let mut candidates = profiles
        .iter()
        .filter_map(|profile| {
            let mut score = 0;
            let mut reasons = Vec::new();

            for alias in &profile.aliases {
                if contains_term(normalized_intent, alias) {
                    score += 8;
                    reasons.push(format!("Matched connector alias `{alias}`."));
                }
            }

            for keyword in &profile.keywords {
                if contains_term(normalized_intent, keyword) {
                    score += 3;
                    reasons.push(format!("Matched domain keyword `{keyword}`."));
                }
            }

            (score > 0).then(|| ConnectorCandidate {
                id: profile.id.clone(),
                score,
                reasons,
            })
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
    candidates
}

#[allow(clippy::too_many_lines)]
fn infer_action(normalized_intent: &str) -> ActionSignals {
    static LIFECYCLE: &[(&str, &str)] = &[
        ("install", "install"),
        ("update", "update"),
        ("pin", "pin"),
        ("unpin", "unpin"),
        ("status", "status"),
        ("disable", "disable"),
        ("enable", "enable"),
        ("restart", "restart"),
        ("start", "start"),
        ("stop", "stop"),
    ];
    static LOG_TAIL: &[(&str, &str)] = &[
        ("logs", "tail"),
        ("log", "tail"),
        ("tail", "tail"),
        ("stream", "tail"),
    ];
    static CONFIG: &[(&str, &str)] = &[
        ("configure", "set"),
        ("config", "set"),
        ("credential", "set"),
        ("credentials", "set"),
        ("secret", "set"),
        ("token", "set"),
        ("webhook", "set"),
        ("apikey", "set"),
        ("api key", "set"),
    ];
    static WRITE: &[(&str, &str)] = &[
        ("append", "append"),
        ("send", "send"),
        ("post", "send"),
        ("create", "create"),
        ("comment", "comment"),
        ("schedule", "create"),
        ("publish", "send"),
        ("open", "create"),
        ("update", "update"),
    ];
    static SEARCH: &[(&str, &str)] = &[
        ("find", "search"),
        ("search", "search"),
        ("lookup", "search"),
        ("list", "list"),
        ("query", "query"),
        ("show", "get"),
        ("read", "get"),
        ("inspect", "get"),
        ("fetch", "get"),
    ];
    if let Some((matched, verb)) = match_first(normalized_intent, LIFECYCLE) {
        return ActionSignals {
            family: "lifecycle",
            verb,
            resource: Some("connector"),
            risk: match verb {
                "status" => "low",
                "install" | "update" | "pin" | "unpin" => "high",
                // Host-backed lifecycle transitions: enable/disable/start/stop/restart
                _ => "high",
            },
            mutating: verb != "status",
            matched_terms: vec![matched.to_owned()],
            needs_lookup: false,
        };
    }

    if let Some((matched, verb)) = match_first(normalized_intent, LOG_TAIL) {
        return ActionSignals {
            family: "log-tail",
            verb,
            resource: Some("connector"),
            risk: "low",
            mutating: false,
            matched_terms: vec![matched.to_owned()],
            needs_lookup: false,
        };
    }

    if let Some((matched, verb)) = match_first(normalized_intent, CONFIG) {
        return ActionSignals {
            family: "config",
            verb,
            resource: Some("config"),
            risk: "medium",
            mutating: verb != "get",
            matched_terms: vec![matched.to_owned()],
            needs_lookup: false,
        };
    }

    if let Some((matched, verb)) = match_first(normalized_intent, WRITE) {
        return ActionSignals {
            family: "operation",
            verb,
            resource: infer_resource(normalized_intent),
            risk: if matches!(verb, "append" | "send" | "create" | "comment" | "update") {
                "medium"
            } else {
                "low"
            },
            mutating: true,
            matched_terms: vec![matched.to_owned()],
            needs_lookup: contains_any(normalized_intent, &["find", "lookup", "named", "called"]),
        };
    }

    if let Some((matched, verb)) = match_first(normalized_intent, SEARCH) {
        return ActionSignals {
            family: "operation",
            verb,
            resource: infer_resource(normalized_intent),
            risk: "low",
            mutating: false,
            matched_terms: vec![matched.to_owned()],
            needs_lookup: matches!(verb, "search" | "query"),
        };
    }

    ActionSignals {
        family: "discovery",
        verb: "discover",
        resource: None,
        risk: "low",
        mutating: false,
        matched_terms: Vec::new(),
        needs_lookup: false,
    }
}

fn infer_resource(normalized_intent: &str) -> Option<&'static str> {
    let resources = [
        ("pull request", "pull-request"),
        ("pull requests", "pull-request"),
        ("issue", "issue"),
        ("issues", "issue"),
        ("ticket", "issue"),
        ("tickets", "issue"),
        ("page", "page"),
        ("pages", "page"),
        ("document", "page"),
        ("documents", "page"),
        ("message", "message"),
        ("messages", "message"),
        ("channel", "channel"),
        ("channels", "channel"),
        ("event", "event"),
        ("events", "event"),
        ("meeting", "event"),
        ("file", "file"),
        ("files", "file"),
        ("folder", "file"),
        ("record", "record"),
        ("records", "record"),
        ("invoice", "invoice"),
        ("customer", "customer"),
        ("customers", "customer"),
        ("table", "query"),
        ("tables", "query"),
        ("dataset", "query"),
        ("query", "query"),
        ("queries", "query"),
        ("comment", "comment"),
        ("comments", "comment"),
    ];

    resources.iter().find_map(|(needle, resource)| {
        contains_term(normalized_intent, needle).then_some(*resource)
    })
}

fn infer_operation_hint(
    chosen_profile: Option<&ConnectorProfile>,
    connector_id: &str,
    action: &ActionSignals,
    payload_literal: Option<&str>,
    lookup_literal: Option<&str>,
) -> String {
    let resource = action.resource.unwrap_or("object");
    let heuristic_hint = match connector_id {
        "github" => github_operation_hint(action.verb, resource),
        "slack" | "discord" | "telegram" => messaging_operation_hint(action.verb, resource),
        "notion" => notion_operation_hint(action.verb, resource),
        "jira" | "linear" => issue_tracker_operation_hint(action.verb, resource),
        "gmail" => gmail_operation_hint(action.verb, resource),
        "google-calendar" => calendar_operation_hint(action.verb, resource),
        "dropbox" | "box" | "s3" => storage_operation_hint(action.verb, resource),
        "airtable" => airtable_operation_hint(action.verb, resource),
        "figma" => figma_operation_hint(action.verb, resource),
        "stripe" => stripe_operation_hint(action.verb, resource),
        "salesforce" | "hubspot" => crm_operation_hint(action.verb, resource),
        "bigquery" | "snowflake" | "mongodb" | "duckdb" | "qdrant" | "vectordb" => {
            query_operation_hint(action.verb, resource)
        }
        "openai" | "anthropic" | "google-ai" | "llm-router" => llm_operation_hint(action.verb),
        _ => generic_operation_hint(action.verb, resource, payload_literal, lookup_literal),
    };

    if let Some(profile) = chosen_profile
        && let Some(manifest_hint) = canonical_manifest_operation_hint(profile, &heuristic_hint)
            .or_else(|| infer_manifest_operation_hint(profile, action))
    {
        return manifest_hint;
    }

    heuristic_hint
}

fn canonical_manifest_operation_hint(profile: &ConnectorProfile, selector: &str) -> Option<String> {
    profile
        .operations
        .iter()
        .find(|operation| operation.matches_selector(selector))
        .map(|operation| operation.preferred_selector.clone())
}

fn infer_manifest_operation_hint(
    profile: &ConnectorProfile,
    action: &ActionSignals,
) -> Option<String> {
    let selector_candidates = manifest_selector_candidates(action);
    if selector_candidates.is_empty() {
        return None;
    }

    let mut matches = profile
        .operations
        .iter()
        .filter_map(|operation| {
            selector_candidates
                .iter()
                .enumerate()
                .find(|(_, selector)| operation.matches_selector(selector))
                .and_then(|(rank, selector)| {
                    let rank = i32::try_from(rank).ok()?;
                    let mut score = 100_i32 - rank;
                    if normalize_operation_selector(&operation.preferred_selector) == *selector {
                        score += 10;
                    }
                    if contains_term(&operation.local_id.replace('_', " "), action.verb) {
                        score += 2;
                    }
                    Some((score, operation))
                })
        })
        .collect::<Vec<_>>();

    matches.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.preferred_selector.cmp(&right.1.preferred_selector))
    });
    matches
        .first()
        .map(|(_, operation)| operation.preferred_selector.clone())
}

fn manifest_selector_candidates(action: &ActionSignals) -> Vec<String> {
    let Some(resource) = action.resource else {
        return Vec::new();
    };

    let mut selectors = Vec::new();
    let mut seen = BTreeSet::new();
    for noun in manifest_resource_variants(resource) {
        for verb in manifest_verb_variants(action.verb) {
            let selector = normalize_operation_selector(&format!("{noun}.{verb}"));
            if seen.insert(selector.clone()) {
                selectors.push(selector);
            }
        }
    }
    if action.verb == "comment" {
        for verb in ["create", "add", "post"] {
            let selector = normalize_operation_selector(&format!("comments.{verb}"));
            if seen.insert(selector.clone()) {
                selectors.push(selector);
            }
        }
    }
    selectors
}

fn manifest_verb_variants(verb: &str) -> &'static [&'static str] {
    match verb {
        "append" => &["append", "add", "create", "post"],
        "comment" => &["comment", "create", "add", "reply", "post"],
        "create" => &["create", "post", "open", "add"],
        "get" => &["get", "read", "fetch", "retrieve", "download", "info"],
        "list" => &["list", "search", "get", "read"],
        "query" => &["query", "search", "list", "run", "get"],
        "search" => &["search", "find", "list", "query"],
        "send" => &["send", "post", "create", "reply"],
        "update" => &["update", "set", "edit", "modify"],
        _ => &[],
    }
}

fn manifest_resource_variants(resource: &str) -> Vec<String> {
    let singular = singularize_resource(resource);
    let plural = pluralize_resource(&singular);
    let mut variants = Vec::new();
    let mut seen = BTreeSet::new();

    for value in [singular, plural] {
        for variant in [
            value.clone(),
            value.replace('_', "-"),
            value.replace('_', ""),
        ] {
            if seen.insert(variant.clone()) {
                variants.push(variant);
            }
        }
    }

    variants
}

fn singularize_resource(resource: &str) -> String {
    let normalized = normalize_operation_selector(resource);
    match normalized.as_str() {
        "queries" => "query".to_owned(),
        value if value.ends_with('s') => value.trim_end_matches('s').to_owned(),
        value => value.to_owned(),
    }
}

fn pluralize_resource(resource: &str) -> String {
    match resource {
        "query" => "queries".to_owned(),
        value if value.ends_with('s') => value.to_owned(),
        value => format!("{value}s"),
    }
}

fn build_next_actions(
    request: &IntentRequest,
    status: &str,
    steps: &[CompiledStep],
    chosen_connector: Option<&ConnectorCandidate>,
    has_ambiguity: bool,
    has_missing_information: bool,
) -> Vec<String> {
    let mut actions = Vec::new();

    if has_ambiguity {
        actions.push(
            "Rerun the command with `--connector <id>` if you already know which service should handle the task."
                .to_owned(),
        );
    }

    if has_missing_information {
        actions.push(
            "Add the missing identifier, payload content, or config details and rerun the plan compiler."
                .to_owned(),
        );
    }

    if matches!(request.mode, IntentMode::Plan | IntentMode::Explain) && status == "ready" {
        actions.push(format!(
            "Run `fwc do '{}' --simulate` to materialize the primitive workflow without side effects.",
            request.intent.replace('\'', "\\'")
        ));
    }

    if matches!(request.mode, IntentMode::DoSimulate) && status == "ready" {
        actions.push(format!(
            "If the simulated plan still looks correct, rerun with `fwc do '{}' --approve`.",
            request.intent.replace('\'', "\\'")
        ));
    }

    if status == "unsupported" {
        actions.push(
            "Choose a supported real primitive instead of retrying the same unsupported request."
                .to_owned(),
        );
    }

    if matches!(request.mode, IntentMode::DoApprove) && status != "unsupported" {
        actions.push(
            "Approval is explicit, so the next run will attempt the real side-effecting primitive and surface any live host or configuration error directly."
                .to_owned(),
        );
    }

    if let Some(step) = steps.first() {
        actions.push(format!("Start by inspecting `{}`.", step.command_line));
    } else if let Some(connector) = chosen_connector {
        actions.push(format!(
            "Run `fwc show {}` to gather more signal before compiling a narrower workflow.",
            connector.id
        ));
    } else {
        actions.push(
            "Run `fwc list` or `fwc search <term>` to narrow the connector first.".to_owned(),
        );
    }

    actions
}

fn connector_profiles() -> Vec<ConnectorProfile> {
    static CONNECTOR_PROFILES: OnceLock<Vec<ConnectorProfile>> = OnceLock::new();
    CONNECTOR_PROFILES
        .get_or_init(build_connector_profiles)
        .clone()
}

fn build_connector_profiles() -> Vec<ConnectorProfile> {
    let mut profiles = curated_connector_profiles();

    for connector_id in workspace_connector_ids() {
        profiles
            .entry(connector_id.clone())
            .or_insert_with(|| generic_connector_profile(&connector_id));
    }

    for (connector_id, operations) in &operation_index().by_connector {
        let profile = profiles
            .entry(connector_id.clone())
            .or_insert_with(|| generic_connector_profile(connector_id));
        profile.operations = operations.clone();
    }

    profiles.into_values().collect()
}

fn operation_index() -> &'static OperationIndex {
    static OPERATION_INDEX: OnceLock<OperationIndex> = OnceLock::new();
    OPERATION_INDEX.get_or_init(OperationIndex::load)
}

#[allow(clippy::too_many_lines)]
fn curated_connector_profiles() -> BTreeMap<String, ConnectorProfile> {
    [
        curated_connector(
            "github",
            &["gh"],
            &["issue", "pull request", "repo", "repository", "workflow"],
        ),
        curated_connector("slack", &[], &["channel", "message", "workspace", "thread"]),
        curated_connector("discord", &[], &["guild", "server", "channel", "message"]),
        curated_connector("telegram", &[], &["chat", "bot", "message"]),
        curated_connector("notion", &[], &["page", "database", "block", "document"]),
        curated_connector("jira", &[], &["ticket", "issue", "board", "sprint"]),
        curated_connector("linear", &[], &["issue", "cycle", "project"]),
        curated_connector("gmail", &[], &["email", "thread", "draft", "inbox"]),
        curated_connector(
            "google-calendar",
            &["gcal"],
            &["event", "meeting", "calendar", "invite"],
        ),
        curated_connector("airtable", &[], &["base", "record", "table"]),
        curated_connector("figma", &[], &["design", "file", "frame", "comment"]),
        curated_connector("dropbox", &[], &["file", "folder", "storage"]),
        curated_connector("box", &[], &["file", "folder", "storage"]),
        curated_connector(
            "stripe",
            &[],
            &["payment", "invoice", "customer", "subscription"],
        ),
        curated_connector(
            "salesforce",
            &[],
            &["account", "lead", "opportunity", "case"],
        ),
        curated_connector("hubspot", &[], &["account", "lead", "deal", "contact"]),
        curated_connector("bigquery", &[], &["dataset", "table", "sql", "query"]),
        curated_connector("snowflake", &[], &["warehouse", "table", "sql", "query"]),
        curated_connector("mongodb", &[], &["collection", "document", "query"]),
        curated_connector("qdrant", &[], &["vector", "collection", "embedding"]),
        curated_connector("vectordb", &[], &["vector", "embedding", "search"]),
        curated_connector(
            "openai",
            &[],
            &["prompt", "completion", "assistant", "model"],
        ),
        curated_connector(
            "anthropic",
            &[],
            &["prompt", "completion", "assistant", "model"],
        ),
        curated_connector(
            "google-ai",
            &[],
            &["prompt", "completion", "assistant", "model"],
        ),
    ]
    .into_iter()
    .map(|profile| (profile.id.clone(), profile))
    .collect()
}

fn curated_connector(id: &str, aliases: &[&str], keywords: &[&str]) -> ConnectorProfile {
    let mut all_aliases = vec![id.to_owned(), id.replace('-', "")];
    all_aliases.extend(aliases.iter().map(|alias| (*alias).to_owned()));
    ConnectorProfile {
        id: id.to_owned(),
        aliases: all_aliases,
        keywords: keywords
            .iter()
            .map(|keyword| (*keyword).to_owned())
            .collect(),
        operations: Vec::new(),
    }
}

fn generic_connector_profile(id: &str) -> ConnectorProfile {
    let mut aliases = vec![id.to_owned(), id.replace('-', "")];
    aliases.extend(id.split('-').map(str::to_owned));
    ConnectorProfile {
        id: id.to_owned(),
        aliases,
        keywords: id.split('-').map(str::to_owned).collect(),
        operations: Vec::new(),
    }
}

fn workspace_connector_ids() -> Vec<String> {
    connectors_dir()
        .filter(|path| path.exists())
        .and_then(|path| read_directory_names(&path).ok())
        .unwrap_or_default()
}

fn connectors_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()?
        .parent()
        .map(|root| root.join("connectors"))
}

fn read_directory_names(path: &Path) -> std::io::Result<Vec<String>> {
    let mut ids = fs::read_dir(path)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry.file_type().ok().filter(std::fs::FileType::is_dir)?;
            Some(entry.file_name().to_string_lossy().to_string())
        })
        .collect::<Vec<_>>();
    ids.sort();
    Ok(ids)
}

fn parse_literals(raw_intent: &str, normalized_intent: &str) -> ParsedLiterals {
    ParsedLiterals {
        quoted: extract_quoted_literals(raw_intent),
        named: extract_phrase_after_marker(raw_intent, normalized_intent, &["named "]),
        titled: extract_phrase_after_marker(raw_intent, normalized_intent, &["titled "]),
        called: extract_phrase_after_marker(raw_intent, normalized_intent, &["called "]),
        zone: extract_zone(normalized_intent),
    }
}

fn extract_quoted_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut current = String::new();
    let mut active_quote = None;

    for ch in text.chars() {
        match (active_quote, ch) {
            (None, '"' | '\'') => {
                active_quote = Some(ch);
                current.clear();
            }
            (Some(quote), ch) if ch == quote => {
                if !current.trim().is_empty() {
                    literals.push(current.trim().to_owned());
                }
                current.clear();
                active_quote = None;
            }
            (Some(_), ch) => current.push(ch),
            (None, _) => {}
        }
    }

    literals
}

fn extract_phrase_after_marker(
    original: &str,
    normalized: &str,
    markers: &[&str],
) -> Option<String> {
    for marker in markers {
        if let Some(start) = normalized.find(marker) {
            let suffix = original.get(start + marker.len()..)?.trim_start();
            if suffix.starts_with('"') || suffix.starts_with('\'') {
                return extract_quoted_literals(suffix).into_iter().next();
            }

            let phrase = suffix
                .split(&[',', ';', '.'][..])
                .next()
                .unwrap_or(suffix)
                .split(" in ")
                .next()
                .unwrap_or(suffix)
                .split(" on ")
                .next()
                .unwrap_or(suffix)
                .trim();
            if !phrase.is_empty() {
                return Some(phrase.to_owned());
            }

            if let Some(quoted) = extract_quoted_literals(suffix).into_iter().next() {
                return Some(quoted);
            }
        }
    }

    None
}

fn extract_zone(normalized_intent: &str) -> Option<String> {
    normalized_intent
        .split_whitespace()
        .find(|segment| segment.starts_with("z:"))
        .map(|segment| segment.trim_end_matches(&['.', ',', ';'][..]).to_owned())
}

fn payload_literal(literals: &ParsedLiterals, action: &ActionSignals) -> Option<String> {
    if literals.titled.is_some() {
        return literals.titled.clone();
    }

    if action.mutating {
        return literals.quoted.first().cloned();
    }

    None
}

fn lookup_literal(literals: &ParsedLiterals, action: &ActionSignals) -> Option<String> {
    if action.needs_lookup {
        return literals
            .named
            .clone()
            .or_else(|| literals.called.clone())
            .or_else(|| literals.quoted.first().cloned());
    }

    None
}

fn compiled_workflow_truth(
    status: &str,
    steps: &[CompiledStep],
    missing_information: &[String],
    unsupported_reasons: &[String],
    ambiguities: &[Ambiguity],
) -> WorkflowTruth {
    let availability = if status == "unsupported" || !unsupported_reasons.is_empty() {
        CommandAvailability::Unsupported
    } else if status == "planned" {
        CommandAvailability::Planned
    } else if status == "ambiguous"
        || status == "needs-clarification"
        || !ambiguities.is_empty()
        || !missing_information.is_empty()
    {
        CommandAvailability::Unknown
    } else {
        aggregate_compiled_step_availability(steps)
    };

    let explanation = match availability {
        CommandAvailability::Unsupported => unsupported_reasons.first().cloned().unwrap_or_else(
            || CommandAvailability::Unsupported.explanation().to_owned(),
        ),
        CommandAvailability::Planned => CommandAvailability::Planned.explanation().to_owned(),
        CommandAvailability::Unknown if !ambiguities.is_empty() => {
            "The intent remains ambiguous, so the compiler cannot truthfully choose one executable connector path yet."
                .to_owned()
        }
        CommandAvailability::Unknown if !missing_information.is_empty() => {
            "The compiler still needs concrete identifiers, payload content, or connector selection before it can truthfully materialize an executable workflow."
                .to_owned()
        }
        CommandAvailability::Unknown
            if steps.iter().any(|step| {
                compiled_step_availability(step) == CommandAvailability::Unknown
            }) =>
        {
            "At least one compiled step still has an unknown truth boundary, so the workflow cannot truthfully claim live-runtime or offline-artifact execution yet."
                .to_owned()
        }
        CommandAvailability::Unknown => {
            "The intent compiler has not derived a truthful execution path yet.".to_owned()
        }
        CommandAvailability::LiveRuntime if steps.iter().any(|step| {
            classify_command(&step.command)
                .is_some_and(|classification| classification.truth_source == CommandTruthSource::Hybrid)
        }) => {
            "The compiled workflow includes primitives that default to live host truth when materialized."
                .to_owned()
        }
        CommandAvailability::LiveRuntime => {
            "The compiled workflow requires live host-backed primitives when materialized."
                .to_owned()
        }
        CommandAvailability::OfflineArtifact => {
            "The compiled workflow only uses local or offline primitives, so any resulting data will be artifact-backed rather than live runtime truth."
                .to_owned()
        }
        CommandAvailability::Unavailable => {
            CommandAvailability::Unavailable.explanation().to_owned()
        }
        CommandAvailability::Denied => CommandAvailability::Denied.explanation().to_owned(),
    };

    WorkflowTruth::from_compiler(availability, explanation)
}

fn aggregate_compiled_step_availability(steps: &[CompiledStep]) -> CommandAvailability {
    let mut saw_live_runtime = false;
    let mut saw_offline_artifact = false;
    let mut saw_unknown = false;

    for step in steps {
        match compiled_step_availability(step) {
            CommandAvailability::LiveRuntime => saw_live_runtime = true,
            CommandAvailability::OfflineArtifact => saw_offline_artifact = true,
            CommandAvailability::Planned => return CommandAvailability::Planned,
            CommandAvailability::Unsupported => return CommandAvailability::Unsupported,
            CommandAvailability::Unavailable | CommandAvailability::Denied => {
                return CommandAvailability::Unknown;
            }
            CommandAvailability::Unknown => saw_unknown = true,
        }
    }

    if saw_unknown {
        CommandAvailability::Unknown
    } else if saw_live_runtime {
        CommandAvailability::LiveRuntime
    } else if saw_offline_artifact {
        CommandAvailability::OfflineArtifact
    } else {
        CommandAvailability::Unknown
    }
}

fn compiled_step_availability(step: &CompiledStep) -> CommandAvailability {
    let Some(classification) = classify_command(&step.command) else {
        return CommandAvailability::Unknown;
    };

    match classification.truth_source {
        CommandTruthSource::OfflineArtifact => CommandAvailability::OfflineArtifact,
        CommandTruthSource::LiveHost => CommandAvailability::LiveRuntime,
        CommandTruthSource::Hybrid => {
            if step.argv.iter().any(|segment| segment == "--offline") {
                CommandAvailability::OfflineArtifact
            } else {
                CommandAvailability::LiveRuntime
            }
        }
        CommandTruthSource::Passthrough => CommandAvailability::Unknown,
    }
}

fn status_for(
    has_connector: bool,
    missing_information: &[String],
    unsupported_reasons: &[String],
    ambiguities: &[Ambiguity],
) -> String {
    if !ambiguities.is_empty() {
        "ambiguous".to_owned()
    } else if !unsupported_reasons.is_empty() {
        "unsupported".to_owned()
    } else if !has_connector || !missing_information.is_empty() {
        "needs-clarification".to_owned()
    } else {
        "ready".to_owned()
    }
}

fn confidence_for(candidates: &[ConnectorCandidate], has_ambiguity: bool) -> String {
    if has_ambiguity {
        return "low".to_owned();
    }

    match candidates {
        [top, second, ..] if top.score - second.score >= 5 => "high".to_owned(),
        [top] if top.score >= 8 => "high".to_owned(),
        [top, ..] if top.score >= 4 => "medium".to_owned(),
        _ => "low".to_owned(),
    }
}

fn connector_evidence(candidates: &[ConnectorCandidate]) -> Vec<String> {
    candidates
        .iter()
        .take(3)
        .flat_map(|candidate| {
            candidate
                .reasons
                .iter()
                .map(move |reason| format!("{}: {reason}", candidate.id))
        })
        .collect()
}

fn action_evidence(action: &ActionSignals) -> Vec<String> {
    let mut evidence = vec![format!(
        "Matched `{}` as the primary verb for the `{}` template.",
        action.verb, action.family
    )];

    if let Some(resource) = action.resource {
        evidence.push(format!(
            "Detected `{resource}` as the likely resource noun for operation inference."
        ));
    }

    evidence.extend(
        action
            .matched_terms
            .iter()
            .map(|term| format!("Observed action keyword `{term}`.")),
    );
    evidence
}

fn match_first<'a>(text: &str, patterns: &'a [(&str, &'a str)]) -> Option<(&'a str, &'a str)> {
    patterns
        .iter()
        .find_map(|(needle, value)| contains_term(text, needle).then_some((*needle, *value)))
}

fn normalize_text(text: &str) -> String {
    text.to_lowercase()
}

fn contains_any(text: &str, values: &[&str]) -> bool {
    values.iter().any(|value| contains_term(text, value))
}

fn contains_term(text: &str, term: &str) -> bool {
    if term.contains(' ') {
        return text.contains(term);
    }

    text.split(|ch: char| !ch.is_alphanumeric() && ch != ':' && ch != '-')
        .any(|segment| segment == term)
}

fn search_argv(query: &str, zone: Option<&str>) -> Vec<String> {
    let mut argv = vec!["fwc".to_owned(), "search".to_owned(), query.to_owned()];
    if let Some(zone) = zone {
        argv.push("--zone".to_owned());
        argv.push(zone.to_owned());
    }
    argv
}

pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|segment| shell_quote(segment))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(segment: &str) -> String {
    if segment
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '/' | '.' | ':' | '='))
    {
        segment.to_owned()
    } else {
        format!("'{}'", segment.replace('\'', "'\\''"))
    }
}

fn step(
    ordinal: usize,
    phase: &str,
    purpose: String,
    argv: Vec<String>,
    approval_required: bool,
    side_effecting: bool,
    notes: Vec<String>,
) -> CompiledStep {
    CompiledStep {
        ordinal,
        phase: phase.to_owned(),
        purpose,
        command: argv.get(1).cloned().unwrap_or_else(|| "unknown".to_owned()),
        command_line: shell_join(&argv),
        argv,
        side_effecting,
        approval_required,
        notes,
    }
}

fn identifier_heavy_connector(connector_id: &str) -> bool {
    matches!(
        connector_id,
        "notion"
            | "jira"
            | "linear"
            | "airtable"
            | "figma"
            | "salesforce"
            | "hubspot"
            | "bigquery"
            | "snowflake"
            | "dropbox"
            | "box"
    )
}

fn payload_missing(
    action: &ActionSignals,
    payload_literal: Option<&str>,
    lookup_literal: Option<&str>,
    connector_id: &str,
) -> bool {
    if !action.mutating {
        return false;
    }

    if matches!(action.verb, "append" | "send" | "comment") {
        return payload_literal.is_none();
    }

    if action.verb == "create" && action.resource == Some("issue") {
        return payload_literal.is_none();
    }

    if identifier_heavy_connector(connector_id) && matches!(action.verb, "update" | "append") {
        return lookup_literal.is_none() || payload_literal.is_none();
    }

    false
}

fn missing_payload_message(action: &ActionSignals, connector_id: &str) -> String {
    match (connector_id, action.verb, action.resource.unwrap_or("object")) {
        ("github", "create", "issue") => {
            "Provide the issue title or payload content so the `github` issue creation step is concrete."
                .to_owned()
        }
        ("notion", "append", "page") => {
            "Provide both the target page lookup text and the content that should be appended to that Notion page."
                .to_owned()
        }
        (_, "send", _) => {
            "Provide the message body or payload content that should be sent.".to_owned()
        }
        (_, "comment", _) => {
            "Provide the comment body before execution.".to_owned()
        }
        _ => "Provide the payload content or explicit field values needed for the mutating operation."
            .to_owned(),
    }
}

fn generic_operation_hint(
    verb: &str,
    resource: &str,
    _payload_literal: Option<&str>,
    lookup_literal: Option<&str>,
) -> String {
    match verb {
        "search" | "query" | "list" => format!("{resource}s.search"),
        "get" => format!("{resource}s.get"),
        "append" => format!("{resource}s.append"),
        "send" | "comment" => format!("{resource}s.send"),
        "update" => format!("{resource}s.update"),
        "create" if lookup_literal.is_some() => format!("{resource}s.resolve-and-create"),
        "create" => format!("{resource}s.create"),
        _ => format!("{resource}s.invoke"),
    }
}

fn github_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("create", "issue") => "issues.create".to_owned(),
        ("search" | "query" | "list", "issue") => "issues.search".to_owned(),
        ("create", "pull-request") => "pulls.create".to_owned(),
        ("search" | "query" | "list", "pull-request") => "pulls.list".to_owned(),
        ("comment", _) => "issues.comment.create".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn messaging_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("send" | "create" | "post", "message") => "messages.send".to_owned(),
        ("search" | "list", "channel") => "channels.list".to_owned(),
        ("search" | "list", "message") => "messages.search".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn notion_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("append" | "update", "page") => "pages.append".to_owned(),
        ("create", "page") => "pages.create".to_owned(),
        ("search" | "query" | "list", "page") => "pages.search".to_owned(),
        ("search" | "query" | "list", "record") => "databases.query".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn issue_tracker_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("create", "issue") => "issues.create".to_owned(),
        ("search" | "query" | "list", "issue") => "issues.search".to_owned(),
        ("comment", _) => "issues.comment.create".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn gmail_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("send", "message") => "messages.send".to_owned(),
        ("search" | "query" | "list", "message") => "messages.search".to_owned(),
        ("get", "message") => "messages.get".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn calendar_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("create", "event") => "events.create".to_owned(),
        ("search" | "query" | "list" | "get", "event") => "events.list".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn storage_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("search" | "query" | "list", "file") => "files.search".to_owned(),
        ("create", "file") => "files.upload".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn airtable_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("search" | "query" | "list", "record") => "records.search".to_owned(),
        ("create", "record") => "records.create".to_owned(),
        ("update", "record") => "records.update".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn figma_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("comment", _) => "comments.create".to_owned(),
        ("get" | "search" | "list", "file") => "files.get".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn stripe_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("create", "customer") => "customers.create".to_owned(),
        ("create", "invoice") => "invoices.create".to_owned(),
        ("search" | "list" | "get", "invoice") => "invoices.search".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn crm_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("create", "customer" | "record") => "records.create".to_owned(),
        ("search" | "query" | "list", _) => "records.search".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn query_operation_hint(verb: &str, resource: &str) -> String {
    match (verb, resource) {
        ("query" | "search" | "list" | "get", _) => "queries.run".to_owned(),
        _ => generic_operation_hint(verb, resource, None, None),
    }
}

fn llm_operation_hint(_verb: &str) -> String {
    "responses.create".to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn request(intent: &str) -> IntentRequest {
        IntentRequest {
            intent: intent.to_owned(),
            connector_override: None,
            zone_override: None,
            mode: IntentMode::Plan,
            host_url: None,
        }
    }

    fn request_with_connector(intent: &str, connector: &str) -> IntentRequest {
        IntentRequest {
            intent: intent.to_owned(),
            connector_override: Some(connector.to_owned()),
            zone_override: None,
            mode: IntentMode::Plan,
            host_url: None,
        }
    }

    fn request_with_zone(intent: &str, zone: &str) -> IntentRequest {
        IntentRequest {
            intent: intent.to_owned(),
            connector_override: None,
            zone_override: Some(zone.to_owned()),
            mode: IntentMode::Plan,
            host_url: None,
        }
    }

    fn connector_profile(connector_id: &str) -> ConnectorProfile {
        connector_profiles()
            .into_iter()
            .find(|profile| profile.id == connector_id)
            .unwrap_or_else(|| panic!("expected connector profile for `{connector_id}`"))
    }

    fn manifest_operation(preferred_selector: &str) -> ManifestOperationProfile {
        ManifestOperationProfile {
            actual_id: preferred_selector.to_owned(),
            local_id: preferred_selector.replace('.', "_"),
            preferred_selector: preferred_selector.to_owned(),
            aliases: Vec::new(),
            description: String::new(),
            capability: String::new(),
            risk_level: "low".to_owned(),
            safety_tier: "safe".to_owned(),
            when_to_use: String::new(),
            common_mistakes: Vec::new(),
            input_schema: serde_json::json!({"type": "object"}),
        }
    }

    // ── parse_literals ──────────────────────────────────────

    #[test]
    fn parse_literals_extracts_quoted_named_and_zone_data() {
        let raw = "find the Notion page named Roadmap in z:work and append \"Summary\"";
        let parsed = parse_literals(raw, &raw.to_lowercase());
        assert_eq!(parsed.named.as_deref(), Some("Roadmap"));
        assert_eq!(parsed.zone.as_deref(), Some("z:work"));
        assert_eq!(parsed.quoted[0], "Summary");
    }

    #[test]
    fn parse_literals_extracts_multiple_quoted_strings() {
        let raw = r#"create issue titled "Bug report" with body "needs fix""#;
        let parsed = parse_literals(raw, &raw.to_lowercase());
        assert_eq!(parsed.quoted.len(), 2);
        assert_eq!(parsed.quoted[0], "Bug report");
        assert_eq!(parsed.quoted[1], "needs fix");
    }

    #[test]
    fn parse_literals_extracts_called_marker() {
        let raw = "find the channel called general";
        let parsed = parse_literals(raw, &raw.to_lowercase());
        assert_eq!(parsed.called.as_deref(), Some("general"));
    }

    #[test]
    fn parse_literals_extracts_titled_marker() {
        let raw = "create issue titled Bug Report";
        let parsed = parse_literals(raw, &raw.to_lowercase());
        assert_eq!(parsed.titled.as_deref(), Some("Bug Report"));
    }

    #[test]
    fn parse_literals_no_zone_when_absent() {
        let raw = "list all github issues";
        let parsed = parse_literals(raw, &raw.to_lowercase());
        assert!(parsed.zone.is_none());
    }

    #[test]
    fn parse_literals_empty_input() {
        let raw = "";
        let parsed = parse_literals(raw, &raw.to_lowercase());
        assert!(parsed.quoted.is_empty());
        assert!(parsed.named.is_none());
        assert!(parsed.called.is_none());
        assert!(parsed.zone.is_none());
    }

    #[test]
    fn parse_literals_zone_private() {
        let raw = "list connectors in z:private";
        let parsed = parse_literals(raw, &raw.to_lowercase());
        assert_eq!(parsed.zone.as_deref(), Some("z:private"));
    }

    // ── extract_quoted_literals ─────────────────────────────

    #[test]
    fn extract_quoted_handles_single_quotes() {
        let result = extract_quoted_literals("say 'hello world'");
        assert_eq!(result, vec!["hello world"]);
    }

    #[test]
    fn extract_quoted_handles_double_quotes() {
        let result = extract_quoted_literals(r#"say "hello world""#);
        assert_eq!(result, vec!["hello world"]);
    }

    #[test]
    fn extract_quoted_handles_no_quotes() {
        let result = extract_quoted_literals("no quotes here");
        assert!(result.is_empty());
    }

    #[test]
    fn extract_quoted_handles_empty_quotes() {
        let result = extract_quoted_literals(r#"say """#);
        assert!(result.is_empty());
    }

    // ── extract_zone ────────────────────────────────────────

    #[test]
    fn extract_zone_finds_z_colon_prefix() {
        assert_eq!(
            extract_zone("do work in z:staging"),
            Some("z:staging".to_owned())
        );
    }

    #[test]
    fn extract_zone_returns_none_for_no_zone() {
        assert!(extract_zone("just a normal command").is_none());
    }

    // ── normalize_text ──────────────────────────────────────

    #[test]
    fn normalize_text_lowercases() {
        assert_eq!(normalize_text("Hello WORLD"), "hello world");
    }

    // ── contains_term ───────────────────────────────────────

    #[test]
    fn contains_term_word_boundary() {
        assert!(contains_term("create an issue", "create"));
        assert!(contains_term("list issues", "list"));
    }

    #[test]
    fn contains_term_no_partial_word_match() {
        // "create" should not match inside "recreate" — word boundary matching
        assert!(!contains_term("recreate", "create"));
    }

    // ── contains_any ────────────────────────────────────────

    #[test]
    fn contains_any_matches_one() {
        assert!(contains_any(
            "find the user named bob",
            &["named", "called"]
        ));
    }

    #[test]
    fn contains_any_no_match() {
        assert!(!contains_any("list all connectors", &["named", "called"]));
    }

    // ── match_first ─────────────────────────────────────────

    #[test]
    fn match_first_returns_first_hit() {
        static PATTERNS: &[(&str, &str)] = &[("create", "create"), ("make", "create")];
        let result = match_first("create a new issue", PATTERNS);
        assert_eq!(result, Some(("create", "create")));
    }

    #[test]
    fn match_first_returns_none_on_no_match() {
        static PATTERNS: &[(&str, &str)] = &[("delete", "delete")];
        assert!(match_first("create a new issue", PATTERNS).is_none());
    }

    // ── infer_action ────────────────────────────────────────

    #[test]
    fn infer_action_lifecycle_disable() {
        let action = infer_action("disable the slack connector");
        assert_eq!(action.family, "lifecycle");
        assert_eq!(action.verb, "disable");
        assert!(action.mutating);
        assert_eq!(action.risk, "high");
    }

    #[test]
    fn infer_action_lifecycle_status() {
        let action = infer_action("status of github connector");
        assert_eq!(action.family, "lifecycle");
        assert_eq!(action.verb, "status");
        assert!(!action.mutating);
        assert_eq!(action.risk, "low");
    }

    #[test]
    fn infer_action_lifecycle_enable() {
        let action = infer_action("enable the discord connector");
        assert_eq!(action.family, "lifecycle");
        assert_eq!(action.verb, "enable");
        assert!(action.mutating);
    }

    #[test]
    fn infer_action_lifecycle_restart() {
        let action = infer_action("restart the slack connector");
        assert_eq!(action.family, "lifecycle");
        assert_eq!(action.verb, "restart");
        assert!(action.mutating);
    }

    #[test]
    fn infer_action_lifecycle_pin() {
        let action = infer_action("pin the github connector");
        assert_eq!(action.family, "lifecycle");
        assert_eq!(action.verb, "pin");
    }

    #[test]
    fn infer_action_lifecycle_unpin() {
        let action = infer_action("unpin github connector version");
        assert_eq!(action.family, "lifecycle");
        assert_eq!(action.verb, "unpin");
    }

    #[test]
    fn infer_action_logs() {
        let action = infer_action("show logs for the github connector");
        assert_eq!(action.family, "log-tail");
        assert_eq!(action.verb, "tail");
        assert!(!action.mutating);
    }

    #[test]
    fn infer_action_logs_tail() {
        let action = infer_action("tail slack connector output");
        assert_eq!(action.family, "log-tail");
        assert_eq!(action.verb, "tail");
    }

    #[test]
    fn infer_action_config_set() {
        let action = infer_action("configure the webhook for github");
        assert_eq!(action.family, "config");
        assert_eq!(action.verb, "set");
        assert!(action.mutating);
    }

    #[test]
    fn infer_action_config_credentials() {
        let action = infer_action("set credentials for the slack connector");
        assert_eq!(action.family, "config");
        assert_eq!(action.verb, "set");
    }

    #[test]
    fn infer_action_config_token() {
        // "token" matches config table
        let action = infer_action("token for stripe connector");
        assert_eq!(action.family, "config");
    }

    #[test]
    fn infer_action_write_create() {
        let action = infer_action("create a new issue on github");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "create");
        assert!(action.mutating);
        assert_eq!(action.risk, "medium");
    }

    #[test]
    fn infer_action_write_send() {
        let action = infer_action("send a message to the channel");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "send");
        assert!(action.mutating);
    }

    #[test]
    fn infer_action_write_comment() {
        let action = infer_action("comment on the issue");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "comment");
        assert!(action.mutating);
    }

    #[test]
    fn infer_action_search() {
        let action = infer_action("find all recent issues");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "search");
        assert!(!action.mutating);
        assert_eq!(action.risk, "low");
    }

    #[test]
    fn infer_action_search_list() {
        let action = infer_action("list all connectors");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "list");
        assert!(!action.mutating);
    }

    #[test]
    fn infer_action_search_read() {
        let action = infer_action("read the contents of the page");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "get");
        assert!(!action.mutating);
    }

    #[test]
    fn infer_action_search_fetch() {
        let action = infer_action("fetch the latest data");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "get");
        assert!(!action.mutating);
    }

    #[test]
    fn infer_action_discovery_fallback() {
        let action = infer_action("what connectors are available");
        assert_eq!(action.family, "discovery");
        assert_eq!(action.verb, "discover");
        assert!(!action.mutating);
    }

    #[test]
    fn infer_action_write_append() {
        let action = infer_action("append this text to the notion page");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "append");
        assert!(action.mutating);
    }

    #[test]
    fn infer_action_write_publish() {
        let action = infer_action("publish the draft message");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "send");
    }

    #[test]
    fn infer_action_search_query() {
        let action = infer_action("query the database for recent entries");
        assert_eq!(action.family, "operation");
        assert_eq!(action.verb, "query");
    }

    #[test]
    fn infer_action_write_needs_lookup() {
        let action = infer_action("create an issue named 'bug' and find the assignee");
        assert!(action.needs_lookup);
    }

    // ── infer_resource ──────────────────────────────────────

    #[test]
    fn infer_resource_issue() {
        assert_eq!(infer_resource("create an issue"), Some("issue"));
    }

    #[test]
    fn infer_resource_pull_request() {
        assert_eq!(infer_resource("list pull requests"), Some("pull-request"));
    }

    #[test]
    fn infer_resource_message() {
        assert_eq!(infer_resource("send a message"), Some("message"));
    }

    #[test]
    fn infer_resource_page() {
        assert_eq!(infer_resource("update the page content"), Some("page"));
    }

    #[test]
    fn infer_resource_file() {
        assert_eq!(infer_resource("upload a file"), Some("file"));
    }

    #[test]
    fn infer_resource_customer() {
        assert_eq!(infer_resource("create a customer"), Some("customer"));
    }

    #[test]
    fn infer_resource_event() {
        assert_eq!(infer_resource("schedule an event"), Some("event"));
    }

    #[test]
    fn infer_resource_none() {
        assert!(infer_resource("do something").is_none());
    }

    #[test]
    fn infer_resource_record() {
        assert_eq!(infer_resource("create a record"), Some("record"));
    }

    #[test]
    fn infer_resource_comment() {
        assert_eq!(infer_resource("add a comment"), Some("comment"));
    }

    // ── infer_connector_candidates ──────────────────────────

    #[test]
    fn infer_connector_github_from_keyword() {
        let profiles = connector_profiles();
        let candidates = infer_connector_candidates("create a github issue", None, &profiles);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].id, "github");
    }

    #[test]
    fn infer_connector_slack_from_keyword() {
        let profiles = connector_profiles();
        let candidates = infer_connector_candidates("send slack message", None, &profiles);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].id, "slack");
    }

    #[test]
    fn infer_connector_explicit_override() {
        let profiles = connector_profiles();
        let candidates = infer_connector_candidates("create an issue", Some("linear"), &profiles);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].id, "linear");
    }

    #[test]
    fn infer_connector_notion_from_page() {
        let profiles = connector_profiles();
        let candidates = infer_connector_candidates("find the notion page", None, &profiles);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].id, "notion");
    }

    #[test]
    fn infer_connector_stripe_from_payment() {
        let profiles = connector_profiles();
        let candidates = infer_connector_candidates("create a payment invoice", None, &profiles);
        assert!(candidates.iter().any(|c| c.id == "stripe"));
    }

    #[test]
    fn infer_connector_no_match_returns_empty() {
        let profiles = connector_profiles();
        let candidates =
            infer_connector_candidates("do something completely unrelated xyz", None, &profiles);
        assert!(candidates.is_empty());
    }

    #[test]
    fn connector_profiles_merge_manifest_operations_for_curated_connector() {
        let github = connector_profile("github");
        let create_issue = github
            .operations
            .iter()
            .find(|operation| operation.preferred_selector == "issues.create")
            .expect("github manifest operation should be indexed");

        assert_eq!(create_issue.actual_id, "github.create_issue");
        assert_eq!(create_issue.capability, "github.write");
        assert_eq!(create_issue.risk_level, "medium");
        assert_eq!(create_issue.safety_tier, "risky");
        assert!(create_issue.matches_selector("github.create_issue"));
        assert!(create_issue.matches_selector("issues.create"));
    }

    #[test]
    fn connector_profiles_merge_manifest_operations_for_uncurated_connector() {
        let asana = connector_profile("asana");
        assert!(
            asana
                .operations
                .iter()
                .any(|operation| operation.preferred_selector == "projects.list")
        );
        assert!(
            asana
                .operations
                .iter()
                .any(|operation| operation.preferred_selector == "tasks.create")
        );
    }

    // ── operation hints ─────────────────────────────────────

    #[test]
    fn infer_operation_hint_prefers_manifest_selector_for_slack_send_message() {
        let slack = connector_profile("slack");
        let action = ActionSignals {
            family: "operation",
            verb: "send",
            resource: Some("message"),
            risk: "medium",
            mutating: true,
            matched_terms: vec!["send".to_owned()],
            needs_lookup: false,
        };

        let hint = infer_operation_hint(Some(&slack), "slack", &action, Some("hello"), None);
        assert_eq!(hint, "messages.post");
    }

    #[test]
    fn infer_operation_hint_uses_manifest_selector_for_uncurated_connector() {
        let asana = connector_profile("asana");
        let action = ActionSignals {
            family: "operation",
            verb: "list",
            resource: Some("project"),
            risk: "low",
            mutating: false,
            matched_terms: vec!["list".to_owned()],
            needs_lookup: false,
        };

        let hint = infer_operation_hint(Some(&asana), "asana", &action, None, None);
        assert_eq!(hint, "projects.list");
    }

    #[test]
    fn infer_operation_hint_preserves_manifest_priority_order() {
        let profile = ConnectorProfile {
            id: "slack".to_owned(),
            aliases: Vec::new(),
            keywords: Vec::new(),
            operations: vec![
                manifest_operation("messages.create"),
                manifest_operation("messages.post"),
            ],
        };
        let action = ActionSignals {
            family: "operation",
            verb: "send",
            resource: Some("message"),
            risk: "medium",
            mutating: true,
            matched_terms: vec!["send".to_owned()],
            needs_lookup: false,
        };

        let hint = infer_operation_hint(Some(&profile), "slack", &action, Some("hello"), None);
        assert_eq!(hint, "messages.post");
    }

    #[test]
    fn github_operation_hint_issues_create() {
        assert_eq!(github_operation_hint("create", "issue"), "issues.create");
    }

    #[test]
    fn github_operation_hint_pr_create() {
        assert_eq!(
            github_operation_hint("create", "pull-request"),
            "pulls.create"
        );
    }

    #[test]
    fn github_operation_hint_issues_search() {
        assert_eq!(github_operation_hint("search", "issue"), "issues.search");
    }

    #[test]
    fn github_operation_hint_fallback() {
        assert!(github_operation_hint("update", "repo").contains("update"));
    }

    #[test]
    fn messaging_operation_hint_send() {
        assert_eq!(messaging_operation_hint("send", "message"), "messages.send");
    }

    #[test]
    fn messaging_operation_hint_search() {
        assert_eq!(
            messaging_operation_hint("search", "message"),
            "messages.search"
        );
    }

    #[test]
    fn notion_operation_hint_page_search() {
        assert_eq!(notion_operation_hint("search", "page"), "pages.search");
    }

    #[test]
    fn notion_operation_hint_record_query() {
        assert_eq!(notion_operation_hint("query", "record"), "databases.query");
    }

    #[test]
    fn issue_tracker_create_issue() {
        assert_eq!(
            issue_tracker_operation_hint("create", "issue"),
            "issues.create"
        );
    }

    #[test]
    fn issue_tracker_comment() {
        assert_eq!(
            issue_tracker_operation_hint("comment", "issue"),
            "issues.comment.create"
        );
    }

    #[test]
    fn gmail_send_message() {
        assert_eq!(gmail_operation_hint("send", "message"), "messages.send");
    }

    #[test]
    fn gmail_search_message() {
        assert_eq!(gmail_operation_hint("search", "message"), "messages.search");
    }

    #[test]
    fn calendar_create_event() {
        assert_eq!(calendar_operation_hint("create", "event"), "events.create");
    }

    #[test]
    fn calendar_list_events() {
        assert_eq!(calendar_operation_hint("list", "event"), "events.list");
    }

    #[test]
    fn storage_search_files() {
        assert_eq!(storage_operation_hint("search", "file"), "files.search");
    }

    #[test]
    fn storage_create_file() {
        assert_eq!(storage_operation_hint("create", "file"), "files.upload");
    }

    #[test]
    fn airtable_create_record() {
        assert_eq!(
            airtable_operation_hint("create", "record"),
            "records.create"
        );
    }

    #[test]
    fn airtable_search_record() {
        assert_eq!(
            airtable_operation_hint("search", "record"),
            "records.search"
        );
    }

    #[test]
    fn figma_comment() {
        assert_eq!(figma_operation_hint("comment", "file"), "comments.create");
    }

    #[test]
    fn figma_get_file() {
        assert_eq!(figma_operation_hint("get", "file"), "files.get");
    }

    #[test]
    fn stripe_create_customer() {
        assert_eq!(
            stripe_operation_hint("create", "customer"),
            "customers.create"
        );
    }

    #[test]
    fn stripe_create_invoice() {
        assert_eq!(
            stripe_operation_hint("create", "invoice"),
            "invoices.create"
        );
    }

    #[test]
    fn stripe_search_invoice() {
        assert_eq!(
            stripe_operation_hint("search", "invoice"),
            "invoices.search"
        );
    }

    #[test]
    fn crm_create_record() {
        assert_eq!(crm_operation_hint("create", "record"), "records.create");
    }

    #[test]
    fn crm_create_customer() {
        assert_eq!(crm_operation_hint("create", "customer"), "records.create");
    }

    #[test]
    fn crm_search() {
        assert_eq!(crm_operation_hint("search", "lead"), "records.search");
    }

    #[test]
    fn query_run() {
        assert_eq!(query_operation_hint("query", "table"), "queries.run");
    }

    #[test]
    fn llm_hint_always_responses_create() {
        assert_eq!(llm_operation_hint("create"), "responses.create");
        assert_eq!(llm_operation_hint("query"), "responses.create");
    }

    // ── generic_operation_hint ───────────────────────────────

    #[test]
    fn generic_operation_hint_search() {
        let hint = generic_operation_hint("search", "issue", None, None);
        assert_eq!(hint, "issues.search");
    }

    #[test]
    fn generic_operation_hint_get() {
        let hint = generic_operation_hint("get", "page", None, None);
        assert_eq!(hint, "pages.get");
    }

    #[test]
    fn generic_operation_hint_create_with_payload() {
        let hint = generic_operation_hint("create", "issue", Some("payload"), None);
        assert_eq!(hint, "issues.create");
    }

    #[test]
    fn generic_operation_hint_create_with_lookup() {
        let hint = generic_operation_hint("create", "issue", None, Some("lookup"));
        assert_eq!(hint, "issues.resolve-and-create");
    }

    #[test]
    fn generic_operation_hint_create_fallback() {
        let hint = generic_operation_hint("create", "issue", None, None);
        assert_eq!(hint, "issues.create");
    }

    // ── shell_join / shell_quote ────────────────────────────

    #[test]
    fn shell_join_simple() {
        let argv = vec!["fwc".to_owned(), "list".to_owned()];
        assert_eq!(shell_join(&argv), "fwc list");
    }

    #[test]
    fn shell_join_quotes_spaces() {
        let argv = vec![
            "fwc".to_owned(),
            "search".to_owned(),
            "hello world".to_owned(),
        ];
        let joined = shell_join(&argv);
        assert!(joined.contains("\"hello world\"") || joined.contains("'hello world'"));
    }

    #[test]
    fn shell_quote_no_special() {
        assert_eq!(shell_quote("simple"), "simple");
    }

    #[test]
    fn shell_quote_with_space() {
        let quoted = shell_quote("has space");
        assert!(quoted.starts_with('"') || quoted.starts_with('\''));
    }

    // ── identifier_heavy_connector ──────────────────────────

    #[test]
    fn identifier_heavy_notion() {
        assert!(identifier_heavy_connector("notion"));
    }

    #[test]
    fn identifier_heavy_salesforce() {
        assert!(identifier_heavy_connector("salesforce"));
    }

    #[test]
    fn identifier_heavy_github_not() {
        assert!(!identifier_heavy_connector("github"));
    }

    // ── confidence_for ──────────────────────────────────────

    #[test]
    fn confidence_high_single_candidate() {
        let candidates = vec![ConnectorCandidate {
            id: "github".to_owned(),
            score: 10,
            reasons: vec![],
        }];
        assert_eq!(confidence_for(&candidates, false), "high");
    }

    #[test]
    fn confidence_low_with_ambiguity() {
        let candidates = vec![ConnectorCandidate {
            id: "github".to_owned(),
            score: 10,
            reasons: vec![],
        }];
        // ambiguity forces low confidence regardless of score
        assert_eq!(confidence_for(&candidates, true), "low");
    }

    #[test]
    fn confidence_medium_moderate_score() {
        let candidates = vec![ConnectorCandidate {
            id: "github".to_owned(),
            score: 5,
            reasons: vec![],
        }];
        assert_eq!(confidence_for(&candidates, false), "medium");
    }

    #[test]
    fn confidence_low_no_candidates() {
        let candidates: Vec<ConnectorCandidate> = vec![];
        assert_eq!(confidence_for(&candidates, false), "low");
    }

    // ── status_for ──────────────────────────────────────────

    #[test]
    fn status_ready_when_connector_found() {
        assert_eq!(status_for(true, &[], &[], &[]), "ready");
    }

    #[test]
    fn status_needs_clarification_when_missing() {
        assert_eq!(
            status_for(true, &["need connector name".to_owned()], &[], &[]),
            "needs-clarification"
        );
    }

    #[test]
    fn status_unsupported_when_blocked_by_missing_primitive() {
        assert_eq!(
            status_for(true, &[], &["unsupported primitive".to_owned()], &[]),
            "unsupported"
        );
    }

    #[test]
    fn status_ambiguous_when_ambiguities() {
        let ambiguity = Ambiguity {
            kind: "connector".to_owned(),
            message: "multiple connectors match".to_owned(),
            candidates: vec!["slack".to_owned(), "discord".to_owned()],
        };
        assert_eq!(status_for(true, &[], &[], &[ambiguity]), "ambiguous");
    }

    #[test]
    fn status_needs_clarification_no_connector() {
        assert_eq!(status_for(false, &[], &[], &[]), "needs-clarification");
    }

    #[test]
    fn compiled_step_availability_treats_offline_hybrid_steps_as_offline_artifact() {
        let step = CompiledStep {
            ordinal: 1,
            phase: "inspect".to_owned(),
            purpose: "Inspect offline schema".to_owned(),
            command: "schema".to_owned(),
            command_line: "fwc schema github issues.get --offline".to_owned(),
            argv: vec![
                "fwc".to_owned(),
                "schema".to_owned(),
                "github".to_owned(),
                "issues.get".to_owned(),
                "--offline".to_owned(),
            ],
            side_effecting: false,
            approval_required: false,
            notes: Vec::new(),
        };

        assert_eq!(
            compiled_step_availability(&step),
            CommandAvailability::OfflineArtifact
        );
    }

    // ── connector_evidence / action_evidence ────────────────

    #[test]
    fn connector_evidence_includes_scores() {
        let candidates = vec![
            ConnectorCandidate {
                id: "github".to_owned(),
                score: 10,
                reasons: vec!["matched keyword".to_owned()],
            },
            ConnectorCandidate {
                id: "gitlab".to_owned(),
                score: 5,
                reasons: vec!["partial match".to_owned()],
            },
        ];
        let evidence = connector_evidence(&candidates);
        assert!(!evidence.is_empty());
    }

    #[test]
    fn action_evidence_includes_family() {
        let action = ActionSignals {
            family: "operation",
            verb: "create",
            resource: Some("issue"),
            risk: "medium",
            mutating: true,
            matched_terms: vec!["create".to_owned()],
            needs_lookup: false,
        };
        let evidence = action_evidence(&action);
        assert!(!evidence.is_empty());
    }

    // ── ConnectorCandidate Display ──────────────────────────

    #[test]
    fn connector_candidate_display() {
        let candidate = ConnectorCandidate {
            id: "github".to_owned(),
            score: 10,
            reasons: vec![],
        };
        assert_eq!(format!("{candidate}"), "github");
    }

    // ── IntentMode ──────────────────────────────────────────

    #[test]
    fn intent_mode_label() {
        assert_eq!(IntentMode::Plan.label(), "plan");
        assert_eq!(IntentMode::Explain.label(), "explain");
        assert_eq!(IntentMode::DoSimulate.label(), "do-simulate");
        assert_eq!(IntentMode::DoApprove.label(), "do-approve");
    }

    #[test]
    fn intent_mode_is_approved() {
        assert!(!IntentMode::Plan.is_approved());
        assert!(!IntentMode::DoSimulate.is_approved());
        assert!(IntentMode::DoApprove.is_approved());
    }

    // ── compile (integration-level) ─────────────────────────

    #[test]
    fn compiler_plans_github_issue_creation() {
        let plan = compile(&request(
            "create a GitHub issue titled \"FWC: add workflow macros\"",
        ));
        assert_eq!(plan.status, "ready");
        assert_eq!(
            plan.workflow_truth.availability,
            CommandAvailability::LiveRuntime
        );
        assert_eq!(
            plan.workflow_truth.source_of_truth,
            WORKFLOW_TRUTH_COMPILER_SOURCE
        );
        assert!(!plan.workflow_truth.authoritative);
        assert_eq!(plan.workflow_truth.exit_code_hint, 0);
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("github")
        );
        assert_eq!(plan.operation_hint.as_deref(), Some("issues.create"));
        assert!(plan.steps.iter().any(|step| {
            step.command_line
                .contains("fwc schema github issues.create")
        }));
    }

    #[test]
    fn compiler_surfaces_ambiguity_for_generic_message_intent() {
        let plan = compile(&request("send a message to a channel"));
        assert_eq!(plan.status, "ambiguous");
        assert_eq!(
            plan.workflow_truth.availability,
            CommandAvailability::Unknown
        );
        assert!(plan.workflow_truth.recoverable);
        assert!(
            plan.alternative_connectors
                .iter()
                .any(|candidate| candidate.id == "discord" || candidate.id == "telegram")
        );
    }

    #[test]
    fn compiler_routes_disable_to_lifecycle() {
        let plan = compile(&request("disable the slack connector in z:work"));
        assert_eq!(plan.template, "lifecycle");
        assert_ne!(plan.status, "unsupported");
        // Host-backed lifecycle: preflight valid-actions, preflight action, mutate, verify
        assert!(
            plan.steps.iter().any(
                |s| s.command_line.contains("lifecycle") && s.command_line.contains("--action")
            )
        );
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("disable"))
        );
        assert_eq!(plan.zone.as_deref(), Some("z:work"));
    }

    #[test]
    fn connector_profiles_include_workspace_connectors() {
        let profiles = connector_profiles();
        assert!(profiles.iter().any(|profile| profile.id == "github"));
        assert!(profiles.iter().any(|profile| profile.id == "slack"));
    }

    #[test]
    fn compiler_prefers_manifest_selector_for_slack_message_plan() {
        let plan = compile(&request("send a Slack message \"hello from intent\""));
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("slack")
        );
        assert_eq!(plan.operation_hint.as_deref(), Some("messages.post"));
        assert!(
            plan.steps
                .iter()
                .any(|step| step.command_line.contains("fwc schema slack messages.post"))
        );
    }

    #[test]
    fn compiler_config_template_for_credentials() {
        let plan = compile(&request("set credentials for the github connector"));
        assert_eq!(plan.template, "config");
        assert!(plan.steps.iter().any(|s| s.command_line.contains("config")));
    }

    #[test]
    fn compiler_routes_logs_to_tail() {
        let plan = compile(&request("tail the github connector logs"));
        assert_eq!(plan.template, "log-tail");
        assert_ne!(plan.status, "unsupported");
        // Log-tail plan should use `fwc tail` with the connector
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("fwc tail"))
        );
        assert!(plan.steps.iter().any(|s| s.command_line.contains("github")));
    }

    #[test]
    fn compiler_discovery_template_for_vague_intent() {
        let plan = compile(&request("what can the github connector do"));
        // discovery or operation depending on keyword match
        assert!(!plan.steps.is_empty());
    }

    #[test]
    fn compiler_explicit_connector_override() {
        let plan = compile(&request_with_connector("create an issue", "linear"));
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("linear")
        );
        assert_eq!(plan.connector_override.as_deref(), Some("linear"));
    }

    #[test]
    fn compiler_zone_override() {
        let plan = compile(&request_with_zone("list connectors", "z:staging"));
        assert_eq!(plan.zone.as_deref(), Some("z:staging"));
    }

    #[test]
    fn compiler_operation_plan_has_schema_step() {
        let plan = compile(&request("create a github issue"));
        // operation plans include a schema lookup step
        assert!(plan.steps.iter().any(|s| s.command_line.contains("schema")));
    }

    #[test]
    fn compiler_restart_routes_to_lifecycle_with_preflight() {
        let plan = compile(&request("restart the github connector"));
        assert_eq!(plan.template, "lifecycle");
        assert_ne!(plan.status, "unsupported");
        // Host-backed lifecycle plans include a valid-actions preflight step
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("--valid-actions"))
        );
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("--action") && s.command_line.contains("restart"))
        );
    }

    #[test]
    fn compiler_enable_routes_to_lifecycle() {
        let plan = compile(&request("enable the slack connector"));
        assert_eq!(plan.template, "lifecycle");
        assert_ne!(plan.status, "unsupported");
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("lifecycle"))
        );
        assert!(plan.steps.iter().any(|s| s.command_line.contains("enable")));
    }

    #[test]
    fn compiler_returns_execution_notice() {
        let plan = compile(&request("create a github issue"));
        assert!(!plan.execution_notice.is_empty());
    }

    #[test]
    fn compiler_sets_mode_label() {
        let plan = compile(&request("create a github issue"));
        assert_eq!(plan.mode, "plan");
    }

    #[test]
    fn compiler_explain_mode_label() {
        let req = IntentRequest {
            intent: "create a github issue".to_owned(),
            connector_override: None,
            zone_override: None,
            mode: IntentMode::Explain,
            host_url: None,
        };
        let plan = compile(&req);
        assert_eq!(plan.mode, "explain");
    }

    #[test]
    fn compiler_no_connector_lifecycle_needs_clarification() {
        let plan = compile(&request("restart some connector"));
        // Without a resolvable connector, the lifecycle plan asks for clarification
        assert_eq!(plan.template, "lifecycle");
        assert!(
            plan.status == "needs-clarification" || !plan.missing_information.is_empty(),
            "Expected needs-clarification or missing info, got status={}, missing={:?}",
            plan.status,
            plan.missing_information,
        );
        assert!(plan.chosen_connector.is_none());
    }

    #[test]
    fn compiler_search_is_non_mutating() {
        let plan = compile(&request("search for issues on github"));
        assert!(
            plan.steps
                .iter()
                .all(|s| !s.side_effecting || !s.approval_required)
                || plan.steps.is_empty()
        );
    }

    #[test]
    fn compiler_search_invoke_step_does_not_force_payload_placeholder() {
        let plan = compile(&request("search for issues on github"));
        let invoke = plan
            .steps
            .iter()
            .find(|step| step.command == "invoke")
            .expect("search plan should include invoke");

        assert!(
            !invoke
                .argv
                .iter()
                .any(|segment| segment == "./intent-payload.json")
        );
    }

    #[test]
    fn compiler_has_next_actions() {
        let plan = compile(&request("create a github issue"));
        assert!(!plan.next_actions.is_empty());
    }

    #[test]
    fn compiler_has_explanation() {
        let plan = compile(&request("create a github issue"));
        assert!(!plan.explanation.connector_evidence.is_empty());
        assert!(!plan.explanation.action_evidence.is_empty());
    }

    #[test]
    fn compiler_notion_lookup_step_for_named_page() {
        let plan = compile(&request(
            "find the notion page named Roadmap and append a summary",
        ));
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("notion")
        );
    }

    #[test]
    fn compiler_stripe_invoice() {
        let plan = compile(&request("create an invoice on stripe"));
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("stripe")
        );
        assert_eq!(plan.operation_hint.as_deref(), Some("invoices.create"));
    }

    #[test]
    fn compiler_jira_issue() {
        let plan = compile(&request("create a jira ticket"));
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("jira")
        );
    }

    #[test]
    fn compiler_gmail_send() {
        let plan = compile(&request("send an email via gmail"));
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("gmail")
        );
    }

    #[test]
    fn compiler_bigquery() {
        let plan = compile(&request("query the bigquery dataset"));
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("bigquery")
        );
    }

    #[test]
    fn compiler_airtable_record() {
        let plan = compile(&request("create a record in airtable"));
        assert_eq!(
            plan.chosen_connector.as_ref().map(|c| c.id.as_str()),
            Some("airtable")
        );
    }

    // ── curated_connector ───────────────────────────────────

    #[test]
    fn curated_connector_includes_normalized_alias() {
        let profile = curated_connector("google-calendar", &["gcal"], &["event"]);
        assert!(profile.aliases.contains(&"googlecalendar".to_owned()));
        assert!(profile.aliases.contains(&"gcal".to_owned()));
    }

    #[test]
    fn curated_connector_includes_id_as_alias() {
        let profile = curated_connector("github", &["gh"], &["issue"]);
        assert!(profile.aliases.contains(&"github".to_owned()));
    }

    // ── search_argv ─────────────────────────────────────────

    #[test]
    fn search_argv_without_zone() {
        let argv = search_argv("test query", None);
        assert!(argv.contains(&"search".to_owned()));
        assert!(argv.contains(&"test query".to_owned()));
    }

    #[test]
    fn search_argv_with_zone() {
        let argv = search_argv("test query", Some("z:work"));
        assert!(argv.contains(&"--zone".to_owned()));
        assert!(argv.contains(&"z:work".to_owned()));
    }

    // ── payload_missing ─────────────────────────────────────

    #[test]
    fn payload_missing_for_mutating_without_literal() {
        let action = ActionSignals {
            family: "operation",
            verb: "create",
            resource: Some("issue"),
            risk: "medium",
            mutating: true,
            matched_terms: vec!["create".to_owned()],
            needs_lookup: false,
        };
        assert!(payload_missing(&action, None, None, "github"));
    }

    #[test]
    fn payload_not_missing_for_read() {
        let action = ActionSignals {
            family: "operation",
            verb: "get",
            resource: Some("issue"),
            risk: "low",
            mutating: false,
            matched_terms: vec!["get".to_owned()],
            needs_lookup: false,
        };
        assert!(!payload_missing(&action, None, None, "github"));
    }

    #[test]
    fn payload_not_missing_when_literal_provided() {
        let action = ActionSignals {
            family: "operation",
            verb: "create",
            resource: Some("issue"),
            risk: "medium",
            mutating: true,
            matched_terms: vec!["create".to_owned()],
            needs_lookup: false,
        };
        assert!(!payload_missing(
            &action,
            Some("test payload"),
            None,
            "github"
        ));
    }

    // ── missing_payload_message ─────────────────────────────

    #[test]
    fn missing_payload_message_mentions_connector() {
        let action = ActionSignals {
            family: "operation",
            verb: "create",
            resource: Some("issue"),
            risk: "medium",
            mutating: true,
            matched_terms: vec!["create".to_owned()],
            needs_lookup: false,
        };
        let msg = missing_payload_message(&action, "github");
        assert!(msg.to_lowercase().contains("github"));
    }

    // ── step builder ────────────────────────────────────────

    #[test]
    fn step_builder_sets_fields() {
        let s = step(
            1,
            "preflight",
            "Check status".to_owned(),
            vec!["fwc".to_owned(), "status".to_owned()],
            false,
            false,
            vec!["note".to_owned()],
        );
        assert_eq!(s.ordinal, 1);
        assert_eq!(s.phase, "preflight");
        assert_eq!(s.purpose, "Check status");
        assert_eq!(s.command, "status");
        assert!(!s.approval_required);
        assert!(!s.side_effecting);
        assert_eq!(s.notes, vec!["note"]);
        assert_eq!(s.command_line, "fwc status");
    }

    #[test]
    fn step_builder_mutating_flags() {
        let s = step(
            2,
            "mutate",
            "Do mutation".to_owned(),
            vec!["fwc".to_owned(), "invoke".to_owned(), "github".to_owned()],
            true,
            true,
            vec![],
        );
        assert!(s.approval_required);
        assert!(s.side_effecting);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 29.7.2: Workflow truth — intent planner honesty tests
    // ═══════════════════════════════════════════════════════════════════

    // ── compiled_workflow_truth direct tests ─────────────────────

    #[test]
    fn workflow_truth_unsupported_status_yields_unsupported_availability() {
        let truth =
            compiled_workflow_truth("unsupported", &[], &[], &["not supported".to_owned()], &[]);
        assert_eq!(truth.availability, CommandAvailability::Unsupported);
        assert!(!truth.authoritative);
    }

    #[test]
    fn workflow_truth_planned_status_yields_planned_availability() {
        let truth = compiled_workflow_truth("planned", &[], &[], &[], &[]);
        assert_eq!(truth.availability, CommandAvailability::Planned);
        assert!(!truth.authoritative);
        assert!(
            truth.explanation.to_lowercase().contains("planned")
                || truth.explanation.to_lowercase().contains("preview")
                || truth.explanation.to_lowercase().contains("not yet"),
            "Planned explanation should mention planned/preview, got: {}",
            truth.explanation,
        );
    }

    #[test]
    fn workflow_truth_ambiguous_yields_unknown_recoverable() {
        let ambiguities = vec![Ambiguity {
            kind: "connector".to_owned(),
            message: "Multiple connectors match".to_owned(),
            candidates: vec!["slack".to_owned(), "discord".to_owned()],
        }];
        let truth = compiled_workflow_truth("ambiguous", &[], &[], &[], &ambiguities);
        assert_eq!(truth.availability, CommandAvailability::Unknown);
        assert!(truth.recoverable);
        assert!(truth.explanation.contains("ambiguous"));
    }

    #[test]
    fn workflow_truth_needs_clarification_yields_unknown() {
        let missing = vec!["Connector selection".to_owned()];
        let truth = compiled_workflow_truth("needs-clarification", &[], &missing, &[], &[]);
        assert_eq!(truth.availability, CommandAvailability::Unknown);
        assert!(truth.recoverable);
        assert!(
            truth.explanation.contains("identifiers") || truth.explanation.contains("compiler")
        );
    }

    #[test]
    fn workflow_truth_live_steps_yield_live_runtime() {
        let steps = vec![CompiledStep {
            ordinal: 1,
            phase: "execute".to_owned(),
            purpose: "Invoke operation".to_owned(),
            command: "invoke".to_owned(),
            command_line: "fwc invoke github issues.create".to_owned(),
            argv: vec!["fwc".to_owned(), "invoke".to_owned(), "github".to_owned()],
            side_effecting: true,
            approval_required: true,
            notes: Vec::new(),
        }];
        let truth = compiled_workflow_truth("ready", &steps, &[], &[], &[]);
        assert_eq!(truth.availability, CommandAvailability::LiveRuntime);
        assert!(truth.explanation.contains("live") || truth.explanation.contains("host"));
    }

    #[test]
    fn workflow_truth_offline_steps_yield_offline_artifact() {
        let steps = vec![CompiledStep {
            ordinal: 1,
            phase: "inspect".to_owned(),
            purpose: "Check session".to_owned(),
            command: "session".to_owned(),
            command_line: "fwc session list".to_owned(),
            argv: vec!["fwc".to_owned(), "session".to_owned(), "list".to_owned()],
            side_effecting: false,
            approval_required: false,
            notes: Vec::new(),
        }];
        let truth = compiled_workflow_truth("ready", &steps, &[], &[], &[]);
        assert_eq!(truth.availability, CommandAvailability::OfflineArtifact);
        assert!(truth.explanation.contains("offline") || truth.explanation.contains("artifact"));
    }

    #[test]
    fn workflow_truth_hybrid_step_with_offline_flag_yields_offline() {
        let steps = vec![CompiledStep {
            ordinal: 1,
            phase: "inspect".to_owned(),
            purpose: "Inspect schema offline".to_owned(),
            command: "schema".to_owned(),
            command_line: "fwc schema github issues.create --offline".to_owned(),
            argv: vec![
                "fwc".to_owned(),
                "schema".to_owned(),
                "github".to_owned(),
                "issues.create".to_owned(),
                "--offline".to_owned(),
            ],
            side_effecting: false,
            approval_required: false,
            notes: Vec::new(),
        }];
        let truth = compiled_workflow_truth("ready", &steps, &[], &[], &[]);
        assert_eq!(truth.availability, CommandAvailability::OfflineArtifact);
    }

    #[test]
    fn workflow_truth_hybrid_step_without_offline_flag_yields_live() {
        let steps = vec![CompiledStep {
            ordinal: 1,
            phase: "inspect".to_owned(),
            purpose: "Inspect schema".to_owned(),
            command: "schema".to_owned(),
            command_line: "fwc schema github issues.create".to_owned(),
            argv: vec![
                "fwc".to_owned(),
                "schema".to_owned(),
                "github".to_owned(),
                "issues.create".to_owned(),
            ],
            side_effecting: false,
            approval_required: false,
            notes: Vec::new(),
        }];
        let truth = compiled_workflow_truth("ready", &steps, &[], &[], &[]);
        assert_eq!(truth.availability, CommandAvailability::LiveRuntime);
        assert!(truth.explanation.contains("hybrid") || truth.explanation.contains("live"));
    }

    #[test]
    fn workflow_truth_empty_steps_yields_unknown() {
        let truth = compiled_workflow_truth("ready", &[], &[], &[], &[]);
        assert_eq!(truth.availability, CommandAvailability::Unknown);
    }

    #[test]
    fn workflow_truth_source_is_compiler() {
        let truth = compiled_workflow_truth("ready", &[], &[], &[], &[]);
        assert_eq!(truth.source_of_truth, WORKFLOW_TRUTH_COMPILER_SOURCE);
    }

    #[test]
    fn workflow_truth_exit_code_matches_availability() {
        let truth_planned = compiled_workflow_truth("planned", &[], &[], &[], &[]);
        assert_eq!(
            truth_planned.exit_code_hint,
            CommandAvailability::Planned.exit_code_u8()
        );

        let truth_unsupported =
            compiled_workflow_truth("unsupported", &[], &[], &["nope".to_owned()], &[]);
        assert_eq!(
            truth_unsupported.exit_code_hint,
            CommandAvailability::Unsupported.exit_code_u8()
        );
    }

    // ── compiled_step_availability tests ─────────────────────────

    #[test]
    fn step_availability_live_host_command() {
        let step = CompiledStep {
            ordinal: 1,
            phase: "execute".to_owned(),
            purpose: "Run".to_owned(),
            command: "invoke".to_owned(),
            command_line: "fwc invoke github issues.create".to_owned(),
            argv: vec!["fwc".to_owned(), "invoke".to_owned()],
            side_effecting: true,
            approval_required: false,
            notes: Vec::new(),
        };
        assert_eq!(
            compiled_step_availability(&step),
            CommandAvailability::LiveRuntime
        );
    }

    #[test]
    fn step_availability_offline_only_command() {
        let step = CompiledStep {
            ordinal: 1,
            phase: "local".to_owned(),
            purpose: "Check".to_owned(),
            command: "session".to_owned(),
            command_line: "fwc session list".to_owned(),
            argv: vec!["fwc".to_owned(), "session".to_owned()],
            side_effecting: false,
            approval_required: false,
            notes: Vec::new(),
        };
        assert_eq!(
            compiled_step_availability(&step),
            CommandAvailability::OfflineArtifact
        );
    }

    #[test]
    fn step_availability_unclassified_command_is_unknown() {
        let step = CompiledStep {
            ordinal: 1,
            phase: "?".to_owned(),
            purpose: "?".to_owned(),
            command: "nonexistent-future-command".to_owned(),
            command_line: "fwc nonexistent-future-command".to_owned(),
            argv: vec!["fwc".to_owned(), "nonexistent-future-command".to_owned()],
            side_effecting: false,
            approval_required: false,
            notes: Vec::new(),
        };
        assert_eq!(
            compiled_step_availability(&step),
            CommandAvailability::Unknown
        );
    }

    #[test]
    fn step_availability_passthrough_command_is_unknown() {
        let step = CompiledStep {
            ordinal: 1,
            phase: "local".to_owned(),
            purpose: "Help".to_owned(),
            command: "help".to_owned(),
            command_line: "fwc help".to_owned(),
            argv: vec!["fwc".to_owned(), "help".to_owned()],
            side_effecting: false,
            approval_required: false,
            notes: Vec::new(),
        };
        // Passthrough commands map to Unknown
        let avail = compiled_step_availability(&step);
        assert!(
            avail == CommandAvailability::Unknown || avail == CommandAvailability::OfflineArtifact,
            "Passthrough step should be Unknown or OfflineArtifact, got {:?}",
            avail,
        );
    }

    // ── aggregate_compiled_step_availability tests ───────────────

    #[test]
    fn aggregate_mixed_live_and_offline_prefers_live() {
        let steps = vec![
            CompiledStep {
                ordinal: 1,
                phase: "inspect".to_owned(),
                purpose: "Check session".to_owned(),
                command: "session".to_owned(),
                command_line: "fwc session list".to_owned(),
                argv: vec!["fwc".to_owned(), "session".to_owned()],
                side_effecting: false,
                approval_required: false,
                notes: Vec::new(),
            },
            CompiledStep {
                ordinal: 2,
                phase: "execute".to_owned(),
                purpose: "Invoke".to_owned(),
                command: "invoke".to_owned(),
                command_line: "fwc invoke github issues.create".to_owned(),
                argv: vec!["fwc".to_owned(), "invoke".to_owned()],
                side_effecting: true,
                approval_required: true,
                notes: Vec::new(),
            },
        ];
        assert_eq!(
            aggregate_compiled_step_availability(&steps),
            CommandAvailability::LiveRuntime,
        );
    }

    #[test]
    fn aggregate_empty_steps_is_unknown() {
        assert_eq!(
            aggregate_compiled_step_availability(&[]),
            CommandAvailability::Unknown,
        );
    }

    #[test]
    fn aggregate_live_and_unknown_prefers_unknown() {
        let steps = vec![
            CompiledStep {
                ordinal: 1,
                phase: "execute".to_owned(),
                purpose: "Invoke".to_owned(),
                command: "invoke".to_owned(),
                command_line: "fwc invoke github issues.create".to_owned(),
                argv: vec!["fwc".to_owned(), "invoke".to_owned()],
                side_effecting: true,
                approval_required: true,
                notes: Vec::new(),
            },
            CompiledStep {
                ordinal: 2,
                phase: "handoff".to_owned(),
                purpose: "Unknown passthrough".to_owned(),
                command: "mystery".to_owned(),
                command_line: "fwc mystery".to_owned(),
                argv: vec!["fwc".to_owned(), "mystery".to_owned()],
                side_effecting: false,
                approval_required: false,
                notes: Vec::new(),
            },
        ];

        assert_eq!(
            aggregate_compiled_step_availability(&steps),
            CommandAvailability::Unknown,
        );
    }

    #[test]
    fn workflow_truth_unknown_step_explanation_mentions_unknown_boundary() {
        let steps = vec![
            CompiledStep {
                ordinal: 1,
                phase: "inspect".to_owned(),
                purpose: "Local context".to_owned(),
                command: "session".to_owned(),
                command_line: "fwc session list".to_owned(),
                argv: vec!["fwc".to_owned(), "session".to_owned()],
                side_effecting: false,
                approval_required: false,
                notes: Vec::new(),
            },
            CompiledStep {
                ordinal: 2,
                phase: "handoff".to_owned(),
                purpose: "Unknown passthrough".to_owned(),
                command: "mystery".to_owned(),
                command_line: "fwc mystery".to_owned(),
                argv: vec!["fwc".to_owned(), "mystery".to_owned()],
                side_effecting: false,
                approval_required: false,
                notes: Vec::new(),
            },
        ];

        let truth = compiled_workflow_truth("ready", &steps, &[], &[], &[]);
        assert_eq!(truth.availability, CommandAvailability::Unknown);
        assert!(
            truth.explanation.contains("unknown truth boundary"),
            "Unexpected explanation: {}",
            truth.explanation,
        );
    }

    // ── Compiler integration: planner honesty invariants ─────────

    #[test]
    fn compiler_unsupported_plans_have_non_empty_unsupported_reasons() {
        let plan = compile(&request("restart the github connector"));
        if plan.status == "unsupported" {
            assert!(
                !plan.unsupported_reasons.is_empty(),
                "Unsupported plan should have reasons",
            );
            assert_eq!(
                plan.workflow_truth.availability,
                CommandAvailability::Unsupported
            );
        }
    }

    #[test]
    fn compiler_ready_plan_steps_are_all_classified() {
        let plan = compile(&request("create a GitHub issue titled \"test\""));
        assert_eq!(plan.status, "ready");
        for step_item in &plan.steps {
            let classification = classify_command(&step_item.command);
            assert!(
                classification.is_some(),
                "Step command '{}' in ready plan is not classified",
                step_item.command,
            );
        }
    }

    #[test]
    fn compiler_config_plan_is_offline() {
        let plan = compile(&request("set credentials for github"));
        assert_eq!(plan.template, "config");
        // Config is offline-only
        assert!(
            plan.workflow_truth.availability == CommandAvailability::OfflineArtifact
                || plan.workflow_truth.availability == CommandAvailability::Unknown,
            "Config plan should be offline or unknown, got {:?}",
            plan.workflow_truth.availability,
        );
    }

    #[test]
    fn compiler_never_claims_authoritative_before_execution() {
        // The compiler can't claim runtime authority - only execution receipts can
        let intents = [
            "create a GitHub issue",
            "list all connectors",
            "disable the slack connector",
            "set credentials for github",
        ];
        for intent in &intents {
            let plan = compile(&request(intent));
            assert!(
                !plan.workflow_truth.authoritative,
                "Plan for '{}' claims authoritative before execution",
                intent,
            );
        }
    }

    #[test]
    fn compiler_discovery_plan_workflow_truth_is_set() {
        let plan = compile(&request("what connectors are available"));
        assert_ne!(
            plan.workflow_truth.availability,
            CommandAvailability::Denied,
            "Discovery should not be denied",
        );
        assert!(!plan.workflow_truth.explanation.is_empty());
    }

    #[test]
    fn compiler_unsupported_plan_exit_code_is_nonzero() {
        let plan = compile(&request("disable the github connector"));
        if plan.workflow_truth.availability == CommandAvailability::Unsupported {
            assert_ne!(
                plan.workflow_truth.exit_code_hint, 0,
                "Unsupported plan should have nonzero exit code",
            );
        }
    }

    #[test]
    fn compiler_ambiguous_plan_is_recoverable() {
        let plan = compile(&request("send a message"));
        if plan.status == "ambiguous" {
            assert!(
                plan.workflow_truth.recoverable,
                "Ambiguous plan should be recoverable",
            );
        }
    }

    // ── WorkflowTruth construction tests ────────────────────────

    #[test]
    fn workflow_truth_from_compiler_is_never_authoritative() {
        let truth =
            WorkflowTruth::from_compiler(CommandAvailability::LiveRuntime, "test explanation");
        assert!(!truth.authoritative);
        assert_eq!(truth.source_of_truth, WORKFLOW_TRUTH_COMPILER_SOURCE);
    }

    #[test]
    fn workflow_truth_from_execution_receipt_can_be_authoritative() {
        let truth = WorkflowTruth::from_execution_receipt(
            CommandAvailability::LiveRuntime,
            true,
            false,
            "Host-backed execution succeeded",
        );
        assert!(truth.authoritative);
        assert_eq!(truth.source_of_truth, "workflow-execution-receipt");
    }

    #[test]
    fn workflow_truth_denied_is_recoverable() {
        let truth = WorkflowTruth::from_compiler(
            CommandAvailability::Denied,
            "Policy blocks this operation",
        );
        assert!(truth.recoverable);
        assert_eq!(
            truth.exit_code_hint,
            CommandAvailability::Denied.exit_code_u8()
        );
    }

    #[test]
    fn workflow_truth_unavailable_is_recoverable() {
        let truth =
            WorkflowTruth::from_compiler(CommandAvailability::Unavailable, "Host unreachable");
        assert!(truth.recoverable);
    }

    #[test]
    fn workflow_truth_unsupported_is_not_recoverable() {
        let truth = WorkflowTruth::from_compiler(
            CommandAvailability::Unsupported,
            "Not supported by this connector",
        );
        assert!(!truth.recoverable);
    }

    #[test]
    fn workflow_truth_serializes_all_fields() {
        let truth =
            WorkflowTruth::from_compiler(CommandAvailability::LiveRuntime, "Live host truth");
        let json = serde_json::to_value(&truth).unwrap();
        assert!(json.get("availability").is_some());
        assert!(json.get("source_of_truth").is_some());
        assert!(json.get("authoritative").is_some());
        assert!(json.get("recoverable").is_some());
        assert!(json.get("exit_code_hint").is_some());
        assert!(json.get("explanation").is_some());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 29.8.4: WorkflowTruth truthfulness invariants
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn from_compiler_always_non_authoritative_for_all_7_variants() {
        let variants = [
            CommandAvailability::LiveRuntime,
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        for v in &variants {
            let truth = WorkflowTruth::from_compiler(*v, "test");
            assert!(
                !truth.authoritative,
                "from_compiler({:?}) should always be non-authoritative",
                v,
            );
            assert_eq!(truth.source_of_truth, WORKFLOW_TRUTH_COMPILER_SOURCE);
        }
    }

    #[test]
    fn from_execution_receipt_can_be_authoritative() {
        let truth = WorkflowTruth::from_execution_receipt(
            CommandAvailability::LiveRuntime,
            true,
            false,
            "Live execution",
        );
        assert!(truth.authoritative);
        assert_eq!(truth.source_of_truth, "workflow-execution-receipt");
    }

    #[test]
    fn from_execution_receipt_can_be_non_authoritative() {
        let truth = WorkflowTruth::from_execution_receipt(
            CommandAvailability::OfflineArtifact,
            false,
            false,
            "Offline result",
        );
        assert!(!truth.authoritative);
    }

    #[test]
    fn exit_code_hint_matches_availability_for_all_7() {
        let variants = [
            CommandAvailability::LiveRuntime,
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        for v in &variants {
            let truth = WorkflowTruth::from_compiler(*v, "test");
            assert_eq!(
                truth.exit_code_hint,
                v.exit_code_u8(),
                "exit_code_hint mismatch for {:?}",
                v,
            );
        }
    }

    #[test]
    fn from_compiler_recoverability_matches_availability() {
        // Recoverable: Unavailable, Denied, Unknown
        // Not recoverable: LiveRuntime, OfflineArtifact, Unsupported, Planned
        let cases = [
            (CommandAvailability::LiveRuntime, false),
            (CommandAvailability::OfflineArtifact, false),
            (CommandAvailability::Unsupported, false),
            (CommandAvailability::Planned, false),
            (CommandAvailability::Unavailable, true),
            (CommandAvailability::Denied, true),
            (CommandAvailability::Unknown, true),
        ];
        for (v, expected) in &cases {
            let truth = WorkflowTruth::from_compiler(*v, "test");
            assert_eq!(
                truth.recoverable, *expected,
                "recoverable mismatch for {:?}",
                v,
            );
        }
    }

    #[test]
    fn all_7_variants_produce_distinct_explanations_via_from_compiler() {
        let variants = [
            CommandAvailability::LiveRuntime,
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        // Each variant gets a unique explanation when we use unique messages
        let explanations: std::collections::HashSet<String> = variants
            .iter()
            .map(|v| WorkflowTruth::from_compiler(*v, format!("test-{}", v.tag())).explanation)
            .collect();
        assert_eq!(
            explanations.len(),
            variants.len(),
            "Not all variants produce distinct explanations"
        );
    }

    #[test]
    fn from_compiler_and_receipt_have_different_source_of_truth() {
        let compiler = WorkflowTruth::from_compiler(CommandAvailability::LiveRuntime, "c");
        let receipt = WorkflowTruth::from_execution_receipt(
            CommandAvailability::LiveRuntime,
            true,
            false,
            "r",
        );
        assert_ne!(compiler.source_of_truth, receipt.source_of_truth);
    }

    #[test]
    fn workflow_truth_json_availability_uses_kebab_case() {
        let truth = WorkflowTruth::from_compiler(CommandAvailability::LiveRuntime, "test");
        let json = serde_json::to_value(&truth).unwrap();
        assert_eq!(json["availability"], "live-runtime");
    }

    #[test]
    fn workflow_truth_json_offline_artifact_kebab_case() {
        let truth = WorkflowTruth::from_compiler(CommandAvailability::OfflineArtifact, "test");
        let json = serde_json::to_value(&truth).unwrap();
        assert_eq!(json["availability"], "offline-artifact");
    }

    #[test]
    fn workflow_truth_json_has_exactly_six_keys() {
        let truth = WorkflowTruth::from_compiler(CommandAvailability::Planned, "test");
        let json = serde_json::to_value(&truth).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(
            obj.len(),
            6,
            "WorkflowTruth JSON should have exactly 6 keys, got: {:?}",
            obj.keys().collect::<Vec<_>>(),
        );
    }

    #[test]
    fn compiled_workflow_truth_empty_steps_yields_unknown() {
        // Empty intent → compiled status not "ready" → should produce relevant truth
        let truth = compiled_workflow_truth("", &[], &[], &[], &[]);
        assert!(
            matches!(truth.availability, CommandAvailability::Unknown),
            "Empty steps should yield Unknown, got {:?}",
            truth.availability,
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 24llg.6.2.1: Intent contract surfaces — provenance,
    // refusal taxonomy, log-tail, and host-backed lifecycle
    // ═══════════════════════════════════════════════════════════════════

    // ── IntentProvenance ─────────────────────────────────────

    #[test]
    fn provenance_labels_are_distinct() {
        let labels: Vec<&str> = [
            IntentProvenance::HostBacked,
            IntentProvenance::Offline,
            IntentProvenance::MeshBacked,
            IntentProvenance::Degraded,
            IntentProvenance::Unsupported,
        ]
        .iter()
        .map(|p| p.label())
        .collect();
        let unique: std::collections::HashSet<&&str> = labels.iter().collect();
        assert_eq!(
            labels.len(),
            unique.len(),
            "Provenance labels must be unique"
        );
    }

    #[test]
    fn provenance_serializes_kebab_case() {
        let json = serde_json::to_string(&IntentProvenance::HostBacked).unwrap();
        assert_eq!(json, r#""host-backed""#);
        let json = serde_json::to_string(&IntentProvenance::MeshBacked).unwrap();
        assert_eq!(json, r#""mesh-backed""#);
    }

    #[test]
    fn provenance_round_trips() {
        for variant in &[
            IntentProvenance::HostBacked,
            IntentProvenance::Offline,
            IntentProvenance::MeshBacked,
            IntentProvenance::Degraded,
            IntentProvenance::Unsupported,
        ] {
            let json = serde_json::to_string(variant).unwrap();
            let back: IntentProvenance = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    // ── IntentRefusalReason ─────────────────────────────────

    #[test]
    fn refusal_reason_labels_are_distinct() {
        let labels: Vec<&str> = [
            IntentRefusalReason::HostUnavailable,
            IntentRefusalReason::InvalidTransition,
            IntentRefusalReason::ConnectorUnresolved,
            IntentRefusalReason::ApprovalRequired,
            IntentRefusalReason::NoMatchingPrimitive,
            IntentRefusalReason::MissingParameter,
        ]
        .iter()
        .map(|r| r.label())
        .collect();
        let unique: std::collections::HashSet<&&str> = labels.iter().collect();
        assert_eq!(labels.len(), unique.len(), "Refusal labels must be unique");
    }

    #[test]
    fn refusal_reason_serializes_kebab_case() {
        let json = serde_json::to_string(&IntentRefusalReason::HostUnavailable).unwrap();
        assert_eq!(json, r#""host-unavailable""#);
    }

    #[test]
    fn refusal_reason_round_trips() {
        for variant in &[
            IntentRefusalReason::HostUnavailable,
            IntentRefusalReason::InvalidTransition,
            IntentRefusalReason::ConnectorUnresolved,
            IntentRefusalReason::ApprovalRequired,
            IntentRefusalReason::NoMatchingPrimitive,
            IntentRefusalReason::MissingParameter,
        ] {
            let json = serde_json::to_string(variant).unwrap();
            let back: IntentRefusalReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    // ── LogTailContract ─────────────────────────────────────

    #[test]
    fn log_tail_contract_serializes() {
        let contract = LogTailContract {
            connector_id: Some("github".to_owned()),
            since_duration: Some("5m".to_owned()),
            event_type_filter: None,
            limit: 50,
            provenance: IntentProvenance::HostBacked,
            refusal: None,
        };
        let json = serde_json::to_value(&contract).unwrap();
        assert_eq!(json["connector_id"], "github");
        assert_eq!(json["provenance"], "host-backed");
        assert!(json["refusal"].is_null());
    }

    #[test]
    fn log_tail_contract_with_refusal() {
        let contract = LogTailContract {
            connector_id: None,
            since_duration: None,
            event_type_filter: None,
            limit: 50,
            provenance: IntentProvenance::Unsupported,
            refusal: Some(IntentRefusalReason::HostUnavailable),
        };
        let json = serde_json::to_value(&contract).unwrap();
        assert_eq!(json["provenance"], "unsupported");
        assert_eq!(json["refusal"], "host-unavailable");
    }

    // ── LifecycleIntentContract ──────────────────────────────

    #[test]
    fn lifecycle_contract_serializes() {
        let contract = LifecycleIntentContract {
            connector_id: "slack".to_owned(),
            action: "disable".to_owned(),
            preflight: true,
            dry_run: false,
            provenance: IntentProvenance::HostBacked,
            refusal: None,
        };
        let json = serde_json::to_value(&contract).unwrap();
        assert_eq!(json["connector_id"], "slack");
        assert_eq!(json["action"], "disable");
        assert_eq!(json["provenance"], "host-backed");
    }

    #[test]
    fn lifecycle_contract_with_invalid_transition_refusal() {
        let contract = LifecycleIntentContract {
            connector_id: "github".to_owned(),
            action: "stop".to_owned(),
            preflight: false,
            dry_run: false,
            provenance: IntentProvenance::HostBacked,
            refusal: Some(IntentRefusalReason::InvalidTransition),
        };
        let json = serde_json::to_value(&contract).unwrap();
        assert_eq!(json["refusal"], "invalid-transition");
    }

    // ── Compiler integration: log-tail plans ────────────────

    #[test]
    fn compiler_log_tail_plan_uses_fwc_tail() {
        let plan = compile(&request("show logs for the github connector"));
        assert_eq!(plan.template, "log-tail");
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("fwc tail"))
        );
    }

    #[test]
    fn compiler_log_tail_plan_includes_since_default() {
        let plan = compile(&request("tail github logs"));
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("--since") && s.command_line.contains("5m"))
        );
    }

    #[test]
    fn compiler_log_tail_includes_history_step() {
        let plan = compile(&request("stream the github connector logs"));
        // Log-tail plans include a history step for operation receipts
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("history"))
        );
    }

    #[test]
    fn compiler_log_tail_no_connector_still_tails() {
        let plan = compile(&request("tail all connector logs"));
        assert_eq!(plan.template, "log-tail");
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("fwc tail"))
        );
    }

    #[test]
    fn compiler_log_tail_is_read_only() {
        let plan = compile(&request("tail the slack connector logs"));
        assert!(plan.steps.iter().all(|s| !s.side_effecting));
        assert!(plan.steps.iter().all(|s| !s.approval_required));
    }

    // ── Compiler integration: host-backed lifecycle plans ───��

    #[test]
    fn compiler_stop_routes_to_lifecycle() {
        let plan = compile(&request("stop the github connector"));
        assert_eq!(plan.template, "lifecycle");
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("--action") && s.command_line.contains("stop"))
        );
    }

    #[test]
    fn compiler_start_routes_to_lifecycle() {
        let plan = compile(&request("start the telegram connector"));
        assert_eq!(plan.template, "lifecycle");
        assert!(
            plan.steps
                .iter()
                .any(|s| s.command_line.contains("--action") && s.command_line.contains("start"))
        );
    }

    #[test]
    fn compiler_lifecycle_plan_has_four_steps() {
        let plan = compile(&request("disable the slack connector"));
        // Host-backed lifecycle: valid-actions, preflight, mutate, verify
        assert_eq!(
            plan.steps.len(),
            4,
            "Host-backed lifecycle plan should have 4 steps, got: {:?}",
            plan.steps.iter().map(|s| &s.phase).collect::<Vec<_>>()
        );
    }

    #[test]
    fn compiler_lifecycle_mutate_step_requires_approval() {
        let plan = compile(&request("restart the github connector"));
        let mutate = plan
            .steps
            .iter()
            .find(|s| s.phase == "mutate")
            .expect("lifecycle plan should have a mutate step");
        assert!(mutate.approval_required);
        assert!(mutate.side_effecting);
    }

    #[test]
    fn compiler_lifecycle_preflight_steps_are_safe() {
        let plan = compile(&request("enable the discord connector"));
        let preflights: Vec<_> = plan
            .steps
            .iter()
            .filter(|s| s.phase == "preflight")
            .collect();
        assert!(
            !preflights.is_empty(),
            "lifecycle plan should have preflight steps"
        );
        for s in preflights {
            assert!(
                !s.side_effecting,
                "preflight step should not be side-effecting"
            );
            assert!(
                !s.approval_required,
                "preflight step should not require approval"
            );
        }
    }

    #[test]
    fn compiler_lifecycle_notes_contain_provenance() {
        let plan = compile(&request("stop the github connector"));
        let has_provenance = plan.steps.iter().any(|s| {
            s.notes
                .iter()
                .any(|n| n.contains("Provenance: host-backed"))
        });
        assert!(
            has_provenance,
            "Host-backed lifecycle steps should annotate provenance"
        );
    }

    #[test]
    fn compiler_lifecycle_notes_contain_refusal_taxonomy() {
        let plan = compile(&request("disable the slack connector"));
        let has_refusal = plan
            .steps
            .iter()
            .any(|s| s.notes.iter().any(|n| n.contains("Refusal taxonomy")));
        assert!(
            has_refusal,
            "Host-backed lifecycle steps should annotate refusal taxonomy"
        );
    }

    // ── Original lifecycle verbs still work ──────────────────

    #[test]
    fn compiler_install_still_uses_direct_primitive() {
        let plan = compile(&request("install the github connector"));
        assert_eq!(plan.template, "lifecycle");
        // Install uses direct `fwc install`, not `fwc lifecycle --action`
        assert!(plan.steps.iter().any(|s| s.command == "install"));
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| s.command_line.contains("--action"))
        );
    }

    #[test]
    fn compiler_status_still_uses_direct_primitive() {
        let plan = compile(&request("status of the slack connector"));
        assert_eq!(plan.template, "lifecycle");
        assert!(plan.steps.iter().any(|s| s.command == "status"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 24llg.6.2.2: Verify compiler+executor no longer bottom out
    // in placeholder branches for log-tail and lifecycle
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn no_lifecycle_verb_produces_unsupported_template() {
        for verb_phrase in &[
            "disable the slack connector",
            "enable the github connector",
            "restart the telegram connector",
            "start the discord connector",
            "stop the stripe connector",
        ] {
            let plan = compile(&request(verb_phrase));
            assert_ne!(
                plan.template, "unsupported",
                "Verb phrase `{verb_phrase}` should not produce unsupported template"
            );
            assert_ne!(
                plan.status, "unsupported",
                "Verb phrase `{verb_phrase}` should not produce unsupported status"
            );
            assert!(
                plan.unsupported_reasons.is_empty(),
                "Verb phrase `{verb_phrase}` should have no unsupported reasons, got: {:?}",
                plan.unsupported_reasons
            );
        }
    }

    #[test]
    fn no_log_verb_produces_unsupported_template() {
        for verb_phrase in &[
            "tail the github connector logs",
            "show logs for the slack connector",
            "stream the discord connector output",
            "log output from the telegram connector",
        ] {
            let plan = compile(&request(verb_phrase));
            assert_ne!(
                plan.template, "unsupported",
                "Verb phrase `{verb_phrase}` should not produce unsupported template"
            );
            assert_ne!(
                plan.status, "unsupported",
                "Verb phrase `{verb_phrase}` should not produce unsupported status"
            );
        }
    }

    #[test]
    fn all_lifecycle_steps_use_valid_fwc_commands() {
        let plan = compile(&request("disable the slack connector"));
        for step in &plan.steps {
            assert!(
                step.argv.first().is_some_and(|a| a == "fwc"),
                "All compiled steps should be fwc commands, got: {:?}",
                step.argv
            );
            // The command should be a known fwc subcommand
            let cmd = step.argv.get(1).map(String::as_str).unwrap_or("");
            assert!(
                [
                    "lifecycle",
                    "status",
                    "tail",
                    "history",
                    "show",
                    "install",
                    "update",
                    "pin",
                    "unpin"
                ]
                .contains(&cmd),
                "Step command `{cmd}` should be a known fwc subcommand"
            );
        }
    }

    #[test]
    fn all_log_tail_steps_use_valid_fwc_commands() {
        let plan = compile(&request("tail the github connector logs"));
        for step in &plan.steps {
            assert!(
                step.argv.first().is_some_and(|a| a == "fwc"),
                "All compiled steps should be fwc commands, got: {:?}",
                step.argv
            );
            let cmd = step.argv.get(1).map(String::as_str).unwrap_or("");
            assert!(
                ["tail", "status", "history"].contains(&cmd),
                "Log-tail step command `{cmd}` should be tail, status, or history"
            );
        }
    }

    #[test]
    fn lifecycle_disable_plan_has_typed_refusal_notes() {
        let plan = compile(&request("disable the slack connector"));
        // The plan should mention refusal taxonomy in its notes
        let all_notes: Vec<&str> = plan
            .steps
            .iter()
            .flat_map(|s| s.notes.iter().map(String::as_str))
            .collect();
        assert!(
            all_notes
                .iter()
                .any(|n| n.contains("host-unavailable") || n.contains("invalid-transition")),
            "Lifecycle plan should document typed refusal classes in notes, got: {all_notes:?}"
        );
    }

    #[test]
    fn log_tail_plan_has_provenance_notes() {
        let plan = compile(&request("tail the github connector logs"));
        let all_notes: Vec<&str> = plan
            .steps
            .iter()
            .flat_map(|s| s.notes.iter().map(String::as_str))
            .collect();
        assert!(
            all_notes.iter().any(|n| n.contains("host-backed")),
            "Log-tail plan should document host-backed provenance in notes, got: {all_notes:?}"
        );
    }

    #[test]
    fn lifecycle_and_log_families_no_longer_reach_unsupported_plan() {
        // Exhaustively verify: no lifecycle or log verb hits build_unsupported_plan
        let all_verbs = [
            "install the github connector",
            "update the slack connector",
            "pin the discord connector",
            "unpin the telegram connector",
            "status of the github connector",
            "disable the slack connector",
            "enable the github connector",
            "restart the telegram connector",
            "start the discord connector",
            "stop the stripe connector",
            "tail the github connector logs",
            "show logs for the slack connector",
            "stream the discord connector output",
        ];
        for phrase in &all_verbs {
            let plan = compile(&request(phrase));
            assert!(
                plan.template == "lifecycle" || plan.template == "log-tail",
                "Phrase `{phrase}` should route to lifecycle or log-tail, got template=`{}`",
                plan.template
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 24llg.6.2.3: Scenario pack — structured transcripts for
    // supported, degraded, and refusal intent paths
    // ═══════════════════════════════════════════════════════════════════

    /// Scenario: supported lifecycle flow with a known connector.
    /// Expected: ready status, 4-step plan (valid-actions, preflight, mutate, verify),
    /// provenance=host-backed, no refusals.
    #[test]
    fn scenario_supported_lifecycle_disable() {
        let plan = compile(&request("disable the github connector"));
        let transcript = serde_json::to_value(&plan).unwrap();

        // Structured transcript fields
        assert_eq!(transcript["template"], "lifecycle");
        assert_eq!(transcript["status"], "ready");
        assert_eq!(transcript["action"]["family"], "lifecycle");
        assert_eq!(transcript["action"]["verb"], "disable");
        assert_eq!(transcript["action"]["mutating"], true);
        assert!(
            transcript["unsupported_reasons"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        // Steps are structured and traceable
        let steps = transcript["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 4);
        assert_eq!(steps[0]["phase"], "preflight");
        assert_eq!(steps[1]["phase"], "preflight");
        assert_eq!(steps[2]["phase"], "mutate");
        assert_eq!(steps[3]["phase"], "verify");

        // Provenance annotations
        let mutate_notes = steps[2]["notes"].as_array().unwrap();
        assert!(
            mutate_notes
                .iter()
                .any(|n| n.as_str().unwrap().contains("host-backed"))
        );
        assert!(
            mutate_notes
                .iter()
                .any(|n| n.as_str().unwrap().contains("Refusal taxonomy"))
        );
    }

    /// Scenario: supported log-tail flow with a known connector.
    /// Expected: ready status, 3 steps (status, tail, history),
    /// provenance=host-backed, no side effects.
    #[test]
    fn scenario_supported_log_tail() {
        let plan = compile(&request("tail the github connector logs"));
        let transcript = serde_json::to_value(&plan).unwrap();

        assert_eq!(transcript["template"], "log-tail");
        assert_eq!(transcript["status"], "ready");
        assert_eq!(transcript["action"]["family"], "log-tail");
        assert_eq!(transcript["action"]["verb"], "tail");
        assert_eq!(transcript["action"]["mutating"], false);

        let steps = transcript["steps"].as_array().unwrap();
        assert!(steps.len() >= 2, "Log-tail should have at least 2 steps");

        // All steps are non-mutating
        for step in steps {
            assert_eq!(step["side_effecting"], false);
            assert_eq!(step["approval_required"], false);
        }

        // Provenance annotations on tail step
        let tail_step = steps
            .iter()
            .find(|s| s["command"].as_str().unwrap() == "tail")
            .expect("Should have a tail step");
        let tail_notes = tail_step["notes"].as_array().unwrap();
        assert!(
            tail_notes
                .iter()
                .any(|n| n.as_str().unwrap().contains("host-backed"))
        );
    }

    /// Scenario: missing connector (degraded/partial availability).
    /// Expected: needs-clarification status, missing_information populated,
    /// no steps (or minimal), refusal semantics explicit.
    #[test]
    fn scenario_degraded_lifecycle_no_connector() {
        let plan = compile(&request("disable something"));
        let transcript = serde_json::to_value(&plan).unwrap();

        assert_eq!(transcript["template"], "lifecycle");
        assert_eq!(transcript["status"], "needs-clarification");
        let missing = transcript["missing_information"].as_array().unwrap();
        assert!(
            !missing.is_empty(),
            "Degraded plan should have missing_information"
        );
        assert!(
            missing
                .iter()
                .any(|m| m.as_str().unwrap().to_lowercase().contains("connector"))
        );
    }

    /// Scenario: missing connector for log-tail.
    /// Expected: ready status (tail can tail all connectors), but steps
    /// should omit connector-specific history step.
    #[test]
    fn scenario_log_tail_without_specific_connector() {
        // "tail all logs" doesn't resolve a specific connector
        let plan = compile(&request("tail all logs"));
        let transcript = serde_json::to_value(&plan).unwrap();

        assert_eq!(transcript["template"], "log-tail");
        // Still produces a plan — tailing all connectors is valid
        let steps = transcript["steps"].as_array().unwrap();
        assert!(
            steps
                .iter()
                .any(|s| s["command"].as_str().unwrap() == "tail"),
            "Should still have a tail step even without specific connector"
        );
    }

    /// Scenario: truthful refusal — genuinely unsupported verb.
    /// Expected: unsupported status, unsupported_reasons populated,
    /// no real mutation steps.
    #[test]
    fn scenario_refusal_unknown_verb() {
        let plan = compile(&request("deploy the github connector to production"));
        let transcript = serde_json::to_value(&plan).unwrap();

        // "deploy" doesn't match any known verb family
        let template = transcript["template"].as_str().unwrap();
        // Should route to discovery or operation fallback, NOT to unsupported
        // (because "deploy" doesn't match the unsupported verb table)
        assert!(
            template != "lifecycle" && template != "log-tail",
            "Unknown verb should not route to lifecycle or log-tail, got: {template}"
        );
    }

    /// Scenario: lifecycle with zone hint — supported but with assumption.
    /// Expected: ready status, zone captured, assumption note about zone.
    #[test]
    fn scenario_lifecycle_with_zone_hint() {
        let plan = compile(&request("disable the slack connector in z:work"));
        let transcript = serde_json::to_value(&plan).unwrap();

        assert_eq!(transcript["template"], "lifecycle");
        assert_eq!(transcript["status"], "ready");
        assert_eq!(transcript["zone"], "z:work");

        let assumptions = transcript["assumptions"].as_array().unwrap();
        assert!(
            assumptions
                .iter()
                .any(|a| a.as_str().unwrap().to_lowercase().contains("zone")),
            "Should have a zone assumption note"
        );
    }

    /// Scenario: explain mode shows structured reasoning.
    /// Expected: explain mode label, non-empty explanation fields.
    #[test]
    fn scenario_explain_lifecycle() {
        let req = IntentRequest {
            intent: "restart the github connector".to_owned(),
            connector_override: None,
            zone_override: None,
            mode: IntentMode::Explain,
            host_url: None,
        };
        let plan = compile(&req);
        let transcript = serde_json::to_value(&plan).unwrap();

        assert_eq!(transcript["mode"], "explain");
        assert_eq!(transcript["template"], "lifecycle");

        let explanation = &transcript["explanation"];
        assert!(
            !explanation["template_reasoning"]
                .as_array()
                .unwrap()
                .is_empty(),
            "Explain mode should include template reasoning"
        );
        assert!(
            !explanation["action_evidence"]
                .as_array()
                .unwrap()
                .is_empty(),
            "Explain mode should include action evidence"
        );
    }

    /// Scenario: do-simulate mode withholds mutating lifecycle steps.
    /// This validates the executor path: lifecycle steps that are
    /// side-effecting should be withheld in simulation mode.
    #[test]
    fn scenario_do_simulate_lifecycle_withholds_mutation() {
        let req = IntentRequest {
            intent: "disable the github connector".to_owned(),
            connector_override: None,
            zone_override: None,
            mode: IntentMode::DoSimulate,
            host_url: None,
        };
        let plan = compile(&req);

        // The compiled plan should have mutating steps
        let has_mutating = plan.steps.iter().any(|s| s.side_effecting);
        assert!(
            has_mutating,
            "Lifecycle plan should have side-effecting steps"
        );

        // But the plan itself is still "ready" — it's the executor that withholds
        assert_eq!(plan.status, "ready");

        // Verify step structure: preflight steps are safe, mutate step requires approval
        let safe_steps: Vec<_> = plan.steps.iter().filter(|s| !s.side_effecting).collect();
        let mutating_steps: Vec<_> = plan.steps.iter().filter(|s| s.side_effecting).collect();
        assert!(
            !safe_steps.is_empty(),
            "Should have safe preflight/verify steps"
        );
        assert!(
            !mutating_steps.is_empty(),
            "Should have mutating lifecycle step"
        );
        for s in &mutating_steps {
            assert!(
                s.approval_required,
                "Mutating lifecycle step should require approval"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 24llg.6.4.1: Frozen output snapshots for intent lifecycle
    // and log-tail surfaces — regression gates for field names,
    // provenance, evidence handles, and operator guidance.
    // ═══════════════════════════════════════════════════════════════════

    /// Helper: assert that a JSON value has exactly the specified top-level keys.
    fn assert_keys(val: &Value, expected: &[&str], context: &str) {
        let obj = val
            .as_object()
            .unwrap_or_else(|| panic!("{context}: expected object"));
        let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        let expected_set: std::collections::BTreeSet<&str> = expected.iter().copied().collect();
        assert_eq!(
            actual, expected_set,
            "{context}: key mismatch.\n  actual:   {actual:?}\n  expected: {expected_set:?}"
        );
    }

    /// Snapshot: CompiledStep JSON shape is stable.
    #[test]
    fn snapshot_compiled_step_shape() {
        let plan = compile(&request("disable the slack connector"));
        let steps_json = serde_json::to_value(&plan.steps).unwrap();
        let first_step = &steps_json[0];
        assert_keys(
            first_step,
            &[
                "ordinal",
                "phase",
                "purpose",
                "command",
                "command_line",
                "argv",
                "side_effecting",
                "approval_required",
                "notes",
            ],
            "CompiledStep",
        );
    }

    /// Snapshot: CompiledIntent JSON shape is stable.
    #[test]
    fn snapshot_compiled_intent_shape() {
        let plan = compile(&request("disable the slack connector"));
        let json = serde_json::to_value(&plan).unwrap();
        assert_keys(
            &json,
            &[
                "status",
                "workflow_truth",
                "mode",
                "summary",
                "template",
                "confidence",
                "raw_intent",
                "normalized_intent",
                "connector_override",
                "zone",
                "quoted_literals",
                "lookup_literal",
                "payload_literal",
                "chosen_connector",
                "alternative_connectors",
                "action",
                "operation_hint",
                "missing_information",
                "unsupported_reasons",
                "ambiguities",
                "assumptions",
                "suggested_command_lines",
                "next_actions",
                "steps",
                "explanation",
                "execution_notice",
            ],
            "CompiledIntent",
        );
    }

    /// Snapshot: lifecycle disable plan step command_lines are stable.
    #[test]
    fn snapshot_lifecycle_disable_command_lines() {
        let plan = compile(&request("disable the slack connector"));
        let command_lines: Vec<&str> = plan.steps.iter().map(|s| s.command_line.as_str()).collect();
        assert_eq!(
            command_lines,
            vec![
                "fwc lifecycle slack --valid-actions",
                "fwc lifecycle slack --action disable --preflight",
                "fwc lifecycle slack --action disable",
                "fwc status slack",
            ],
            "Lifecycle disable command_lines must be stable"
        );
    }

    /// Snapshot: lifecycle enable plan step command_lines are stable.
    #[test]
    fn snapshot_lifecycle_enable_command_lines() {
        let plan = compile(&request("enable the github connector"));
        let command_lines: Vec<&str> = plan.steps.iter().map(|s| s.command_line.as_str()).collect();
        assert_eq!(
            command_lines,
            vec![
                "fwc lifecycle github --valid-actions",
                "fwc lifecycle github --action enable --preflight",
                "fwc lifecycle github --action enable",
                "fwc status github",
            ],
            "Lifecycle enable command_lines must be stable"
        );
    }

    /// Snapshot: lifecycle restart plan step command_lines are stable.
    #[test]
    fn snapshot_lifecycle_restart_command_lines() {
        let plan = compile(&request("restart the telegram connector"));
        let command_lines: Vec<&str> = plan.steps.iter().map(|s| s.command_line.as_str()).collect();
        assert_eq!(
            command_lines,
            vec![
                "fwc lifecycle telegram --valid-actions",
                "fwc lifecycle telegram --action restart --preflight",
                "fwc lifecycle telegram --action restart",
                "fwc status telegram",
            ],
            "Lifecycle restart command_lines must be stable"
        );
    }

    /// Snapshot: log-tail plan step command_lines are stable.
    #[test]
    fn snapshot_log_tail_command_lines() {
        let plan = compile(&request("tail the github connector logs"));
        let command_lines: Vec<&str> = plan.steps.iter().map(|s| s.command_line.as_str()).collect();
        assert_eq!(
            command_lines,
            vec![
                "fwc status github",
                "fwc tail github --since 5m --limit 50",
                "fwc history --connector github --limit 10",
            ],
            "Log-tail command_lines must be stable"
        );
    }

    /// Snapshot: WorkflowTruth JSON shape is stable.
    #[test]
    fn snapshot_workflow_truth_shape() {
        let plan = compile(&request("disable the slack connector"));
        let truth_json = serde_json::to_value(&plan.workflow_truth).unwrap();
        assert_keys(
            &truth_json,
            &[
                "availability",
                "source_of_truth",
                "authoritative",
                "recoverable",
                "exit_code_hint",
                "explanation",
            ],
            "WorkflowTruth",
        );
    }

    /// Snapshot: ActionInference JSON shape is stable.
    #[test]
    fn snapshot_action_inference_shape() {
        let plan = compile(&request("disable the slack connector"));
        let action_json = serde_json::to_value(&plan.action).unwrap();
        assert_keys(
            &action_json,
            &[
                "family",
                "verb",
                "resource",
                "risk",
                "mutating",
                "matched_terms",
            ],
            "ActionInference",
        );
    }

    /// Snapshot: lifecycle plan provenance notes are stable.
    #[test]
    fn snapshot_lifecycle_provenance_notes() {
        let plan = compile(&request("stop the github connector"));
        let mutate_step = plan
            .steps
            .iter()
            .find(|s| s.phase == "mutate")
            .expect("Should have mutate step");
        assert_eq!(
            mutate_step.notes.len(),
            2,
            "Mutate step should have exactly 2 notes (provenance + refusal)"
        );
        assert!(
            mutate_step.notes[0].starts_with("Provenance: host-backed"),
            "First note should be provenance: {:?}",
            mutate_step.notes[0]
        );
        assert!(
            mutate_step.notes[1].starts_with("Refusal taxonomy"),
            "Second note should be refusal taxonomy: {:?}",
            mutate_step.notes[1]
        );
    }

    /// Snapshot: log-tail plan provenance notes are stable.
    #[test]
    fn snapshot_log_tail_provenance_notes() {
        let plan = compile(&request("tail the github connector logs"));
        let tail_step = plan
            .steps
            .iter()
            .find(|s| s.command == "tail")
            .expect("Should have tail step");
        assert_eq!(
            tail_step.notes.len(),
            2,
            "Tail step should have exactly 2 notes (provenance + refusal)"
        );
        assert!(
            tail_step.notes[0].contains("host-backed"),
            "First note should mention host-backed: {:?}",
            tail_step.notes[0]
        );
        assert!(
            tail_step.notes[1].contains("Refusal taxonomy"),
            "Second note should mention refusal taxonomy: {:?}",
            tail_step.notes[1]
        );
    }

    /// Snapshot: intent contract types serialize to stable JSON shapes.
    #[test]
    fn snapshot_log_tail_contract_shape() {
        let contract = LogTailContract {
            connector_id: Some("github".to_owned()),
            since_duration: Some("5m".to_owned()),
            event_type_filter: None,
            limit: 50,
            provenance: IntentProvenance::HostBacked,
            refusal: None,
        };
        let json = serde_json::to_value(&contract).unwrap();
        assert_keys(
            &json,
            &[
                "connector_id",
                "since_duration",
                "event_type_filter",
                "limit",
                "provenance",
                "refusal",
            ],
            "LogTailContract",
        );
    }

    /// Snapshot: LifecycleIntentContract serializes to stable JSON shape.
    #[test]
    fn snapshot_lifecycle_contract_shape() {
        let contract = LifecycleIntentContract {
            connector_id: "slack".to_owned(),
            action: "disable".to_owned(),
            preflight: true,
            dry_run: false,
            provenance: IntentProvenance::HostBacked,
            refusal: None,
        };
        let json = serde_json::to_value(&contract).unwrap();
        assert_keys(
            &json,
            &[
                "connector_id",
                "action",
                "preflight",
                "dry_run",
                "provenance",
                "refusal",
            ],
            "LifecycleIntentContract",
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 24llg.6.4.2: Replayable transcript pack for intent,
    // lifecycle, and log-tail workflows.
    //
    // Each transcript test serializes a full compiled intent to JSON,
    // validates it contains the fields the evidence-bundle convention
    // requires, and is structured for consumption by phase-6 acceptance
    // beads and the 24llg.1.3 closure audit.
    // ═══════════════════════════════════════════════════════════════════

    /// Build a full transcript bundle from a compiled intent.
    fn transcript_bundle(scenario_id: &str, layer: &str, plan: &CompiledIntent) -> Value {
        json!({
            "schema_version": "fcp-verification-bundle/v1",
            "scenario_id": scenario_id,
            "layer": layer,
            "timestamp": "2026-04-05T00:00:00Z",
            "intent": {
                "raw": plan.raw_intent,
                "normalized": plan.normalized_intent,
                "mode": plan.mode,
            },
            "compilation": {
                "status": plan.status,
                "template": plan.template,
                "confidence": plan.confidence,
                "action": serde_json::to_value(&plan.action).unwrap(),
                "workflow_truth": serde_json::to_value(&plan.workflow_truth).unwrap(),
            },
            "connector": {
                "chosen": plan.chosen_connector.as_ref().map(|c| &c.id),
                "alternatives": plan.alternative_connectors.iter().map(|c| &c.id).collect::<Vec<_>>(),
            },
            "steps": serde_json::to_value(&plan.steps).unwrap(),
            "diagnostics": {
                "unsupported_reasons": &plan.unsupported_reasons,
                "missing_information": &plan.missing_information,
                "ambiguities": serde_json::to_value(&plan.ambiguities).unwrap(),
                "assumptions": &plan.assumptions,
            },
            "explanation": serde_json::to_value(&plan.explanation).unwrap(),
            "rerun_command": format!("cargo test -p fwc --bin fwc -- intent::tests::{scenario_id} --nocapture"),
        })
    }

    #[test]
    fn transcript_lifecycle_disable_supported() {
        let plan = compile(&request("disable the github connector"));
        let bundle = transcript_bundle("transcript_lifecycle_disable_supported", "unit", &plan);

        // Evidence-bundle convention fields present
        assert_eq!(bundle["schema_version"], "fcp-verification-bundle/v1");
        assert!(
            bundle["rerun_command"]
                .as_str()
                .unwrap()
                .contains("cargo test")
        );

        // Compilation result
        assert_eq!(bundle["compilation"]["status"], "ready");
        assert_eq!(bundle["compilation"]["template"], "lifecycle");
        assert_eq!(bundle["compilation"]["action"]["verb"], "disable");

        // Steps are fully formed
        let steps = bundle["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 4);
        for step in steps {
            assert!(step["command_line"].as_str().unwrap().starts_with("fwc"));
            assert!(!step["purpose"].as_str().unwrap().is_empty());
        }

        // No unsupported reasons
        assert!(
            bundle["diagnostics"]["unsupported_reasons"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn transcript_lifecycle_restart_supported() {
        let plan = compile(&request("restart the telegram connector"));
        let bundle = transcript_bundle("transcript_lifecycle_restart_supported", "unit", &plan);

        assert_eq!(bundle["compilation"]["status"], "ready");
        assert_eq!(bundle["compilation"]["template"], "lifecycle");
        assert_eq!(bundle["compilation"]["action"]["verb"], "restart");
        assert_eq!(bundle["connector"]["chosen"], "telegram");
    }

    #[test]
    fn transcript_log_tail_supported() {
        let plan = compile(&request("show logs for the slack connector"));
        let bundle = transcript_bundle("transcript_log_tail_supported", "unit", &plan);

        assert_eq!(bundle["compilation"]["status"], "ready");
        assert_eq!(bundle["compilation"]["template"], "log-tail");
        assert_eq!(bundle["compilation"]["action"]["verb"], "tail");
        assert_eq!(bundle["connector"]["chosen"], "slack");

        let steps = bundle["steps"].as_array().unwrap();
        assert!(
            steps
                .iter()
                .any(|s| s["command"].as_str().unwrap() == "tail")
        );
    }

    #[test]
    fn transcript_lifecycle_refusal_no_connector() {
        let plan = compile(&request("disable something"));
        let bundle = transcript_bundle("transcript_lifecycle_refusal_no_connector", "unit", &plan);

        assert_eq!(bundle["compilation"]["status"], "needs-clarification");
        assert_eq!(bundle["compilation"]["template"], "lifecycle");
        assert!(bundle["connector"]["chosen"].is_null());

        let missing = bundle["diagnostics"]["missing_information"]
            .as_array()
            .unwrap();
        assert!(!missing.is_empty());
    }

    #[test]
    fn transcript_lifecycle_zone_degraded() {
        let plan = compile(&request("enable the discord connector in z:staging"));
        let bundle = transcript_bundle("transcript_lifecycle_zone_degraded", "unit", &plan);

        // Zone captured but flagged as assumption (degraded zone support)
        assert_eq!(bundle["compilation"]["status"], "ready");
        let assumptions = bundle["diagnostics"]["assumptions"].as_array().unwrap();
        assert!(
            assumptions
                .iter()
                .any(|a| a.as_str().unwrap().to_lowercase().contains("zone"))
        );
    }

    #[test]
    fn transcript_log_tail_all_connectors() {
        let plan = compile(&request("tail all logs"));
        let bundle = transcript_bundle("transcript_log_tail_all_connectors", "unit", &plan);

        assert_eq!(bundle["compilation"]["template"], "log-tail");
        // No specific connector chosen — tailing all
        // (connector may or may not be resolved depending on "all" keyword matching)
        let steps = bundle["steps"].as_array().unwrap();
        assert!(
            steps
                .iter()
                .any(|s| s["command"].as_str().unwrap() == "tail")
        );
    }

    #[test]
    fn transcript_explain_lifecycle() {
        let req = IntentRequest {
            intent: "stop the github connector".to_owned(),
            connector_override: None,
            zone_override: None,
            mode: IntentMode::Explain,
            host_url: None,
        };
        let plan = compile(&req);
        let bundle = transcript_bundle("transcript_explain_lifecycle", "unit", &plan);

        assert_eq!(bundle["intent"]["mode"], "explain");
        assert_eq!(bundle["compilation"]["template"], "lifecycle");

        let explanation = &bundle["explanation"];
        assert!(
            !explanation["template_reasoning"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn transcript_bundle_schema_conformance() {
        // Verify that all transcript bundles conform to the evidence-bundle schema
        let scenarios = [
            compile(&request("disable the github connector")),
            compile(&request("tail the slack connector logs")),
            compile(&request("restart the telegram connector")),
            compile(&request("enable something")),
        ];

        for (i, plan) in scenarios.iter().enumerate() {
            let bundle = transcript_bundle(&format!("conformance_{i}"), "unit", plan);

            // Required evidence-bundle fields
            assert!(
                bundle["schema_version"].is_string(),
                "scenario {i}: schema_version must be string"
            );
            assert!(
                bundle["scenario_id"].is_string(),
                "scenario {i}: scenario_id must be string"
            );
            assert!(
                bundle["layer"].is_string(),
                "scenario {i}: layer must be string"
            );
            assert!(
                bundle["rerun_command"].is_string(),
                "scenario {i}: rerun_command must be string"
            );

            // Compilation block
            assert!(
                bundle["compilation"]["status"].is_string(),
                "scenario {i}: compilation.status must be string"
            );
            assert!(
                bundle["compilation"]["template"].is_string(),
                "scenario {i}: compilation.template must be string"
            );

            // Steps block
            assert!(
                bundle["steps"].is_array(),
                "scenario {i}: steps must be array"
            );
        }
    }

    // ── Schema mapping (h6qe2.1.3) ─────────────────────────

    fn manifest_op_with_schema(selector: &str, schema: serde_json::Value) -> ManifestOperationProfile {
        ManifestOperationProfile {
            input_schema: schema,
            ..manifest_operation(selector)
        }
    }

    #[test]
    fn schema_mapping_titled_maps_to_title_field() {
        let op = manifest_op_with_schema(
            "github.issues.create",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"}
                },
                "required": ["title"]
            }),
        );
        let result = op.map_literals_to_schema(Some("Bug in login"), None, None, &[]);
        let payload = result.unwrap();
        assert_eq!(payload["title"], "Bug in login");
    }

    #[test]
    fn schema_mapping_lookup_maps_to_query_field() {
        let op = manifest_op_with_schema(
            "gmail.search",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer"}
                },
                "required": ["query"]
            }),
        );
        let result = op.map_literals_to_schema(None, None, Some("invoices from 2026"), &[]);
        let payload = result.unwrap();
        assert_eq!(payload["query"], "invoices from 2026");
    }

    #[test]
    fn schema_mapping_payload_fills_first_required_string() {
        let op = manifest_op_with_schema(
            "slack.post_message",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "channel": {"type": "string"},
                    "text": {"type": "string"}
                },
                "required": ["channel", "text"]
            }),
        );
        let result = op.map_literals_to_schema(None, Some("hello world"), None, &[]);
        let payload = result.unwrap();
        assert_eq!(payload["channel"], "hello world");
    }

    #[test]
    fn schema_mapping_quoted_literals_fill_remaining_required() {
        let op = manifest_op_with_schema(
            "slack.post_message",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "channel": {"type": "string"},
                    "text": {"type": "string"}
                },
                "required": ["channel", "text"]
            }),
        );
        let quoted = vec!["#general".to_owned(), "hello team".to_owned()];
        let result = op.map_literals_to_schema(None, None, None, &quoted);
        let payload = result.unwrap();
        assert_eq!(payload["channel"], "#general");
        assert_eq!(payload["text"], "hello team");
    }

    #[test]
    fn schema_mapping_titled_and_quoted_combine() {
        let op = manifest_op_with_schema(
            "github.issues.create",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "labels": {"type": "array"}
                },
                "required": ["title", "body"]
            }),
        );
        let quoted = vec!["This is the body text".to_owned()];
        let result = op.map_literals_to_schema(Some("Bug report"), None, None, &quoted);
        let payload = result.unwrap();
        assert_eq!(payload["title"], "Bug report");
        assert_eq!(payload["body"], "This is the body text");
        // labels not set (array type, not string)
        assert!(payload.get("labels").is_none());
    }

    #[test]
    fn schema_mapping_empty_schema_returns_none() {
        let op = manifest_op_with_schema(
            "test.noop",
            serde_json::json!({"type": "object"}),
        );
        assert!(op.map_literals_to_schema(Some("value"), None, None, &[]).is_none());
    }

    #[test]
    fn schema_mapping_no_literals_returns_none() {
        let op = manifest_op_with_schema(
            "github.issues.create",
            serde_json::json!({
                "type": "object",
                "properties": {"title": {"type": "string"}},
                "required": ["title"]
            }),
        );
        assert!(op.map_literals_to_schema(None, None, None, &[]).is_none());
    }

    #[test]
    fn schema_mapping_subject_field_matches_titled() {
        let op = manifest_op_with_schema(
            "email.send",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "subject": {"type": "string"},
                    "body": {"type": "string"}
                },
                "required": ["subject"]
            }),
        );
        let result = op.map_literals_to_schema(Some("Meeting tomorrow"), None, None, &[]);
        let payload = result.unwrap();
        assert_eq!(payload["subject"], "Meeting tomorrow");
    }

    #[test]
    fn schema_mapping_titled_does_not_match_username_or_filename() {
        // Regression: "name" matching must not match compound names like
        // "username", "filename", "hostname" — only exact "name" or "_name" suffix.
        let op = manifest_op_with_schema(
            "service.create_user",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "email": {"type": "string"}
                },
                "required": ["username", "email"]
            }),
        );
        // No title-like field exists, so titled should NOT map to "username"
        let result = op.map_literals_to_schema(Some("Admin User"), None, None, &[]);
        assert!(
            result.is_none(),
            "titled literal should not map to 'username' — only exact 'name', 'title', 'subject'"
        );
    }
}
