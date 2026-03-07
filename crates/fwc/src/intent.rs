use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

const SCAFFOLD_NOTICE: &str = "The plan compiler is real, but primitive command execution is still scaffold-backed in this repo state. `fwc` will never claim that external side effects happened unless host-backed execution is actually wired in.";

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
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledIntent {
    pub status: String,
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
    pub ambiguities: Vec<Ambiguity>,
    pub assumptions: Vec<String>,
    pub suggested_command_lines: Vec<String>,
    pub next_actions: Vec<String>,
    pub steps: Vec<CompiledStep>,
    pub explanation: Explanation,
    pub scaffold_notice: String,
}

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
pub struct ActionInference {
    pub family: String,
    pub verb: String,
    pub resource: Option<String>,
    pub risk: String,
    pub mutating: bool,
    pub matched_terms: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Ambiguity {
    pub kind: String,
    pub message: String,
    pub candidates: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
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
        &connector_candidates,
        &action_signals,
    );
    let confidence = confidence_for(&connector_candidates, !plan.ambiguities.is_empty());
    let status = status_for(
        chosen_connector.is_some(),
        &plan.missing_information,
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
        chosen_connector.as_ref(),
        !plan.ambiguities.is_empty(),
        !plan.missing_information.is_empty(),
    );

    CompiledIntent {
        status,
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
        action: ActionInference {
            family: action_signals.family.to_owned(),
            verb: action_signals.verb.to_owned(),
            resource: action_signals.resource.map(str::to_owned),
            risk: action_signals.risk.to_owned(),
            mutating: action_signals.mutating,
            matched_terms: action_signals.matched_terms.clone(),
        },
        operation_hint: plan.operation_hint.take(),
        missing_information: plan.missing_information,
        ambiguities: plan.ambiguities,
        assumptions: plan.assumptions,
        suggested_command_lines,
        next_actions,
        steps: plan.steps,
        explanation: Explanation {
            connector_evidence: connector_evidence(&connector_candidates),
            action_evidence: action_evidence(&action_signals),
            lookup_evidence: plan.lookup_evidence,
            template_reasoning: plan.template_reasoning,
        },
        scaffold_notice: SCAFFOLD_NOTICE.to_owned(),
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
    connector_candidates: &[ConnectorCandidate],
    action: &ActionSignals,
) -> PlanBuild {
    match action.family {
        "lifecycle" => {
            build_lifecycle_plan(request, zone, payload_literal, chosen_connector, action)
        }
        "config" => build_config_plan(request, zone, payload_literal, chosen_connector, action),
        "logs" => build_logs_plan(zone, chosen_connector),
        "discovery" => build_discovery_plan(request, zone, normalized_intent, chosen_connector),
        _ => build_operation_plan(
            request,
            zone,
            literals,
            payload_literal,
            lookup_literal,
            chosen_connector,
            connector_candidates,
            action,
        ),
    }
}

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

    plan.summary = format!(
        "Plan a {} workflow for the `{}` connector.",
        action.verb, connector.id
    );
    plan.template_reasoning.push(
        "Lifecycle verbs map directly onto `status` plus the mutating lifecycle command."
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
                "This placeholder must be replaced with a concrete version or channel before real execution."
                    .to_owned(),
            );
        }
    }

    if matches!(request.mode, IntentMode::DoApprove) {
        plan.assumptions.push(
            "Approval is explicit, but external side effects remain scaffolded until host-backed execution lands."
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
            "Approval is explicit, but config writes remain scaffold-backed in the current repo state."
                .to_owned(),
        );
    }

    plan
}

fn build_logs_plan(zone: Option<&str>, chosen_connector: Option<&ConnectorCandidate>) -> PlanBuild {
    let mut plan = PlanBuild::default();
    let Some(connector) = chosen_connector else {
        "Clarify which connector logs should be inspected.".clone_into(&mut plan.summary);
        plan.missing_information.push(
            "Name the connector explicitly or pass `--connector <id>` for log inspection."
                .to_owned(),
        );
        return plan;
    };

    plan.summary = format!("Plan a log-inspection workflow for `{}`.", connector.id);
    plan.template_reasoning.push(
        "Log-oriented words map directly onto the `logs` primitive, with `status` as a useful preflight."
            .to_owned(),
    );
    plan.steps.push(step(
        1,
        "preflight",
        "Confirm current connector status before log inspection.".to_owned(),
        vec!["fwc".to_owned(), "status".to_owned(), connector.id.clone()],
        false,
        false,
        vec![],
    ));
    let mut argv = vec!["fwc".to_owned(), "logs".to_owned(), connector.id.clone()];
    if zone.is_some() {
        plan.assumptions.push(
            "The current `logs` scaffold has no explicit zone flag; captured zone intent must be enforced later by the host layer."
                .to_owned(),
        );
    }
    argv.push("--follow".to_owned());
    plan.steps.push(step(
        2,
        "inspect",
        "Tail the connector logs or event stream.".to_owned(),
        argv,
        false,
        false,
        vec![],
    ));
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

    let operation_hint =
        infer_operation_hint(&connector.id, action, payload_literal, lookup_literal);
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
                    "Use the search result to replace any placeholder resource identifiers before real execution on `{connector}`."
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
        vec![
            "fwc".to_owned(),
            "invoke".to_owned(),
            connector.id.clone(),
            operation_hint,
            "--file".to_owned(),
            "./intent-payload.json".to_owned(),
        ],
        action.mutating,
        action.mutating,
        vec![
            "This step remains scaffold-backed today; it is still valuable because it proves the exact primitive command shape."
                .to_owned(),
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
            "Approval was explicit, but the final invoke step remains scaffold-backed until host-backed execution is implemented."
                .to_owned(),
        );
    }

    plan
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
        ("disable", "disable"),
        ("enable", "enable"),
        ("restart", "restart"),
        ("start", "start"),
        ("stop", "stop"),
        ("install", "install"),
        ("update", "update"),
        ("pin", "pin"),
        ("unpin", "unpin"),
        ("status", "status"),
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
    static LOGS: &[(&str, &str)] = &[
        ("logs", "logs"),
        ("log", "logs"),
        ("tail", "logs"),
        ("stream", "logs"),
    ];

    if let Some((matched, verb)) = match_first(normalized_intent, LIFECYCLE) {
        return ActionSignals {
            family: "lifecycle",
            verb,
            resource: Some("connector"),
            risk: if verb == "status" { "low" } else { "high" },
            mutating: verb != "status",
            matched_terms: vec![matched.to_owned()],
            needs_lookup: false,
        };
    }

    if let Some((matched, _)) = match_first(normalized_intent, LOGS) {
        return ActionSignals {
            family: "logs",
            verb: "logs",
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
    connector_id: &str,
    action: &ActionSignals,
    payload_literal: Option<&str>,
    lookup_literal: Option<&str>,
) -> String {
    let resource = action.resource.unwrap_or("object");
    match connector_id {
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

    if matches!(request.mode, IntentMode::DoApprove) {
        actions.push(
            "Approval is explicit, but host-backed execution must land before `fwc` can claim real side effects."
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
    let mut profiles = curated_connector_profiles();

    for connector_id in workspace_connector_ids() {
        profiles
            .entry(connector_id.clone())
            .or_insert_with(|| generic_connector_profile(&connector_id));
    }

    profiles.into_values().collect()
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
    }
}

fn generic_connector_profile(id: &str) -> ConnectorProfile {
    let mut aliases = vec![id.to_owned(), id.replace('-', "")];
    aliases.extend(id.split('-').map(str::to_owned));
    ConnectorProfile {
        id: id.to_owned(),
        aliases,
        keywords: id.split('-').map(str::to_owned).collect(),
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

fn status_for(
    has_connector: bool,
    missing_information: &[String],
    ambiguities: &[Ambiguity],
) -> String {
    if !ambiguities.is_empty() {
        "ambiguous".to_owned()
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

fn shell_join(argv: &[String]) -> String {
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
            "Provide the issue title or payload content so the GitHub issue creation step is concrete."
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
    payload_literal: Option<&str>,
    lookup_literal: Option<&str>,
) -> String {
    match verb {
        "search" | "query" | "list" => format!("{resource}s.search"),
        "get" => format!("{resource}s.get"),
        "append" => format!("{resource}s.append"),
        "send" | "comment" => format!("{resource}s.send"),
        "update" => format!("{resource}s.update"),
        "create" if payload_literal.is_some() => format!("{resource}s.create"),
        "create" if lookup_literal.is_some() => format!("{resource}s.resolve-and-create"),
        _ => "objects.invoke".to_owned(),
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
    use super::{IntentMode, IntentRequest, compile, connector_profiles, parse_literals};

    fn request(intent: &str) -> IntentRequest {
        IntentRequest {
            intent: intent.to_owned(),
            connector_override: None,
            zone_override: None,
            mode: IntentMode::Plan,
        }
    }

    #[test]
    fn parse_literals_extracts_quoted_named_and_zone_data() {
        let raw = "find the Notion page named Roadmap in z:work and append \"Summary\"";
        let parsed = parse_literals(raw, &raw.to_lowercase());
        assert_eq!(parsed.named.as_deref(), Some("Roadmap"));
        assert_eq!(parsed.zone.as_deref(), Some("z:work"));
        assert_eq!(parsed.quoted[0], "Summary");
    }

    #[test]
    fn compiler_plans_github_issue_creation() {
        let plan = compile(&request(
            "create a GitHub issue titled \"FWC: add workflow macros\"",
        ));
        assert_eq!(plan.status, "ready");
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
        assert!(
            plan.alternative_connectors
                .iter()
                .any(|candidate| candidate.id == "discord" || candidate.id == "telegram")
        );
    }

    #[test]
    fn compiler_uses_lifecycle_template_for_disable() {
        let plan = compile(&request("disable the slack connector in z:work"));
        assert_eq!(plan.template, "lifecycle");
        assert_eq!(plan.steps[1].command_line, "fwc disable slack");
        assert_eq!(plan.zone.as_deref(), Some("z:work"));
    }

    #[test]
    fn connector_profiles_include_workspace_connectors() {
        let profiles = connector_profiles();
        assert!(profiles.iter().any(|profile| profile.id == "github"));
        assert!(profiles.iter().any(|profile| profile.id == "slack"));
    }
}
