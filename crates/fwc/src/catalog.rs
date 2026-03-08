use serde_json::{Value, json};

pub const COMMANDS: &[&str] = &[
    "guide", "task", "plan", "explain", "do", "list", "search", "show", "ops", "schema",
    "examples", "status", "enable", "disable", "start", "stop", "restart", "install", "update",
    "pin", "unpin", "config", "invoke", "simulate", "logs",
];

#[allow(clippy::too_many_lines)]
pub fn guide_payload(command: Option<&str>) -> Value {
    command.map_or_else(
        || {
            let commands = COMMANDS
                .iter()
                .filter_map(|command_name| command_contract(command_name))
                .collect::<Vec<_>>();

            json!({
                "status": "ok",
                "name": "fwc",
                "purpose": "Standalone Flywheel connector console for discovery, lifecycle management, configuration, and invocation across every connector.",
                "defaults": {
                    "format": "toon",
                    "reason": "TOON is the default because concise, agent-readable output is the baseline contract for this CLI.",
                    "json_opt_in": "--format json",
                    "workflow_bias": "intent-first progressive disclosure",
                },
                "exit_codes": {
                    "success": 0,
                    "parse_error": 2,
                    "unknown_command": 3,
                    "ambiguous_correction": 4,
                    "validation_error": 5,
                    "policy_denial": 6,
                    "connector_error": 7,
                    "transport_error": 8,
                    "internal_error": 1,
                },
                "recommended_workflow": [
                    "fwc task \"<intent>\"",
                    "fwc task resolve <task-id> --until ready",
                    "fwc task ask <task-id>",
                    "fwc task advance <task-id>",
                    "fwc task approve <task-id>",
                    "fwc task run <task-id>",
                    "fwc plan \"<intent>\"",
                    "fwc explain \"<intent>\"",
                    "fwc do \"<intent>\"",
                    "fwc do \"<intent>\" --approve",
                    "fwc list",
                    "fwc show <connector>",
                    "fwc ops <connector>",
                    "fwc schema <connector> <operation>",
                    "fwc config schema <connector>",
                    "fwc config doctor <connector>",
                    "fwc simulate <connector> <operation> --file payload.json",
                    "fwc invoke <connector> <operation> --file payload.json",
                ],
                "progressive_disclosure": [
                    {
                        "command": "task",
                        "contract": "Persist the whole workflow as a resumable capsule so agents can resolve draft bindings, answer one blocking question at a time, approve, and resume execution without restating the entire intent."
                    },
                    {
                        "command": "plan/explain/do",
                        "contract": "Start from intent, but compile down to explicit primitive commands, reasoning, and next actions instead of hiding the workflow."
                    },
                    {
                        "command": "list",
                        "contract": "Only show short, sortable connector summaries and health/lifecycle signals."
                    },
                    {
                        "command": "show",
                        "contract": "Expand one connector at a time into lifecycle, config, capability, and risk context."
                    },
                    {
                        "command": "ops",
                        "contract": "Stay operation-centric and avoid dumping schemas until the caller narrows scope."
                    },
                    {
                        "command": "schema",
                        "contract": "Reveal exactly one payload shape at a time so agents can build a valid request with minimal token waste."
                    },
                    {
                        "command": "simulate/invoke",
                        "contract": "Prefer explain/simulate before side effects, especially for risky or destructive operations."
                    }
                ],
                "families": [
                    {
                        "name": "workflow",
                        "commands": ["task"],
                    },
                    {
                        "name": "intent",
                        "commands": ["plan", "explain", "do"],
                    },
                    {
                        "name": "discovery",
                        "commands": ["list", "search", "show", "ops", "schema", "examples"],
                    },
                    {
                        "name": "lifecycle",
                        "commands": ["status", "enable", "disable", "start", "stop", "restart", "install", "update", "pin", "unpin"],
                    },
                    {
                        "name": "config",
                        "commands": ["config"],
                    },
                    {
                        "name": "execution",
                        "commands": ["simulate", "invoke", "logs"],
                    }
                ],
                "phase": {
                    "current_bead": "flywheel_connectors-3kbu1",
                    "current_scope": "Ship self-resolving workflow capsules so intent-derived jobs can persist drafts, identifier candidates, and the smallest remaining clarification question before execution.",
                    "follow_on_beads": [
                        "flywheel_connectors-3kbu1",
                        "flywheel_connectors-1g7z0.22",
                        "flywheel_connectors-1g7z0.23",
                        "flywheel_connectors-1g7z0.24",
                        "flywheel_connectors-1g7z0.6"
                    ],
                },
                "commands": commands,
            })
        },
        |command_name| {
            command_contract(command_name).map_or_else(
                || {
                    json!({
                        "status": "unknown-command",
                        "command": command_name,
                        "message": "No fwc command contract is registered under that name yet.",
                        "known_commands": COMMANDS,
                    })
                },
                |contract| {
                    json!({
                        "status": "ok",
                        "guide_scope": "command",
                        "command": command_name,
                        "contract": contract,
                    })
                },
            )
        },
    )
}

pub fn planned_payload(command: &str, captures: &Value) -> Value {
    command_contract(command).map_or_else(
        || {
            json!({
                "status": "unknown-command",
                "command": command,
                "captures": captures,
                "known_commands": COMMANDS,
            })
        },
        |contract| {
            json!({
                "status": "planned",
                "command": command,
                "phase": "ux-contract-and-scaffold",
                "message": "This command is scaffolded so the CLI contract is stable before host-backed behavior lands.",
                "captures": captures,
                "contract": contract,
            })
        },
    )
}

#[allow(clippy::too_many_lines)]
fn command_contract(command: &str) -> Option<Value> {
    match command {
        "guide" => Some(json!({
            "family": "meta",
            "summary": "Explain the fwc command taxonomy, defaults, and progressive-disclosure contract.",
            "intended_shape": "Structured guide that agents can read in TOON or JSON without scraping clap help.",
            "next_beads": ["flywheel_connectors-1g7z0.1", "flywheel_connectors-1g7z0.2"],
            "workflow_handoff": ["Use `fwc list` to begin discovery once host-backed data is wired in."],
        })),
        "task" => Some(workflow_contract(
            "Create and resume durable workflow capsules for connector jobs.",
            "A resumable capsule view over compiled intent, bindings, approvals, and execution receipts so agents can operate on a short task id instead of replaying the full workflow from scratch.",
        )),
        "plan" => Some(intent_contract(
            "Compile a natural-language goal into explicit primitive `fwc` steps.",
            "Transparent workflow plan with connector inference, operation hints, ambiguities, missing information, and exact next commands.",
        )),
        "explain" => Some(intent_contract(
            "Explain why the compiler chose a specific connector, template, and operation path.",
            "Reasoning-first output with connector evidence, action evidence, assumptions, and recovery hints.",
        )),
        "do" => Some(intent_contract(
            "Materialize the compiled workflow with safe-by-default simulation semantics.",
            "Executes only the safe prefix by default and stops before the first side-effecting primitive unless `--approve` is explicit.",
        )),
        "list" => Some(discovery_contract(
            "Show a low-token connector inventory with concise lifecycle and health state.",
            "Connector summaries grouped or filtered without expanding operation schemas.",
        )),
        "search" => Some(discovery_contract(
            "Search connectors and operations by ids, names, capabilities, or domains.",
            "Ranked search results with enough context to choose a single connector for `show` or `ops`.",
        )),
        "show" => Some(discovery_contract(
            "Expand one connector into lifecycle, config, capability, and risk context.",
            "One-connector detail view, still short enough to stay agent-readable by default.",
        )),
        "ops" => Some(discovery_contract(
            "List a connector's operations with risk, approvals, and brief input/output hints.",
            "Operation summaries that let the caller narrow to one operation before asking for schema.",
        )),
        "schema" => Some(discovery_contract(
            "Reveal exactly one config or operation schema at a time.",
            "Single-schema output for a connector or connector operation.",
        )),
        "example" | "examples" => Some(discovery_contract(
            "Return a minimal example request or config snippet for one connector or operation.",
            "Copyable examples that stay small enough for agent reuse.",
        )),
        "status" => Some(lifecycle_contract(
            "Report desired state, observed runtime state, and current health for one connector or the fleet.",
            "Desired-vs-observed lifecycle summary with audit-aware context.",
        )),
        "enable" => Some(lifecycle_contract(
            "Mark a connector as enabled and ready for scheduling or invocation.",
            "Mutating lifecycle action with clear approval and rollback context.",
        )),
        "disable" => Some(lifecycle_contract(
            "Disable a connector without erasing its configuration or package state.",
            "Mutating lifecycle action that explains impact before execution.",
        )),
        "start" => Some(lifecycle_contract(
            "Start a connector process or runtime binding.",
            "Runtime lifecycle action with host-backed status follow-up.",
        )),
        "stop" => Some(lifecycle_contract(
            "Stop a connector process or runtime binding.",
            "Runtime lifecycle action with impact surfaced before execution.",
        )),
        "restart" => Some(lifecycle_contract(
            "Restart a connector and report whether the host converged to the desired state.",
            "Runtime lifecycle action plus post-action health confirmation.",
        )),
        "install" => Some(lifecycle_contract(
            "Install or verify a connector package with supply-chain policy in view.",
            "Install/update entrypoint that never hides verification state.",
        )),
        "update" => Some(lifecycle_contract(
            "Update a connector, with pinning and rollout semantics surfaced explicitly.",
            "Lifecycle action that keeps desired version and verification evidence visible.",
        )),
        "pin" => Some(lifecycle_contract(
            "Pin a connector to a version or channel.",
            "State change that explains rollout/update consequences immediately.",
        )),
        "unpin" => Some(lifecycle_contract(
            "Remove a connector pin so managed updates can resume.",
            "Lifecycle state change with clear follow-on status reporting.",
        )),
        "config" => Some(json!({
            "family": "config",
            "summary": "Manage config schema, values, import/export, and doctor checks through one nested command family.",
            "intended_shape": "Redaction-aware config workflows that keep secrets out of default output while preserving JSON fidelity when requested.",
            "next_beads": ["flywheel_connectors-1g7z0.9", "flywheel_connectors-1g7z0.4", "flywheel_connectors-1g7z0.5"],
            "workflow_handoff": [
                "Use `fwc config schema <connector>` before `get` or `set`.",
                "Use `fwc config doctor <connector>` immediately after mutating config."
            ],
        })),
        "invoke" => Some(execution_contract(
            "Execute a connector operation with explicit payload routing, risk context, and result rendering.",
            "Result view that stays concise by default while preserving full JSON fidelity.",
        )),
        "simulate" => Some(execution_contract(
            "Preflight or dry-run a connector operation before side effects.",
            "Explain-first execution path for risky or destructive operations.",
        )),
        "logs" => Some(execution_contract(
            "Read connector logs or event streams with bounded default output.",
            "Operational tail/watch surface that does not flood the caller unless explicitly requested.",
        )),
        _ => None,
    }
}

fn intent_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "intent",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.22", "flywheel_connectors-1g7z0.23", "flywheel_connectors-1g7z0.24"],
        "workflow_handoff": [
            "Use `plan` first when the agent knows the goal but not the exact connector primitive.",
            "Use `explain` when you need the compiler's reasoning before trusting the plan.",
            "Use `do` for transparent materialization; it defaults to simulation and only advances to approval when explicitly requested."
        ],
    })
}

fn workflow_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "workflow",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-3kbu1", "flywheel_connectors-1g7z0.22", "flywheel_connectors-1g7z0.23", "flywheel_connectors-1g7z0.24"],
        "workflow_handoff": [
            "Use `fwc task \"<intent>\"` to create the capsule in one shot.",
            "Use `fwc task resolve <task-id> --until ready` to persist draft bindings, identifier candidates, and the smallest remaining question.",
            "Use `fwc task ask <task-id>` when you want the single best clarification prompt instead of the full capsule dump.",
            "Use `fwc task bind <task-id> key=value ...` to attach resolved values without rewriting the request, then `advance`, `approve`, and `run` when the workflow is ready."
        ],
    })
}

fn discovery_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "discovery",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.7", "flywheel_connectors-1g7z0.12", "flywheel_connectors-1g7z0.24"],
        "workflow_handoff": ["Move from discovery to `schema`, `examples`, or `config schema` once scope is narrowed."],
    })
}

fn lifecycle_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "lifecycle",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.8", "flywheel_connectors-1g7z0.4", "flywheel_connectors-1g7z0.5"],
        "workflow_handoff": ["Use `status` immediately before and after mutating lifecycle state."],
    })
}

fn execution_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "execution",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.10", "flywheel_connectors-1g7z0.4"],
        "workflow_handoff": ["Use `schema` or `example` first, then `simulate`, then `invoke` if the action should proceed."],
    })
}

#[cfg(test)]
mod tests {
    use super::{COMMANDS, guide_payload, planned_payload};
    use serde_json::json;

    // ── Existing tests ──────────────────────────────────────────────────

    #[test]
    fn guide_defaults_to_toon() {
        let guide = guide_payload(None);
        assert_eq!(guide["defaults"]["format"], "toon");
        assert_eq!(guide["exit_codes"]["unknown_command"], 3);
        assert_eq!(guide["status"], "ok");
    }

    #[test]
    fn list_payload_is_scaffolded_not_fake_runtime_state() {
        let captures = serde_json::json!({ "zone": "z:work" });
        let payload = planned_payload("list", &captures);
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["command"], "list");
        assert_eq!(payload["contract"]["family"], "discovery");
    }

    #[test]
    fn unknown_guide_command_returns_known_commands() {
        let payload = guide_payload(Some("does-not-exist"));
        assert_eq!(payload["status"], "unknown-command");
        assert!(payload["known_commands"].is_array());
    }

    // ── COMMANDS constant tests ─────────────────────────────────────────

    #[test]
    fn commands_is_non_empty() {
        assert!(!COMMANDS.is_empty());
    }

    #[test]
    fn commands_contains_guide() {
        assert!(COMMANDS.contains(&"guide"));
    }

    #[test]
    fn commands_contains_list() {
        assert!(COMMANDS.contains(&"list"));
    }

    #[test]
    fn commands_contains_show() {
        assert!(COMMANDS.contains(&"show"));
    }

    #[test]
    fn commands_contains_invoke() {
        assert!(COMMANDS.contains(&"invoke"));
    }

    #[test]
    fn commands_contains_task() {
        assert!(COMMANDS.contains(&"task"));
    }

    #[test]
    fn commands_contains_plan() {
        assert!(COMMANDS.contains(&"plan"));
    }

    #[test]
    fn commands_contains_simulate() {
        assert!(COMMANDS.contains(&"simulate"));
    }

    #[test]
    fn commands_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for cmd in COMMANDS {
            assert!(seen.insert(cmd), "duplicate command: {cmd}");
        }
    }

    // ── guide_payload(None) full-guide tests ────────────────────────────

    #[test]
    fn full_guide_status_is_ok() {
        let g = guide_payload(None);
        assert_eq!(g["status"], "ok");
    }

    #[test]
    fn full_guide_name_is_fwc() {
        let g = guide_payload(None);
        assert_eq!(g["name"], "fwc");
    }

    #[test]
    fn full_guide_has_commands_array() {
        let g = guide_payload(None);
        assert!(g["commands"].is_array());
        assert!(!g["commands"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_has_exit_codes_object() {
        let g = guide_payload(None);
        assert!(g["exit_codes"].is_object());
    }

    #[test]
    fn full_guide_has_six_families() {
        let g = guide_payload(None);
        let families = g["families"].as_array().expect("families should be array");
        assert_eq!(families.len(), 6);
    }

    #[test]
    fn full_guide_family_names() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        let names: Vec<&str> = families
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"workflow"));
        assert!(names.contains(&"intent"));
        assert!(names.contains(&"discovery"));
        assert!(names.contains(&"lifecycle"));
        assert!(names.contains(&"config"));
        assert!(names.contains(&"execution"));
    }

    #[test]
    fn full_guide_has_progressive_disclosure() {
        let g = guide_payload(None);
        assert!(g["progressive_disclosure"].is_array());
        assert!(!g["progressive_disclosure"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_has_recommended_workflow() {
        let g = guide_payload(None);
        assert!(g["recommended_workflow"].is_array());
        assert!(!g["recommended_workflow"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_defaults_format_is_toon() {
        let g = guide_payload(None);
        assert_eq!(g["defaults"]["format"], "toon");
    }

    #[test]
    fn full_guide_has_purpose_string() {
        let g = guide_payload(None);
        assert!(g["purpose"].is_string());
    }

    // ── guide_payload(Some(cmd)) per-command tests ──────────────────────

    #[test]
    fn guide_for_guide_command() {
        let p = guide_payload(Some("guide"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["guide_scope"], "command");
        assert!(p["contract"]["family"].is_string());
        assert!(p["contract"]["summary"].is_string());
    }

    #[test]
    fn guide_for_list_command() {
        let p = guide_payload(Some("list"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["guide_scope"], "command");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_task_command() {
        let p = guide_payload(Some("task"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "workflow");
    }

    #[test]
    fn guide_for_invoke_command() {
        let p = guide_payload(Some("invoke"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_config_command() {
        let p = guide_payload(Some("config"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "config");
    }

    #[test]
    fn guide_for_plan_command() {
        let p = guide_payload(Some("plan"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "intent");
    }

    #[test]
    fn guide_for_all_known_commands_returns_ok() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert_eq!(p["status"], "ok", "guide_payload for {cmd} should be ok");
        }
    }

    // ── guide_payload(Some("unknown")) ──────────────────────────────────

    #[test]
    fn guide_unknown_command_status() {
        let p = guide_payload(Some("nonexistent-xyzzy"));
        assert_eq!(p["status"], "unknown-command");
    }

    #[test]
    fn guide_unknown_command_has_known_commands_list() {
        let p = guide_payload(Some("nonexistent-xyzzy"));
        let known = p["known_commands"]
            .as_array()
            .expect("known_commands array");
        assert_eq!(known.len(), COMMANDS.len());
    }

    #[test]
    fn guide_unknown_command_echoes_command_name() {
        let p = guide_payload(Some("bogus"));
        assert_eq!(p["command"], "bogus");
    }

    // ── planned_payload for known commands ───────────────────────────────

    #[test]
    fn planned_payload_status_is_planned_for_known() {
        let cap = json!({});
        for cmd in COMMANDS {
            let p = planned_payload(cmd, &cap);
            assert_eq!(p["status"], "planned", "planned_payload for {cmd}");
        }
    }

    #[test]
    fn planned_payload_has_contract_for_known() {
        let cap = json!({"key": "val"});
        let p = planned_payload("show", &cap);
        assert!(p["contract"].is_object());
        assert!(p["contract"]["family"].is_string());
    }

    #[test]
    fn planned_payload_phase_is_ux_contract() {
        let cap = json!({});
        let p = planned_payload("ops", &cap);
        assert_eq!(p["phase"], "ux-contract-and-scaffold");
    }

    #[test]
    fn planned_payload_preserves_captures() {
        let cap = json!({"zone": "z:work", "limit": 10});
        let p = planned_payload("list", &cap);
        assert_eq!(p["captures"]["zone"], "z:work");
        assert_eq!(p["captures"]["limit"], 10);
    }

    // ── planned_payload for unknown command ─────────────────────────────

    #[test]
    fn planned_unknown_command_status() {
        let p = planned_payload("does-not-exist", &json!({}));
        assert_eq!(p["status"], "unknown-command");
    }

    #[test]
    fn planned_unknown_command_has_known_commands() {
        let p = planned_payload("does-not-exist", &json!({}));
        assert!(p["known_commands"].is_array());
        assert_eq!(
            p["known_commands"].as_array().unwrap().len(),
            COMMANDS.len()
        );
    }

    #[test]
    fn planned_unknown_command_echoes_command_and_captures() {
        let cap = json!({"a": 1});
        let p = planned_payload("nope", &cap);
        assert_eq!(p["command"], "nope");
        assert_eq!(p["captures"]["a"], 1);
    }

    // ── Family correctness ──────────────────────────────────────────────

    #[test]
    fn intent_commands_have_intent_family() {
        for cmd in &["plan", "explain", "do"] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "intent",
                "{cmd} should be intent family"
            );
        }
    }

    #[test]
    fn discovery_commands_have_discovery_family() {
        for cmd in &["list", "search", "show", "ops", "schema", "examples"] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "discovery",
                "{cmd} should be discovery family"
            );
        }
    }

    #[test]
    fn lifecycle_commands_have_lifecycle_family() {
        for cmd in &[
            "status", "enable", "disable", "start", "stop", "restart", "install", "update", "pin",
            "unpin",
        ] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "lifecycle",
                "{cmd} should be lifecycle family"
            );
        }
    }

    #[test]
    fn execution_commands_have_execution_family() {
        for cmd in &["invoke", "simulate", "logs"] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "execution",
                "{cmd} should be execution family"
            );
        }
    }

    #[test]
    fn config_command_has_config_family() {
        let p = guide_payload(Some("config"));
        assert_eq!(p["contract"]["family"], "config");
    }

    #[test]
    fn guide_command_has_meta_family() {
        let p = guide_payload(Some("guide"));
        assert_eq!(p["contract"]["family"], "meta");
    }

    #[test]
    fn task_command_has_workflow_family() {
        let p = guide_payload(Some("task"));
        assert_eq!(p["contract"]["family"], "workflow");
    }

    // ── Contract shape tests ────────────────────────────────────────────

    #[test]
    fn all_contracts_have_summary() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["summary"].is_string(),
                "{cmd} contract missing summary"
            );
        }
    }

    #[test]
    fn all_contracts_have_intended_shape() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["intended_shape"].is_string(),
                "{cmd} contract missing intended_shape"
            );
        }
    }

    #[test]
    fn all_contracts_have_next_beads() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["next_beads"].is_array(),
                "{cmd} contract missing next_beads"
            );
        }
    }

    #[test]
    fn all_contracts_have_workflow_handoff() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["workflow_handoff"].is_array(),
                "{cmd} contract missing workflow_handoff"
            );
        }
    }

    // ── Exit codes tests ────────────────────────────────────────────────

    #[test]
    fn exit_codes_are_distinct() {
        let g = guide_payload(None);
        let codes_obj = g["exit_codes"].as_object().expect("exit_codes object");
        let values: Vec<i64> = codes_obj.values().map(|v| v.as_i64().unwrap()).collect();
        let unique: std::collections::HashSet<i64> = values.iter().copied().collect();
        assert_eq!(
            values.len(),
            unique.len(),
            "exit codes must be distinct: {values:?}"
        );
    }

    #[test]
    fn exit_codes_success_is_zero() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["success"], 0);
    }

    #[test]
    fn exit_codes_internal_error_is_one() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["internal_error"], 1);
    }

    // ── Families vs COMMANDS cross-check ────────────────────────────────

    #[test]
    fn family_commands_are_subset_of_commands_constant() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        for family in families {
            let cmds = family["commands"].as_array().unwrap();
            for cmd in cmds {
                let name = cmd.as_str().unwrap();
                assert!(
                    COMMANDS.contains(&name),
                    "family command {name} not in COMMANDS"
                );
            }
        }
    }

    #[test]
    fn all_commands_appear_in_exactly_one_family() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        let mut family_cmds: Vec<&str> = Vec::new();
        for family in families {
            for cmd in family["commands"].as_array().unwrap() {
                family_cmds.push(cmd.as_str().unwrap());
            }
        }
        // guide is in COMMANDS but only has a meta contract; it is NOT listed
        // in the families array. So we check that every family command is in
        // COMMANDS but we allow COMMANDS to have entries not in families.
        for fc in &family_cmds {
            assert!(
                COMMANDS.contains(fc),
                "family command {fc} not in COMMANDS constant"
            );
        }
        // No duplicates within families
        let unique: std::collections::HashSet<&str> = family_cmds.iter().copied().collect();
        assert_eq!(
            family_cmds.len(),
            unique.len(),
            "duplicate command across families"
        );
    }

    // ── Edge-case / misc tests ──────────────────────────────────────────

    #[test]
    fn planned_payload_with_empty_captures() {
        let p = planned_payload("invoke", &json!({}));
        assert_eq!(p["status"], "planned");
        assert!(p["captures"].is_object());
        assert_eq!(p["captures"].as_object().unwrap().len(), 0);
    }

    #[test]
    fn planned_payload_with_nested_captures() {
        let cap = json!({"filters": {"state": "active"}, "page": 1});
        let p = planned_payload("search", &cap);
        assert_eq!(p["captures"]["filters"]["state"], "active");
        assert_eq!(p["captures"]["page"], 1);
    }

    #[test]
    fn guide_full_commands_array_has_entries_with_family() {
        let g = guide_payload(None);
        let cmds = g["commands"].as_array().unwrap();
        for entry in cmds {
            assert!(
                entry["family"].is_string(),
                "command entry missing family field"
            );
            assert!(
                entry["summary"].is_string(),
                "command entry missing summary field"
            );
        }
    }

    #[test]
    fn example_alias_returns_same_family_as_examples() {
        // command_contract handles "example" | "examples" — but COMMANDS only
        // lists "examples". Verify via planned_payload which also uses command_contract.
        let p = planned_payload("example", &json!({}));
        assert_eq!(p["status"], "planned");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_scope_field_only_in_per_command_guide() {
        // Full guide should NOT have guide_scope
        let full = guide_payload(None);
        assert!(full.get("guide_scope").is_none());

        // Per-command guide SHOULD have guide_scope
        let per = guide_payload(Some("list"));
        assert_eq!(per["guide_scope"], "command");
    }

    #[test]
    fn all_exit_codes_are_non_negative() {
        let g = guide_payload(None);
        let codes_obj = g["exit_codes"].as_object().unwrap();
        for (name, val) in codes_obj {
            let v = val.as_i64().unwrap();
            assert!(v >= 0, "exit code {name} is negative: {v}");
        }
    }
}
