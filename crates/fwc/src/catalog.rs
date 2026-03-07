use serde_json::{Value, json};

pub const COMMANDS: &[&str] = &[
    "guide", "plan", "explain", "do", "list", "search", "show", "ops", "schema", "examples",
    "status", "enable", "disable", "start", "stop", "restart", "install", "update", "pin", "unpin",
    "config", "invoke", "simulate", "logs",
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
                    "current_bead": "flywheel_connectors-1g7z0.22",
                    "current_scope": "Build workflow macros and stronger next-action guidance on top of the new intent compiler and standalone fwc scaffold.",
                    "follow_on_beads": [
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
    use super::{guide_payload, planned_payload};

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
}
