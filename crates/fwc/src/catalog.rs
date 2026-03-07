use serde_json::{Value, json};

const COMMANDS: &[&str] = &[
    "guide", "list", "search", "show", "ops", "schema", "example", "status", "enable", "disable",
    "start", "stop", "restart", "install", "update", "pin", "unpin", "config", "invoke",
    "simulate", "logs",
];

pub fn guide_payload(command: Option<&str>) -> Value {
    match command {
        Some(command_name) => match command_contract(command_name) {
            Some(contract) => json!({
                "status": "ok",
                "guide_scope": "command",
                "command": command_name,
                "contract": contract,
            }),
            None => json!({
                "status": "unknown-command",
                "command": command_name,
                "message": "No fwc command contract is registered under that name yet.",
                "known_commands": COMMANDS,
            }),
        },
        None => {
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
                    "workflow_bias": "progressive-disclosure",
                },
                "recommended_workflow": [
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
                        "name": "discovery",
                        "commands": ["list", "search", "show", "ops", "schema", "example"],
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
                    "current_bead": "flywheel_connectors-1g7z0.1",
                    "current_scope": "Lock the UX contract and scaffold the real fwc command tree.",
                    "follow_on_beads": ["flywheel_connectors-1g7z0.2", "flywheel_connectors-1g7z0.3", "flywheel_connectors-1g7z0.6"],
                },
                "commands": commands,
            })
        }
    }
}

pub fn planned_payload(command: &str, captures: Value) -> Value {
    match command_contract(command) {
        Some(contract) => json!({
            "status": "planned",
            "command": command,
            "phase": "ux-contract-and-scaffold",
            "message": "This command is scaffolded so the CLI contract is stable before host-backed behavior lands.",
            "captures": captures,
            "contract": contract,
        }),
        None => json!({
            "status": "unknown-command",
            "command": command,
            "captures": captures,
            "known_commands": COMMANDS,
        }),
    }
}

fn command_contract(command: &str) -> Option<Value> {
    match command {
        "guide" => Some(json!({
            "family": "meta",
            "summary": "Explain the fwc command taxonomy, defaults, and progressive-disclosure contract.",
            "intended_shape": "Structured guide that agents can read in TOON or JSON without scraping clap help.",
            "next_beads": ["flywheel_connectors-1g7z0.1", "flywheel_connectors-1g7z0.2"],
            "workflow_handoff": ["Use `fwc list` to begin discovery once host-backed data is wired in."],
        })),
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
        "example" => Some(discovery_contract(
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

fn discovery_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "discovery",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.7", "flywheel_connectors-1g7z0.12"],
        "workflow_handoff": ["Move from discovery to `schema`, `example`, or `config schema` once scope is narrowed."],
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
        assert_eq!(guide["status"], "ok");
    }

    #[test]
    fn list_payload_is_scaffolded_not_fake_runtime_state() {
        let payload = planned_payload("list", serde_json::json!({ "zone": "z:work" }));
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
