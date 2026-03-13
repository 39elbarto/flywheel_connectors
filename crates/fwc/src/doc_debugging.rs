//! Debugging, replay, and observability field guide documentation contract (bead 21.4).
//!
//! Encodes debugging techniques, replay guides, and observability checks as
//! testable structures so that the debugging documentation stays accurate.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// A debugging technique with step-by-step instructions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebugTechnique {
    /// Name of the technique.
    pub name: String,
    /// What this technique does.
    pub description: String,
    /// When to use this technique.
    pub when_to_use: String,
    /// Commands to run (in order).
    pub commands: Vec<String>,
    /// Tips for effective use.
    pub tips: Vec<String>,
    /// Related techniques that complement this one.
    pub related_techniques: Vec<String>,
}

/// A guide for replaying historical invocations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayGuide {
    /// Name of the replay scenario.
    pub name: String,
    /// What this replay guide covers.
    pub description: String,
    /// Steps to set up for replay.
    pub setup_steps: Vec<String>,
    /// The replay command to execute.
    pub replay_command: String,
    /// Steps to verify the replay result.
    pub verification_steps: Vec<String>,
}

/// An observability check for monitoring system health.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservabilityCheck {
    /// Name of the check.
    pub name: String,
    /// What this check examines.
    pub what_to_check: String,
    /// The command to run.
    pub command: String,
    /// What the output should look like when healthy.
    pub expected_output: String,
    /// What to do if the check fails.
    pub failure_action: String,
}

/// Complete field guide combining all debugging resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldGuide {
    /// Debugging techniques.
    pub techniques: Vec<DebugTechnique>,
    /// Replay guides.
    pub replay_guides: Vec<ReplayGuide>,
    /// Observability checks.
    pub observability_checks: Vec<ObservabilityCheck>,
}

// ── Data ─────────────────────────────────────────────────────────────────────

/// Returns at least 10 debugging techniques.
#[must_use]
pub fn get_debug_techniques() -> Vec<DebugTechnique> {
    vec![
        DebugTechnique {
            name: "Trace-Based Diagnosis".into(),
            description: "Use distributed tracing to follow a request through the system".into(),
            when_to_use: "When an invocation fails and you need to see where it broke".into(),
            commands: vec![
                "fwc history --connector my-connector --limit 10 --format json".into(),
                "fwc trace <REQUEST_ID> --format json".into(),
            ],
            tips: vec![
                "Look for the first span with an error status".into(),
                "Check timing gaps between spans for latency issues".into(),
                "Compare successful and failed traces for the same operation".into(),
            ],
            related_techniques: vec![
                "Event Stream Analysis".into(),
                "Health Dashboard Review".into(),
            ],
        },
        DebugTechnique {
            name: "Event Stream Analysis".into(),
            description: "Analyze the event stream for patterns and anomalies".into(),
            when_to_use: "When investigating intermittent failures or performance degradation"
                .into(),
            commands: vec![
                "fwc events --connector my-connector --since 1h --format json".into(),
                "fwc events --since 30m --format json".into(),
            ],
            tips: vec![
                "Filter by event type to reduce noise".into(),
                "Look for correlations between error events and time of day".into(),
                "Watch for rate limit events preceding failures".into(),
            ],
            related_techniques: vec![
                "Trace-Based Diagnosis".into(),
                "Rate Limit Detection".into(),
            ],
        },
        DebugTechnique {
            name: "Schema Mismatch Detection".into(),
            description: "Compare expected vs actual input/output schemas to find mismatches"
                .into(),
            when_to_use: "When invocations fail with validation errors".into(),
            commands: vec![
                "fwc schema my-connector my-operation --format json".into(),
                "fwc introspect my-connector --format json".into(),
            ],
            tips: vec![
                "Check if required fields have changed since last successful invocation".into(),
                "Compare schema versions between environments".into(),
                "Look for type changes (string vs number) in field definitions".into(),
            ],
            related_techniques: vec!["History Comparison".into(), "Replay Testing".into()],
        },
        DebugTechnique {
            name: "Health Dashboard Review".into(),
            description: "Comprehensive health check across all connectors".into(),
            when_to_use: "As a first step when something is wrong but you're not sure what".into(),
            commands: vec![
                "fwc health --format table".into(),
                "fwc health --connector my-connector --format json".into(),
                "fwc doctor".into(),
            ],
            tips: vec![
                "Start with the table view for a quick overview".into(),
                "Drill into unhealthy connectors with JSON format for details".into(),
                "Run doctor to check for system-level issues".into(),
            ],
            related_techniques: vec![
                "Network Connectivity Probe".into(),
                "Event Stream Analysis".into(),
            ],
        },
        DebugTechnique {
            name: "Network Connectivity Probe".into(),
            description: "Test network connectivity to upstream APIs".into(),
            when_to_use: "When connectors are timing out or returning connection errors".into(),
            commands: vec![
                "fwc net check my-connector".into(),
                "fwc health --connector my-connector --format json".into(),
            ],
            tips: vec![
                "Check if DNS resolution is working correctly".into(),
                "Verify TLS certificates haven't expired".into(),
                "Test from the same network location as the host".into(),
            ],
            related_techniques: vec![
                "Health Dashboard Review".into(),
                "Trace-Based Diagnosis".into(),
            ],
        },
        DebugTechnique {
            name: "History Comparison".into(),
            description: "Compare successful and failed invocations of the same operation".into(),
            when_to_use: "When an operation that used to work starts failing".into(),
            commands: vec!["fwc history --connector my-connector --limit 50 --format json".into()],
            tips: vec![
                "Sort by timestamp to find when failures started".into(),
                "Compare input payloads between success and failure".into(),
                "Check if credential rotation coincides with failure onset".into(),
            ],
            related_techniques: vec!["Replay Testing".into(), "Schema Mismatch Detection".into()],
        },
        DebugTechnique {
            name: "Replay Testing".into(),
            description: "Reproduce a failure by replaying a historical invocation".into(),
            when_to_use: "When you need to verify if a fix resolves the issue".into(),
            commands: vec![
                "fwc history --connector my-connector --limit 5 --format json".into(),
                "fwc replay <ENTRY_ID>".into(),
            ],
            tips: vec![
                "Replay in a test environment first if the operation has side effects".into(),
                "Use --override-input to test with modified parameters".into(),
                "Compare replay result with original result".into(),
            ],
            related_techniques: vec!["History Comparison".into(), "Trace-Based Diagnosis".into()],
        },
        DebugTechnique {
            name: "Rate Limit Detection".into(),
            description: "Identify if operations are being throttled by rate limits".into(),
            when_to_use: "When operations fail with 429 errors or after bursts of activity".into(),
            commands: vec![
                "fwc events --connector my-connector --since 30m --format json".into(),
                "fwc history --connector my-connector --limit 100 --format json".into(),
            ],
            tips: vec![
                "Look for 429 status codes in event data".into(),
                "Calculate request rate from history timestamps".into(),
                "Check if batch parallelism is too high".into(),
            ],
            related_techniques: vec![
                "Event Stream Analysis".into(),
                "Health Dashboard Review".into(),
            ],
        },
        DebugTechnique {
            name: "Credential Validation".into(),
            description: "Verify that credentials are valid and have correct permissions".into(),
            when_to_use: "When operations fail with authentication or authorization errors".into(),
            commands: vec![
                "fwc credential verify my-connector".into(),
                "fwc invoke my-connector list_items --input '{}' --format json".into(),
            ],
            tips: vec![
                "Check if the token has expired".into(),
                "Verify the token has the required scopes for the operation".into(),
                "Test with a simple read-only operation first".into(),
            ],
            related_techniques: vec![
                "Health Dashboard Review".into(),
                "Schema Mismatch Detection".into(),
            ],
        },
        DebugTechnique {
            name: "Policy Audit".into(),
            description: "Review policy rules that may be blocking operations".into(),
            when_to_use: "When operations are denied that should be allowed".into(),
            commands: vec![
                "fwc policy show --connector my-connector --format json".into(),
                "fwc invoke my-connector my-operation --dry-run".into(),
            ],
            tips: vec![
                "Check if recent policy changes coincide with the problem".into(),
                "Use --dry-run to test without actually invoking".into(),
                "Look for catch-all deny rules that may be too broad".into(),
            ],
            related_techniques: vec![
                "Credential Validation".into(),
                "Event Stream Analysis".into(),
            ],
        },
        DebugTechnique {
            name: "Lifecycle State Inspection".into(),
            description: "Check connector lifecycle state for unexpected transitions".into(),
            when_to_use: "When a connector stops responding or behaves erratically".into(),
            commands: vec![
                "fwc lifecycle status my-connector".into(),
                "fwc events --connector my-connector --since 2h --format json".into(),
            ],
            tips: vec![
                "Look for unexpected state transitions (e.g., enabled -> errored)".into(),
                "Check if automatic restarts are happening".into(),
                "Verify resource limits haven't been exceeded".into(),
            ],
            related_techniques: vec![
                "Health Dashboard Review".into(),
                "Event Stream Analysis".into(),
            ],
        },
    ]
}

/// Returns at least 5 replay guides.
#[must_use]
pub fn get_replay_guides() -> Vec<ReplayGuide> {
    vec![
        ReplayGuide {
            name: "Basic Replay".into(),
            description: "Replay an invocation exactly as it was originally executed".into(),
            setup_steps: vec![
                "Find the entry ID from history: fwc history --limit 10 --format json".into(),
                "Verify the operation is still available: fwc introspect <connector>".into(),
            ],
            replay_command: "fwc replay <ENTRY_ID>".into(),
            verification_steps: vec![
                "Compare output with original invocation result".into(),
                "Check that the status is the same or improved".into(),
            ],
        },
        ReplayGuide {
            name: "Modified Input Replay".into(),
            description: "Replay with modified input parameters to test variations".into(),
            setup_steps: vec![
                "Find the original entry: fwc history --connector <conn> --limit 10 --format json"
                    .into(),
                "Get the original input from history entry".into(),
                "Modify the input JSON as needed".into(),
            ],
            replay_command:
                "fwc replay <ENTRY_ID> --override-input '{\"modified_field\": \"new_value\"}'"
                    .into(),
            verification_steps: vec![
                "Verify the modified input was accepted".into(),
                "Check that output reflects the input changes".into(),
                "Confirm no unintended side effects".into(),
            ],
        },
        ReplayGuide {
            name: "Failure Reproduction".into(),
            description: "Replay a failed invocation to reproduce and diagnose the failure".into(),
            setup_steps: vec![
                "Identify the failed entry from history".into(),
                "Check that the failure conditions still exist".into(),
                "Verify connector health before replay".into(),
            ],
            replay_command: "fwc replay <ENTRY_ID>".into(),
            verification_steps: vec![
                "If failure reproduces: examine error details".into(),
                "If success: the issue was transient".into(),
                "Compare error messages between original and replay".into(),
            ],
        },
        ReplayGuide {
            name: "Post-Fix Verification".into(),
            description: "Replay a previously failing invocation after applying a fix".into(),
            setup_steps: vec![
                "Apply the fix (credential rotation, policy change, etc.)".into(),
                "Verify the fix with fwc doctor or fwc health".into(),
                "Find the original failing entry ID".into(),
            ],
            replay_command: "fwc replay <ENTRY_ID>".into(),
            verification_steps: vec![
                "Verify the replay succeeds where it previously failed".into(),
                "Check trace to confirm the fix was effective".into(),
                "Run multiple replays to confirm consistency".into(),
            ],
        },
        ReplayGuide {
            name: "Batch Replay".into(),
            description: "Replay multiple failed invocations from a batch operation".into(),
            setup_steps: vec![
                "Identify failed entries from the batch: fwc history --limit 100 --format json"
                    .into(),
                "Filter for entries with error status".into(),
                "Verify connector is healthy before replaying".into(),
            ],
            replay_command: "fwc replay <ENTRY_ID_1> && fwc replay <ENTRY_ID_2>".into(),
            verification_steps: vec![
                "Check success rate of replayed operations".into(),
                "Compare with original batch results".into(),
                "Investigate any that still fail".into(),
            ],
        },
        ReplayGuide {
            name: "Cross-Environment Replay".into(),
            description: "Replay an invocation against a different connector instance".into(),
            setup_steps: vec![
                "Find the original entry: fwc history --limit 10".into(),
                "Verify target environment connector is available".into(),
                "Check that credentials for target environment are set".into(),
            ],
            replay_command: "fwc replay <ENTRY_ID> --override-input '{\"_target\": \"staging\"}'"
                .into(),
            verification_steps: vec![
                "Compare output between environments".into(),
                "Verify data consistency across environments".into(),
            ],
        },
    ]
}

/// Returns at least 8 observability checks.
#[must_use]
pub fn get_observability_checks() -> Vec<ObservabilityCheck> {
    vec![
        ObservabilityCheck {
            name: "Connector Health Status".into(),
            what_to_check: "Overall health of all registered connectors".into(),
            command: "fwc health --format json".into(),
            expected_output: "All connectors showing 'healthy' status".into(),
            failure_action: "Investigate unhealthy connectors with fwc events --connector <id>"
                .into(),
        },
        ObservabilityCheck {
            name: "System Diagnostics".into(),
            what_to_check: "FWC system configuration and prerequisites".into(),
            command: "fwc doctor".into(),
            expected_output: "All checks passing with no warnings".into(),
            failure_action: "Run fwc doctor --fix to attempt automatic remediation".into(),
        },
        ObservabilityCheck {
            name: "Event Stream Activity".into(),
            what_to_check: "Whether events are flowing and recent".into(),
            command: "fwc events --since 5m --format json".into(),
            expected_output: "Recent events present with timestamps within the window".into(),
            failure_action:
                "If no events, check if the host process is running and event logging is enabled"
                    .into(),
        },
        ObservabilityCheck {
            name: "Credential Validity".into(),
            what_to_check: "Whether stored credentials are still valid".into(),
            command: "fwc credential verify <CONNECTOR>".into(),
            expected_output: "Verification result: valid".into(),
            failure_action:
                "Rotate credentials: fwc credential set <connector> --token <new_token>".into(),
        },
        ObservabilityCheck {
            name: "Network Connectivity".into(),
            what_to_check: "TCP/TLS connectivity to upstream APIs".into(),
            command: "fwc net check <CONNECTOR>".into(),
            expected_output: "DNS, TCP, and TLS checks all passing".into(),
            failure_action: "Check firewall rules, DNS configuration, and certificate validity"
                .into(),
        },
        ObservabilityCheck {
            name: "Invocation Error Rate".into(),
            what_to_check: "Ratio of failed to successful invocations".into(),
            command: "fwc history --connector <CONNECTOR> --limit 100 --format json".into(),
            expected_output: "Error rate below 5% for healthy operation".into(),
            failure_action: "Investigate common error patterns in recent history".into(),
        },
        ObservabilityCheck {
            name: "Lifecycle State Consistency".into(),
            what_to_check: "Whether connectors are in expected lifecycle states".into(),
            command: "fwc lifecycle status <CONNECTOR>".into(),
            expected_output: "State is 'enabled' for active connectors".into(),
            failure_action: "If errored or disabled unexpectedly, follow restart playbook".into(),
        },
        ObservabilityCheck {
            name: "Policy Enforcement".into(),
            what_to_check: "Whether policies are correctly enforced".into(),
            command: "fwc policy show --format json".into(),
            expected_output: "Policies matching the expected configuration".into(),
            failure_action: "Re-apply policies if they don't match expected state".into(),
        },
        ObservabilityCheck {
            name: "Manifest Integrity".into(),
            what_to_check: "Whether connector manifests are valid and consistent".into(),
            command: "fwc validate connectors/*/manifest.toml".into(),
            expected_output: "All manifests pass validation with no errors".into(),
            failure_action: "Fix manifest validation errors before next deployment".into(),
        },
        ObservabilityCheck {
            name: "Supply Chain Status".into(),
            what_to_check: "Whether connector attestations are valid and current".into(),
            command: "fwc supply-chain verify <CONNECTOR>".into(),
            expected_output: "All attestations valid and signatures verified".into(),
            failure_action: "Rebuild connector with proper signing if attestations fail".into(),
        },
    ]
}

/// Build the complete field guide from all component data.
#[must_use]
pub fn build_field_guide() -> FieldGuide {
    FieldGuide {
        techniques: get_debug_techniques(),
        replay_guides: get_replay_guides(),
        observability_checks: get_observability_checks(),
    }
}

// ── Formatting ───────────────────────────────────────────────────────────────

/// Format a debug technique as a human-readable string.
#[must_use]
pub fn format_technique_toon(technique: &DebugTechnique) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Technique: {}", technique.name);
    let _ = writeln!(out, "{}", technique.description);
    let _ = writeln!(out, "When to use: {}", technique.when_to_use);

    let _ = writeln!(out, "\nCommands:");
    for cmd in &technique.commands {
        let _ = writeln!(out, "  $ {cmd}");
    }

    if !technique.tips.is_empty() {
        let _ = writeln!(out, "\nTips:");
        for tip in &technique.tips {
            let _ = writeln!(out, "  - {tip}");
        }
    }

    if !technique.related_techniques.is_empty() {
        let _ = writeln!(
            out,
            "\nRelated: {}",
            technique.related_techniques.join(", ")
        );
    }

    out
}

/// Format the complete field guide as a human-readable string.
#[must_use]
pub fn format_field_guide_toon(guide: &FieldGuide) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "FWC Debugging Field Guide");
    let _ = writeln!(out, "========================");

    let _ = writeln!(
        out,
        "\n## Debug Techniques ({} total)",
        guide.techniques.len()
    );
    for tech in &guide.techniques {
        let _ = writeln!(out, "\n### {}", tech.name);
        let _ = writeln!(out, "{}", tech.description);
        let _ = writeln!(out, "When: {}", tech.when_to_use);
        for cmd in &tech.commands {
            let _ = writeln!(out, "  $ {cmd}");
        }
    }

    let _ = writeln!(
        out,
        "\n## Replay Guides ({} total)",
        guide.replay_guides.len()
    );
    for rg in &guide.replay_guides {
        let _ = writeln!(out, "\n### {}", rg.name);
        let _ = writeln!(out, "{}", rg.description);
        let _ = writeln!(out, "Command: {}", rg.replay_command);
    }

    let _ = writeln!(
        out,
        "\n## Observability Checks ({} total)",
        guide.observability_checks.len()
    );
    for oc in &guide.observability_checks {
        let _ = writeln!(out, "\n### {}", oc.name);
        let _ = writeln!(out, "Check: {}", oc.what_to_check);
        let _ = writeln!(out, "  $ {}", oc.command);
        let _ = writeln!(out, "Expected: {}", oc.expected_output);
    }

    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;

    // ── Technique count and structure ────────────────────────────────────

    #[test]
    fn techniques_has_at_least_10() {
        let techs = get_debug_techniques();
        assert!(techs.len() >= 10, "Only {} techniques", techs.len());
    }

    #[test]
    fn techniques_have_unique_names() {
        let techs = get_debug_techniques();
        let mut names = std::collections::BTreeSet::new();
        for t in &techs {
            assert!(names.insert(&t.name), "Duplicate name: {}", t.name);
        }
    }

    #[test]
    fn techniques_have_names() {
        for t in &get_debug_techniques() {
            assert!(!t.name.is_empty());
        }
    }

    #[test]
    fn techniques_have_descriptions() {
        for t in &get_debug_techniques() {
            assert!(
                !t.description.is_empty(),
                "Technique {} missing description",
                t.name
            );
        }
    }

    #[test]
    fn techniques_have_when_to_use() {
        for t in &get_debug_techniques() {
            assert!(
                !t.when_to_use.is_empty(),
                "Technique {} missing when_to_use",
                t.name
            );
        }
    }

    #[test]
    fn techniques_have_commands() {
        for t in &get_debug_techniques() {
            assert!(
                !t.commands.is_empty(),
                "Technique {} has no commands",
                t.name
            );
        }
    }

    #[test]
    fn techniques_commands_reference_fwc() {
        for t in &get_debug_techniques() {
            for cmd in &t.commands {
                assert!(
                    cmd.starts_with("fwc"),
                    "Command in {} doesn't start with fwc: {}",
                    t.name,
                    cmd
                );
            }
        }
    }

    #[test]
    fn techniques_have_tips() {
        for t in &get_debug_techniques() {
            assert!(!t.tips.is_empty(), "Technique {} has no tips", t.name);
        }
    }

    #[test]
    fn techniques_have_related() {
        for t in &get_debug_techniques() {
            assert!(
                !t.related_techniques.is_empty(),
                "Technique {} has no related",
                t.name
            );
        }
    }

    #[test]
    fn techniques_commands_non_empty_strings() {
        for t in &get_debug_techniques() {
            for cmd in &t.commands {
                assert!(!cmd.is_empty(), "Empty command in {}", t.name);
            }
        }
    }

    #[test]
    fn techniques_tips_non_empty_strings() {
        for t in &get_debug_techniques() {
            for tip in &t.tips {
                assert!(!tip.is_empty(), "Empty tip in {}", t.name);
            }
        }
    }

    #[test]
    fn techniques_related_non_empty_strings() {
        for t in &get_debug_techniques() {
            for r in &t.related_techniques {
                assert!(!r.is_empty(), "Empty related in {}", t.name);
            }
        }
    }

    // ── Related technique cross-references ───────────────────────────────

    #[test]
    fn techniques_related_reference_valid_names() {
        let techs = get_debug_techniques();
        let names: std::collections::BTreeSet<&str> =
            techs.iter().map(|t| t.name.as_str()).collect();
        for t in &techs {
            for r in &t.related_techniques {
                assert!(
                    names.contains(r.as_str()),
                    "Technique {} references unknown: {}",
                    t.name,
                    r
                );
            }
        }
    }

    // ── Specific technique existence ─────────────────────────────────────

    #[test]
    fn technique_trace_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Trace")));
    }

    #[test]
    fn technique_event_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Event")));
    }

    #[test]
    fn technique_schema_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Schema")));
    }

    #[test]
    fn technique_health_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Health")));
    }

    #[test]
    fn technique_network_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Network")));
    }

    #[test]
    fn technique_replay_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Replay")));
    }

    #[test]
    fn technique_credential_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Credential")));
    }

    // ── Replay guide count and structure ─────────────────────────────────

    #[test]
    fn replay_guides_has_at_least_5() {
        let guides = get_replay_guides();
        assert!(guides.len() >= 5, "Only {} guides", guides.len());
    }

    #[test]
    fn replay_guides_have_unique_names() {
        let guides = get_replay_guides();
        let mut names = std::collections::BTreeSet::new();
        for g in &guides {
            assert!(names.insert(&g.name), "Duplicate name: {}", g.name);
        }
    }

    #[test]
    fn replay_guides_have_names() {
        for g in &get_replay_guides() {
            assert!(!g.name.is_empty());
        }
    }

    #[test]
    fn replay_guides_have_descriptions() {
        for g in &get_replay_guides() {
            assert!(
                !g.description.is_empty(),
                "Guide {} missing description",
                g.name
            );
        }
    }

    #[test]
    fn replay_guides_have_setup_steps() {
        for g in &get_replay_guides() {
            assert!(
                !g.setup_steps.is_empty(),
                "Guide {} has no setup steps",
                g.name
            );
        }
    }

    #[test]
    fn replay_guides_have_replay_command() {
        for g in &get_replay_guides() {
            assert!(
                !g.replay_command.is_empty(),
                "Guide {} has no replay command",
                g.name
            );
        }
    }

    #[test]
    fn replay_guides_commands_reference_fwc() {
        for g in &get_replay_guides() {
            assert!(
                g.replay_command.starts_with("fwc"),
                "Command in {} doesn't start with fwc: {}",
                g.name,
                g.replay_command
            );
        }
    }

    #[test]
    fn replay_guides_have_verification_steps() {
        for g in &get_replay_guides() {
            assert!(
                !g.verification_steps.is_empty(),
                "Guide {} has no verification steps",
                g.name
            );
        }
    }

    #[test]
    fn replay_guides_setup_non_empty_strings() {
        for g in &get_replay_guides() {
            for s in &g.setup_steps {
                assert!(!s.is_empty(), "Empty setup step in {}", g.name);
            }
        }
    }

    #[test]
    fn replay_guides_verification_non_empty_strings() {
        for g in &get_replay_guides() {
            for v in &g.verification_steps {
                assert!(!v.is_empty(), "Empty verification step in {}", g.name);
            }
        }
    }

    // ── Observability check count and structure ──────────────────────────

    #[test]
    fn observability_checks_has_at_least_8() {
        let checks = get_observability_checks();
        assert!(checks.len() >= 8, "Only {} checks", checks.len());
    }

    #[test]
    fn observability_checks_have_unique_names() {
        let checks = get_observability_checks();
        let mut names = std::collections::BTreeSet::new();
        for c in &checks {
            assert!(names.insert(&c.name), "Duplicate name: {}", c.name);
        }
    }

    #[test]
    fn observability_checks_have_names() {
        for c in &get_observability_checks() {
            assert!(!c.name.is_empty());
        }
    }

    #[test]
    fn observability_checks_have_what_to_check() {
        for c in &get_observability_checks() {
            assert!(
                !c.what_to_check.is_empty(),
                "Check {} missing what_to_check",
                c.name
            );
        }
    }

    #[test]
    fn observability_checks_have_commands() {
        for c in &get_observability_checks() {
            assert!(!c.command.is_empty(), "Check {} missing command", c.name);
        }
    }

    #[test]
    fn observability_checks_commands_reference_fwc() {
        for c in &get_observability_checks() {
            assert!(
                c.command.starts_with("fwc"),
                "Command in {} doesn't start with fwc: {}",
                c.name,
                c.command
            );
        }
    }

    #[test]
    fn observability_checks_have_expected_output() {
        for c in &get_observability_checks() {
            assert!(
                !c.expected_output.is_empty(),
                "Check {} missing expected_output",
                c.name
            );
        }
    }

    #[test]
    fn observability_checks_have_failure_action() {
        for c in &get_observability_checks() {
            assert!(
                !c.failure_action.is_empty(),
                "Check {} missing failure_action",
                c.name
            );
        }
    }

    // ── Specific check existence ─────────────────────────────────────────

    #[test]
    fn check_health_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Health")));
    }

    #[test]
    fn check_diagnostics_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Diagnostics")));
    }

    #[test]
    fn check_events_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Event")));
    }

    #[test]
    fn check_credential_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Credential")));
    }

    // ── Field guide ──────────────────────────────────────────────────────

    #[test]
    fn field_guide_has_techniques() {
        let guide = build_field_guide();
        assert!(!guide.techniques.is_empty());
    }

    #[test]
    fn field_guide_has_replay_guides() {
        let guide = build_field_guide();
        assert!(!guide.replay_guides.is_empty());
    }

    #[test]
    fn field_guide_has_observability_checks() {
        let guide = build_field_guide();
        assert!(!guide.observability_checks.is_empty());
    }

    #[test]
    fn field_guide_technique_count_matches() {
        let guide = build_field_guide();
        assert_eq!(guide.techniques.len(), get_debug_techniques().len());
    }

    #[test]
    fn field_guide_replay_count_matches() {
        let guide = build_field_guide();
        assert_eq!(guide.replay_guides.len(), get_replay_guides().len());
    }

    #[test]
    fn field_guide_check_count_matches() {
        let guide = build_field_guide();
        assert_eq!(
            guide.observability_checks.len(),
            get_observability_checks().len()
        );
    }

    // ── Serialization ────────────────────────────────────────────────────

    #[test]
    fn technique_serializes() {
        let t = &get_debug_techniques()[0];
        let json = serde_json::to_string(t).unwrap();
        assert!(json.contains(&t.name));
    }

    #[test]
    fn technique_deserializes_roundtrip() {
        let t = &get_debug_techniques()[0];
        let json = serde_json::to_string(t).unwrap();
        let back: DebugTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t.name, back.name);
    }

    #[test]
    fn replay_guide_serializes() {
        let g = &get_replay_guides()[0];
        let json = serde_json::to_string(g).unwrap();
        assert!(json.contains(&g.name));
    }

    #[test]
    fn replay_guide_deserializes_roundtrip() {
        let g = &get_replay_guides()[0];
        let json = serde_json::to_string(g).unwrap();
        let back: ReplayGuide = serde_json::from_str(&json).unwrap();
        assert_eq!(g.name, back.name);
    }

    #[test]
    fn observability_check_serializes() {
        let c = &get_observability_checks()[0];
        let json = serde_json::to_string(c).unwrap();
        assert!(json.contains(&c.name));
    }

    #[test]
    fn observability_check_deserializes_roundtrip() {
        let c = &get_observability_checks()[0];
        let json = serde_json::to_string(c).unwrap();
        let back: ObservabilityCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(c.name, back.name);
    }

    #[test]
    fn field_guide_serializes() {
        let guide = build_field_guide();
        let json = serde_json::to_string(&guide).unwrap();
        assert!(json.contains("techniques"));
    }

    #[test]
    fn field_guide_deserializes_roundtrip() {
        let guide = build_field_guide();
        let json = serde_json::to_string(&guide).unwrap();
        let back: FieldGuide = serde_json::from_str(&json).unwrap();
        assert_eq!(guide.techniques.len(), back.techniques.len());
    }

    // ── Clone and Debug ──────────────────────────────────────────────────

    #[test]
    fn technique_clone() {
        let t = &get_debug_techniques()[0];
        let cloned = t.clone();
        assert_eq!(t.name, cloned.name);
    }

    #[test]
    fn technique_debug() {
        let t = &get_debug_techniques()[0];
        let dbg = format!("{t:?}");
        assert!(dbg.contains("DebugTechnique"));
    }

    #[test]
    fn replay_guide_clone() {
        let g = &get_replay_guides()[0];
        let cloned = g.clone();
        assert_eq!(g.name, cloned.name);
    }

    #[test]
    fn replay_guide_debug() {
        let g = &get_replay_guides()[0];
        let dbg = format!("{g:?}");
        assert!(dbg.contains("ReplayGuide"));
    }

    #[test]
    fn observability_check_clone() {
        let c = &get_observability_checks()[0];
        let cloned = c.clone();
        assert_eq!(c.name, cloned.name);
    }

    #[test]
    fn observability_check_debug() {
        let c = &get_observability_checks()[0];
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ObservabilityCheck"));
    }

    #[test]
    fn field_guide_clone() {
        let guide = build_field_guide();
        let cloned = guide.clone();
        assert_eq!(guide.techniques.len(), cloned.techniques.len());
    }

    #[test]
    fn field_guide_debug() {
        let guide = build_field_guide();
        let dbg = format!("{guide:?}");
        assert!(dbg.contains("FieldGuide"));
    }

    // ── Format tests ─────────────────────────────────────────────────────

    #[test]
    fn format_technique_toon_contains_name() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains(&t.name));
    }

    #[test]
    fn format_technique_toon_contains_when_to_use() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains("When to use"));
    }

    #[test]
    fn format_technique_toon_contains_commands() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains("Commands:"));
        assert!(out.contains("$"));
    }

    #[test]
    fn format_technique_toon_contains_tips() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains("Tips:"));
    }

    #[test]
    fn format_technique_toon_contains_related() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains("Related:"));
    }

    #[test]
    fn format_field_guide_toon_contains_header() {
        let guide = build_field_guide();
        let out = format_field_guide_toon(&guide);
        assert!(out.contains("FWC Debugging Field Guide"));
    }

    #[test]
    fn format_field_guide_toon_contains_sections() {
        let guide = build_field_guide();
        let out = format_field_guide_toon(&guide);
        assert!(out.contains("Debug Techniques"));
        assert!(out.contains("Replay Guides"));
        assert!(out.contains("Observability Checks"));
    }

    #[test]
    fn format_field_guide_toon_contains_counts() {
        let guide = build_field_guide();
        let out = format_field_guide_toon(&guide);
        assert!(out.contains(&format!("{} total", guide.techniques.len())));
        assert!(out.contains(&format!("{} total", guide.replay_guides.len())));
        assert!(out.contains(&format!("{} total", guide.observability_checks.len())));
    }

    // ── All format without panic ─────────────────────────────────────────

    #[test]
    fn all_techniques_format_without_panic() {
        for t in &get_debug_techniques() {
            let out = format_technique_toon(t);
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn field_guide_format_without_panic() {
        let guide = build_field_guide();
        let out = format_field_guide_toon(&guide);
        assert!(!out.is_empty());
    }
}
