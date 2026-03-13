//! Operator playbooks for lifecycle, config, and recovery documentation contract (bead 21.2).
//!
//! Encodes operator-focused runbooks as testable structures so that operational
//! documentation stays in sync with real FWC commands and procedures.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// A single step in an operator playbook.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorStep {
    /// What the operator does in this step.
    pub action: String,
    /// The FWC command (or shell command) to run.
    pub command: String,
    /// Why this step is needed.
    pub explanation: String,
    /// What to do if this step fails.
    pub on_failure: String,
}

/// A complete operator playbook for a specific scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorPlaybook {
    /// Unique identifier for the playbook.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// The scenario this playbook addresses.
    pub scenario: String,
    /// Ordered steps to follow.
    pub steps: Vec<OperatorStep>,
    /// Hints for recovery if the playbook fails.
    pub recovery_hints: Vec<String>,
    /// Estimated duration to complete (e.g. "5 minutes").
    pub estimated_duration: String,
}

/// A recovery procedure for a specific failure scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryProcedure {
    /// Name of the procedure.
    pub name: String,
    /// Observable symptoms that indicate this procedure is needed.
    pub symptoms: Vec<String>,
    /// Steps to diagnose the root cause.
    pub diagnosis_steps: Vec<String>,
    /// Steps to resolve the issue.
    pub resolution_steps: Vec<String>,
    /// How to prevent recurrence.
    pub prevention: Vec<String>,
}

// ── Playbook Data ────────────────────────────────────────────────────────────

/// Returns at least 10 operator playbooks covering lifecycle, config, and recovery.
#[must_use]
pub fn get_operator_playbooks() -> Vec<OperatorPlaybook> {
    vec![
        OperatorPlaybook {
            id: "op-001".into(),
            title: "Initial Connector Setup".into(),
            scenario: "Setting up a new connector for the first time".into(),
            steps: vec![
                OperatorStep {
                    action: "Verify the connector manifest".into(),
                    command: "fwc validate connectors/my-connector/manifest.toml".into(),
                    explanation: "Ensures the manifest is well-formed before deployment".into(),
                    on_failure: "Fix validation errors reported in output".into(),
                },
                OperatorStep {
                    action: "Store credentials".into(),
                    command: "fwc credential set my-connector --token $API_TOKEN".into(),
                    explanation: "Securely stores the API token in the credential store".into(),
                    on_failure: "Check keyring access: fwc doctor --fix".into(),
                },
                OperatorStep {
                    action: "Verify credentials".into(),
                    command: "fwc credential verify my-connector".into(),
                    explanation: "Confirms credentials are valid by testing against the API".into(),
                    on_failure: "Re-check API token, ensure it has correct scopes".into(),
                },
                OperatorStep {
                    action: "Check health".into(),
                    command: "fwc health --connector my-connector".into(),
                    explanation: "Verify the connector responds correctly".into(),
                    on_failure: "Check network connectivity: fwc net check my-connector".into(),
                },
            ],
            recovery_hints: vec![
                "If credential store fails, try fwc doctor --fix to repair keyring".into(),
                "If health check times out, verify DNS and firewall rules".into(),
            ],
            estimated_duration: "5 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-002".into(),
            title: "Connector Restart After Failure".into(),
            scenario: "A connector has entered an error state and needs to be restarted".into(),
            steps: vec![
                OperatorStep {
                    action: "Check current lifecycle status".into(),
                    command: "fwc lifecycle status my-connector".into(),
                    explanation: "Confirms the connector is in an error state".into(),
                    on_failure: "If status command fails, the host may be down".into(),
                },
                OperatorStep {
                    action: "Review recent events for root cause".into(),
                    command: "fwc events --connector my-connector --since 1h".into(),
                    explanation: "Look for error events that caused the failure".into(),
                    on_failure: "Check host logs directly if events unavailable".into(),
                },
                OperatorStep {
                    action: "Disable the connector".into(),
                    command: "fwc lifecycle disable my-connector".into(),
                    explanation: "Gracefully drain in-flight requests before restart".into(),
                    on_failure: "Force stop may be required if graceful drain times out".into(),
                },
                OperatorStep {
                    action: "Restart the connector".into(),
                    command: "fwc lifecycle restart my-connector".into(),
                    explanation: "Performs a clean restart of the connector process".into(),
                    on_failure: "Check resource limits and connector logs".into(),
                },
                OperatorStep {
                    action: "Verify recovery".into(),
                    command: "fwc health --connector my-connector".into(),
                    explanation: "Confirms the connector is healthy after restart".into(),
                    on_failure: "Escalate: the connector may need manual intervention".into(),
                },
            ],
            recovery_hints: vec![
                "If restart loop detected, check for configuration or credential issues".into(),
                "Review fwc events for patterns that triggered the failure".into(),
            ],
            estimated_duration: "3 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-003".into(),
            title: "Credential Rotation".into(),
            scenario: "API credentials are expiring or compromised and need rotation".into(),
            steps: vec![
                OperatorStep {
                    action: "Verify current credential status".into(),
                    command: "fwc credential verify my-connector".into(),
                    explanation: "Check if current credentials are still valid".into(),
                    on_failure: "Credentials may already be expired".into(),
                },
                OperatorStep {
                    action: "Store new credentials".into(),
                    command: "fwc credential set my-connector --token $NEW_TOKEN".into(),
                    explanation: "Overwrites the old token with the new one".into(),
                    on_failure: "Ensure the new token was generated correctly".into(),
                },
                OperatorStep {
                    action: "Verify new credentials".into(),
                    command: "fwc credential verify my-connector".into(),
                    explanation: "Confirm new credentials work against the API".into(),
                    on_failure: "Roll back to old credentials if new ones fail".into(),
                },
            ],
            recovery_hints: vec![
                "Keep old credentials until new ones are verified".into(),
                "If both old and new fail, re-generate from the service provider".into(),
            ],
            estimated_duration: "2 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-004".into(),
            title: "Policy Update and Verification".into(),
            scenario: "Organization policies changed and connector policies need updating".into(),
            steps: vec![
                OperatorStep {
                    action: "Review current policy".into(),
                    command: "fwc policy show --connector my-connector".into(),
                    explanation: "See what rules are currently in effect".into(),
                    on_failure: "Host must be running for policy queries".into(),
                },
                OperatorStep {
                    action: "Apply new policy rule".into(),
                    command: "fwc policy set deny-destructive --connector my-connector".into(),
                    explanation: "Adds the deny-destructive rule to prevent data loss".into(),
                    on_failure: "Check policy syntax; use fwc policy show for valid rule names"
                        .into(),
                },
                OperatorStep {
                    action: "Verify policy is enforced".into(),
                    command: "fwc invoke my-connector delete_all --dry-run".into(),
                    explanation: "Dry-run a destructive operation to confirm it is blocked".into(),
                    on_failure: "Policy may not have propagated yet; wait and retry".into(),
                },
            ],
            recovery_hints: vec![
                "Policies are applied immediately but may take a moment to propagate".into(),
                "Use fwc policy show to verify the current state".into(),
            ],
            estimated_duration: "3 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-005".into(),
            title: "Batch Operation Monitoring".into(),
            scenario: "A large batch operation is running and needs monitoring".into(),
            steps: vec![
                OperatorStep {
                    action: "Submit the batch".into(),
                    command: "fwc batch jobs.json --parallel 4".into(),
                    explanation: "Starts parallel execution of the batch file".into(),
                    on_failure: "Validate the batch file: fwc validate jobs.json".into(),
                },
                OperatorStep {
                    action: "Monitor progress".into(),
                    command: "fwc history --connector my-connector --limit 50".into(),
                    explanation: "Check recent invocations for completion and errors".into(),
                    on_failure: "If history is unavailable, check host connectivity".into(),
                },
                OperatorStep {
                    action: "Review failures".into(),
                    command: "fwc events --connector my-connector --since 10m".into(),
                    explanation: "Look for error events from the batch operations".into(),
                    on_failure: "Check connector health if events are not flowing".into(),
                },
            ],
            recovery_hints: vec![
                "Failed batch items can be retried individually with fwc replay".into(),
                "Check rate limits if many operations failed simultaneously".into(),
            ],
            estimated_duration: "10 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-006".into(),
            title: "Supply Chain Verification".into(),
            scenario: "Verifying connector integrity before production deployment".into(),
            steps: vec![
                OperatorStep {
                    action: "Verify supply chain attestations".into(),
                    command: "fwc supply-chain verify my-connector".into(),
                    explanation: "Checks SBOM, signatures, and provenance attestations".into(),
                    on_failure: "Do not deploy if verification fails; contact connector author"
                        .into(),
                },
                OperatorStep {
                    action: "Validate manifest".into(),
                    command: "fwc validate connectors/my-connector/manifest.toml".into(),
                    explanation: "Ensure manifest meets all schema requirements".into(),
                    on_failure: "Fix manifest errors before deployment".into(),
                },
                OperatorStep {
                    action: "Run connector benchmarks".into(),
                    command: "fwc bench my-connector --iterations 100".into(),
                    explanation: "Baseline performance characteristics".into(),
                    on_failure: "Poor performance may indicate resource issues".into(),
                },
            ],
            recovery_hints: vec![
                "If attestations are missing, the connector may need to be rebuilt".into(),
                "Check the connector's build pipeline for signing steps".into(),
            ],
            estimated_duration: "5 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-007".into(),
            title: "Network Connectivity Troubleshooting".into(),
            scenario: "A connector cannot reach its upstream API".into(),
            steps: vec![
                OperatorStep {
                    action: "Run network check".into(),
                    command: "fwc net check my-connector".into(),
                    explanation: "Tests DNS resolution, TCP connectivity, and TLS handshake".into(),
                    on_failure: "Network check itself failing suggests host network issues".into(),
                },
                OperatorStep {
                    action: "Check health dashboard".into(),
                    command: "fwc health --format json".into(),
                    explanation: "See if other connectors are also affected".into(),
                    on_failure: "If all connectors are down, check host network stack".into(),
                },
                OperatorStep {
                    action: "Review connector events".into(),
                    command: "fwc events --connector my-connector --since 30m".into(),
                    explanation: "Look for timeout or connection refused errors".into(),
                    on_failure: "Events may be delayed if the host is under load".into(),
                },
                OperatorStep {
                    action: "Test with trace".into(),
                    command: "fwc invoke my-connector ping --input '{}'".into(),
                    explanation: "Attempt a lightweight operation to verify end-to-end".into(),
                    on_failure: "If ping fails, the issue is confirmed upstream".into(),
                },
            ],
            recovery_hints: vec![
                "Check if the upstream API has a status page".into(),
                "Verify firewall rules haven't changed recently".into(),
                "DNS cache may need flushing if endpoints changed".into(),
            ],
            estimated_duration: "5 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-008".into(),
            title: "Connector Upgrade".into(),
            scenario: "Upgrading a connector to a new version".into(),
            steps: vec![
                OperatorStep {
                    action: "Disable the connector".into(),
                    command: "fwc lifecycle disable my-connector".into(),
                    explanation: "Stop accepting new requests during upgrade".into(),
                    on_failure: "Wait for in-flight requests to drain".into(),
                },
                OperatorStep {
                    action: "Validate new manifest".into(),
                    command: "fwc validate connectors/my-connector/manifest.toml".into(),
                    explanation: "Ensure new version's manifest is valid".into(),
                    on_failure: "Do not proceed if validation fails".into(),
                },
                OperatorStep {
                    action: "Verify supply chain".into(),
                    command: "fwc supply-chain verify my-connector".into(),
                    explanation: "Confirm new binary is properly signed".into(),
                    on_failure: "Reject unsigned or tampered binaries".into(),
                },
                OperatorStep {
                    action: "Enable the connector".into(),
                    command: "fwc lifecycle enable my-connector".into(),
                    explanation: "Bring the new version online".into(),
                    on_failure: "Roll back to previous version if enable fails".into(),
                },
                OperatorStep {
                    action: "Smoke test".into(),
                    command: "fwc invoke my-connector list_items --input '{}'".into(),
                    explanation: "Verify basic operation works with new version".into(),
                    on_failure: "Roll back immediately if smoke test fails".into(),
                },
            ],
            recovery_hints: vec![
                "Keep the old binary available for rollback".into(),
                "Compare introspection output before and after upgrade".into(),
            ],
            estimated_duration: "10 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-009".into(),
            title: "System Health Audit".into(),
            scenario: "Periodic health check of all connectors".into(),
            steps: vec![
                OperatorStep {
                    action: "Run system diagnostics".into(),
                    command: "fwc doctor".into(),
                    explanation: "Check for common configuration issues".into(),
                    on_failure: "Fix issues with fwc doctor --fix".into(),
                },
                OperatorStep {
                    action: "Check all connector health".into(),
                    command: "fwc health --format table".into(),
                    explanation: "Overview of all connector health statuses".into(),
                    on_failure: "Investigate unhealthy connectors individually".into(),
                },
                OperatorStep {
                    action: "Review recent events".into(),
                    command: "fwc events --since 24h".into(),
                    explanation: "Look for error patterns across the fleet".into(),
                    on_failure: "Check host logs if event stream is unavailable".into(),
                },
            ],
            recovery_hints: vec![
                "Schedule this audit daily or weekly".into(),
                "Track health trends over time to catch degradation early".into(),
            ],
            estimated_duration: "5 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-010".into(),
            title: "History-Based Incident Investigation".into(),
            scenario: "Investigating a reported issue using invocation history".into(),
            steps: vec![
                OperatorStep {
                    action: "Search history for the timeframe".into(),
                    command: "fwc history --connector my-connector --limit 100".into(),
                    explanation: "Find invocations around the reported incident time".into(),
                    on_failure: "Widen the time window or remove connector filter".into(),
                },
                OperatorStep {
                    action: "Get trace for suspicious invocation".into(),
                    command: "fwc trace <REQUEST_ID>".into(),
                    explanation: "View the full distributed trace".into(),
                    on_failure: "Trace data may have been rotated".into(),
                },
                OperatorStep {
                    action: "Replay the failing invocation".into(),
                    command: "fwc replay <ENTRY_ID>".into(),
                    explanation: "Reproduce the issue with the same inputs".into(),
                    on_failure: "If replay succeeds, the issue may be transient".into(),
                },
                OperatorStep {
                    action: "Check for related failures".into(),
                    command: "fwc events --connector my-connector --since 2h".into(),
                    explanation: "See if the failure pattern affects other operations".into(),
                    on_failure: "Broaden search to all connectors".into(),
                },
            ],
            recovery_hints: vec![
                "Correlate request IDs across multiple connectors".into(),
                "Check if policy changes coincide with the incident timeframe".into(),
            ],
            estimated_duration: "15 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-011".into(),
            title: "Rate Limit Recovery".into(),
            scenario: "A connector is being rate-limited by its upstream API".into(),
            steps: vec![
                OperatorStep {
                    action: "Check connector events for rate limit errors".into(),
                    command: "fwc events --connector my-connector --since 30m".into(),
                    explanation: "Identify 429/rate-limit responses".into(),
                    on_failure: "Check connector logs directly".into(),
                },
                OperatorStep {
                    action: "Review recent invocation volume".into(),
                    command: "fwc history --connector my-connector --limit 200".into(),
                    explanation: "See if invocation rate spiked recently".into(),
                    on_failure: "Check batch job submissions".into(),
                },
                OperatorStep {
                    action: "Temporarily reduce parallelism".into(),
                    command: "fwc policy set max-concurrent=2 --connector my-connector".into(),
                    explanation: "Limit concurrent requests to stay under rate limits".into(),
                    on_failure: "If policy set fails, check host connectivity".into(),
                },
            ],
            recovery_hints: vec![
                "Wait for the rate limit window to reset before resuming full throughput".into(),
                "Consider implementing exponential backoff in batch configurations".into(),
            ],
            estimated_duration: "5 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-012".into(),
            title: "Config Rollback After Bad Change".into(),
            scenario: "A config change broke the connector and needs to be reverted".into(),
            steps: vec![
                OperatorStep {
                    action: "Check current broken config".into(),
                    command: "fwc config get my-connector --json".into(),
                    explanation: "Capture the current (broken) state for reference".into(),
                    on_failure: "Config may not be readable; proceed to export".into(),
                },
                OperatorStep {
                    action: "Export current config before rollback".into(),
                    command: "fwc config export my-connector > backup.json".into(),
                    explanation: "Safety backup in case the rollback itself fails".into(),
                    on_failure: "If export fails, the connector may be in a bad state; use doctor".into(),
                },
                OperatorStep {
                    action: "Import the last known good config".into(),
                    command: "fwc config import my-connector < last_good.json".into(),
                    explanation: "Restores the connector to the previously working configuration".into(),
                    on_failure: "Run fwc config doctor my-connector to diagnose import failure".into(),
                },
                OperatorStep {
                    action: "Verify the rollback worked".into(),
                    command: "fwc status my-connector && fwc invoke my-connector health_check".into(),
                    explanation: "Confirm the connector is healthy with the restored config".into(),
                    on_failure: "If still broken, check fwc history for the original config change and try an earlier backup".into(),
                },
            ],
            recovery_hints: vec![
                "Keep config exports in version control for reliable rollback".into(),
                "Use fwc config doctor before and after changes to catch drift".into(),
            ],
            estimated_duration: "5 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-013".into(),
            title: "Auth Bootstrap for New Connector".into(),
            scenario: "Setting up authentication for a connector from scratch".into(),
            steps: vec![
                OperatorStep {
                    action: "Check what auth the connector needs".into(),
                    command: "fwc schema my-connector --section auth".into(),
                    explanation: "Shows required auth fields (API key, OAuth, etc.)".into(),
                    on_failure: "Check connector README or manifest for auth docs".into(),
                },
                OperatorStep {
                    action: "Add credentials to the store".into(),
                    command: "fwc auth add my-connector --type api_key --token $TOKEN".into(),
                    explanation: "Stores the credential securely in the local keyring".into(),
                    on_failure: "Ensure keyring daemon is running; check fwc doctor".into(),
                },
                OperatorStep {
                    action: "Verify credentials work".into(),
                    command: "fwc auth verify my-connector".into(),
                    explanation: "Tests the stored credentials against the live API".into(),
                    on_failure: "Double-check token value, expiry, and required scopes".into(),
                },
            ],
            recovery_hints: vec![
                "OAuth tokens expire; set up rotation reminders".into(),
                "Use fwc auth status to check credential health regularly".into(),
            ],
            estimated_duration: "3 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-014".into(),
            title: "Auth Repair After Token Expiry".into(),
            scenario: "A connector's auth token has expired and operations are failing".into(),
            steps: vec![
                OperatorStep {
                    action: "Confirm auth is the problem".into(),
                    command: "fwc auth status my-connector".into(),
                    explanation: "Shows credential health: valid, expired, or missing".into(),
                    on_failure: "If status itself fails, the credential store may be corrupted".into(),
                },
                OperatorStep {
                    action: "Remove the expired credential".into(),
                    command: "fwc auth remove my-connector".into(),
                    explanation: "Clears the expired token from the store".into(),
                    on_failure: "If removal fails, try fwc doctor --fix for store repair".into(),
                },
                OperatorStep {
                    action: "Add fresh credentials".into(),
                    command: "fwc auth add my-connector --type api_key --token $NEW_TOKEN".into(),
                    explanation: "Stores the new token".into(),
                    on_failure: "Verify the new token is valid before storing".into(),
                },
                OperatorStep {
                    action: "Verify and test".into(),
                    command: "fwc auth verify my-connector && fwc invoke my-connector list_items --limit 1".into(),
                    explanation: "Confirms the new token works end-to-end".into(),
                    on_failure: "Check token scopes and permissions".into(),
                },
            ],
            recovery_hints: vec![
                "Set up monitoring for auth token expiry before it happens".into(),
                "Use fwc health to detect auth failures in the fleet".into(),
            ],
            estimated_duration: "5 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-015".into(),
            title: "Context/Profile Switching".into(),
            scenario: "Switching between different host environments (staging, production)".into(),
            steps: vec![
                OperatorStep {
                    action: "List available contexts".into(),
                    command: "fwc context list".into(),
                    explanation: "Shows all configured host contexts".into(),
                    on_failure: "Create a context with fwc context create".into(),
                },
                OperatorStep {
                    action: "Check current context".into(),
                    command: "fwc context current".into(),
                    explanation: "Confirms which host you're currently targeting".into(),
                    on_failure: "No context set; use fwc context use <name>".into(),
                },
                OperatorStep {
                    action: "Switch to target context".into(),
                    command: "fwc context use staging".into(),
                    explanation: "All subsequent fwc commands target the staging host".into(),
                    on_failure: "Context may not exist; create it first".into(),
                },
                OperatorStep {
                    action: "Verify the switch".into(),
                    command: "fwc context current && fwc list --limit 3".into(),
                    explanation: "Confirms you see the connectors from the new context".into(),
                    on_failure: "Check host connectivity: fwc doctor".into(),
                },
            ],
            recovery_hints: vec![
                "Always check fwc context current before destructive operations".into(),
                "Use named contexts for every environment to avoid confusion".into(),
            ],
            estimated_duration: "2 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-016".into(),
            title: "Reading Evidence Bundles After Failure".into(),
            scenario: "An operation failed and you need to understand what happened from the evidence".into(),
            steps: vec![
                OperatorStep {
                    action: "Find the failed invocation".into(),
                    command: "fwc history --status failed --limit 5".into(),
                    explanation: "Lists recent failed operations with their entry IDs".into(),
                    on_failure: "If history is empty, check the operation was recorded".into(),
                },
                OperatorStep {
                    action: "Get full invocation detail".into(),
                    command: "fwc history <entry_id> --json".into(),
                    explanation: "Shows the complete evidence: input, output, error, timing, approval status".into(),
                    on_failure: "Entry may have been pruned; check retention settings".into(),
                },
                OperatorStep {
                    action: "Compare with a successful run".into(),
                    command: "fwc compare <failed_id> <success_id>".into(),
                    explanation: "Side-by-side diff shows what differed between success and failure".into(),
                    on_failure: "No prior success to compare; check schema for expected output".into(),
                },
                OperatorStep {
                    action: "Check the error code".into(),
                    command: "fwc history <entry_id> --json | jq '.error_code'".into(),
                    explanation: "Machine-readable error code for programmatic diagnosis".into(),
                    on_failure: "If no error_code, the failure may be unstructured; check raw output".into(),
                },
            ],
            recovery_hints: vec![
                "Error codes like FCP_ERR_AUTH, FCP_ERR_RATE_LIMIT, FCP_ERR_TIMEOUT have specific remediation paths".into(),
                "Use fwc undo <entry_id> to check if the failed operation left partial state".into(),
            ],
            estimated_duration: "5 minutes".into(),
        },
        OperatorPlaybook {
            id: "op-017".into(),
            title: "Drift Recovery After Unexpected State Change".into(),
            scenario: "A connector's live state has drifted from expected configuration".into(),
            steps: vec![
                OperatorStep {
                    action: "Run doctor to detect drift".into(),
                    command: "fwc doctor my-connector".into(),
                    explanation: "Diagnoses state mismatches, config drift, and health issues".into(),
                    on_failure: "If doctor itself fails, the host connection may be down".into(),
                },
                OperatorStep {
                    action: "Export current live state".into(),
                    command: "fwc config export my-connector > live_state.json".into(),
                    explanation: "Captures what the connector currently has".into(),
                    on_failure: "Config may be unreadable; try status first".into(),
                },
                OperatorStep {
                    action: "Diff live state vs expected".into(),
                    command: "fwc config doctor my-connector --diff expected_config.json".into(),
                    explanation: "Shows exactly which fields drifted from the expected config".into(),
                    on_failure: "If no expected config file exists, reconstruct from history".into(),
                },
                OperatorStep {
                    action: "Apply corrective config".into(),
                    command: "fwc config import my-connector < expected_config.json".into(),
                    explanation: "Restores the connector to the desired state".into(),
                    on_failure: "Some fields may be read-only; apply changes individually with fwc config set".into(),
                },
                OperatorStep {
                    action: "Verify drift is resolved".into(),
                    command: "fwc doctor my-connector".into(),
                    explanation: "Doctor should report no issues after correction".into(),
                    on_failure: "Remaining issues may require lifecycle restart".into(),
                },
            ],
            recovery_hints: vec![
                "Store expected configs in version control for drift detection".into(),
                "Run fwc doctor periodically to catch drift early".into(),
                "Use fwc config doctor for config-specific health checks".into(),
            ],
            estimated_duration: "10 minutes".into(),
        },
    ]
}

/// Returns at least 8 recovery procedures for common failure scenarios.
#[must_use]
pub fn get_recovery_procedures() -> Vec<RecoveryProcedure> {
    vec![
        RecoveryProcedure {
            name: "Credential Store Corruption".into(),
            symptoms: vec![
                "fwc credential verify returns 'store error'".into(),
                "fwc doctor reports credential store issues".into(),
                "Invocations fail with 'authentication error'".into(),
            ],
            diagnosis_steps: vec![
                "Run fwc doctor to identify the specific error".into(),
                "Check keyring backend availability".into(),
                "Verify file permissions on credential store path".into(),
            ],
            resolution_steps: vec![
                "Run fwc doctor --fix to attempt automatic repair".into(),
                "Re-set credentials: fwc credential set <connector> --token <token>".into(),
                "If keyring is unavailable, check system keyring service".into(),
            ],
            prevention: vec![
                "Regularly run fwc doctor to catch issues early".into(),
                "Back up credential store configuration".into(),
            ],
        },
        RecoveryProcedure {
            name: "Host Connection Lost".into(),
            symptoms: vec![
                "All host-requiring commands fail with 'connection refused'".into(),
                "fwc health returns no results".into(),
                "Timeouts on invoke and introspect commands".into(),
            ],
            diagnosis_steps: vec![
                "Check if the FCP host process is running".into(),
                "Verify the host address and port configuration".into(),
                "Test basic TCP connectivity to the host".into(),
            ],
            resolution_steps: vec![
                "Restart the FCP host process".into(),
                "Check host configuration file for correct bind address".into(),
                "Verify no other process is using the host port".into(),
            ],
            prevention: vec![
                "Monitor host process with a process supervisor".into(),
                "Set up health check alerts".into(),
            ],
        },
        RecoveryProcedure {
            name: "Connector Crash Loop".into(),
            symptoms: vec![
                "fwc lifecycle status shows repeated restart attempts".into(),
                "Events show rapid start/stop cycles".into(),
                "Invocations intermittently fail".into(),
            ],
            diagnosis_steps: vec![
                "Check fwc events --connector <id> --since 1h for crash patterns".into(),
                "Review connector resource usage".into(),
                "Check if recent configuration changes triggered the loop".into(),
            ],
            resolution_steps: vec![
                "Disable the connector: fwc lifecycle disable <id>".into(),
                "Fix the root cause (config, resources, or bug)".into(),
                "Re-enable: fwc lifecycle enable <id>".into(),
            ],
            prevention: vec![
                "Test configuration changes in a staging environment first".into(),
                "Set resource limits to prevent memory exhaustion crashes".into(),
            ],
        },
        RecoveryProcedure {
            name: "Manifest Validation Failure".into(),
            symptoms: vec![
                "fwc validate reports schema errors".into(),
                "Connector fails to load after manifest edit".into(),
                "Missing or malformed operation definitions".into(),
            ],
            diagnosis_steps: vec![
                "Run fwc validate <manifest> and read error messages carefully".into(),
                "Compare against a known-good manifest".into(),
                "Check for TOML syntax errors (duplicate keys, missing quotes)".into(),
            ],
            resolution_steps: vec![
                "Fix the specific validation errors reported".into(),
                "Use fwc manifest show <connector> to see the parsed result".into(),
                "Re-validate after each fix".into(),
            ],
            prevention: vec![
                "Run fwc validate in CI before merging manifest changes".into(),
                "Use fwc new to scaffold manifests from templates".into(),
            ],
        },
        RecoveryProcedure {
            name: "Pipeline Execution Failure".into(),
            symptoms: vec![
                "Pipeline run exits with non-zero status".into(),
                "Partial results: some steps completed, others did not".into(),
                "Error output referencing a specific step index".into(),
            ],
            diagnosis_steps: vec![
                "Identify the failed step from the error output".into(),
                "Check the step's connector health: fwc health --connector <id>".into(),
                "Validate the pipeline definition: fwc pipeline validate <file>".into(),
            ],
            resolution_steps: vec![
                "Fix the failing step (credential, input, or connector issue)".into(),
                "Re-run the pipeline with --dry-run to verify fixes".into(),
                "Use fwc replay to re-run individual failed steps if needed".into(),
            ],
            prevention: vec![
                "Always validate pipelines before production runs".into(),
                "Add error handling steps to pipeline definitions".into(),
            ],
        },
        RecoveryProcedure {
            name: "Network Timeout Cascade".into(),
            symptoms: vec![
                "Multiple connectors showing timeout errors simultaneously".into(),
                "fwc net check fails for several connectors".into(),
                "Batch operations stalling".into(),
            ],
            diagnosis_steps: vec![
                "Run fwc health to see which connectors are affected".into(),
                "Check if it is a single upstream or multiple upstreams".into(),
                "Test DNS resolution and basic TCP connectivity".into(),
            ],
            resolution_steps: vec![
                "If DNS issue, flush DNS cache and verify resolver config".into(),
                "If proxy issue, check proxy settings and availability".into(),
                "If upstream outage, wait and monitor the status page".into(),
            ],
            prevention: vec![
                "Configure appropriate timeout values per connector".into(),
                "Use circuit breakers to prevent cascade failures".into(),
            ],
        },
        RecoveryProcedure {
            name: "Policy Enforcement Blocking Operations".into(),
            symptoms: vec![
                "Operations that previously worked now return 'denied by policy'".into(),
                "New policy rules were recently applied".into(),
                "Only specific operation types are blocked".into(),
            ],
            diagnosis_steps: vec![
                "Review current policies: fwc policy show --connector <id>".into(),
                "Identify which rule is blocking: check the deny reason in output".into(),
                "Compare against the intended policy configuration".into(),
            ],
            resolution_steps: vec![
                "Adjust the policy rule if it is too restrictive".into(),
                "If the block is intentional, inform the requesting party".into(),
                "Use fwc invoke --dry-run to test without actual execution".into(),
            ],
            prevention: vec![
                "Test policy changes with --dry-run before applying".into(),
                "Document policy changes in a change log".into(),
            ],
        },
        RecoveryProcedure {
            name: "History Database Corruption".into(),
            symptoms: vec![
                "fwc history returns errors or incomplete results".into(),
                "Replay commands fail with 'entry not found'".into(),
                "Trace lookups return partial data".into(),
            ],
            diagnosis_steps: vec![
                "Run fwc doctor to check database integrity".into(),
                "Check disk space and permissions on the data directory".into(),
                "Look for database lock files that may be stale".into(),
            ],
            resolution_steps: vec![
                "Run fwc doctor --fix to attempt automatic repair".into(),
                "If repair fails, restore from the last known-good backup".into(),
                "Clear stale lock files if the database is locked".into(),
            ],
            prevention: vec![
                "Enable regular backups of the history database".into(),
                "Monitor disk space to prevent write failures".into(),
            ],
        },
        RecoveryProcedure {
            name: "Batch Job Stuck".into(),
            symptoms: vec![
                "Batch operation shows no progress for extended time".into(),
                "Some items completed but rest are pending".into(),
                "No error events but no progress either".into(),
            ],
            diagnosis_steps: vec![
                "Check connector health for the batch target".into(),
                "Review events for rate limiting or throttling".into(),
                "Check if parallel limit is too high causing contention".into(),
            ],
            resolution_steps: vec![
                "Reduce batch parallelism if hitting rate limits".into(),
                "Restart stuck items individually with fwc replay".into(),
                "If connector is overloaded, disable and re-enable after cool-down".into(),
            ],
            prevention: vec![
                "Set conservative parallelism limits initially".into(),
                "Monitor batch progress and set timeout thresholds".into(),
            ],
        },
    ]
}

// ── Formatting ───────────────────────────────────────────────────────────────

/// Format a playbook as a human-readable string.
#[must_use]
pub fn format_playbook_toon(playbook: &OperatorPlaybook) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Playbook: {} ({})", playbook.title, playbook.id);
    let _ = writeln!(out, "Scenario: {}", playbook.scenario);
    let _ = writeln!(out, "Estimated duration: {}", playbook.estimated_duration);
    let _ = writeln!(out, "\nSteps:");
    for (i, step) in playbook.steps.iter().enumerate() {
        let _ = writeln!(out, "  {}. {}", i + 1, step.action);
        let _ = writeln!(out, "     $ {}", step.command);
        let _ = writeln!(out, "     {}", step.explanation);
        let _ = writeln!(out, "     On failure: {}", step.on_failure);
    }
    if !playbook.recovery_hints.is_empty() {
        let _ = writeln!(out, "\nRecovery hints:");
        for hint in &playbook.recovery_hints {
            let _ = writeln!(out, "  - {hint}");
        }
    }
    out
}

/// Format a recovery procedure as a human-readable string.
#[must_use]
pub fn format_procedure_toon(procedure: &RecoveryProcedure) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Recovery Procedure: {}", procedure.name);

    let _ = writeln!(out, "\nSymptoms:");
    for s in &procedure.symptoms {
        let _ = writeln!(out, "  - {s}");
    }

    let _ = writeln!(out, "\nDiagnosis:");
    for (i, d) in procedure.diagnosis_steps.iter().enumerate() {
        let _ = writeln!(out, "  {}. {d}", i + 1);
    }

    let _ = writeln!(out, "\nResolution:");
    for (i, r) in procedure.resolution_steps.iter().enumerate() {
        let _ = writeln!(out, "  {}. {r}", i + 1);
    }

    let _ = writeln!(out, "\nPrevention:");
    for p in &procedure.prevention {
        let _ = writeln!(out, "  - {p}");
    }

    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;

    // ── Playbook count and structure ─────────────────────────────────────

    #[test]
    fn playbooks_has_at_least_10() {
        let pbs = get_operator_playbooks();
        assert!(pbs.len() >= 10, "Only {} playbooks", pbs.len());
    }

    #[test]
    fn playbooks_have_unique_ids() {
        let pbs = get_operator_playbooks();
        let mut ids = std::collections::BTreeSet::new();
        for pb in &pbs {
            assert!(ids.insert(&pb.id), "Duplicate id: {}", pb.id);
        }
    }

    #[test]
    fn playbooks_have_titles() {
        for pb in &get_operator_playbooks() {
            assert!(!pb.title.is_empty(), "Playbook {} missing title", pb.id);
        }
    }

    #[test]
    fn playbooks_have_scenarios() {
        for pb in &get_operator_playbooks() {
            assert!(
                !pb.scenario.is_empty(),
                "Playbook {} missing scenario",
                pb.id
            );
        }
    }

    #[test]
    fn playbooks_have_steps() {
        for pb in &get_operator_playbooks() {
            assert!(!pb.steps.is_empty(), "Playbook {} has no steps", pb.id);
        }
    }

    #[test]
    fn playbooks_have_estimated_duration() {
        for pb in &get_operator_playbooks() {
            assert!(
                !pb.estimated_duration.is_empty(),
                "Playbook {} missing duration",
                pb.id
            );
        }
    }

    #[test]
    fn playbooks_steps_have_actions() {
        for pb in &get_operator_playbooks() {
            for step in &pb.steps {
                assert!(
                    !step.action.is_empty(),
                    "Step in {} has empty action",
                    pb.id
                );
            }
        }
    }

    #[test]
    fn playbooks_steps_have_commands() {
        for pb in &get_operator_playbooks() {
            for step in &pb.steps {
                assert!(
                    !step.command.is_empty(),
                    "Step in {} has empty command",
                    pb.id
                );
            }
        }
    }

    #[test]
    fn playbooks_steps_have_explanations() {
        for pb in &get_operator_playbooks() {
            for step in &pb.steps {
                assert!(
                    !step.explanation.is_empty(),
                    "Step in {} has empty explanation",
                    pb.id
                );
            }
        }
    }

    #[test]
    fn playbooks_steps_have_on_failure() {
        for pb in &get_operator_playbooks() {
            for step in &pb.steps {
                assert!(
                    !step.on_failure.is_empty(),
                    "Step in {} has empty on_failure",
                    pb.id
                );
            }
        }
    }

    #[test]
    fn playbooks_commands_reference_fwc() {
        for pb in &get_operator_playbooks() {
            for step in &pb.steps {
                assert!(
                    step.command.starts_with("fwc"),
                    "Command in {} doesn't start with fwc: {}",
                    pb.id,
                    step.command
                );
            }
        }
    }

    // ── Recovery procedures count and structure ──────────────────────────

    #[test]
    fn procedures_has_at_least_8() {
        let procs = get_recovery_procedures();
        assert!(procs.len() >= 8, "Only {} procedures", procs.len());
    }

    #[test]
    fn procedures_have_names() {
        for proc in &get_recovery_procedures() {
            assert!(!proc.name.is_empty());
        }
    }

    #[test]
    fn procedures_have_unique_names() {
        let procs = get_recovery_procedures();
        let mut names = std::collections::BTreeSet::new();
        for p in &procs {
            assert!(names.insert(&p.name), "Duplicate name: {}", p.name);
        }
    }

    #[test]
    fn procedures_have_symptoms() {
        for proc in &get_recovery_procedures() {
            assert!(
                !proc.symptoms.is_empty(),
                "Procedure {} has no symptoms",
                proc.name
            );
        }
    }

    #[test]
    fn procedures_have_diagnosis_steps() {
        for proc in &get_recovery_procedures() {
            assert!(
                !proc.diagnosis_steps.is_empty(),
                "Procedure {} has no diagnosis",
                proc.name
            );
        }
    }

    #[test]
    fn procedures_have_resolution_steps() {
        for proc in &get_recovery_procedures() {
            assert!(
                !proc.resolution_steps.is_empty(),
                "Procedure {} has no resolution",
                proc.name
            );
        }
    }

    #[test]
    fn procedures_have_prevention() {
        for proc in &get_recovery_procedures() {
            assert!(
                !proc.prevention.is_empty(),
                "Procedure {} has no prevention",
                proc.name
            );
        }
    }

    #[test]
    fn procedures_symptoms_non_empty_strings() {
        for proc in &get_recovery_procedures() {
            for s in &proc.symptoms {
                assert!(!s.is_empty(), "Empty symptom in {}", proc.name);
            }
        }
    }

    #[test]
    fn procedures_diagnosis_non_empty_strings() {
        for proc in &get_recovery_procedures() {
            for d in &proc.diagnosis_steps {
                assert!(!d.is_empty(), "Empty diagnosis step in {}", proc.name);
            }
        }
    }

    #[test]
    fn procedures_resolution_non_empty_strings() {
        for proc in &get_recovery_procedures() {
            for r in &proc.resolution_steps {
                assert!(!r.is_empty(), "Empty resolution step in {}", proc.name);
            }
        }
    }

    #[test]
    fn procedures_prevention_non_empty_strings() {
        for proc in &get_recovery_procedures() {
            for p in &proc.prevention {
                assert!(!p.is_empty(), "Empty prevention item in {}", proc.name);
            }
        }
    }

    // ── Serialization ────────────────────────────────────────────────────

    #[test]
    fn playbook_serializes() {
        let pb = &get_operator_playbooks()[0];
        let json = serde_json::to_string(pb).unwrap();
        assert!(json.contains(&pb.id));
    }

    #[test]
    fn playbook_deserializes_roundtrip() {
        let pb = &get_operator_playbooks()[0];
        let json = serde_json::to_string(pb).unwrap();
        let back: OperatorPlaybook = serde_json::from_str(&json).unwrap();
        assert_eq!(pb.id, back.id);
        assert_eq!(pb.title, back.title);
    }

    #[test]
    fn procedure_serializes() {
        let proc = &get_recovery_procedures()[0];
        let json = serde_json::to_string(proc).unwrap();
        assert!(json.contains(&proc.name));
    }

    #[test]
    fn procedure_deserializes_roundtrip() {
        let proc = &get_recovery_procedures()[0];
        let json = serde_json::to_string(proc).unwrap();
        let back: RecoveryProcedure = serde_json::from_str(&json).unwrap();
        assert_eq!(proc.name, back.name);
    }

    #[test]
    fn operator_step_serializes() {
        let step = &get_operator_playbooks()[0].steps[0];
        let json = serde_json::to_string(step).unwrap();
        assert!(json.contains("action"));
    }

    #[test]
    fn operator_step_deserializes_roundtrip() {
        let step = &get_operator_playbooks()[0].steps[0];
        let json = serde_json::to_string(step).unwrap();
        let back: OperatorStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step.action, back.action);
    }

    // ── Clone and Debug ──────────────────────────────────────────────────

    #[test]
    fn playbook_clone() {
        let pb = &get_operator_playbooks()[0];
        let cloned = pb.clone();
        assert_eq!(pb.id, cloned.id);
    }

    #[test]
    fn playbook_debug() {
        let pb = &get_operator_playbooks()[0];
        let dbg = format!("{pb:?}");
        assert!(dbg.contains("OperatorPlaybook"));
    }

    #[test]
    fn procedure_clone() {
        let proc = &get_recovery_procedures()[0];
        let cloned = proc.clone();
        assert_eq!(proc.name, cloned.name);
    }

    #[test]
    fn procedure_debug() {
        let proc = &get_recovery_procedures()[0];
        let dbg = format!("{proc:?}");
        assert!(dbg.contains("RecoveryProcedure"));
    }

    #[test]
    fn operator_step_clone() {
        let step = &get_operator_playbooks()[0].steps[0];
        let cloned = step.clone();
        assert_eq!(step.action, cloned.action);
    }

    #[test]
    fn operator_step_debug() {
        let step = &get_operator_playbooks()[0].steps[0];
        let dbg = format!("{step:?}");
        assert!(dbg.contains("OperatorStep"));
    }

    // ── Format tests ─────────────────────────────────────────────────────

    #[test]
    fn format_playbook_toon_contains_title() {
        let pb = &get_operator_playbooks()[0];
        let out = format_playbook_toon(pb);
        assert!(out.contains(&pb.title));
    }

    #[test]
    fn format_playbook_toon_contains_id() {
        let pb = &get_operator_playbooks()[0];
        let out = format_playbook_toon(pb);
        assert!(out.contains(&pb.id));
    }

    #[test]
    fn format_playbook_toon_contains_scenario() {
        let pb = &get_operator_playbooks()[0];
        let out = format_playbook_toon(pb);
        assert!(out.contains(&pb.scenario));
    }

    #[test]
    fn format_playbook_toon_contains_steps() {
        let pb = &get_operator_playbooks()[0];
        let out = format_playbook_toon(pb);
        assert!(out.contains("Steps:"));
        assert!(out.contains("1."));
    }

    #[test]
    fn format_playbook_toon_contains_commands() {
        let pb = &get_operator_playbooks()[0];
        let out = format_playbook_toon(pb);
        assert!(out.contains("$"));
    }

    #[test]
    fn format_playbook_toon_contains_recovery_hints() {
        let pb = &get_operator_playbooks()[0];
        let out = format_playbook_toon(pb);
        assert!(out.contains("Recovery hints"));
    }

    #[test]
    fn format_playbook_toon_contains_duration() {
        let pb = &get_operator_playbooks()[0];
        let out = format_playbook_toon(pb);
        assert!(out.contains(&pb.estimated_duration));
    }

    #[test]
    fn format_procedure_toon_contains_name() {
        let proc = &get_recovery_procedures()[0];
        let out = format_procedure_toon(proc);
        assert!(out.contains(&proc.name));
    }

    #[test]
    fn format_procedure_toon_contains_symptoms() {
        let proc = &get_recovery_procedures()[0];
        let out = format_procedure_toon(proc);
        assert!(out.contains("Symptoms"));
    }

    #[test]
    fn format_procedure_toon_contains_diagnosis() {
        let proc = &get_recovery_procedures()[0];
        let out = format_procedure_toon(proc);
        assert!(out.contains("Diagnosis"));
    }

    #[test]
    fn format_procedure_toon_contains_resolution() {
        let proc = &get_recovery_procedures()[0];
        let out = format_procedure_toon(proc);
        assert!(out.contains("Resolution"));
    }

    #[test]
    fn format_procedure_toon_contains_prevention() {
        let proc = &get_recovery_procedures()[0];
        let out = format_procedure_toon(proc);
        assert!(out.contains("Prevention"));
    }

    // ── Content-specific tests ───────────────────────────────────────────

    #[test]
    fn playbook_initial_setup_exists() {
        let pbs = get_operator_playbooks();
        assert!(
            pbs.iter()
                .any(|pb| pb.title.contains("Initial Connector Setup"))
        );
    }

    #[test]
    fn playbook_restart_exists() {
        let pbs = get_operator_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Restart")));
    }

    #[test]
    fn playbook_credential_rotation_exists() {
        let pbs = get_operator_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Credential")));
    }

    #[test]
    fn playbook_policy_update_exists() {
        let pbs = get_operator_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Policy")));
    }

    #[test]
    fn playbook_upgrade_exists() {
        let pbs = get_operator_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Upgrade")));
    }

    #[test]
    fn procedure_credential_corruption_exists() {
        let procs = get_recovery_procedures();
        assert!(procs.iter().any(|p| p.name.contains("Credential")));
    }

    #[test]
    fn procedure_host_connection_exists() {
        let procs = get_recovery_procedures();
        assert!(procs.iter().any(|p| p.name.contains("Host")));
    }

    #[test]
    fn procedure_crash_loop_exists() {
        let procs = get_recovery_procedures();
        assert!(procs.iter().any(|p| p.name.contains("Crash Loop")));
    }

    #[test]
    fn procedure_network_exists() {
        let procs = get_recovery_procedures();
        assert!(procs.iter().any(|p| p.name.contains("Network")));
    }

    // ── Playbook step count tests ────────────────────────────────────────

    #[test]
    fn playbooks_have_at_least_3_steps() {
        for pb in &get_operator_playbooks() {
            assert!(
                pb.steps.len() >= 3,
                "Playbook {} has only {} steps",
                pb.id,
                pb.steps.len()
            );
        }
    }

    #[test]
    fn procedures_have_at_least_2_symptoms() {
        for proc in &get_recovery_procedures() {
            assert!(
                proc.symptoms.len() >= 2,
                "Procedure {} has only {} symptoms",
                proc.name,
                proc.symptoms.len()
            );
        }
    }

    #[test]
    fn procedures_have_at_least_2_diagnosis_steps() {
        for proc in &get_recovery_procedures() {
            assert!(
                proc.diagnosis_steps.len() >= 2,
                "Procedure {} has only {} diagnosis steps",
                proc.name,
                proc.diagnosis_steps.len()
            );
        }
    }

    #[test]
    fn procedures_have_at_least_2_resolution_steps() {
        for proc in &get_recovery_procedures() {
            assert!(
                proc.resolution_steps.len() >= 2,
                "Procedure {} has only {} resolution steps",
                proc.name,
                proc.resolution_steps.len()
            );
        }
    }

    // ── Format all playbooks ─────────────────────────────────────────────

    #[test]
    fn all_playbooks_format_without_panic() {
        for pb in &get_operator_playbooks() {
            let out = format_playbook_toon(pb);
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn all_procedures_format_without_panic() {
        for proc in &get_recovery_procedures() {
            let out = format_procedure_toon(proc);
            assert!(!out.is_empty());
        }
    }

    // ── Additional coverage ──────────────────────────────────────────────

    #[test]
    fn playbook_health_audit_exists() {
        let pbs = get_operator_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Health Audit")));
    }

    #[test]
    fn playbook_incident_investigation_exists() {
        let pbs = get_operator_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Incident")));
    }

    #[test]
    fn playbook_rate_limit_exists() {
        let pbs = get_operator_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Rate Limit")));
    }

    #[test]
    fn playbook_batch_monitoring_exists() {
        let pbs = get_operator_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Batch")));
    }

    #[test]
    fn procedure_pipeline_failure_exists() {
        let procs = get_recovery_procedures();
        assert!(procs.iter().any(|p| p.name.contains("Pipeline")));
    }

    #[test]
    fn procedure_history_corruption_exists() {
        let procs = get_recovery_procedures();
        assert!(procs.iter().any(|p| p.name.contains("History")));
    }

    #[test]
    fn procedure_policy_blocking_exists() {
        let procs = get_recovery_procedures();
        assert!(procs.iter().any(|p| p.name.contains("Policy")));
    }

    #[test]
    fn procedure_batch_stuck_exists() {
        let procs = get_recovery_procedures();
        assert!(procs.iter().any(|p| p.name.contains("Batch")));
    }

    // ── New playbook coverage ───────────────────────────────────────────

    #[test]
    fn playbook_config_rollback_exists() {
        let playbooks = get_operator_playbooks();
        assert!(
            playbooks
                .iter()
                .any(|p| p.title.contains("Config Rollback"))
        );
    }

    #[test]
    fn playbook_config_rollback_has_export_step() {
        let playbooks = get_operator_playbooks();
        let pb = playbooks
            .iter()
            .find(|p| p.title.contains("Config Rollback"))
            .unwrap();
        assert!(pb.steps.iter().any(|s| s.command.contains("config export")));
    }

    #[test]
    fn playbook_config_rollback_has_import_step() {
        let playbooks = get_operator_playbooks();
        let pb = playbooks
            .iter()
            .find(|p| p.title.contains("Config Rollback"))
            .unwrap();
        assert!(pb.steps.iter().any(|s| s.command.contains("config import")));
    }

    #[test]
    fn playbook_auth_bootstrap_exists() {
        let playbooks = get_operator_playbooks();
        assert!(playbooks.iter().any(|p| p.title.contains("Auth Bootstrap")));
    }

    #[test]
    fn playbook_auth_bootstrap_includes_verify() {
        let playbooks = get_operator_playbooks();
        let pb = playbooks
            .iter()
            .find(|p| p.title.contains("Auth Bootstrap"))
            .unwrap();
        assert!(pb.steps.iter().any(|s| s.command.contains("auth verify")));
    }

    #[test]
    fn playbook_auth_repair_exists() {
        let playbooks = get_operator_playbooks();
        assert!(playbooks.iter().any(|p| p.title.contains("Auth Repair")));
    }

    #[test]
    fn playbook_auth_repair_includes_remove_and_add() {
        let playbooks = get_operator_playbooks();
        let pb = playbooks
            .iter()
            .find(|p| p.title.contains("Auth Repair"))
            .unwrap();
        assert!(pb.steps.iter().any(|s| s.command.contains("auth remove")));
        assert!(pb.steps.iter().any(|s| s.command.contains("auth add")));
    }

    #[test]
    fn playbook_context_switching_exists() {
        let playbooks = get_operator_playbooks();
        assert!(
            playbooks
                .iter()
                .any(|p| p.title.contains("Context") || p.title.contains("Profile"))
        );
    }

    #[test]
    fn playbook_context_switching_uses_context_commands() {
        let playbooks = get_operator_playbooks();
        let pb = playbooks
            .iter()
            .find(|p| p.title.contains("Context") || p.title.contains("Profile"))
            .unwrap();
        assert!(pb.steps.iter().any(|s| s.command.contains("context")));
    }

    #[test]
    fn playbook_evidence_bundles_exists() {
        let playbooks = get_operator_playbooks();
        assert!(playbooks.iter().any(|p| p.title.contains("Evidence")));
    }

    #[test]
    fn playbook_evidence_bundles_uses_history_and_compare() {
        let playbooks = get_operator_playbooks();
        let pb = playbooks
            .iter()
            .find(|p| p.title.contains("Evidence"))
            .unwrap();
        assert!(pb.steps.iter().any(|s| s.command.contains("history")));
        assert!(pb.steps.iter().any(|s| s.command.contains("compare")));
    }

    #[test]
    fn playbook_drift_recovery_exists() {
        let playbooks = get_operator_playbooks();
        assert!(playbooks.iter().any(|p| p.title.contains("Drift")));
    }

    #[test]
    fn playbook_drift_recovery_uses_doctor() {
        let playbooks = get_operator_playbooks();
        let pb = playbooks
            .iter()
            .find(|p| p.title.contains("Drift"))
            .unwrap();
        assert!(pb.steps.iter().any(|s| s.command.contains("doctor")));
    }

    #[test]
    fn playbook_drift_recovery_has_verify_step() {
        let playbooks = get_operator_playbooks();
        let pb = playbooks
            .iter()
            .find(|p| p.title.contains("Drift"))
            .unwrap();
        // Last step should verify drift is resolved
        assert!(pb.steps.last().unwrap().command.contains("doctor"));
    }

    #[test]
    fn all_new_playbooks_have_unique_ids() {
        let playbooks = get_operator_playbooks();
        let ids: Vec<&str> = playbooks.iter().map(|p| p.id.as_str()).collect();
        let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique.len(), "Duplicate playbook IDs found");
    }

    #[test]
    fn total_playbook_count_at_least_17() {
        let playbooks = get_operator_playbooks();
        assert!(
            playbooks.len() >= 17,
            "Expected at least 17 playbooks, got {}",
            playbooks.len()
        );
    }

    #[test]
    fn all_new_playbooks_have_on_failure() {
        let playbooks = get_operator_playbooks();
        for pb in &playbooks {
            for step in &pb.steps {
                assert!(
                    !step.on_failure.is_empty(),
                    "Playbook '{}' step '{}' has no on_failure guidance",
                    pb.title,
                    step.action
                );
            }
        }
    }

    #[test]
    fn playbook_new_entries_serialize() {
        let playbooks = get_operator_playbooks();
        for pb in &playbooks {
            let json = serde_json::to_value(pb).unwrap();
            assert!(!json["title"].as_str().unwrap().is_empty());
        }
    }
}
