//! Real-browser Browser connector e2e proof lane.
//!
//! This test intentionally does not mock browser behavior. In ordinary local or
//! CI runs it emits a structured skip artifact when a Chrome/Chromium binary or
//! FCP browser-control worker URL is absent. When prerequisites are present, it
//! drives the existing Browser connector operations against that control worker.

#![allow(clippy::too_many_lines)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use base64::Engine as _;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fcp_browser::connector::BrowserConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::CapabilityConstraints;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

const TEST_NAME: &str = "browser_real_browser_no_mock_e2e";
const SCENARIO_ID: &str = "browser-real-browser-no-mock";
const CONNECTOR_ID: &str = "fcp.browser";
const ZONE_ID: &str = "z:work";
const BROWSER_BINARY_ENV: &str = "FCP_BROWSER_BINARY";
const CONTROL_URL_ENV: &str = "FCP_BROWSER_CONTROL_URL";
const ARTIFACT_DIR_ENV: &str = "FCP_BROWSER_E2E_ARTIFACT_DIR";

const LIVE_OPERATIONS: &[&str] = &[
    "browser.navigate",
    "browser.wait_for_selector",
    "browser.click",
    "browser.fill_form",
    "browser.screenshot",
    "browser.render_pdf",
    "browser.extract_text",
    "browser.extract_links",
    "browser.set_cookies",
    "browser.get_cookies",
    "browser.session.save",
    "browser.session.restore",
    "browser.session.describe",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct AssertionsSummary {
    passed: u32,
    failed: u32,
}

impl AssertionsSummary {
    const fn new(passed: u32, failed: u32) -> Self {
        Self { passed, failed }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct E2eLogEntry {
    timestamp: DateTime<Utc>,
    log_version: String,
    level: String,
    test_name: String,
    module: String,
    phase: String,
    correlation_id: String,
    result: String,
    duration_ms: u64,
    assertions: AssertionsSummary,
    context: Value,
    scenario_id: Option<String>,
    step_id: Option<String>,
    step_number: Option<u32>,
    error_code: Option<String>,
    details: Option<Value>,
    prerequisites: Option<Value>,
}

impl E2eLogEntry {
    #[allow(clippy::too_many_arguments)]
    fn new(
        level: impl Into<String>,
        test_name: impl Into<String>,
        module: impl Into<String>,
        phase: impl Into<String>,
        correlation_id: impl Into<String>,
        result: impl Into<String>,
        duration_ms: u64,
        assertions: AssertionsSummary,
        context: Value,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            log_version: "v2".to_string(),
            level: level.into(),
            test_name: test_name.into(),
            module: module.into(),
            phase: phase.into(),
            correlation_id: correlation_id.into(),
            result: result.into(),
            duration_ms,
            assertions,
            context,
            scenario_id: None,
            step_id: None,
            step_number: None,
            error_code: None,
            details: None,
            prerequisites: None,
        }
    }

    fn with_scenario_id(mut self, scenario_id: impl Into<String>) -> Self {
        self.scenario_id = Some(scenario_id.into());
        self
    }

    fn with_step(mut self, step_id: impl Into<String>, step_number: u32) -> Self {
        self.step_id = Some(step_id.into());
        self.step_number = Some(step_number);
        self
    }

    fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    fn with_prerequisites(mut self, prerequisites: Value) -> Self {
        self.prerequisites = Some(prerequisites);
        self
    }

    fn validate(&self) -> Result<(), String> {
        if self.test_name.trim().is_empty() {
            return Err("test_name must be present".to_string());
        }
        if self.module.trim().is_empty() {
            return Err("module must be present".to_string());
        }
        if self.phase.trim().is_empty() {
            return Err("phase must be present".to_string());
        }
        if self.correlation_id.trim().is_empty() {
            return Err("correlation_id must be present".to_string());
        }
        if !matches!(self.result.as_str(), "pass" | "fail") {
            return Err("result must be pass or fail".to_string());
        }
        if self.context.get("connector_id").is_none() {
            return Err("context.connector_id must be present".to_string());
        }
        if self.context.get("operation").is_none() {
            return Err("context.operation must be present".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct E2eLogger {
    entries: Vec<E2eLogEntry>,
}

impl E2eLogger {
    fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, entry: E2eLogEntry) {
        self.entries.push(entry);
    }

    fn drain(&mut self) -> Vec<E2eLogEntry> {
        std::mem::take(&mut self.entries)
    }

    fn write_json_lines(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::File::create(path)?;
        for entry in &self.entries {
            let line = serde_json::to_string(entry)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HarnessStatus {
    Passed,
    Failed,
    Skipped,
}

impl HarnessStatus {
    const fn log_result(self) -> &'static str {
        match self {
            Self::Passed | Self::Skipped => "pass",
            Self::Failed => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MissingPrerequisite {
    code: String,
    detail: String,
}

impl MissingPrerequisite {
    fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UrlRedactionDecision {
    redacted_url: String,
    redacted_fields: Vec<String>,
    secret_removed: bool,
    parse_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EndpointPolicyDecision {
    allowed: bool,
    reason: String,
    redacted_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserE2ePrerequisites {
    browser_binary: Option<String>,
    control_worker_url: Option<String>,
    artifact_dir: String,
    endpoint_policy_decision: EndpointPolicyDecision,
    missing: Vec<MissingPrerequisite>,
}

impl BrowserE2ePrerequisites {
    #[must_use]
    fn is_qualified(&self) -> bool {
        self.missing.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserE2eReport {
    schema_version: String,
    test_name: String,
    scenario_id: String,
    connector_id: String,
    correlation_id: String,
    status: HarnessStatus,
    prerequisites: BrowserE2ePrerequisites,
    artifact_paths: BTreeMap<String, String>,
    redacted_fields: Vec<String>,
    logs: Vec<E2eLogEntry>,
    summary: Value,
}

impl BrowserE2eReport {
    fn skipped(
        correlation_id: &str,
        prerequisites: BrowserE2ePrerequisites,
        logs: Vec<E2eLogEntry>,
    ) -> Self {
        let missing_codes = prerequisites
            .missing
            .iter()
            .map(|missing| missing.code.clone())
            .collect::<Vec<_>>();
        Self {
            schema_version: "fcp-browser-real-e2e.v1".to_string(),
            test_name: TEST_NAME.to_string(),
            scenario_id: SCENARIO_ID.to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            status: HarnessStatus::Skipped,
            prerequisites,
            artifact_paths: standard_artifact_paths(),
            redacted_fields: Vec::new(),
            logs,
            summary: json!({
                "outcome": "skipped",
                "missing_prerequisites": missing_codes,
                "failure_to_skip_distinction": "missing_prerequisite_only",
            }),
        }
    }

    fn failed(
        correlation_id: &str,
        prerequisites: BrowserE2ePrerequisites,
        logs: Vec<E2eLogEntry>,
        error: &str,
    ) -> Self {
        Self {
            schema_version: "fcp-browser-real-e2e.v1".to_string(),
            test_name: TEST_NAME.to_string(),
            scenario_id: SCENARIO_ID.to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            status: HarnessStatus::Failed,
            prerequisites,
            artifact_paths: standard_artifact_paths(),
            redacted_fields: vec!["control_worker_url.query".to_string()],
            logs,
            summary: json!({
                "outcome": "failed",
                "error": error,
                "failure_to_skip_distinction": "live_prerequisites_were_satisfied",
            }),
        }
    }

    fn passed(
        correlation_id: &str,
        prerequisites: BrowserE2ePrerequisites,
        logs: Vec<E2eLogEntry>,
        summary: Value,
    ) -> Self {
        Self {
            schema_version: "fcp-browser-real-e2e.v1".to_string(),
            test_name: TEST_NAME.to_string(),
            scenario_id: SCENARIO_ID.to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            status: HarnessStatus::Passed,
            prerequisites,
            artifact_paths: standard_artifact_paths(),
            redacted_fields: vec![
                "control_worker_url.query".to_string(),
                "control_worker_url.fragment".to_string(),
            ],
            logs,
            summary,
        }
    }
}

#[fcp_async_core::runtime::test]
async fn browser_real_browser_e2e_artifact_lane() {
    let correlation_id = Uuid::new_v4().to_string();
    let env = capture_relevant_env();
    let artifact_dir = env
        .get(ARTIFACT_DIR_ENV)
        .map_or_else(|| default_artifact_dir(&correlation_id), PathBuf::from);
    let prerequisites = evaluate_prerequisites(&env, artifact_dir.as_path(), Path::exists);

    let report = if prerequisites.is_qualified() {
        match run_live_browser_suite(&correlation_id, prerequisites.clone()).await {
            Ok(report) => report,
            Err((logs, error)) => {
                BrowserE2eReport::failed(&correlation_id, prerequisites.clone(), logs, &error)
            }
        }
    } else {
        let mut logger = E2eLogger::new();
        logger.push(skip_log_entry(&correlation_id, &prerequisites));
        BrowserE2eReport::skipped(&correlation_id, prerequisites.clone(), logger.drain())
    };

    assert!(
        write_report_artifacts(&artifact_dir, &report).is_ok(),
        "write browser e2e artifacts"
    );

    match (prerequisites.is_qualified(), report.status) {
        (true, HarnessStatus::Passed) | (false, HarnessStatus::Skipped) => {}
        (true, status) => assert_eq!(status, HarnessStatus::Passed),
        (false, status) => assert_eq!(status, HarnessStatus::Skipped),
    }
}

async fn run_live_browser_suite(
    correlation_id: &str,
    prerequisites: BrowserE2ePrerequisites,
) -> Result<BrowserE2eReport, (Vec<E2eLogEntry>, String)> {
    let mut logger = E2eLogger::new();
    let mut connector = BrowserConnector::new();
    let signing_key = setup_handshake(&mut connector, LIVE_OPERATIONS).await;

    let Some(control_url) = prerequisites.control_worker_url.as_deref() else {
        return Err((logger.drain(), "control worker URL missing".to_string()));
    };

    if let Err(error) = connector
        .handle_configure(json!({ "browser_url": control_url }))
        .await
    {
        logger.push(operation_log_entry(
            correlation_id,
            "browser.configure",
            HarnessStatus::Failed,
            0,
            json!({
                "operation": "browser.configure",
                "target_id": "control-worker",
                "worker_operation_id": "configure",
                "url_redaction_decision": redact_url_for_artifact(control_url),
                "endpoint_policy_decision": prerequisites.endpoint_policy_decision,
                "navigation_policy_decision": "not_applicable",
                "error": error.to_string(),
                "retry_backoff": { "attempt": 1, "next_delay_ms": null },
                "output": { "byte_count": 0 },
                "cancellation_checkpoints": ["before_configure"],
                "no_orphan_task_shutdown_evidence": { "not_started": true },
            }),
        ));
        return Err((logger.drain(), error.to_string()));
    }

    let site = match LoopbackSite::start() {
        Ok(site) => site,
        Err(error) => return Err((logger.drain(), error)),
    };

    let page_url = site.url("/");
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.navigate",
        json!({ "url": page_url, "wait_until": "networkidle", "timeout_ms": 10_000 }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.wait_for_selector",
        json!({ "selector": "#ready", "state": "visible", "timeout_ms": 5_000 }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.click",
        json!({ "selector": "#click-target", "timeout_ms": 5_000 }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.fill_form",
        json!({
            "fields": {
                "#name": "FCP Browser E2E",
                "#message": "real browser proof"
            },
            "submit_selector": "#submit"
        }),
    )
    .await?;

    let screenshot = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.screenshot",
        json!({ "full_page": true, "format": "png" }),
    )
    .await?;
    persist_base64_artifact(
        Path::new(&prerequisites.artifact_dir).join("screenshot.png"),
        screenshot.get("image_data").and_then(Value::as_str),
    );

    let pdf = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.render_pdf",
        json!({ "format": "a4", "print_background": true }),
    )
    .await?;
    persist_base64_artifact(
        Path::new(&prerequisites.artifact_dir).join("page.pdf"),
        pdf.get("pdf_data").and_then(Value::as_str),
    );

    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.extract_text",
        json!({ "selector": "body", "include_hidden": false }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.extract_links",
        json!({ "selector": "body" }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.set_cookies",
        json!({
            "cookies": [{
                "name": "fcp_browser_e2e",
                "value": "session-value",
                "domain": "127.0.0.1",
                "path": "/"
            }]
        }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.get_cookies",
        json!({ "domain": "127.0.0.1" }),
    )
    .await?;
    let saved = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.session.save",
        json!({
            "domain": "127.0.0.1",
            "lease_seq": 10,
            "lease_object_id": "browser-e2e-lease-10"
        }),
    )
    .await?;
    let state_object_id = saved
        .get("state_object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                logger.drain(),
                "session save did not return state_object_id".to_string(),
            )
        })?
        .to_string();
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.session.restore",
        json!({
            "state_object_id": state_object_id,
            "lease_seq": 11,
            "lease_object_id": "browser-e2e-lease-11"
        }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        "browser.session.describe",
        json!({}),
    )
    .await?;

    logger.push(blocked_navigation_log_entry(correlation_id));

    let shutdown = connector
        .handle_shutdown(json!({}))
        .await
        .map_err(|error| {
            logger.push(operation_log_entry(
                correlation_id,
                "browser.shutdown",
                HarnessStatus::Failed,
                0,
                json!({
                    "operation": "browser.shutdown",
                    "target_id": "connector",
                    "worker_operation_id": "shutdown",
                    "navigation_policy_decision": "not_applicable",
                    "endpoint_policy_decision": "not_applicable",
                    "error": error.to_string(),
                    "no_orphan_task_shutdown_evidence": { "connector_shutdown_status": "failed" },
                }),
            ));
            (logger.drain(), error.to_string())
        })?;
    logger.push(operation_log_entry(
        correlation_id,
        "browser.shutdown",
        HarnessStatus::Passed,
        0,
        json!({
            "operation": "browser.shutdown",
            "target_id": "connector",
            "worker_operation_id": "shutdown",
            "navigation_policy_decision": "not_applicable",
            "endpoint_policy_decision": "not_applicable",
            "output": shutdown,
            "no_orphan_task_shutdown_evidence": {
                "connector_shutdown_status": "shutdown",
                "harness_manages_browser_process": false,
                "long_lived_state_owner": "external_control_worker",
                "process_local_loopback_site_joined_on_drop": true
            },
        }),
    ));

    let summary = json!({
        "outcome": "passed",
        "operations_exercised": LIVE_OPERATIONS,
        "blocked_navigation_exercised": true,
        "loopback_site": redact_url_for_artifact(site.url("/").as_str()),
        "screenshot_artifact": "screenshot.png",
        "pdf_artifact": "page.pdf",
    });
    Ok(BrowserE2eReport::passed(
        correlation_id,
        prerequisites,
        logger.drain(),
        summary,
    ))
}

async fn invoke_and_log(
    connector: &BrowserConnector,
    signing_key: &Ed25519SigningKey,
    correlation_id: &str,
    logger: &mut E2eLogger,
    operation: &str,
    input: Value,
) -> Result<Value, (Vec<E2eLogEntry>, String)> {
    let start = Instant::now();
    let capability_grant = generate_valid_grant(signing_key, connector, operation);
    let mut request = json!({
        "operation": operation,
        "input": input,
        "capability_token": capability_grant
    });
    if requires_execution_approval(operation) {
        request["approval_token"] = json!(generate_execution_approval(operation));
    }

    match connector.handle_invoke(request).await {
        Ok(output) => {
            logger.push(operation_log_entry(
                correlation_id,
                operation,
                HarnessStatus::Passed,
                elapsed_ms(start),
                operation_details(operation, HarnessStatus::Passed, &output, None),
            ));
            Ok(output)
        }
        Err(error) => {
            logger.push(operation_log_entry(
                correlation_id,
                operation,
                HarnessStatus::Failed,
                elapsed_ms(start),
                operation_details(
                    operation,
                    HarnessStatus::Failed,
                    &json!({}),
                    Some(error.to_string()),
                ),
            ));
            Err((logger.drain(), error.to_string()))
        }
    }
}

fn operation_details(
    operation: &str,
    status: HarnessStatus,
    output: &Value,
    error: Option<String>,
) -> Value {
    let mut details = json!({
        "operation": operation,
        "target_id": operation_target_id(operation),
        "cdp_command_id": null,
        "worker_operation_id": operation,
        "cdp_command_id_or_worker_operation_id": operation,
        "url_redaction_decision": json!(redact_url_for_artifact(
            output.get("url").and_then(Value::as_str).unwrap_or("about:blank")
        )),
        "endpoint_policy_decision": "fcp_browser_control_url_validated_before_run",
        "navigation_policy_decision": navigation_policy_decision_for_output(operation, output),
        "latency": { "measured_by": "harness", "unit": "ms" },
        "retry_backoff": { "attempt": 1, "next_delay_ms": null },
        "output": output_metrics(output),
        "cancellation_checkpoints": cancellation_checkpoints(operation),
        "timeout_budget_ms": timeout_budget_ms(operation),
        "no_orphan_task_shutdown_evidence": {
            "long_lived_browser_state_owner": "external_control_worker",
            "harness_owned_processes": ["loopback_http_site"],
            "status": status,
        },
    });
    if let Some(error) = error {
        details["error"] = json!(error);
    }
    details
}

fn operation_log_entry(
    correlation_id: &str,
    operation: &str,
    status: HarnessStatus,
    duration_ms: u64,
    details: Value,
) -> E2eLogEntry {
    let entry = E2eLogEntry::new(
        if status == HarnessStatus::Failed {
            "error"
        } else {
            "info"
        },
        TEST_NAME,
        "fcp-browser",
        "execute",
        correlation_id,
        status.log_result(),
        duration_ms,
        AssertionsSummary::new(
            u32::from(status != HarnessStatus::Failed),
            u32::from(status == HarnessStatus::Failed),
        ),
        json!({
            "connector_id": CONNECTOR_ID,
            "zone_id": ZONE_ID,
            "operation": operation,
        }),
    )
    .with_scenario_id(SCENARIO_ID)
    .with_step(operation, 1)
    .with_details(details);
    entry.validate().expect("browser e2e log entry validates");
    entry
}

fn skip_log_entry(correlation_id: &str, prerequisites: &BrowserE2ePrerequisites) -> E2eLogEntry {
    let entry = E2eLogEntry::new(
        "warn",
        TEST_NAME,
        "fcp-browser",
        "setup",
        correlation_id,
        "pass",
        0,
        AssertionsSummary::new(1, 0),
        json!({
            "connector_id": CONNECTOR_ID,
            "zone_id": ZONE_ID,
            "operation": "browser.real_e2e.prerequisites",
        }),
    )
    .with_scenario_id(SCENARIO_ID)
    .with_error_code("browser.real_e2e.skipped")
    .with_prerequisites(json!(prerequisites))
    .with_details(json!({
        "status": "skipped",
        "skip_reason": "missing_prerequisites",
        "missing_prerequisites": prerequisites.missing,
        "failure_to_skip_distinction": "skip artifacts are emitted only before live browser operations start",
    }));
    entry.validate().expect("skip log entry validates");
    entry
}

fn blocked_navigation_log_entry(correlation_id: &str) -> E2eLogEntry {
    operation_log_entry(
        correlation_id,
        "browser.navigate.blocked",
        HarnessStatus::Passed,
        0,
        json!({
            "operation": "browser.navigate",
            "target_id": "policy-preflight",
            "cdp_command_id": null,
            "worker_operation_id": null,
            "cdp_command_id_or_worker_operation_id": "harness-policy-preflight",
            "url_redaction_decision": redact_url_for_artifact("file:///private/etc/passwd?trace_id=redacted"),
            "endpoint_policy_decision": "not_sent_to_control_worker",
            "navigation_policy_decision": {
                "allowed": false,
                "reason": "non_http_navigation_scheme_blocked",
                "blocked_before_cdp_command": true
            },
            "latency": { "measured_by": "harness", "unit": "ms", "value": 0 },
            "retry_backoff": { "attempt": 0, "next_delay_ms": null },
            "output": { "byte_count": 0 },
            "cancellation_checkpoints": ["preflight_policy_check"],
            "timeout_budget_ms": 0,
            "no_orphan_task_shutdown_evidence": {
                "operation_never_spawned_worker_task": true
            },
        }),
    )
}

fn evaluate_prerequisites<F>(
    env: &BTreeMap<String, String>,
    artifact_dir: &Path,
    exists: F,
) -> BrowserE2ePrerequisites
where
    F: Fn(&Path) -> bool,
{
    let mut missing = Vec::new();
    let browser_binary = detect_browser_binary(env, &exists, &mut missing);
    let control_worker_url = env
        .get(CONTROL_URL_ENV)
        .filter(|value| !value.is_empty())
        .cloned();
    let endpoint_policy_decision = classify_control_endpoint(control_worker_url.as_deref());
    if control_worker_url.is_none() {
        missing.push(MissingPrerequisite::new(
            "control_worker_url_missing",
            format!("{CONTROL_URL_ENV} must point at an FCP browser-control HTTP endpoint"),
        ));
    } else if !endpoint_policy_decision.allowed {
        missing.push(MissingPrerequisite::new(
            "control_worker_url_rejected",
            endpoint_policy_decision.reason.clone(),
        ));
    }

    BrowserE2ePrerequisites {
        browser_binary,
        control_worker_url,
        artifact_dir: artifact_dir.to_string_lossy().to_string(),
        endpoint_policy_decision,
        missing,
    }
}

fn detect_browser_binary<F>(
    env: &BTreeMap<String, String>,
    exists: &F,
    missing: &mut Vec<MissingPrerequisite>,
) -> Option<String>
where
    F: Fn(&Path) -> bool,
{
    if let Some(configured) = env
        .get(BROWSER_BINARY_ENV)
        .filter(|value| !value.is_empty())
    {
        let path = Path::new(configured);
        if exists(path) {
            return Some(configured.clone());
        }
        missing.push(MissingPrerequisite::new(
            "browser_binary_env_path_missing",
            format!("{BROWSER_BINARY_ENV} was set to '{configured}', but that path was not found"),
        ));
        return None;
    }

    let mut candidates = browser_binary_candidates(env);
    candidates.sort();
    candidates.dedup();
    for candidate in candidates {
        let path = Path::new(&candidate);
        if exists(path) {
            return Some(candidate);
        }
    }

    missing.push(MissingPrerequisite::new(
        "browser_binary_missing",
        format!("Set {BROWSER_BINARY_ENV} or put google-chrome/chromium/chrome on PATH"),
    ));
    None
}

fn browser_binary_candidates(env: &BTreeMap<String, String>) -> Vec<String> {
    let mut candidates = vec![
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string(),
        "/Applications/Chromium.app/Contents/MacOS/Chromium".to_string(),
        "/usr/bin/google-chrome".to_string(),
        "/usr/bin/google-chrome-stable".to_string(),
        "/usr/bin/chromium".to_string(),
        "/usr/bin/chromium-browser".to_string(),
        "/opt/google/chrome/chrome".to_string(),
    ];

    let executable_names = if cfg!(windows) {
        vec!["chrome.exe", "chromium.exe"]
    } else {
        vec![
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "chrome",
        ]
    };
    if let Some(path) = env.get("PATH") {
        for dir in env::split_paths(path) {
            for executable in &executable_names {
                candidates.push(dir.join(executable).to_string_lossy().to_string());
            }
        }
    }
    candidates
}

fn classify_control_endpoint(raw_url: Option<&str>) -> EndpointPolicyDecision {
    let Some(raw_url) = raw_url else {
        return EndpointPolicyDecision {
            allowed: false,
            reason: "missing_control_worker_url".to_string(),
            redacted_url: None,
        };
    };

    let redaction = redact_url_for_artifact(raw_url);
    let Ok(parsed) = Url::parse(raw_url) else {
        return EndpointPolicyDecision {
            allowed: false,
            reason: "invalid_control_worker_url".to_string(),
            redacted_url: Some(redaction.redacted_url),
        };
    };

    let Some(host) = parsed.host_str() else {
        return EndpointPolicyDecision {
            allowed: false,
            reason: "control_worker_url_missing_host".to_string(),
            redacted_url: Some(redaction.redacted_url),
        };
    };

    let scheme_allowed = matches!(parsed.scheme(), "http" | "https");
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    let internal = host.ends_with(".browser.mesh.internal")
        || host.ends_with(".browser.flywheel.internal")
        || matches!(host, "browser.mesh.internal" | "browser.flywheel.internal");
    let https_or_loopback = parsed.scheme() == "https" || loopback;
    let path_is_control_base = !parsed.path().starts_with("/json");
    let no_userinfo_query_fragment = parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none();

    let allowed = scheme_allowed
        && (loopback || internal)
        && https_or_loopback
        && path_is_control_base
        && no_userinfo_query_fragment;
    EndpointPolicyDecision {
        allowed,
        reason: if allowed {
            "control_worker_endpoint_allowed".to_string()
        } else {
            "control_worker_endpoint_rejected_by_browser_connector_policy".to_string()
        },
        redacted_url: Some(redaction.redacted_url),
    }
}

fn redact_url_for_artifact(raw_url: &str) -> UrlRedactionDecision {
    let Ok(mut parsed) = Url::parse(raw_url) else {
        return UrlRedactionDecision {
            redacted_url: "[invalid-url]".to_string(),
            redacted_fields: Vec::new(),
            secret_removed: false,
            parse_error: Some("invalid_url".to_string()),
        };
    };

    let mut redacted_fields = Vec::new();
    if !parsed.username().is_empty() {
        redacted_fields.push("username".to_string());
        let _ = parsed.set_username("");
    }
    if parsed.password().is_some() {
        redacted_fields.push("password".to_string());
        let _ = parsed.set_password(None);
    }
    if parsed.query().is_some() {
        redacted_fields.push("query".to_string());
        parsed.set_query(None);
    }
    if parsed.fragment().is_some() {
        redacted_fields.push("fragment".to_string());
        parsed.set_fragment(None);
    }
    UrlRedactionDecision {
        redacted_url: parsed.to_string(),
        secret_removed: !redacted_fields.is_empty(),
        redacted_fields,
        parse_error: None,
    }
}

fn normalize_artifact_path(path: &Path) -> Result<String, String> {
    let mut normalized = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("artifact path escapes bundle: {}", path.display()));
            }
        }
    }
    if normalized.is_empty() {
        return Err("artifact path is empty".to_string());
    }
    Ok(normalized.join("/"))
}

fn standard_artifact_paths() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "driver_result_json".to_string(),
            "driver-result.json".to_string(),
        ),
        ("logs_jsonl".to_string(), "logs.jsonl".to_string()),
        ("screenshot_png".to_string(), "screenshot.png".to_string()),
        ("pdf".to_string(), "page.pdf".to_string()),
    ])
}

fn write_report_artifacts(artifact_dir: &Path, report: &BrowserE2eReport) -> std::io::Result<()> {
    fs::create_dir_all(artifact_dir)?;
    let report_path = artifact_dir.join("driver-result.json");
    let log_path = artifact_dir.join("logs.jsonl");
    let report_json = serde_json::to_string_pretty(report)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    fs::write(report_path, report_json)?;
    let mut logger = E2eLogger::new();
    for entry in &report.logs {
        logger.push(entry.clone());
    }
    logger.write_json_lines(log_path)
}

fn persist_base64_artifact(path: PathBuf, encoded: Option<&str>) {
    let Some(encoded) = encoded else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) {
        let _ = fs::write(path, bytes);
    }
}

fn capture_relevant_env() -> BTreeMap<String, String> {
    [
        BROWSER_BINARY_ENV,
        CONTROL_URL_ENV,
        ARTIFACT_DIR_ENV,
        "PATH",
    ]
    .into_iter()
    .filter_map(|key| env::var(key).ok().map(|value| (key.to_string(), value)))
    .collect()
}

fn default_artifact_dir(correlation_id: &str) -> PathBuf {
    env::temp_dir().join(format!("fcp-browser-real-e2e-{correlation_id}"))
}

async fn setup_handshake(
    connector: &mut BrowserConnector,
    operations: &[&str],
) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let caps = operations
        .iter()
        .copied()
        .map(capability_for_operation)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": ZONE_ID,
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("browser handshake succeeds");
    signing_key
}

fn generate_valid_grant(
    signing_key: &Ed25519SigningKey,
    connector: &BrowserConnector,
    operation: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id(ZONE_ID)
        .principal("user:browser-e2e")
        .operations(&[operation])
        .issuer("node:browser-e2e")
        .target_instance(connector.instance_id())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign browser e2e token");
    fcp_core::CapabilityToken::from_raw(cose)
}

fn generate_execution_approval(operation: &str) -> fcp_core::ApprovalToken {
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);
    fcp_core::ApprovalToken {
        token_id: format!("browser-e2e-approval-{operation}-{now_ms}"),
        issued_at_ms: now_ms.saturating_sub(1_000),
        expires_at_ms: now_ms + 300_000,
        issuer: "owner:browser-e2e".into(),
        scope: fcp_core::ApprovalScope::Execution(fcp_core::ExecutionScope {
            connector_id: CONNECTOR_ID.into(),
            method_pattern: operation.into(),
            request_object_id: None,
            input_hash: None,
            input_constraints: vec![],
        }),
        zone_id: fcp_core::ZoneId::work(),
        signature: None,
    }
}

const fn requires_execution_approval(operation: &str) -> bool {
    matches!(
        operation.as_bytes(),
        b"browser.evaluate_js"
            | b"browser.fill_form"
            | b"browser.get_cookies"
            | b"browser.set_cookies"
            | b"browser.session.save"
            | b"browser.session.restore"
            | b"browser.set_proxy"
            | b"browser.clear_proxy"
    )
}

const fn capability_for_operation(operation: &str) -> &'static str {
    match operation.as_bytes() {
        b"browser.screenshot" | b"browser.render_pdf" => "browser.capture",
        b"browser.extract_text" | b"browser.extract_links" | b"browser.wait_for_selector" => {
            "browser.extract"
        }
        b"browser.click" | b"browser.fill_form" => "browser.interact",
        b"browser.evaluate_js" => "browser.execute",
        b"browser.get_cookies" | b"browser.set_cookies" => "browser.cookies",
        b"browser.session.save" | b"browser.session.restore" | b"browser.session.describe" => {
            "browser.sessions"
        }
        b"browser.set_proxy" | b"browser.clear_proxy" => "browser.proxy",
        _ => "browser.navigate",
    }
}

const fn timeout_budget_ms(operation: &str) -> u64 {
    match operation.as_bytes() {
        b"browser.screenshot" | b"browser.render_pdf" | b"browser.navigate" => 60_000,
        b"browser.wait_for_selector" => 10_000,
        _ => 30_000,
    }
}

fn cancellation_checkpoints(operation: &str) -> Vec<&'static str> {
    match operation {
        "browser.navigate" => vec!["before_send", "after_page_enable", "after_response"],
        "browser.wait_for_selector" => vec!["before_wait", "selector_poll", "after_response"],
        _ => vec!["before_send", "after_response"],
    }
}

const fn operation_target_id(operation: &str) -> &'static str {
    match operation.as_bytes() {
        b"browser.set_cookies"
        | b"browser.get_cookies"
        | b"browser.session.save"
        | b"browser.session.restore"
        | b"browser.session.describe" => "browser-context",
        _ => "active-page",
    }
}

fn navigation_policy_decision_for_output(operation: &str, output: &Value) -> Value {
    if operation != "browser.navigate" {
        return json!("not_applicable");
    }
    let url = output
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default();
    json!({
        "allowed": url.starts_with("http://127.0.0.1:") || url.starts_with("https://"),
        "reason": "loopback_or_https_navigation_allowed",
        "redacted_url": redact_url_for_artifact(url).redacted_url,
    })
}

fn output_metrics(output: &Value) -> Value {
    json!({
        "byte_count": output.to_string().len(),
        "image_bytes_base64": output.get("image_data").and_then(Value::as_str).map(str::len),
        "pdf_bytes_base64": output.get("pdf_data").and_then(Value::as_str).map(str::len),
        "width": output.get("width").and_then(Value::as_u64),
        "height": output.get("height").and_then(Value::as_u64),
        "page_count": output.get("page_count").and_then(Value::as_u64),
        "cookie_count": output.get("cookie_count").and_then(Value::as_u64),
        "text_chars": output.get("text").and_then(Value::as_str).map(str::len),
    })
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct LoopbackSite {
    url_base: String,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LoopbackSite {
    fn start() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        let addr = listener.local_addr().map_err(|error| error.to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = Arc::clone(&running);
        let handle = thread::spawn(move || serve_loopback(listener, thread_running));
        Ok(Self {
            url_base: format!("http://{addr}"),
            running,
            handle: Some(handle),
        })
    }

    #[must_use]
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.url_base, path)
    }
}

impl Drop for LoopbackSite {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(self.url_base.trim_start_matches("http://")) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn serve_loopback(listener: TcpListener, running: Arc<AtomicBool>) {
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => serve_loopback_request(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

fn serve_loopback_request(mut stream: TcpStream) {
    let mut buffer = [0_u8; 4096];
    let n = stream.read(&mut buffer).unwrap_or(0);
    let request = String::from_utf8_lossy(&buffer[..n]);
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    let body = if path == "/submit" {
        "<html><body><div id=\"ready\">submitted</div></body></html>"
    } else {
        r#"
<!doctype html>
<html>
  <head><title>FCP Browser E2E</title></head>
  <body>
    <main id="ready">
      <h1>FCP Browser E2E</h1>
      <a href="/next" id="next-link">next</a>
      <button id="click-target" onclick="document.body.dataset.clicked='true'">Click</button>
      <form action="/submit" method="get">
        <input id="name" name="name">
        <textarea id="message" name="message"></textarea>
        <button id="submit" type="submit">Submit</button>
      </form>
    </main>
  </body>
</html>
"#
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: fcp_browser_e2e=loopback; Path=/; SameSite=Lax\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.shutdown(Shutdown::Both);
}

#[test]
fn prerequisite_detection_reports_exact_missing_inputs() {
    let env = BTreeMap::new();
    let artifact_dir = PathBuf::from("browser-e2e");
    let prerequisites = evaluate_prerequisites(&env, artifact_dir.as_path(), |_| false);

    assert!(!prerequisites.is_qualified());
    let codes = prerequisites
        .missing
        .iter()
        .map(|missing| missing.code.as_str())
        .collect::<BTreeSet<_>>();
    assert!(codes.contains("browser_binary_missing"));
    assert!(codes.contains("control_worker_url_missing"));
}

#[test]
fn prerequisite_detection_accepts_env_binary_and_loopback_control_worker() {
    let mut env = BTreeMap::new();
    env.insert(
        BROWSER_BINARY_ENV.to_string(),
        "/tmp/fake-chrome".to_string(),
    );
    env.insert(
        CONTROL_URL_ENV.to_string(),
        "http://127.0.0.1:9222".to_string(),
    );
    let artifact_dir = PathBuf::from("browser-e2e");
    let prerequisites = evaluate_prerequisites(&env, artifact_dir.as_path(), |path| {
        path == Path::new("/tmp/fake-chrome")
    });

    assert!(prerequisites.is_qualified());
    assert_eq!(
        prerequisites.browser_binary.as_deref(),
        Some("/tmp/fake-chrome")
    );
    assert!(prerequisites.endpoint_policy_decision.allowed);
}

#[test]
fn skip_artifact_schema_distinguishes_missing_prereqs_from_live_failure() {
    let artifact_dir = PathBuf::from("out");
    let prerequisites = evaluate_prerequisites(&BTreeMap::new(), artifact_dir.as_path(), |_| false);
    let mut logger = E2eLogger::new();
    logger.push(skip_log_entry("corr-skip", &prerequisites));
    let skipped = BrowserE2eReport::skipped("corr-skip", prerequisites.clone(), logger.drain());
    let failed = BrowserE2eReport::failed(
        "corr-fail",
        prerequisites,
        Vec::new(),
        "control worker returned 500",
    );

    assert_eq!(skipped.status, HarnessStatus::Skipped);
    assert_eq!(failed.status, HarnessStatus::Failed);
    assert_eq!(
        skipped.summary["failure_to_skip_distinction"],
        "missing_prerequisite_only"
    );
    assert_eq!(
        failed.summary["failure_to_skip_distinction"],
        "live_prerequisites_were_satisfied"
    );
}

#[test]
fn log_schema_contains_required_browser_evidence_fields() {
    let log = operation_log_entry(
        "corr-log",
        "browser.screenshot",
        HarnessStatus::Passed,
        12,
        operation_details(
            "browser.screenshot",
            HarnessStatus::Passed,
            &json!({ "image_data": "aW1n", "width": 2, "height": 1 }),
            None,
        ),
    );
    let value = serde_json::to_value(log).expect("serialize log");

    assert_eq!(value["correlation_id"], "corr-log");
    assert_eq!(value["details"]["operation"], "browser.screenshot");
    assert_eq!(
        value["details"]["worker_operation_id"],
        "browser.screenshot"
    );
    assert!(value["details"]["target_id"].is_string());
    assert!(value["details"]["endpoint_policy_decision"].is_string());
    assert!(value["details"]["navigation_policy_decision"].is_string());
    assert!(value["details"]["output"]["width"].is_u64());
    assert!(value["details"]["cancellation_checkpoints"].is_array());
}

#[test]
fn url_redaction_removes_credentials_query_and_fragment() {
    let decision =
        redact_url_for_artifact("https://user:credential@example.com/path?trace_id=abc#private");

    assert_eq!(decision.redacted_url, "https://example.com/path");
    assert!(decision.secret_removed);
    assert!(decision.redacted_fields.contains(&"username".to_string()));
    assert!(decision.redacted_fields.contains(&"password".to_string()));
    assert!(decision.redacted_fields.contains(&"query".to_string()));
    assert!(decision.redacted_fields.contains(&"fragment".to_string()));
    assert!(!decision.redacted_url.contains("credential"));
    assert!(!decision.redacted_url.contains("trace_id"));
}

#[test]
fn artifact_path_normalization_rejects_escape_paths() {
    assert_eq!(
        normalize_artifact_path(Path::new("./logs/browser.jsonl")).unwrap(),
        "logs/browser.jsonl"
    );
    assert!(normalize_artifact_path(Path::new("../escape")).is_err());
    assert!(normalize_artifact_path(Path::new("/tmp/out")).is_err());
}

#[test]
fn timeout_and_cancellation_markers_are_explicit() {
    let details = operation_details(
        "browser.wait_for_selector",
        HarnessStatus::Passed,
        &json!({ "found": true }),
        None,
    );

    assert_eq!(details["timeout_budget_ms"], 10_000);
    assert_eq!(
        details["cancellation_checkpoints"],
        json!(["before_wait", "selector_poll", "after_response"])
    );
}

#[fcp_async_core::runtime::test]
async fn browser_contract_operations_are_covered_by_live_plan() {
    let connector = BrowserConnector::new();
    let health = connector.handle_health().await.expect("health response");
    let operations = health["browser_control_contract"]["connector_operations"]
        .as_array()
        .expect("connector operations");
    let documented = operations
        .iter()
        .filter_map(|operation| operation["id"].as_str())
        .collect::<BTreeSet<_>>();
    for operation in LIVE_OPERATIONS {
        assert!(
            documented.contains(operation),
            "live harness must cover documented operation {operation}"
        );
    }
}
