#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use fcp_host::{
    LocalMcpCall, LocalMcpError, LocalMcpProvider, LocalMcpRequest, LocalMcpResultStatus,
};
use fcp_manifest::{
    LOCAL_MCP_CATALOG_TOOLS, LOCAL_MCP_METHODS, LocalMcpPolicy, local_mcp_schema_digest,
};
use fcp_sandbox::{OwnedProcess, ProcessSpec, process_group_absent};
use serde_json::json;
use tempfile::tempdir;

const FIXTURE_SECRET: &str = "fixture-secret-must-not-escape";

#[test]
fn normal_request_runs_all_catalog_tools_and_tears_down() {
    let fixture = Fixture::new("normal");
    let result = fixture
        .provider()
        .run_once(LocalMcpRequest {
            correlation_id: "normal-request".into(),
            calls: LOCAL_MCP_CATALOG_TOOLS
                .iter()
                .map(|tool| LocalMcpCall {
                    tool: (*tool).into(),
                    arguments: json!({}),
                })
                .collect(),
        })
        .expect("normal fake provider");

    assert_eq!(result.responses.len(), LOCAL_MCP_CATALOG_TOOLS.len());
    assert!(result.startup.network_disabled);
    assert!(result.shutdown.reaped);
    assert!(result.shutdown.group_absent);
    assert_eq!(result.correlation_id, "normal-request");
    assert!(result.shutdown.memory_after.available);
    assert_eq!(result.shutdown.memory_after.process_count, 0);
    assert_eq!(result.status, LocalMcpResultStatus::Completed);
    assert_eq!(result.result_code, "ok");
    assert!(result.memory_samples.len() >= 2);
    assert_eq!(result.shutdown.stderr_bytes, 0);
    assert!(!format!("{result:?}").contains(FIXTURE_SECRET));
}

#[test]
fn seccomp_denies_socket_attempt_while_stdio_remains_functional() {
    let fixture = Fixture::new("socket");
    let result = fixture
        .provider()
        .run_once(one_call())
        .expect("socket denial must not break stdio");
    assert_eq!(result.responses.len(), 1);
    assert!(result.shutdown.group_absent);
}

#[test]
fn seccomp_denies_session_escape_while_stdio_remains_functional() {
    let fixture = Fixture::new("escape");
    let result = fixture
        .provider()
        .run_once(one_call())
        .expect("session escape denial must not break stdio");
    assert_eq!(result.responses.len(), 1);
    assert!(result.shutdown.group_absent);
}

#[test]
fn launcher_and_runtime_digest_drift_fail_before_provider_effect() {
    let fixture = Fixture::new("normal");
    let mut policy = fixture.policy();
    policy.launcher_digest = "0".repeat(64);
    let provider = LocalMcpProvider::new(policy).expect("policy shape");
    let error = provider
        .run_once(one_call())
        .expect_err("changed launcher must be denied");
    assert!(matches!(error, LocalMcpError::ProcessStart));

    let mut policy = fixture.policy();
    policy.runtime_executable_digest = "0".repeat(64);
    let provider = LocalMcpProvider::new(policy).expect("policy shape");
    let error = provider
        .run_once(one_call())
        .expect_err("changed runtime must be denied");
    assert!(matches!(error, LocalMcpError::ProcessIdentity));

    let fixture = Fixture::new("normal");
    fs::write(
        &fixture.package_json,
        r#"{"name":"wrong","version":"1.0.0"}"#,
    )
    .expect("package drift");
    let error = fixture
        .provider()
        .run_once(one_call())
        .expect_err("package metadata drift must be denied before spawn");
    assert!(matches!(error, LocalMcpError::PackageIdentity));
}

#[test]
fn catalog_schema_frame_and_provider_failures_are_safe() {
    for (mode, expected) in [
        ("catalog", "catalog_mismatch"),
        ("schema", "catalog_mismatch"),
        ("malformed", "invalid_frame"),
        ("oversized", "frame_too_large"),
        ("oversized-no-newline", "frame_too_large"),
        ("crash", "invalid_frame"),
        ("bad-jsonrpc", "invalid_frame"),
        ("protocol-mismatch", "invalid_frame"),
        // The first unsolicited frame can be observed before the bounded
        // reader queue records overflow; either way the provider fails closed.
        ("stdout-flood", "invalid_frame"),
    ] {
        let fixture = Fixture::new(mode);
        let result = fixture
            .provider()
            .run_once(one_call())
            .expect("post-spawn failure envelope");
        assert_eq!(
            result.status,
            LocalMcpResultStatus::Failed,
            "mode={mode} result={result:?}"
        );
        let result_code_matches = result.result_code == expected
            || (mode == "stdout-flood" && result.result_code == "frame_too_large");
        assert!(result_code_matches, "mode={mode} result={result:?}");
        assert!(result.startup.pid > 0);
        assert!(!format!("{result:?}").contains(FIXTURE_SECRET));
    }

    let fixture = Fixture::new("stderr");
    let result = fixture
        .provider()
        .run_once(one_call())
        .expect("stderr fixture");
    assert!(result.shutdown.stderr_bytes > 0);
    assert!(!format!("{result:?}").contains("untrusted-provider-text"));
}

#[test]
fn teardown_identity_failure_returns_bounded_envelope_without_foreign_signal() {
    let fixture = Fixture::new("identity-drift");
    let started = std::time::Instant::now();
    let result = fixture
        .provider()
        .run_once(one_call())
        .expect("teardown failure envelope");

    assert_eq!(result.status, LocalMcpResultStatus::Failed);
    assert_eq!(result.result_code, "process_identity");
    assert_eq!(
        result.teardown_error_code.as_deref(),
        Some("process_identity")
    );
    assert!(!result.shutdown.group_absent);
    assert!(result.shutdown.reaped);
    assert!(!result.shutdown.memory_after.available);
    assert!(!result.shutdown.term_sent);
    assert!(!result.shutdown.kill_sent);
    assert!(started.elapsed() < Duration::from_secs(2));

    thread::sleep(Duration::from_secs(2));
    assert!(process_group_absent(result.startup.pgid).expect("fixture cleanup probe"));
}

#[test]
fn late_identity_failure_preserves_sent_signal_receipt() {
    let fixture = Fixture::new("late-identity-drift");
    let result = fixture
        .provider()
        .run_once(one_call())
        .expect("late teardown failure envelope");

    assert_eq!(result.status, LocalMcpResultStatus::Failed);
    assert_eq!(result.result_code, "process_identity");
    assert!(result.shutdown.term_sent);
    assert!(!result.shutdown.kill_sent);
    assert!(result.shutdown.reaped);
    assert!(!result.shutdown.group_absent);

    thread::sleep(Duration::from_secs(2));
    assert!(process_group_absent(result.startup.pgid).expect("fixture cleanup probe"));
}

#[test]
fn request_bounds_timeout_cancellation_and_orphan_are_fail_closed() {
    let fixture = Fixture::new("normal");
    let mut too_many = one_call();
    too_many.calls = (0..8)
        .map(|_| LocalMcpCall {
            tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
            arguments: json!({}),
        })
        .collect();
    let error = fixture
        .provider()
        .run_once(too_many)
        .expect_err("call bound must be enforced before spawn");
    assert!(matches!(error, LocalMcpError::TooManyCalls));

    let startup_timeout = Fixture::new("startup-timeout");
    let result = startup_timeout
        .provider_with_timeouts(100, 100)
        .run_once(one_call())
        .expect("startup timeout envelope");
    assert_eq!(result.status, LocalMcpResultStatus::Failed);
    assert_eq!(result.result_code, "startup_timeout");
    assert!(result.telemetry.startup_latency_ms > 0);

    let timeout_fixture = Fixture::new("timeout");
    let result = timeout_fixture
        .provider_with_timeout(100)
        .run_once(one_call())
        .expect("provider timeout envelope");
    assert_eq!(result.status, LocalMcpResultStatus::Failed);
    assert_eq!(result.result_code, "request_timeout");

    let cancel_fixture = Fixture::new("timeout");
    let cancelled = Arc::new(AtomicBool::new(false));
    let provider = cancel_fixture.provider_with_timeout(2_000);
    let cancel_flag = Arc::clone(&cancelled);
    let handle = thread::spawn(move || provider.run_once_with_cancel(one_call(), cancel_flag));
    thread::sleep(Duration::from_millis(150));
    cancelled.store(true, Ordering::Release);
    let result = handle
        .join()
        .expect("cancellation worker")
        .expect("cancellation envelope");
    assert_eq!(result.status, LocalMcpResultStatus::Failed);
    assert_eq!(result.result_code, "cancelled");

    let orphan_fixture = Fixture::new("orphan-exit");
    let result = orphan_fixture
        .provider_with_timeout(100)
        .run_once(one_call())
        .expect("orphan fixture must be killed as a group");
    assert!(result.shutdown.kill_sent);
    assert!(result.shutdown.group_absent);
    assert!(result.startup.pid > 0);

    let blocked = Fixture::new("blocked-write");
    let started = std::time::Instant::now();
    let result = blocked
        .provider_with_large_frames(1_000, 100)
        .run_once(blocked_write_request())
        .expect("blocked write envelope");
    assert_eq!(result.status, LocalMcpResultStatus::Failed);
    assert_eq!(result.result_code, "request_timeout");
    assert!(result.shutdown.group_absent);
    assert!(result.startup.pid > 0);
    assert!(started.elapsed() < Duration::from_secs(3));

    let blocked_cancel = Fixture::new("blocked-write");
    let cancelled = Arc::new(AtomicBool::new(false));
    let provider = blocked_cancel.provider_with_large_frames(1_000, 2_000);
    let cancel_flag = Arc::clone(&cancelled);
    let handle =
        thread::spawn(move || provider.run_once_with_cancel(blocked_write_request(), cancel_flag));
    thread::sleep(Duration::from_millis(150));
    cancelled.store(true, Ordering::Release);
    let result = handle
        .join()
        .expect("blocked-write cancellation worker")
        .expect("blocked-write cancellation envelope");
    assert_eq!(result.status, LocalMcpResultStatus::Failed);
    assert_eq!(result.result_code, "cancelled");
    assert!(result.shutdown.group_absent);
}

#[test]
fn completed_group_is_absent_after_five_and_thirty_second_idle_windows() {
    let fixture = Fixture::new("normal");
    let result = fixture
        .provider()
        .run_once(one_call())
        .expect("normal request");
    let pgid = result.startup.pgid;
    assert_eq!(result.shutdown.memory_after.process_count, 0);
    assert!(result.shutdown.memory_after.available);

    thread::sleep(Duration::from_secs(5));
    assert!(process_group_absent(pgid).expect("group probe"));

    thread::sleep(Duration::from_secs(30));
    assert!(process_group_absent(pgid).expect("group probe"));
}

#[test]
#[ignore = "requires the host-installed n8n-mcp package; run explicitly for package acceptance"]
fn installed_n8n_mcp_catalog_and_read_only_calls_run_through_supervisor() {
    const NODE_PATH: &str = "/usr/bin/node";
    const WRAPPER_PATH: &str = "/usr/local/lib/node_modules/n8n-mcp/dist/mcp/stdio-wrapper.js";
    const PACKAGE_PATH: &str = "/usr/local/lib/node_modules/n8n-mcp/package.json";

    let runtime = fs::canonicalize(NODE_PATH).expect("installed node runtime");
    let package: serde_json::Value = serde_json::from_slice(
        &fs::read(PACKAGE_PATH).expect("installed n8n-mcp package metadata"),
    )
    .expect("valid n8n-mcp package metadata");
    assert_eq!(
        package.get("name").and_then(serde_json::Value::as_str),
        Some("n8n-mcp")
    );
    let package_version = semver::Version::parse(
        package
            .get("version")
            .and_then(serde_json::Value::as_str)
            .expect("n8n-mcp package version"),
    )
    .expect("semantic n8n-mcp package version");

    let mut fixed_env = BTreeMap::new();
    fixed_env.insert(
        OsString::from("N8N_MCP_TELEMETRY_DISABLED"),
        OsString::from("true"),
    );
    let spec = ProcessSpec {
        launcher_path: runtime.clone(),
        launcher_digest: digest(&runtime),
        runtime_executable: runtime.clone(),
        expected_runtime_executable_digest: digest(&runtime),
        fixed_args: vec![OsString::from(WRAPPER_PATH)],
        fixed_env,
        network_disabled: true,
    };
    let mut discovery = OwnedProcess::spawn(&spec).expect("spawn installed n8n-mcp discovery");
    let mut stdin = discovery.take_stdin().expect("provider stdin");
    let mut stdout = BufReader::new(discovery.take_stdout().expect("provider stdout"));

    write_mcp_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "fcp-n8n-acceptance", "version": "0.1"}
            }
        }),
    );
    let initialized = read_mcp_line(&mut stdout);
    assert_eq!(
        initialized.pointer("/result/protocolVersion"),
        Some(&json!("2024-11-05"))
    );
    write_mcp_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
    );
    write_mcp_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    );
    let catalog = read_mcp_line(&mut stdout);
    let tools = catalog
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .expect("installed n8n-mcp catalog");
    let catalog_names: Vec<&str> = tools
        .iter()
        .map(|tool| {
            tool.get("name")
                .and_then(serde_json::Value::as_str)
                .expect("catalog tool name")
        })
        .collect();
    assert_eq!(catalog_names, LOCAL_MCP_CATALOG_TOOLS);
    let expected_catalog = tools
        .iter()
        .map(|tool| {
            let name = tool
                .get("name")
                .and_then(serde_json::Value::as_str)
                .expect("catalog tool name");
            let schema = tool.get("inputSchema").expect("catalog input schema");
            (name.to_string(), local_mcp_schema_digest(schema))
        })
        .collect();
    drop(stdin);
    let discovery_shutdown = discovery
        .terminate(Duration::from_secs(2))
        .expect("stop installed n8n-mcp discovery");
    assert!(discovery_shutdown.group_absent);

    let policy = LocalMcpPolicy {
        package_id: "n8n-mcp".into(),
        package_version,
        launcher_path: runtime.to_string_lossy().into_owned(),
        launcher_digest: digest(&runtime),
        runtime_executable: runtime.to_string_lossy().into_owned(),
        runtime_executable_digest: digest(&runtime),
        package_metadata_path: PACKAGE_PATH.into(),
        package_metadata_digest: digest(Path::new(PACKAGE_PATH)),
        protocol_version: "2024-11-05".into(),
        fixed_args: vec![WRAPPER_PATH.into()],
        fixed_env: BTreeMap::from([("N8N_MCP_TELEMETRY_DISABLED".into(), "true".into())]),
        allowed_methods: LOCAL_MCP_METHODS
            .iter()
            .map(|method| (*method).into())
            .collect(),
        expected_catalog,
        callable_tools: LOCAL_MCP_CATALOG_TOOLS
            .iter()
            .map(|tool| (*tool).into())
            .collect(),
        max_frame_bytes: 256 * 1024,
        max_request_bytes: 64 * 1024,
        max_result_bytes: 256 * 1024,
        max_sequential_calls: 7,
        startup_timeout_ms: 30_000,
        request_timeout_ms: 30_000,
        shutdown_timeout_ms: 2_000,
        idle_window_ms: 0,
        network_disabled: true,
    };
    let result = LocalMcpProvider::new(policy)
        .expect("installed n8n-mcp policy")
        .run_once(LocalMcpRequest {
            correlation_id: "installed-n8n-mcp-acceptance".into(),
            calls: vec![
                LocalMcpCall {
                    tool: "search_nodes".into(),
                    arguments: json!({"query": "webhook", "limit": 3}),
                },
                LocalMcpCall {
                    tool: "search_templates".into(),
                    arguments: json!({"query": "webhook", "limit": 3}),
                },
                LocalMcpCall {
                    tool: "validate_node".into(),
                    arguments: json!({
                        "nodeType": "nodes-base.webhook",
                        "config": {},
                        "mode": "minimal"
                    }),
                },
                LocalMcpCall {
                    tool: "validate_workflow".into(),
                    arguments: json!({
                        "workflow": {"name": "acceptance", "nodes": [], "connections": {}}
                    }),
                },
            ],
        })
        .expect("installed n8n-mcp supervised request");

    assert_eq!(result.status, LocalMcpResultStatus::Completed);
    assert_eq!(result.result_code, "ok");
    assert_eq!(result.responses.len(), 4);
    assert!(result.startup.network_disabled);
    assert!(result.shutdown.group_absent);
    assert!(result.shutdown.reaped);
    assert_eq!(result.shutdown.memory_after.process_count, 0);
    eprintln!(
        "installed n8n-mcp acceptance: startup_ms={} provider_ms={} total_ms={} peak_samples={:?}",
        result.telemetry.startup_latency_ms,
        result.telemetry.provider_latency_ms,
        result.telemetry.total_latency_ms,
        result.memory_samples
    );
}

fn write_mcp_line(writer: &mut impl Write, value: &serde_json::Value) {
    serde_json::to_writer(&mut *writer, value).expect("serialize MCP frame");
    writer.write_all(b"\n").expect("write MCP frame newline");
    writer.flush().expect("flush MCP frame");
}

fn read_mcp_line(reader: &mut impl BufRead) -> serde_json::Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read MCP frame");
    assert!(
        !line.is_empty(),
        "provider closed stdout before MCP response"
    );
    serde_json::from_str(&line).expect("valid MCP response")
}

fn one_call() -> LocalMcpRequest {
    LocalMcpRequest {
        correlation_id: "negative-matrix".into(),
        calls: vec![LocalMcpCall {
            tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
            arguments: json!({}),
        }],
    }
}

fn blocked_write_request() -> LocalMcpRequest {
    LocalMcpRequest {
        correlation_id: "blocked-write".into(),
        calls: (0..2)
            .map(|_| LocalMcpCall {
                tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
                arguments: json!({"padding": "x".repeat(250_000)}),
            })
            .collect(),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    script: std::path::PathBuf,
    package_json: std::path::PathBuf,
    mode: String,
}

impl Fixture {
    fn new(mode: &str) -> Self {
        let dir = tempdir().expect("fixture directory");
        let script = dir.path().join("provider.sh");
        let package_json = dir.path().join("package.json");
        fs::write(&script, fixture_script()).expect("fixture script");
        fs::write(
            &package_json,
            r#"{"name":"fixture-provider","version":"1.0.0"}"#,
        )
        .expect("fixture package");
        let mut permissions = fs::metadata(&script)
            .expect("fixture metadata")
            .permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o700);
        fs::set_permissions(&script, permissions).expect("fixture permissions");
        Self {
            _dir: dir,
            script,
            package_json,
            mode: mode.into(),
        }
    }

    fn policy(&self) -> LocalMcpPolicy {
        self.policy_with_timeout(1_000)
    }

    fn policy_with_timeout(&self, request_timeout_ms: u64) -> LocalMcpPolicy {
        let launcher = fs::canonicalize("/bin/sh").expect("shell");
        let expected_digest = local_mcp_schema_digest(&json!({"type": "object"}));
        let expected_catalog = LOCAL_MCP_CATALOG_TOOLS
            .iter()
            .map(|tool| ((*tool).into(), expected_digest.clone()))
            .collect();
        LocalMcpPolicy {
            package_id: "fixture-provider".into(),
            package_version: semver::Version::new(1, 0, 0),
            launcher_path: launcher.to_string_lossy().into_owned(),
            launcher_digest: digest(Path::new(&launcher)),
            runtime_executable: launcher.to_string_lossy().into_owned(),
            runtime_executable_digest: digest(Path::new(&launcher)),
            package_metadata_path: self.package_json.to_string_lossy().into_owned(),
            package_metadata_digest: digest(&self.package_json),
            protocol_version: "2024-11-05".into(),
            fixed_args: vec![
                self.script.to_string_lossy().into_owned(),
                self.mode.clone(),
            ],
            fixed_env: BTreeMap::new(),
            allowed_methods: LOCAL_MCP_METHODS
                .iter()
                .map(|method| (*method).into())
                .collect(),
            expected_catalog,
            callable_tools: LOCAL_MCP_CATALOG_TOOLS
                .iter()
                .map(|tool| (*tool).into())
                .collect(),
            max_frame_bytes: 1_024,
            max_request_bytes: 1_024,
            max_result_bytes: 1_024,
            max_sequential_calls: 7,
            startup_timeout_ms: 1_000,
            request_timeout_ms,
            shutdown_timeout_ms: 1_000,
            idle_window_ms: 0,
            network_disabled: true,
        }
    }

    fn provider(&self) -> LocalMcpProvider {
        LocalMcpProvider::new(self.policy()).expect("fixture policy")
    }

    fn provider_with_timeout(&self, request_timeout_ms: u64) -> LocalMcpProvider {
        self.provider_with_timeouts(1_000, request_timeout_ms)
    }

    fn provider_with_timeouts(
        &self,
        startup_timeout_ms: u64,
        request_timeout_ms: u64,
    ) -> LocalMcpProvider {
        let mut policy = self.policy_with_timeout(request_timeout_ms);
        policy.startup_timeout_ms = startup_timeout_ms;
        LocalMcpProvider::new(policy).expect("fixture policy")
    }

    fn provider_with_large_frames(
        &self,
        startup_timeout_ms: u64,
        request_timeout_ms: u64,
    ) -> LocalMcpProvider {
        let mut policy = self.policy_with_timeouts(startup_timeout_ms, request_timeout_ms);
        policy.max_frame_bytes = 262_144;
        policy.max_request_bytes = 262_144;
        policy.max_result_bytes = 262_144;
        LocalMcpProvider::new(policy).expect("fixture policy")
    }

    fn policy_with_timeouts(
        &self,
        startup_timeout_ms: u64,
        request_timeout_ms: u64,
    ) -> LocalMcpPolicy {
        let mut policy = self.policy_with_timeout(request_timeout_ms);
        policy.startup_timeout_ms = startup_timeout_ms;
        policy
    }
}

fn digest(path: &Path) -> String {
    blake3::hash(&fs::read(path).expect("digest input"))
        .to_hex()
        .to_string()
}

fn fixture_script() -> &'static str {
    r##"#!/bin/sh
set -eu
mode="$1"
tools='[{"name":"tools_documentation","inputSchema":{"type":"object"}},{"name":"search_nodes","inputSchema":{"type":"object"}},{"name":"get_node","inputSchema":{"type":"object"}},{"name":"validate_node","inputSchema":{"type":"object"}},{"name":"get_template","inputSchema":{"type":"object"}},{"name":"search_templates","inputSchema":{"type":"object"}},{"name":"validate_workflow","inputSchema":{"type":"object"}}]'
call_count=0
if [ "$mode" = startup-timeout ]; then
  sleep 2
fi
if [ "$mode" = stdout-flood ]; then
  i=0
  while [ "$i" -lt 32 ]; do
    printf '{"jsonrpc":"2.0","id":900,"result":{"unsolicited":true}}\n'
    i=$((i + 1))
  done
fi
if [ "$mode" = socket ]; then
  if getent hosts example.invalid >/dev/null 2>&1; then
    exit 23
  fi
fi
while IFS= read -r line; do
  id=$(printf '%s\n' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' || true)
  case "$line" in
    *'"method":"initialize"'*)
      if [ "$mode" = bad-jsonrpc ]; then
        printf '{"jsonrpc":"1.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id"
      elif [ "$mode" = protocol-mismatch ]; then
        printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-10-01","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id"
      else
        printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id"
      fi
      ;;
    *'"method":"notifications/initialized"'*)
      ;;
    *'"method":"tools/list"'*)
      if [ "$mode" = catalog ]; then
        printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"unexpected","inputSchema":{"type":"object"}}]}}\n' "$id"
      elif [ "$mode" = schema ]; then
        printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"tools_documentation","inputSchema":{"type":"string"}}]}}\n' "$id"
      else
        printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}\n' "$id" "$tools"
      fi
      ;;
    *'"method":"tools/call"'*)
      case "$mode" in
        timeout)
          sleep 2
          ;;
        malformed)
          printf 'not-json\n'
          exit 0
          ;;
        oversized)
          blob=$(head -c 2000 /dev/zero | tr '\000' x)
          printf '{"jsonrpc":"2.0","id":%s,"result":{"blob":"%s"}}\n' "$id" "$blob"
          ;;
        oversized-no-newline)
          head -c 2000 /dev/zero | tr '\000' x
          exit 0
          ;;
        crash)
          exit 17
          ;;
        stderr)
          printf 'untrusted-provider-text\n' >&2
          printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
          ;;
        escape)
          if setsid sh -c 'exit 0' >/dev/null 2>&1; then
            exit 23
          fi
          printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
          ;;
        blocked-write)
          call_count=$((call_count + 1))
          printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
          while :; do sleep 1; done
          ;;
        orphan)
          sh -c 'trap ":" TERM; while :; do sleep 1; done' &
          trap ':' TERM
          printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
          while :; do sleep 1; done
          ;;
        orphan-exit)
          sh -c 'trap ":" TERM; while :; do sleep 1; done' &
          printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
          exit 0
          ;;
        identity-drift)
          printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
          exec /bin/sleep 0.5
          ;;
        late-identity-drift)
          trap 'exec /bin/sleep 0.5' TERM
          printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
          while :; do sleep 1; done
          ;;
        *)
          printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
          ;;
      esac
      ;;
  esac
done
"##
}
