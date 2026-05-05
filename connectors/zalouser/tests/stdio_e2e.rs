use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const REPLAY_COMMAND: &str = "rch exec -- cargo test -p fcp-zalouser binary_stdio_planned_only_denies_helper_without_child_process -- --nocapture";

struct ConnectorProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl ConnectorProcess {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-zalouser"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fcp-zalouser binary");
        let stdin = child.stdin.take().expect("connector stdin");
        let stdout = child.stdout.take().expect("connector stdout");
        Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn request(&mut self, id: u64, method: &str, params: &Value) -> Value {
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let stdin = self.stdin.as_mut().expect("connector stdin open");
        writeln!(stdin, "{request}").expect("write request");
        stdin.flush().expect("flush request");

        let mut response = String::new();
        self.stdout.read_line(&mut response).expect("read response");
        assert!(!response.is_empty(), "connector returned EOF");
        serde_json::from_str(&response).expect("valid JSON-RPC response")
    }

    fn close_stdin(&mut self) {
        self.stdin.take();
    }

    fn wait_for_exit(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait connector") {
                assert!(status.success(), "connector exited with {status}");
                return;
            }
            if Instant::now() >= deadline {
                self.child.kill().expect("kill stuck connector");
                self.child.wait().expect("wait killed connector");
                panic!("connector did not exit after stdin closed");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ConnectorProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(unix)]
fn child_pids(parent_pid: u32) -> Vec<u32> {
    let output = Command::new("ps")
        .args(["-eo", "pid=,ppid="])
        .output()
        .expect("run ps");
    assert!(output.status.success(), "ps should succeed");
    let listing = String::from_utf8(output.stdout).expect("ps output utf8");
    let mut pids = listing
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let process_id = fields.next()?.parse::<u32>().ok()?;
            let parent_process_id = fields.next()?.parse::<u32>().ok()?;
            (parent_process_id == parent_pid).then_some(process_id)
        })
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids
}

#[cfg(not(unix))]
fn child_pids(_parent_pid: u32) -> Vec<u32> {
    Vec::new()
}

fn print_planned_only_evidence(
    correlation_id: &str,
    connector_pid: u32,
    children_after_spawn: &[u32],
    children_after_invoke: &[u32],
) {
    println!(
        "{}",
        json!({
            "schema": "zalouser-planned-only-e2e/v1",
            "correlation_id": correlation_id,
            "scenario": "planned_only_stdio_denial",
            "connector_pid": connector_pid,
            "child_pid_absent": children_after_spawn.is_empty() && children_after_invoke.is_empty(),
            "children_after_spawn": children_after_spawn,
            "children_after_invoke": children_after_invoke,
            "denied_methods": ["invoke", "simulate"],
            "openclaw_current_head": "a52010be7d2da09a8800b7e06316cfb6cb1615b5",
            "openclaw_exec_hardening_applicability": "not_applicable_no_exec_grant_no_helper_runner",
            "replay_command": REPLAY_COMMAND,
        })
    );
}

#[test]
fn binary_stdio_planned_only_denies_helper_without_child_process() {
    let mut connector = ConnectorProcess::spawn();
    let connector_pid = connector.pid();
    let correlation_id = format!("zalouser-e2e-{connector_pid}");
    let children_after_spawn = child_pids(connector_pid);
    assert!(children_after_spawn.is_empty());

    let configure = connector.request(1, "configure", &json!({}));
    assert!(
        configure["result"]["configured"]
            .as_bool()
            .expect("configured flag")
    );

    let handshake = connector.request(2, "handshake", &json!({}));
    assert_eq!(handshake["result"]["surface_status"], "quarantined");
    assert!(
        !handshake["result"]["execution_enabled"]
            .as_bool()
            .expect("execution flag")
    );

    let health = connector.request(3, "health", &json!({}));
    assert_eq!(health["result"]["status"], "degraded");
    assert!(
        !health["result"]["live_requests_supported"]
            .as_bool()
            .expect("live flag")
    );

    let doctor = connector.request(4, "doctor", &json!({}));
    assert_eq!(doctor["result"]["status"], "degraded");
    assert!(
        doctor["result"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["reason_code"] == "helper_exec_disabled")
    );

    let self_check = connector.request(5, "self_check", &json!({}));
    assert_eq!(self_check["result"]["status"], "unsupported");
    assert_eq!(
        self_check["result"]["reason_code"],
        "invoke_surface_unimplemented"
    );

    let introspect = connector.request(6, "introspect", &json!({}));
    assert_eq!(introspect["result"]["surface_status"], "quarantined");
    assert_eq!(introspect["result"]["helper_process_policy"], Value::Null);

    let children_before_invoke = child_pids(connector_pid);
    let invoke = connector.request(
        7,
        "invoke",
        &json!({"operation_id": "zalouser.helper.exec", "action": "send_message"}),
    );
    assert_eq!(invoke["error"]["code"], "FCP-1002");
    assert!(
        invoke["error"]["message"]
            .as_str()
            .expect("invoke error message")
            .contains("planned but not implemented")
    );
    let children_after_invoke = child_pids(connector_pid);
    assert_eq!(children_before_invoke, children_after_invoke);
    assert!(children_after_invoke.is_empty());

    let simulate = connector.request(
        8,
        "simulate",
        &json!({"operation_id": "zalouser.helper.exec", "action": "send_message"}),
    );
    assert!(
        !simulate["result"]["allowed"]
            .as_bool()
            .expect("allowed flag")
    );
    assert_eq!(
        simulate["result"]["reason_code"],
        "invoke_surface_unimplemented"
    );

    let malformed = connector.request(9, "invoke", &json!({"operation_id": 7}));
    assert_eq!(malformed["error"]["code"], "FCP-1003");
    assert!(
        malformed["error"]["message"]
            .as_str()
            .expect("malformed error message")
            .contains("Missing operation_id")
    );

    let shutdown = connector.request(10, "shutdown", &json!({}));
    assert_eq!(shutdown["result"], json!({}));
    connector.close_stdin();
    connector.wait_for_exit(Duration::from_secs(5));

    print_planned_only_evidence(
        &correlation_id,
        connector_pid,
        &children_after_spawn,
        &children_after_invoke,
    );
}
