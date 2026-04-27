#[cfg(not(test))]
use std::io::{Read, Write};
#[cfg(not(test))]
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(not(test))]
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
#[cfg(not(test))]
use std::time::Instant;

#[cfg(not(test))]
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
#[cfg(not(test))]
use serde_json::json;

#[cfg(not(test))]
const CONNECTOR_ID: &str = "fcp.bench.cold-start:utility:1.0.0";
#[cfg(not(test))]
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(not(test))]
fn cargo_bin(env_name: &str, binary_name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(env_name) {
        return PathBuf::from(path);
    }

    let current_exe = std::env::current_exe().expect("current benchmark executable path");
    let deps_dir = current_exe
        .parent()
        .expect("benchmark executable should have parent directory");
    let profile_dir = deps_dir
        .parent()
        .expect("benchmark executable should live under target/<profile>/deps");
    let candidate = profile_dir.join(format!("{binary_name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        candidate.exists(),
        "expected compiled {binary_name} at {}",
        candidate.display()
    );
    candidate
}

#[cfg(not(test))]
fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port");
    listener
        .local_addr()
        .expect("read loopback listener address")
}

#[cfg(not(test))]
fn connector_inventory(connector_binary: &str) -> String {
    serde_json::to_string(&vec![json!({
        "id": CONNECTOR_ID,
        "binary": connector_binary,
        "name": "Cold Start Benchmark Connector",
        "description": "Host-backed cold-start benchmark fixture",
        "env": {
            "FCP_TEST_CONNECTOR_ID": CONNECTOR_ID,
            "FCP_TEST_CONNECTOR_ARCHETYPE": "request_response"
        },
        "config": {}
    })])
    .expect("serialize connector inventory")
}

#[cfg(not(test))]
fn spawn_host(addr: SocketAddr, connector_binary: &str, state_file: &std::path::Path) -> Child {
    let host_binary = cargo_bin("CARGO_BIN_EXE_fcp-host", "fcp-host");
    Command::new(host_binary)
        .env("FCP_HOST_BIND", addr.to_string())
        .env("FCP_HOST_CONNECTORS", connector_inventory(connector_binary))
        .env("FCP_HOST_LIFECYCLE_STATE_FILE", state_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fcp-host")
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    const fn new(child: Child) -> Self {
        Self { child }
    }

    #[cfg(not(test))]
    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(not(test))]
fn request_health(addr: SocketAddr) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(100))?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    write!(
        stream,
        "GET /rpc/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[cfg(not(test))]
fn wait_for_connector_ready(child: &mut Child, addr: SocketAddr) {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut last_response = String::new();
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll fcp-host child") {
            panic!("fcp-host exited before readiness: {status}");
        }

        if let Ok(response) = request_health(addr) {
            let ready = response.starts_with("HTTP/1.1 200")
                && response.contains(CONNECTOR_ID)
                && response.contains("\"healthy\"");
            if ready {
                return;
            }
            last_response = response;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    panic!(
        "timed out after {READINESS_TIMEOUT:?} waiting for activated connector in /rpc/health; last response: {last_response:?}"
    );
}

#[cfg(not(test))]
fn activate_connector_to_ready_once(connector_binary: &str) -> Duration {
    let addr = free_loopback_addr();
    let state_dir = tempfile::tempdir().expect("create host state tempdir");
    let state_file = state_dir.path().join("lifecycle-state.json");

    let started = Instant::now();
    let mut child = ChildGuard::new(spawn_host(addr, connector_binary, &state_file));
    wait_for_connector_ready(child.child_mut(), addr);
    let elapsed = started.elapsed();

    elapsed
}

#[cfg(not(test))]
fn cold_start(c: &mut Criterion) {
    let connector_binary = cargo_bin("CARGO_BIN_EXE_fcp-test-connector", "fcp-test-connector");
    let connector_binary = connector_binary
        .to_str()
        .expect("connector binary path should be UTF-8")
        .to_owned();

    let mut group = c.benchmark_group("host_backed_cold_start");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));
    group.bench_with_input(
        BenchmarkId::new("connector_activate_to_ready", CONNECTOR_ID),
        &connector_binary,
        |bench, binary| {
            bench.iter_custom(|iterations| {
                let mut total = Duration::ZERO;
                for _ in 0..iterations {
                    total += activate_connector_to_ready_once(binary);
                }
                total
            });
        },
    );
    group.finish();
}

#[cfg(not(test))]
criterion_group!(benches, cold_start);
#[cfg(not(test))]
criterion_main!(benches);

#[cfg(all(test, unix))]
fn main() {
    tests::child_guard_kills_child_when_scope_panics();
}

#[cfg(all(test, not(unix)))]
fn main() {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    pub(super) fn child_guard_kills_child_when_scope_panics() {
        let tempdir = tempfile::tempdir().expect("create marker tempdir");
        let marker = tempdir.path().join("survived");
        let script = format!("sleep 2; printf survived > {}", marker.display());

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(|| {
            let child = Command::new("sh")
                .arg("-c")
                .arg(script)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn marker child");
            let _guard = ChildGuard::new(child);
            std::panic::panic_any("simulated readiness panic");
        });
        std::panic::set_hook(previous_hook);

        assert!(result.is_err());
        std::thread::sleep(Duration::from_secs(3));
        assert!(
            !marker.exists(),
            "child survived guard drop long enough to write marker"
        );
    }
}
