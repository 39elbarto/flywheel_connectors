//! Host-backed RSS overhead benchmark for spawned connectors.
//!
//! This benchmark measures the live resident-set-size delta between an empty
//! fcp-host process and an fcp-host process supervising multiple activated test
//! connectors. The reported per-connector overhead is:
//!
//! (RSS(host + connector children) - RSS(empty host)) / connector_count

#[cfg(not(target_os = "linux"))]
use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

const CONNECTOR_PREFIX: &str = "fcp.bench.memory-overhead";
const CONNECTOR_COUNT: usize = 3;
const SAMPLE_COUNT: usize = 5;
const READINESS_TIMEOUT: Duration = Duration::from_secs(15);
const RSS_SETTLE_TIME: Duration = Duration::from_millis(250);
const BYTES_PER_MIB: u64 = 1024 * 1024;
const TARGET_PER_CONNECTOR_BYTES: u64 = 10 * BYTES_PER_MIB;

type BenchResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Debug)]
struct MemorySample {
    empty_host_rss_bytes: u64,
    activated_tree_rss_bytes: u64,
    connector_count: usize,
}

impl MemorySample {
    fn overhead_bytes(&self) -> u64 {
        self.activated_tree_rss_bytes
            .saturating_sub(self.empty_host_rss_bytes)
    }

    fn per_connector_bytes(&self) -> u64 {
        self.overhead_bytes() / self.connector_count as u64
    }
}

fn bench_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

fn cargo_bin(env_name: &str, binary_name: &str) -> BenchResult<PathBuf> {
    if let Some(path) = std::env::var_os(env_name) {
        return Ok(PathBuf::from(path));
    }

    let current_exe = std::env::current_exe()?;
    let deps_dir = current_exe.parent().ok_or_else(|| {
        bench_error(format!(
            "benchmark executable has no parent directory: {}",
            current_exe.display()
        ))
    })?;
    let profile_dir = deps_dir.parent().ok_or_else(|| {
        bench_error(format!(
            "benchmark executable is not under target/<profile>/deps: {}",
            current_exe.display()
        ))
    })?;
    let candidate = profile_dir.join(format!("{binary_name}{}", std::env::consts::EXE_SUFFIX));
    if !candidate.exists() {
        return Err(bench_error(format!(
            "expected compiled {binary_name} at {}",
            candidate.display()
        ))
        .into());
    }
    Ok(candidate)
}

fn free_loopback_addr() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()
}

fn connector_id(index: usize) -> String {
    format!("{CONNECTOR_PREFIX}-{index}:utility:1.0.0")
}

fn connector_inventory(connector_binary: &str, connector_ids: &[String]) -> BenchResult<String> {
    let entries: Vec<_> = connector_ids
        .iter()
        .map(|connector_id| {
            json!({
                "id": connector_id,
                "binary": connector_binary,
                "name": format!("Memory Overhead Benchmark Connector {connector_id}"),
                "description": "Host-backed memory-overhead benchmark fixture",
                "env": {
                    "FCP_TEST_CONNECTOR_ID": connector_id,
                    "FCP_TEST_CONNECTOR_ARCHETYPE": "request_response"
                },
                "config": {}
            })
        })
        .collect();
    Ok(serde_json::to_string(&entries)?)
}

fn spawn_host(
    addr: SocketAddr,
    connector_binary: &str,
    connector_ids: &[String],
    state_file: &Path,
) -> BenchResult<Child> {
    let host_binary = cargo_bin("CARGO_BIN_EXE_fcp-host", "fcp-host")?;
    Ok(Command::new(host_binary)
        .env("FCP_HOST_BIND", addr.to_string())
        .env(
            "FCP_HOST_CONNECTORS",
            connector_inventory(connector_binary, connector_ids)?,
        )
        .env("FCP_HOST_LIFECYCLE_STATE_FILE", state_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn request_health(addr: SocketAddr) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(250))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    write!(
        stream,
        "GET /rpc/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn wait_for_host_ready(
    child: &mut Child,
    addr: SocketAddr,
    connector_ids: &[String],
) -> BenchResult<()> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut last_response = String::new();
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Err(bench_error(format!("fcp-host exited before readiness: {status}")).into());
        }

        if let Ok(response) = request_health(addr) {
            let ready = response.starts_with("HTTP/1.1 200")
                && connector_ids
                    .iter()
                    .all(|connector_id| response.contains(connector_id))
                && (connector_ids.is_empty() || response.contains("\"healthy\""));
            if ready {
                return Ok(());
            }
            last_response = response;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    Err(bench_error(format!(
        "timed out after {READINESS_TIMEOUT:?} waiting for /rpc/health readiness; last response: {last_response:?}"
    ))
    .into())
}

fn run_host_and_measure(connector_binary: &str, connector_ids: &[String]) -> BenchResult<u64> {
    let addr = free_loopback_addr()?;
    let state_dir = tempfile::tempdir()?;
    let state_file = state_dir.path().join("lifecycle-state.json");
    let mut child = spawn_host(addr, connector_binary, connector_ids, &state_file)?;

    let measurement = (|| {
        wait_for_host_ready(&mut child, addr, connector_ids)?;
        std::thread::sleep(RSS_SETTLE_TIME);
        Ok(process_tree_rss_bytes(child.id())?)
    })();

    let _ = child.kill();
    let _ = child.wait();
    measurement
}

fn measure_once(connector_binary: &str) -> BenchResult<MemorySample> {
    let connector_ids: Vec<String> = (0..CONNECTOR_COUNT).map(connector_id).collect();
    let empty_host_rss_bytes = run_host_and_measure(connector_binary, &[])?;
    let activated_tree_rss_bytes = run_host_and_measure(connector_binary, &connector_ids)?;
    Ok(MemorySample {
        empty_host_rss_bytes,
        activated_tree_rss_bytes,
        connector_count: connector_ids.len(),
    })
}

fn median_sample(samples: &mut [MemorySample]) -> BenchResult<MemorySample> {
    if samples.is_empty() {
        return Err(bench_error("memory benchmark needs at least one sample").into());
    }
    samples.sort_by_key(MemorySample::per_connector_bytes);
    Ok(samples[samples.len() / 2].clone())
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / BYTES_PER_MIB as f64
}

fn main() -> BenchResult<()> {
    let connector_binary = cargo_bin("CARGO_BIN_EXE_fcp-test-connector", "fcp-test-connector")?;
    let connector_binary = connector_binary.to_string_lossy().into_owned();

    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    for _ in 0..SAMPLE_COUNT {
        samples.push(measure_once(&connector_binary)?);
    }
    let median = median_sample(&mut samples)?;
    let per_connector_bytes = median.per_connector_bytes();
    let within_target = per_connector_bytes <= TARGET_PER_CONNECTOR_BYTES;

    if median.empty_host_rss_bytes == 0 {
        return Err(bench_error("empty host RSS measurement must be non-zero").into());
    }
    if median.activated_tree_rss_bytes == 0 {
        return Err(bench_error("activated host RSS measurement must be non-zero").into());
    }
    if per_connector_bytes == 0 {
        return Err(bench_error("per-connector RSS overhead measurement must be non-zero").into());
    }

    println!(
        "{}",
        json!({
            "benchmark": "host_backed_memory_overhead",
            "connector_count": median.connector_count,
            "samples": SAMPLE_COUNT,
            "empty_host_rss_bytes": median.empty_host_rss_bytes,
            "activated_tree_rss_bytes": median.activated_tree_rss_bytes,
            "overhead_bytes": median.overhead_bytes(),
            "per_connector_bytes": per_connector_bytes,
            "per_connector_mib": mib(per_connector_bytes),
            "target_per_connector_bytes": TARGET_PER_CONNECTOR_BYTES,
            "target_per_connector_mib": mib(TARGET_PER_CONNECTOR_BYTES),
            "within_target": within_target,
            "slo_status": if within_target { "PASS" } else { "FAIL" },
        })
    );
    if !within_target {
        return Err(bench_error(format!(
            "host-backed memory overhead {:.2} MiB per connector exceeded README SLO < {:.2} MiB",
            mib(per_connector_bytes),
            mib(TARGET_PER_CONNECTOR_BYTES),
        ))
        .into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_tree_rss_bytes(root_pid: u32) -> std::io::Result<u64> {
    let mut seen = HashSet::new();
    let mut stack = vec![root_pid];
    let mut total = 0_u64;

    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        total = total.saturating_add(linux_process_rss_bytes(pid)?);
        stack.extend(linux_child_pids(pid)?);
    }

    Ok(total)
}

#[cfg(target_os = "linux")]
fn linux_process_rss_bytes(pid: u32) -> std::io::Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            let kib = value
                .split_whitespace()
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "missing VmRSS value")
                })?
                .parse::<u64>()
                .map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid VmRSS value: {err}"),
                    )
                })?;
            return Ok(kib.saturating_mul(1024));
        }
    }
    Ok(0)
}

#[cfg(target_os = "linux")]
fn linux_child_pids(pid: u32) -> std::io::Result<Vec<u32>> {
    let task_dir = format!("/proc/{pid}/task");
    let mut children = Vec::new();
    for task in std::fs::read_dir(task_dir)? {
        let children_file = task?.path().join("children");
        let Ok(raw) = std::fs::read_to_string(children_file) else {
            continue;
        };
        for token in raw.split_whitespace() {
            if let Ok(child_pid) = token.parse::<u32>() {
                children.push(child_pid);
            }
        }
    }
    children.sort_unstable();
    children.dedup();
    Ok(children)
}

#[cfg(not(target_os = "linux"))]
fn process_tree_rss_bytes(root_pid: u32) -> std::io::Result<u64> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,ppid=,rss="])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "ps exited with {}",
            output.status
        )));
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let mut rss_by_pid = HashMap::new();
    let mut children_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let (Some(pid), Some(ppid), Some(rss_kib)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let (Ok(pid), Ok(ppid), Ok(rss_kib)) = (
            pid.parse::<u32>(),
            ppid.parse::<u32>(),
            rss_kib.parse::<u64>(),
        ) else {
            continue;
        };
        rss_by_pid.insert(pid, rss_kib.saturating_mul(1024));
        children_by_parent.entry(ppid).or_default().push(pid);
    }

    let mut seen = HashSet::new();
    let mut stack = vec![root_pid];
    let mut total = 0_u64;
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        total = total.saturating_add(*rss_by_pid.get(&pid).unwrap_or(&0));
        if let Some(children) = children_by_parent.get(&pid) {
            stack.extend(children.iter().copied());
        }
    }
    Ok(total)
}
