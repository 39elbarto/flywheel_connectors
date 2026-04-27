//! Criterion benchmark for idle host CPU overhead.
//!
//! Bead flywheel_connectors-xnwpt. This measures the README perf target for
//! idle CPU overhead by spawning a real `fcp-host` with one activated test
//! connector, issuing no invokes, and sampling host-process CPU time across a
//! fixed idle window.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;

const CONNECTOR_ID: &str = "fcp.bench.cpu-overhead:utility:1.0.0";
const READINESS_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_SAMPLE_WINDOW: Duration = Duration::from_secs(5);
const IDLE_SETTLE_TIME: Duration = Duration::from_millis(500);
const MAX_IDLE_CPU_PERCENT: f64 = 1.0;

#[derive(Debug, Clone, Copy)]
struct CpuSample {
    process_cpu: Duration,
    wall: Instant,
}

#[derive(Debug, Clone, Copy)]
struct IdleCpuMeasurement {
    cpu_percent: f64,
    wall: Duration,
}

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

fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port");
    listener
        .local_addr()
        .expect("read loopback listener address")
}

fn connector_inventory(connector_binary: &str) -> String {
    serde_json::to_string(&vec![json!({
        "id": CONNECTOR_ID,
        "binary": connector_binary,
        "name": "CPU Overhead Benchmark Connector",
        "description": "Host-backed idle CPU benchmark fixture",
        "env": {
            "FCP_TEST_CONNECTOR_ID": CONNECTOR_ID,
            "FCP_TEST_CONNECTOR_ARCHETYPE": "request_response"
        },
        "config": {}
    })])
    .expect("serialize connector inventory")
}

fn spawn_host(addr: SocketAddr, connector_binary: &str, state_file: &Path) -> Child {
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

#[cfg(target_os = "linux")]
fn process_cpu_time(pid: u32) -> Duration {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .expect("read Linux process stat for fcp-host");
    let after_comm = stat
        .rsplit_once(") ")
        .expect("Linux process stat should contain command field")
        .1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let user_ticks: u64 = fields
        .get(11)
        .expect("Linux process stat should contain utime")
        .parse()
        .expect("parse process utime ticks");
    let system_ticks: u64 = fields
        .get(12)
        .expect("Linux process stat should contain stime")
        .parse()
        .expect("parse process stime ticks");
    let ticks_per_second = linux_clock_ticks_per_second();
    Duration::from_secs_f64((user_ticks + system_ticks) as f64 / ticks_per_second)
}

#[cfg(target_os = "linux")]
fn linux_clock_ticks_per_second() -> f64 {
    Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|output| {
            output
                .status
                .success()
                .then_some(output.stdout)
                .and_then(|stdout| String::from_utf8(stdout).ok())
        })
        .and_then(|stdout| stdout.trim().parse::<f64>().ok())
        .filter(|ticks| *ticks > 0.0)
        .unwrap_or(100.0)
}

#[cfg(not(target_os = "linux"))]
fn process_cpu_time(pid: u32) -> Duration {
    let output = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .expect("run ps to sample fcp-host CPU time");
    assert!(
        output.status.success(),
        "ps failed while sampling fcp-host CPU time"
    );
    let raw = String::from_utf8(output.stdout).expect("ps output should be UTF-8");
    parse_ps_cpu_time(raw.trim()).expect("parse ps CPU time")
}

#[cfg(not(target_os = "linux"))]
fn parse_ps_cpu_time(raw: &str) -> Option<Duration> {
    let (days, rest) = match raw.split_once('-') {
        Some((days, rest)) => (days.parse().ok()?, rest),
        None => (0_u64, raw),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let seconds = match parts.as_slice() {
        [minutes, seconds] => minutes.parse::<u64>().ok()? * 60 + parse_seconds(seconds)?,
        [hours, minutes, seconds] => {
            hours.parse::<u64>().ok()? * 3600
                + minutes.parse::<u64>().ok()? * 60
                + parse_seconds(seconds)?
        }
        _ => return None,
    };
    Some(Duration::from_secs(days * 86_400 + seconds))
}

#[cfg(not(target_os = "linux"))]
fn parse_seconds(raw: &str) -> Option<u64> {
    raw.split('.').next()?.parse().ok()
}

fn sample_cpu(pid: u32) -> CpuSample {
    CpuSample {
        process_cpu: process_cpu_time(pid),
        wall: Instant::now(),
    }
}

fn measure_idle_cpu_once() -> IdleCpuMeasurement {
    let connector_binary = cargo_bin("CARGO_BIN_EXE_fcp-test-connector", "fcp-test-connector");
    let connector_binary = connector_binary
        .to_str()
        .expect("connector binary path should be UTF-8")
        .to_owned();

    let addr = free_loopback_addr();
    let state_dir = tempfile::tempdir().expect("create host state tempdir");
    let state_file = state_dir.path().join("lifecycle-state.json");
    let mut child = spawn_host(addr, &connector_binary, &state_file);
    wait_for_connector_ready(&mut child, addr);
    std::thread::sleep(IDLE_SETTLE_TIME);

    let before = sample_cpu(child.id());
    std::thread::sleep(IDLE_SAMPLE_WINDOW);
    if let Some(status) = child
        .try_wait()
        .expect("poll fcp-host child after idle sample")
    {
        panic!("fcp-host exited during idle CPU sample: {status}");
    }
    let after = sample_cpu(child.id());

    let _ = child.kill();
    let _ = child.wait();

    let wall = after.wall.duration_since(before.wall);
    let cpu = after
        .process_cpu
        .checked_sub(before.process_cpu)
        .unwrap_or(Duration::ZERO);
    let cpu_percent = cpu.as_secs_f64() / wall.as_secs_f64() * 100.0;

    IdleCpuMeasurement { cpu_percent, wall }
}

fn assert_idle_cpu_target(measurement: IdleCpuMeasurement) {
    assert!(
        measurement.cpu_percent < MAX_IDLE_CPU_PERCENT,
        "idle fcp-host CPU overhead {:.3}% exceeded target < {:.1}% over {:?}",
        measurement.cpu_percent,
        MAX_IDLE_CPU_PERCENT,
        measurement.wall
    );
}

fn cpu_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("host_backed_cpu_overhead");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(IDLE_SAMPLE_WINDOW);
    group.bench_function(
        BenchmarkId::new("idle_host_cpu_percent", CONNECTOR_ID),
        |bench| {
            bench.iter_custom(|iterations| {
                let mut total = Duration::ZERO;
                for _ in 0..iterations {
                    let measurement = measure_idle_cpu_once();
                    assert_idle_cpu_target(measurement);
                    total += measurement.wall;
                }
                total
            });
        },
    );
    group.finish();
}

criterion_group!(benches, cpu_overhead);
criterion_main!(benches);
