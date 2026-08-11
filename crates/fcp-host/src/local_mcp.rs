//! Linux request-scoped MCP stdio supervision for the fixed local n8n catalog.
//!
//! This is an internal host primitive for the later typed n8n router. It does
//! not expose a generic `tools/call` operation and it never accepts a command,
//! argument, environment, or path from model input.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fcp_manifest::{LOCAL_MCP_PROTOCOL_VERSION, LocalMcpPolicy, local_mcp_schema_digest};
use fcp_sandbox::{
    OwnedProcess, ProcessGroupError, ProcessMemorySample, ProcessSpec, TerminationReport,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CLIENT_NAME: &str = "fcp-n8n-local";
const CLIENT_VERSION: &str = "0.1.0";

/// One fixed local MCP tool call. The tool name is checked against policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpCall {
    pub tool: String,
    pub arguments: Value,
}

/// One bounded request containing sequential calls only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpRequest {
    pub correlation_id: String,
    pub calls: Vec<LocalMcpCall>,
}

/// Redacted startup evidence. No endpoint, payload, tool name, or provider
/// response is included.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpStartupReceipt {
    pub pid: u32,
    pub pgid: i32,
    pub session_id: i32,
    pub start_time_ticks: u64,
    pub launcher_digest: String,
    pub runtime_executable_digest: String,
    pub network_disabled: bool,
    pub memory_before: ProcessMemorySample,
}

/// Redacted shutdown evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpShutdownReceipt {
    pub reason: LocalMcpShutdownReason,
    pub term_sent: bool,
    pub kill_sent: bool,
    pub reaped: bool,
    pub group_absent: bool,
    pub stderr_bytes: u64,
    pub memory_after: ProcessMemorySample,
}

/// Why the request-scoped child was torn down.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalMcpShutdownReason {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

/// Bounded provider result. Tool result data is returned to the intended
/// caller, while lifecycle evidence remains content-safe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpResult {
    pub correlation_id: String,
    pub responses: Vec<Value>,
    pub startup: LocalMcpStartupReceipt,
    pub shutdown: LocalMcpShutdownReceipt,
    pub memory_samples: Vec<ProcessMemorySample>,
    pub status: LocalMcpResultStatus,
    pub teardown_error_code: Option<String>,
    pub result_code: String,
    pub telemetry: LocalMcpTelemetry,
}

/// Safe completion status. A post-spawn failure is returned with lifecycle
/// evidence rather than being collapsed into a plain error.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalMcpResultStatus {
    Completed,
    Failed,
}

/// Redacted timing and byte counters for one request-scoped session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalMcpTelemetry {
    pub startup_latency_ms: u64,
    pub provider_latency_ms: u64,
    pub total_latency_ms: u64,
    pub shutdown_latency_ms: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
}

/// Safe failures from the local provider boundary.
#[derive(Debug, thiserror::Error)]
pub enum LocalMcpError {
    #[error("local MCP provider is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("local MCP provider policy is invalid")]
    InvalidPolicy,
    #[error("local MCP request is invalid")]
    InvalidRequest,
    #[error("local MCP provider process could not start")]
    ProcessStart,
    #[error("local MCP package identity could not be verified")]
    PackageIdentity,
    #[error("local MCP provider process identity could not be verified")]
    ProcessIdentity,
    #[error("local MCP provider process could not be stopped safely")]
    ProcessStop,
    #[error("local MCP provider startup timed out")]
    StartupTimeout,
    #[error("local MCP provider request timed out")]
    RequestTimeout,
    #[error("local MCP provider cancellation requested")]
    Cancelled,
    #[error("local MCP provider returned an invalid MCP frame")]
    InvalidFrame,
    #[error("local MCP provider returned an unexpected catalog")]
    CatalogMismatch,
    #[error("local MCP tool is not allowed")]
    UnknownTool,
    #[error("local MCP request exceeds its sequential-call bound")]
    TooManyCalls,
    #[error("local MCP frame exceeds the configured bound")]
    FrameTooLarge,
    #[error("local MCP provider returned an error")]
    ProviderError,
}

impl LocalMcpError {
    fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::InvalidPolicy => "invalid_policy",
            Self::InvalidRequest => "invalid_request",
            Self::ProcessStart => "process_start",
            Self::PackageIdentity => "package_identity",
            Self::ProcessIdentity => "process_identity",
            Self::ProcessStop => "process_stop",
            Self::StartupTimeout => "startup_timeout",
            Self::RequestTimeout => "request_timeout",
            Self::Cancelled => "cancelled",
            Self::InvalidFrame => "invalid_frame",
            Self::CatalogMismatch => "catalog_mismatch",
            Self::UnknownTool => "unknown_tool",
            Self::TooManyCalls => "too_many_calls",
            Self::FrameTooLarge => "frame_too_large",
            Self::ProviderError => "provider_error",
        }
    }
}

/// Request-scoped fixed-policy local MCP provider.
#[derive(Debug, Clone)]
pub struct LocalMcpProvider {
    policy: LocalMcpPolicy,
}

impl LocalMcpProvider {
    /// Construct a provider only from a validated signed-manifest policy.
    pub fn new(policy: LocalMcpPolicy) -> Result<Self, LocalMcpError> {
        policy
            .validate()
            .map_err(|_| LocalMcpError::InvalidPolicy)?;
        Ok(Self { policy })
    }

    /// Return the fixed policy for host-side inspection.
    #[must_use]
    pub const fn policy(&self) -> &LocalMcpPolicy {
        &self.policy
    }

    /// Run one bounded provider request and always execute the teardown path.
    pub fn run_once(&self, request: LocalMcpRequest) -> Result<LocalMcpResult, LocalMcpError> {
        self.run_once_with_cancel(request, Arc::new(std::sync::atomic::AtomicBool::new(false)))
    }

    /// Run one request while observing a host-owned cancellation flag.
    ///
    /// The flag is polled while waiting for provider frames. Cancellation
    /// never skips teardown and never causes a retry.
    pub fn run_once_with_cancel(
        &self,
        request: LocalMcpRequest,
        cancelled: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<LocalMcpResult, LocalMcpError> {
        if !cfg!(target_os = "linux") {
            return Err(LocalMcpError::UnsupportedPlatform);
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(LocalMcpError::Cancelled);
        }
        if self.policy.protocol_version != LOCAL_MCP_PROTOCOL_VERSION {
            return Err(LocalMcpError::InvalidPolicy);
        }
        validate_request(&self.policy, &request)?;
        verify_package_metadata(&self.policy)?;

        let spec = ProcessSpec {
            launcher_path: PathBuf::from(&self.policy.launcher_path),
            launcher_digest: self.policy.launcher_digest.clone(),
            runtime_executable: PathBuf::from(&self.policy.runtime_executable),
            expected_runtime_executable_digest: self.policy.runtime_executable_digest.clone(),
            fixed_args: self.policy.fixed_args.iter().map(OsString::from).collect(),
            fixed_env: self
                .policy
                .fixed_env
                .iter()
                .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                .collect(),
            network_disabled: self.policy.network_disabled,
        };

        let total_started = Instant::now();
        let process = OwnedProcess::spawn(&spec)
            .map_err(|error| map_process_error(error, ProcessPhase::Spawn))?;
        let identity = process.identity().clone();
        let memory_before = zero_memory_sample();
        let memory_during = process
            .memory_sample()
            .unwrap_or_else(|_| unavailable_memory_sample());
        let startup = LocalMcpStartupReceipt {
            pid: identity.pid,
            pgid: identity.pgid,
            session_id: identity.session_id,
            start_time_ticks: identity.start_time_ticks,
            launcher_digest: self.policy.launcher_digest.clone(),
            runtime_executable_digest: identity.runtime_executable_digest.clone(),
            network_disabled: self.policy.network_disabled,
            memory_before,
        };

        let mut session = LocalMcpSession::new(process, self.policy.max_frame_bytes as usize);
        session.memory_during = memory_during;
        let provider_started = Instant::now();
        let outcome = session.execute(&self.policy, &request, &cancelled);
        let provider_latency_ms = elapsed_ms(provider_started.elapsed());
        let reason = match &outcome {
            Ok(_) => LocalMcpShutdownReason::Completed,
            Err(LocalMcpError::StartupTimeout | LocalMcpError::RequestTimeout) => {
                LocalMcpShutdownReason::TimedOut
            }
            Err(LocalMcpError::Cancelled) => LocalMcpShutdownReason::Cancelled,
            Err(_) => LocalMcpShutdownReason::Failed,
        };
        let shutdown_started = Instant::now();
        let (shutdown, memory_samples, teardown_error) = session.finish(&self.policy, reason);
        let shutdown_latency_ms = elapsed_ms(shutdown_started.elapsed());
        let result_code = outcome.as_ref().err().map_or_else(
            || {
                teardown_error
                    .as_ref()
                    .map_or_else(|| "ok".to_string(), |error| error.code().to_string())
            },
            |error| error.code().to_string(),
        );
        let status = if outcome.is_ok() && teardown_error.is_none() {
            LocalMcpResultStatus::Completed
        } else {
            LocalMcpResultStatus::Failed
        };
        Ok(LocalMcpResult {
            correlation_id: request.correlation_id.clone(),
            responses: outcome.unwrap_or_default(),
            startup,
            shutdown,
            memory_samples,
            status,
            teardown_error_code: teardown_error.map(|error| error.code().to_string()),
            telemetry: LocalMcpTelemetry {
                startup_latency_ms: session.startup_latency_ms,
                provider_latency_ms,
                total_latency_ms: elapsed_ms(total_started.elapsed()),
                shutdown_latency_ms,
                request_bytes: session.request_bytes,
                response_bytes: session.response_bytes,
            },
            result_code,
        })
    }
}

fn validate_request(
    policy: &LocalMcpPolicy,
    request: &LocalMcpRequest,
) -> Result<(), LocalMcpError> {
    if request.correlation_id.is_empty()
        || request.correlation_id.len() > 128
        || request
            .correlation_id
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(LocalMcpError::InvalidRequest);
    }
    if request.calls.is_empty() {
        return Err(LocalMcpError::InvalidRequest);
    }
    if request.calls.len() > usize::from(policy.max_sequential_calls) {
        return Err(LocalMcpError::TooManyCalls);
    }
    for call in &request.calls {
        if !policy.callable_tools.iter().any(|tool| tool == &call.tool) {
            return Err(LocalMcpError::UnknownTool);
        }
        if !call.arguments.is_object() {
            return Err(LocalMcpError::InvalidRequest);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum LocalMcpPhase {
    Startup,
    Call,
}

impl LocalMcpPhase {
    const fn timeout_error(self) -> LocalMcpError {
        match self {
            Self::Startup => LocalMcpError::StartupTimeout,
            Self::Call => LocalMcpError::RequestTimeout,
        }
    }
}

struct LocalMcpSession {
    process: Option<OwnedProcess>,
    writer: Option<LocalMcpWriter>,
    frames: Receiver<Result<Vec<u8>, FrameReadError>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    stderr_bytes: Arc<AtomicU64>,
    next_id: u64,
    max_frame_bytes: usize,
    memory_during: ProcessMemorySample,
    startup_latency_ms: u64,
    request_bytes: u64,
    response_bytes: u64,
    stdout_overflow: Arc<AtomicBool>,
    teardown_complete: bool,
}

impl LocalMcpSession {
    fn new(mut process: OwnedProcess, max_frame_bytes: usize) -> Self {
        let (frame_tx, frame_rx) = mpsc::sync_channel(8);
        let stdout_overflow = Arc::new(AtomicBool::new(false));
        let stdout_thread = process.take_stdout().map(|stdout| {
            spawn_stdout_reader(
                stdout,
                frame_tx.clone(),
                max_frame_bytes,
                Arc::clone(&stdout_overflow),
            )
        });
        let stderr_bytes = Arc::new(AtomicU64::new(0));
        let stderr_counter = Arc::clone(&stderr_bytes);
        let stderr_thread = process.take_stderr().map(|stderr| {
            thread::spawn(move || {
                let mut reader = BufReader::new(stderr);
                let mut buffer = [0_u8; 4096];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(bytes) => {
                            stderr_counter.fetch_add(
                                u64::try_from(bytes).unwrap_or(u64::MAX),
                                Ordering::Relaxed,
                            );
                        }
                        Err(_) => break,
                    }
                }
            })
        });
        if stdout_thread.is_none() {
            let _ = frame_tx.try_send(Err(FrameReadError::Io));
        }

        let writer = process.take_stdin().map(LocalMcpWriter::new);
        Self {
            process: Some(process),
            writer,
            frames: frame_rx,
            stdout_thread,
            stderr_thread,
            stderr_bytes,
            next_id: 1,
            max_frame_bytes,
            memory_during: unavailable_memory_sample(),
            startup_latency_ms: 0,
            request_bytes: 0,
            response_bytes: 0,
            stdout_overflow,
            teardown_complete: false,
        }
    }
}

struct LocalMcpWriter {
    sender: Option<SyncSender<WriteCommand>>,
    join: Option<JoinHandle<()>>,
}

struct WriteCommand {
    frame: Vec<u8>,
    acknowledged: SyncSender<Result<(), ()>>,
}

impl LocalMcpWriter {
    fn new(mut stdin: std::process::ChildStdin) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<WriteCommand>(2);
        let join = thread::spawn(move || {
            while let Ok(command) = receiver.recv() {
                let result = stdin
                    .write_all(&command.frame)
                    .and_then(|()| stdin.write_all(b"\n"))
                    .and_then(|()| stdin.flush())
                    .map_err(|_| ());
                let failed = result.is_err();
                let _ = command.acknowledged.send(result);
                if failed {
                    break;
                }
            }
        });
        Self {
            sender: Some(sender),
            join: Some(join),
        }
    }

    fn submit(
        &self,
        frame: Vec<u8>,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<(), LocalMcpError> {
        let (ack_sender, ack_receiver) = mpsc::sync_channel(0);
        let mut command = WriteCommand {
            frame,
            acknowledged: ack_sender,
        };
        let sender = self.sender.as_ref().ok_or(LocalMcpError::ProcessStart)?;
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(LocalMcpError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(phase.timeout_error());
            }
            match sender.try_send(command) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(returned)) => {
                    command = returned;
                    thread::sleep(Duration::from_millis(5));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(LocalMcpError::ProcessStart);
                }
            }
        }
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(LocalMcpError::Cancelled);
            }
            let timeout = deadline.saturating_duration_since(Instant::now());
            if timeout.is_zero() {
                return Err(phase.timeout_error());
            }
            match ack_receiver.recv_timeout(timeout.min(Duration::from_millis(50))) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(())) | Err(RecvTimeoutError::Disconnected) => {
                    return Err(LocalMcpError::ProcessStart);
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn stop_and_join(&mut self) {
        self.sender.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }

    fn detach(&mut self) {
        self.sender.take();
        self.join.take();
    }
}

impl LocalMcpSession {
    fn execute(
        &mut self,
        policy: &LocalMcpPolicy,
        request: &LocalMcpRequest,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Vec<Value>, LocalMcpError> {
        let startup_started = Instant::now();
        if cancelled.load(Ordering::Acquire) {
            self.startup_latency_ms = elapsed_ms(startup_started.elapsed());
            return Err(LocalMcpError::Cancelled);
        }
        let startup_deadline = Instant::now() + millis(policy.startup_timeout_ms);
        let startup_result = (|| {
            let initialize = self.request(
                policy,
                "initialize",
                json!({
                    "protocolVersion": policy.protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}
                }),
                startup_deadline,
                cancelled,
                LocalMcpPhase::Startup,
            )?;
            validate_initialize(policy, &initialize)?;
            self.notify(
                policy,
                "notifications/initialized",
                json!({}),
                startup_deadline,
                cancelled,
                LocalMcpPhase::Startup,
            )?;
            let catalog = self.request(
                policy,
                "tools/list",
                json!({}),
                startup_deadline,
                cancelled,
                LocalMcpPhase::Startup,
            )?;
            validate_catalog(policy, &catalog)
        })();
        self.startup_latency_ms = elapsed_ms(startup_started.elapsed());
        startup_result?;

        let mut responses = Vec::with_capacity(request.calls.len());
        for call in &request.calls {
            let result = self.request(
                policy,
                "tools/call",
                json!({"name": call.tool, "arguments": call.arguments}),
                Instant::now() + millis(policy.request_timeout_ms),
                cancelled,
                LocalMcpPhase::Call,
            )?;
            if serde_json::to_vec(&result)
                .map_err(|_| LocalMcpError::InvalidFrame)?
                .len()
                > policy.max_result_bytes as usize
            {
                return Err(LocalMcpError::FrameTooLarge);
            }
            responses.push(result);
        }
        Ok(responses)
    }

    fn notify(
        &mut self,
        policy: &LocalMcpPolicy,
        method: &str,
        params: Value,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<(), LocalMcpError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(LocalMcpError::Cancelled);
        }
        if !policy
            .allowed_methods
            .iter()
            .any(|allowed| allowed == method)
        {
            return Err(LocalMcpError::InvalidPolicy);
        }
        let frame = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
        .map_err(|_| LocalMcpError::InvalidFrame)?;
        self.write_frame(policy, frame, deadline, cancelled, phase)
    }

    fn request(
        &mut self,
        policy: &LocalMcpPolicy,
        method: &str,
        params: Value,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<Value, LocalMcpError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(LocalMcpError::Cancelled);
        }
        if !policy
            .allowed_methods
            .iter()
            .any(|allowed| allowed == method)
        {
            return Err(LocalMcpError::InvalidPolicy);
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let frame = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|_| LocalMcpError::InvalidFrame)?;
        self.write_frame(policy, frame, deadline, cancelled, phase)?;

        let bytes = self.recv_frame(deadline, cancelled, phase)?;
        self.response_bytes = self
            .response_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let response: Value =
            serde_json::from_slice(&bytes).map_err(|_| LocalMcpError::InvalidFrame)?;
        if response.get("id") != Some(&Value::from(id)) {
            return Err(LocalMcpError::InvalidFrame);
        }
        if response.get("jsonrpc") != Some(&Value::from("2.0")) {
            return Err(LocalMcpError::InvalidFrame);
        }
        if response.get("error").is_some() {
            return Err(LocalMcpError::ProviderError);
        }
        response
            .get("result")
            .cloned()
            .ok_or(LocalMcpError::InvalidFrame)
    }

    fn write_frame(
        &mut self,
        policy: &LocalMcpPolicy,
        frame: Vec<u8>,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<(), LocalMcpError> {
        if frame.len() > self.max_frame_bytes || frame.len() > policy.max_request_bytes as usize {
            return Err(LocalMcpError::FrameTooLarge);
        }
        let bytes = u64::try_from(frame.len()).unwrap_or(u64::MAX);
        let writer = self.writer.as_ref().ok_or(LocalMcpError::ProcessStart)?;
        writer.submit(frame, deadline, cancelled, phase)?;
        self.request_bytes = self.request_bytes.saturating_add(bytes);
        Ok(())
    }

    fn recv_frame(
        &mut self,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        phase: LocalMcpPhase,
    ) -> Result<Vec<u8>, LocalMcpError> {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(LocalMcpError::Cancelled);
            }
            if self.stdout_overflow.load(Ordering::Acquire) {
                return Err(LocalMcpError::FrameTooLarge);
            }
            let timeout = deadline.saturating_duration_since(Instant::now());
            if timeout.is_zero() {
                return Err(phase.timeout_error());
            }
            let poll = timeout.min(Duration::from_millis(50));
            match self.frames.recv_timeout(poll) {
                Ok(Ok(frame)) => return Ok(frame),
                Ok(Err(FrameReadError::Oversized)) => return Err(LocalMcpError::FrameTooLarge),
                Ok(Err(_)) => return Err(LocalMcpError::InvalidFrame),
                Err(RecvTimeoutError::Disconnected) => {
                    return if self.stdout_overflow.load(Ordering::Acquire) {
                        Err(LocalMcpError::FrameTooLarge)
                    } else {
                        Err(LocalMcpError::InvalidFrame)
                    };
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn finish(
        &mut self,
        policy: &LocalMcpPolicy,
        reason: LocalMcpShutdownReason,
    ) -> (
        LocalMcpShutdownReceipt,
        Vec<ProcessMemorySample>,
        Option<LocalMcpError>,
    ) {
        let mut samples = vec![zero_memory_sample(), self.memory_during];
        let mut teardown_error = None;
        let mut termination = None;
        let mut memory_after = unavailable_memory_sample();
        let process = self.process.as_mut();
        if let Some(process) = process {
            if let Ok(sample) = process.memory_sample() {
                samples.push(sample);
            }
            match process.terminate(millis(policy.shutdown_timeout_ms)) {
                Ok(report) => {
                    if report.group_absent {
                        if let Ok(sample) = process.memory_sample() {
                            memory_after = sample;
                            samples.push(sample);
                        }
                    } else {
                        teardown_error = Some(LocalMcpError::ProcessStop);
                    }
                    termination = Some(report);
                }
                Err(error) => {
                    if matches!(&error, ProcessGroupError::IdentityMismatch) {
                        let _ = process.reap_direct_child_until(millis(policy.shutdown_timeout_ms));
                    }
                    termination = Some(process.termination_report(false));
                    teardown_error = Some(map_process_error(error, ProcessPhase::Stop));
                }
            }
        } else {
            teardown_error = Some(LocalMcpError::ProcessStop);
        }
        self.close_or_detach(termination.is_some_and(|report| report.group_absent));
        let report = termination.unwrap_or(TerminationReport {
            term_sent: false,
            kill_sent: false,
            reaped: false,
            group_absent: false,
        });
        let receipt = LocalMcpShutdownReceipt {
            reason,
            term_sent: report.term_sent,
            kill_sent: report.kill_sent,
            reaped: report.reaped,
            group_absent: report.group_absent,
            stderr_bytes: self.stderr_bytes.load(Ordering::Relaxed),
            memory_after,
        };
        (receipt, samples, teardown_error)
    }

    fn close_or_detach(&mut self, group_absent: bool) {
        if self.teardown_complete {
            return;
        }
        if group_absent {
            if let Some(process) = self.process.as_mut() {
                process.abandon();
            }
            if let Some(writer) = self.writer.as_mut() {
                writer.stop_and_join();
            }
            self.join_readers();
        } else {
            self.detach_after_teardown_failure();
        }
        self.teardown_complete = true;
    }

    fn detach_after_teardown_failure(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            writer.detach();
        }
        self.stdout_thread.take();
        self.stderr_thread.take();
        if let Some(process) = self.process.as_mut() {
            process.abandon();
        }
    }

    fn join_readers(&mut self) {
        if let Some(thread) = self.stdout_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for LocalMcpSession {
    fn drop(&mut self) {
        if self.teardown_complete {
            return;
        }
        let group_absent = self
            .process
            .as_mut()
            .and_then(|process| process.terminate(Duration::from_secs(1)).ok())
            .is_some_and(|report| report.group_absent);
        self.close_or_detach(group_absent);
    }
}

#[derive(Debug)]
enum FrameReadError {
    Oversized,
    Io,
    InvalidUtf8,
}

fn spawn_stdout_reader(
    stdout: std::process::ChildStdout,
    sender: SyncSender<Result<Vec<u8>, FrameReadError>>,
    max_frame_bytes: usize,
    overflow: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            match read_bounded_frame(&mut reader, max_frame_bytes) {
                Ok(Some(line)) => {
                    if std::str::from_utf8(&line).is_err() {
                        let _ = sender.try_send(Err(FrameReadError::InvalidUtf8));
                        break;
                    }
                    if sender.try_send(Ok(line)).is_err() {
                        overflow.store(true, Ordering::Release);
                        break;
                    }
                }
                Ok(None) | Err(FrameReadError::Io) => {
                    let _ = sender.try_send(Err(FrameReadError::Io));
                    break;
                }
                Err(error) => {
                    let _ = sender.try_send(Err(error));
                    break;
                }
            }
        }
    })
}

fn read_bounded_frame(
    reader: &mut BufReader<std::process::ChildStdout>,
    max_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, FrameReadError> {
    let mut line = Vec::new();
    let limit = max_frame_bytes.saturating_add(1);
    loop {
        let available = reader.fill_buf().map_err(|_| FrameReadError::Io)?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(FrameReadError::Io)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let available_limit = limit.saturating_sub(line.len());
        if available_limit == 0 {
            return Err(FrameReadError::Oversized);
        }
        let requested = newline.map_or(available.len(), |position| position + 1);
        let take = requested.min(available_limit);
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if take < requested {
            return Err(FrameReadError::Oversized);
        }
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.len() > max_frame_bytes {
                return Err(FrameReadError::Oversized);
            }
            return Ok(Some(line));
        }
        if line.len() >= limit {
            return Err(FrameReadError::Oversized);
        }
    }
}

fn validate_catalog(policy: &LocalMcpPolicy, result: &Value) -> Result<(), LocalMcpError> {
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(LocalMcpError::CatalogMismatch)?;
    if tools.len() != policy.expected_catalog.len() {
        return Err(LocalMcpError::CatalogMismatch);
    }
    let mut seen = BTreeMap::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or(LocalMcpError::CatalogMismatch)?;
        let schema = tool
            .get("inputSchema")
            .ok_or(LocalMcpError::CatalogMismatch)?;
        seen.insert(name.to_string(), local_mcp_schema_digest(schema));
    }
    if seen != policy.expected_catalog {
        return Err(LocalMcpError::CatalogMismatch);
    }
    Ok(())
}

fn validate_initialize(policy: &LocalMcpPolicy, result: &Value) -> Result<(), LocalMcpError> {
    if result.get("protocolVersion") != Some(&Value::from(policy.protocol_version.as_str())) {
        return Err(LocalMcpError::InvalidFrame);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ProcessPhase {
    Spawn,
    Stop,
}

fn map_process_error(error: ProcessGroupError, phase: ProcessPhase) -> LocalMcpError {
    match error {
        ProcessGroupError::UnsupportedPlatform => LocalMcpError::UnsupportedPlatform,
        ProcessGroupError::LauncherDigestMismatch | ProcessGroupError::InvalidSpec => {
            LocalMcpError::ProcessStart
        }
        ProcessGroupError::IdentityMismatch => LocalMcpError::ProcessIdentity,
        ProcessGroupError::TeardownTimeout => LocalMcpError::ProcessStop,
        ProcessGroupError::Io(_) => match phase {
            ProcessPhase::Spawn => LocalMcpError::ProcessStart,
            ProcessPhase::Stop => LocalMcpError::ProcessStop,
        },
    }
}

fn millis(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn zero_memory_sample() -> ProcessMemorySample {
    ProcessMemorySample {
        available: true,
        process_count: 0,
        rss_bytes: Some(0),
        pss_bytes: Some(0),
        private_bytes: Some(0),
    }
}

fn unavailable_memory_sample() -> ProcessMemorySample {
    ProcessMemorySample {
        available: false,
        process_count: 0,
        rss_bytes: None,
        pss_bytes: None,
        private_bytes: None,
    }
}

fn verify_package_metadata(policy: &LocalMcpPolicy) -> Result<(), LocalMcpError> {
    let path = Path::new(&policy.package_metadata_path);
    let bytes = std::fs::read(path).map_err(|_| LocalMcpError::PackageIdentity)?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    if digest != policy.package_metadata_digest {
        return Err(LocalMcpError::PackageIdentity);
    }
    let metadata: Value =
        serde_json::from_slice(&bytes).map_err(|_| LocalMcpError::PackageIdentity)?;
    let name = metadata.get("name").and_then(Value::as_str);
    let version = metadata.get("version").and_then(Value::as_str);
    let expected_version = policy.package_version.to_string();
    if name != Some(policy.package_id.as_str()) || version != Some(expected_version.as_str()) {
        return Err(LocalMcpError::PackageIdentity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_manifest::{LOCAL_MCP_CATALOG_TOOLS, LOCAL_MCP_METHODS};

    #[test]
    fn request_rejects_unknown_tool_before_spawn() {
        let policy = test_policy();
        let provider = LocalMcpProvider::new(policy).expect("policy");
        let error = provider
            .run_once(LocalMcpRequest {
                correlation_id: "test".into(),
                calls: vec![LocalMcpCall {
                    tool: "unknown".into(),
                    arguments: json!({}),
                }],
            })
            .expect_err("unknown tool must fail closed");
        assert!(matches!(error, LocalMcpError::UnknownTool));
    }

    #[test]
    fn request_rejects_overlength_correlation_id_before_spawn() {
        let policy = test_policy();
        let request = LocalMcpRequest {
            correlation_id: "a".repeat(129),
            calls: vec![LocalMcpCall {
                tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
                arguments: json!({}),
            }],
        };
        assert!(matches!(
            validate_request(&policy, &request),
            Err(LocalMcpError::InvalidRequest)
        ));
    }

    #[test]
    fn request_rejects_disallowed_correlation_id_characters_before_spawn() {
        let policy = test_policy();
        let request = LocalMcpRequest {
            correlation_id: "bad/slash".into(),
            calls: vec![LocalMcpCall {
                tool: LOCAL_MCP_CATALOG_TOOLS[0].into(),
                arguments: json!({}),
            }],
        };
        assert!(matches!(
            validate_request(&policy, &request),
            Err(LocalMcpError::InvalidRequest)
        ));
    }

    #[test]
    fn catalog_rejects_unknown_tool_and_schema_drift() {
        let policy = test_policy();
        let mut result = json!({"tools": []});
        assert!(matches!(
            validate_catalog(&policy, &result),
            Err(LocalMcpError::CatalogMismatch)
        ));
        result["tools"] = json!([{"name":"unexpected","inputSchema":{}}]);
        assert!(matches!(
            validate_catalog(&policy, &result),
            Err(LocalMcpError::CatalogMismatch)
        ));
    }

    fn test_policy() -> LocalMcpPolicy {
        let expected_catalog = LOCAL_MCP_CATALOG_TOOLS
            .iter()
            .map(|tool| {
                (
                    (*tool).to_string(),
                    local_mcp_schema_digest(&json!({"type":"object"})),
                )
            })
            .collect();
        LocalMcpPolicy {
            package_id: "test-provider".into(),
            package_version: semver::Version::new(1, 0, 0),
            launcher_path: "/bin/sh".into(),
            launcher_digest: "0".repeat(64),
            runtime_executable: "/usr/bin/dash".into(),
            runtime_executable_digest: "0".repeat(64),
            package_metadata_path: "/usr/share/fcp/package.json".into(),
            package_metadata_digest: "0".repeat(64),
            protocol_version: LOCAL_MCP_PROTOCOL_VERSION.into(),
            fixed_args: Vec::new(),
            fixed_env: BTreeMap::new(),
            allowed_methods: LOCAL_MCP_METHODS
                .iter()
                .map(|value| (*value).into())
                .collect(),
            expected_catalog,
            callable_tools: LOCAL_MCP_CATALOG_TOOLS
                .iter()
                .map(|value| (*value).into())
                .collect(),
            max_frame_bytes: 64 * 1024,
            max_request_bytes: 64 * 1024,
            max_result_bytes: 64 * 1024,
            max_sequential_calls: 7,
            startup_timeout_ms: 1000,
            request_timeout_ms: 1000,
            shutdown_timeout_ms: 1000,
            idle_window_ms: 0,
            network_disabled: true,
        }
    }
}
