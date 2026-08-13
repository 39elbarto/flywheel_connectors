//! Request-scoped native connector supervision.
//!
//! `OwnedInvocationHandle` owns one [`fcp_sandbox::OwnedProcess`] on a
//! dedicated standard-library thread and keeps all blocking process/pipe work
//! off the async executor. The host closes any inherited egress channel before
//! calling [`OwnedInvocationHandle::terminate`].

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

use fcp_sandbox::{
    OwnedProcess, ProcessGroupError, ProcessMemorySample, ProcessSpec, TerminationReport,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Default connector-RPC frame bound, excluding the newline delimiter.
pub const DEFAULT_OWNED_INVOCATION_MAX_FRAME_BYTES: usize = 64 * 1024;

const DEFAULT_OWNED_INVOCATION_RPC_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_OWNED_INVOCATION_TERMINATION_GRACE: Duration = Duration::from_secs(1);
const ACTOR_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STDERR_LINE_LIMIT_BYTES: usize = 64 * 1024;
const WORKER_JOIN_GRACE_MULTIPLIER: u32 = 2;

/// Bounded, per-RPC lifecycle settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedInvocationConfig {
    /// Maximum serialized JSON bytes in either direction.
    pub max_frame_bytes: usize,
    /// Deadline for one JSONL write/read exchange.
    pub rpc_timeout: Duration,
    /// TERM grace period before the process-group implementation sends KILL.
    pub termination_grace: Duration,
}

impl Default for OwnedInvocationConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_OWNED_INVOCATION_MAX_FRAME_BYTES,
            rpc_timeout: DEFAULT_OWNED_INVOCATION_RPC_TIMEOUT,
            termination_grace: DEFAULT_OWNED_INVOCATION_TERMINATION_GRACE,
        }
    }
}

impl OwnedInvocationConfig {
    /// Construct explicit lifecycle settings.
    #[must_use]
    pub const fn new(
        max_frame_bytes: usize,
        rpc_timeout: Duration,
        termination_grace: Duration,
    ) -> Self {
        Self {
            max_frame_bytes,
            rpc_timeout,
            termination_grace,
        }
    }

    fn validate(self) -> Result<Self, OwnedInvocationError> {
        if self.max_frame_bytes == 0
            || self.rpc_timeout.is_zero()
            || self.termination_grace.is_zero()
        {
            return Err(OwnedInvocationError::InvalidConfig);
        }
        Ok(self)
    }
}

/// Redaction-safe stderr evidence. No stderr content is retained.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedInvocationStderrMetadata {
    /// Total bytes consumed from the child stderr pipe.
    pub bytes: u64,
    /// True when at least one stderr line exceeded the metadata reader bound.
    pub truncated: bool,
}

/// Errors returned by the request-scoped actor.
#[derive(Debug, thiserror::Error)]
pub enum OwnedInvocationError {
    #[error("owned invocation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("owned invocation configuration is invalid")]
    InvalidConfig,
    #[error("owned invocation process launch failed: {0}")]
    Launch(#[source] ProcessGroupError),
    #[error("owned invocation process termination failed: {0}")]
    Termination(#[source] ProcessGroupError),
    #[error("owned invocation teardown did not prove group absence and worker joins")]
    TerminationIncomplete,
    #[error("owned invocation transport is closed")]
    Closed,
    #[error("owned invocation worker stopped")]
    WorkerStopped,
    #[error("owned invocation was cancelled")]
    Cancelled,
    #[error("owned invocation I/O failed")]
    Io,
    #[error("owned invocation JSON frame exceeded its bound")]
    FrameTooLarge,
    #[error("owned invocation JSON frame is malformed")]
    MalformedFrame,
    #[error("owned invocation response id did not match the request")]
    WrongResponseId,
    #[error("owned invocation RPC timed out")]
    Timeout,
    #[error("owned invocation process stdio is unavailable")]
    MissingPipe,
}

/// A single request-scoped process actor.
pub struct OwnedInvocationHandle {
    command_tx: Option<SyncSender<ActorCommand>>,
    cancel: Arc<AtomicBool>,
    stderr: Arc<StderrCounters>,
    completion_rx: Option<Receiver<Result<TerminationReport, OwnedInvocationError>>>,
    actor_join: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for OwnedInvocationHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedInvocationHandle")
            .field("closed", &self.command_tx.is_none())
            .field(
                "actor_finished",
                &self
                    .actor_join
                    .as_ref()
                    .map_or(true, |join| join.is_finished()),
            )
            .field("stderr", &self.stderr.metadata())
            .finish()
    }
}

impl OwnedInvocationHandle {
    /// Launch one process and wait until its stdio workers are installed.
    ///
    /// Spawn, digest checks, and all stdio work happen on the dedicated actor
    /// thread. The child endpoint is consumed by the sandbox primitive.
    #[cfg(target_os = "linux")]
    pub async fn launch(
        spec: ProcessSpec,
        child_endpoint: UnixStream,
        config: OwnedInvocationConfig,
    ) -> Result<Self, OwnedInvocationError> {
        let config = config.validate()?;
        let cancel = Arc::new(AtomicBool::new(false));
        let stderr = Arc::new(StderrCounters::default());
        let (command_tx, command_rx) = mpsc::sync_channel(8);
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let (ready_tx, ready_rx) = fcp_async_core::channel::oneshot::channel();
        let actor_cancel = Arc::clone(&cancel);
        let actor_stderr = Arc::clone(&stderr);
        let actor_join = thread::Builder::new()
            .name("fcp-owned-invocation".to_owned())
            .spawn(move || {
                actor_main(
                    spec,
                    child_endpoint,
                    config,
                    command_rx,
                    ready_tx,
                    completion_tx,
                    actor_cancel,
                    actor_stderr,
                );
            })
            .map_err(|_| OwnedInvocationError::WorkerStopped)?;

        match ready_rx.await {
            Ok(Ok(())) => Ok(Self {
                command_tx: Some(command_tx),
                cancel,
                stderr,
                completion_rx: Some(completion_rx),
                actor_join: Some(actor_join),
            }),
            Ok(Err(error)) => {
                detach_actor(actor_join);
                Err(error)
            }
            Err(_) => {
                cancel.store(true, Ordering::Release);
                detach_actor(actor_join);
                Err(OwnedInvocationError::WorkerStopped)
            }
        }
    }

    /// Non-Linux builds retain the API shape but fail closed before spawn.
    #[cfg(not(target_os = "linux"))]
    pub async fn launch(
        _spec: ProcessSpec,
        _child_endpoint: (),
        _config: OwnedInvocationConfig,
    ) -> Result<Self, OwnedInvocationError> {
        Err(OwnedInvocationError::UnsupportedPlatform)
    }

    /// Send one JSON-RPC request. Calls are serialized by the actor.
    pub async fn request(
        &mut self,
        method: impl Into<String>,
        params: Value,
    ) -> Result<Value, OwnedInvocationError> {
        let (reply_tx, reply_rx) = fcp_async_core::channel::oneshot::channel();
        let command_tx = self
            .command_tx
            .as_ref()
            .ok_or(OwnedInvocationError::Closed)?;
        command_tx
            .try_send(ActorCommand::Request {
                method: method.into(),
                params,
                reply: reply_tx,
            })
            .map_err(|error| match error {
                TrySendError::Full(_) => OwnedInvocationError::WorkerStopped,
                TrySendError::Disconnected(_) => OwnedInvocationError::Closed,
            })?;
        reply_rx
            .await
            .map_err(|_| OwnedInvocationError::WorkerStopped)?
    }

    /// Ask the actor for a verified process-group memory sample.
    pub async fn memory_sample(&self) -> Result<ProcessMemorySample, OwnedInvocationError> {
        let (reply_tx, reply_rx) = fcp_async_core::channel::oneshot::channel();
        let command_tx = self
            .command_tx
            .as_ref()
            .ok_or(OwnedInvocationError::Closed)?;
        command_tx
            .try_send(ActorCommand::MemorySample { reply: reply_tx })
            .map_err(|error| match error {
                TrySendError::Full(_) => OwnedInvocationError::WorkerStopped,
                TrySendError::Disconnected(_) => OwnedInvocationError::Closed,
            })?;
        reply_rx
            .await
            .map_err(|_| OwnedInvocationError::WorkerStopped)?
    }

    /// Return redaction-safe stderr metadata collected so far.
    #[must_use]
    pub fn stderr_metadata(&self) -> OwnedInvocationStderrMetadata {
        self.stderr.metadata()
    }

    /// Terminate, reap, and join the request-scoped actor.
    ///
    /// The caller must close the inherited host-egress endpoint before this
    /// method. A separate standard-library joiner keeps the final join off the
    /// async executor.
    pub async fn terminate(mut self) -> Result<TerminationReport, OwnedInvocationError> {
        let command_tx = self.command_tx.take().ok_or(OwnedInvocationError::Closed)?;
        let completion_rx = self
            .completion_rx
            .take()
            .ok_or(OwnedInvocationError::Closed)?;
        let actor_join = self.actor_join.take().ok_or(OwnedInvocationError::Closed)?;
        // Never wait for a full command queue. The atomic cancellation bit is
        // the authoritative exit request if this best-effort command cannot be
        // enqueued or the actor already stopped after a fatal RPC.
        let _ = command_tx.try_send(ActorCommand::Terminate);
        self.cancel.store(true, Ordering::Release);
        drop(command_tx);

        let (final_tx, final_rx) = fcp_async_core::channel::oneshot::channel();
        thread::Builder::new()
            .name("fcp-owned-invocation-join".to_owned())
            .spawn(move || {
                let result = completion_rx
                    .recv()
                    .unwrap_or(Err(OwnedInvocationError::WorkerStopped));
                let result = if actor_join.join().is_ok() {
                    result
                } else {
                    Err(OwnedInvocationError::WorkerStopped)
                };
                let _ = final_tx.send(result);
            })
            .map_err(|_| OwnedInvocationError::WorkerStopped)?;
        final_rx
            .await
            .map_err(|_| OwnedInvocationError::WorkerStopped)?
    }
}

impl Drop for OwnedInvocationHandle {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(command_tx) = self.command_tx.take() {
            let _ = command_tx.try_send(ActorCommand::Cancel);
        }
        if let Some(actor_join) = self.actor_join.take() {
            detach_actor(actor_join);
        }
    }
}

type RpcReply = fcp_async_core::channel::oneshot::Sender<Result<Value, OwnedInvocationError>>;
type MemoryReply =
    fcp_async_core::channel::oneshot::Sender<Result<ProcessMemorySample, OwnedInvocationError>>;

enum ActorCommand {
    Request {
        method: String,
        params: Value,
        reply: RpcReply,
    },
    MemorySample {
        reply: MemoryReply,
    },
    Terminate,
    Cancel,
}

#[derive(Default)]
struct StderrCounters {
    bytes: AtomicU64,
    truncated: AtomicBool,
}

impl StderrCounters {
    fn metadata(&self) -> OwnedInvocationStderrMetadata {
        OwnedInvocationStderrMetadata {
            bytes: self.bytes.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
        }
    }
}

struct WorkerThread {
    join: Option<JoinHandle<()>>,
    done: Receiver<()>,
}

struct WorkerSet {
    writer_tx: SyncSender<WriteCommand>,
    frame_rx: Receiver<Result<Vec<u8>, FrameReadError>>,
    threads: Vec<WorkerThread>,
}

struct WriteCommand {
    frame: Vec<u8>,
    reply: SyncSender<std::io::Result<()>>,
}

#[derive(Debug)]
enum FrameReadError {
    Oversized,
    Io,
    InvalidUtf8,
    UnexpectedEof,
}

#[cfg(target_os = "linux")]
fn actor_main(
    spec: ProcessSpec,
    child_endpoint: UnixStream,
    config: OwnedInvocationConfig,
    command_rx: Receiver<ActorCommand>,
    ready_tx: fcp_async_core::channel::oneshot::Sender<Result<(), OwnedInvocationError>>,
    completion_tx: SyncSender<Result<TerminationReport, OwnedInvocationError>>,
    cancel: Arc<AtomicBool>,
    stderr: Arc<StderrCounters>,
) {
    let mut process = match OwnedProcess::spawn_with_host_egress_channel(&spec, child_endpoint) {
        Ok(process) => process,
        Err(error) => {
            let _ = ready_tx.send(Err(OwnedInvocationError::Launch(error)));
            let _ = completion_tx.send(Err(OwnedInvocationError::WorkerStopped));
            return;
        }
    };
    let workers = match take_and_spawn_workers(&mut process, config.max_frame_bytes, &stderr) {
        Ok(workers) => workers,
        Err(error) => {
            let termination = process.terminate(config.termination_grace);
            let _ = ready_tx.send(Err(error));
            let completion: Result<TerminationReport, OwnedInvocationError> = match termination {
                Ok(_) => Err(OwnedInvocationError::WorkerStopped),
                Err(termination_error) => Err(OwnedInvocationError::Termination(termination_error)),
            };
            let _ = completion_tx.send(completion);
            return;
        }
    };
    if ready_tx.send(Ok(())).is_err() {
        cancel.store(true, Ordering::Release);
    }
    let completion = actor_loop(&mut process, workers, config, command_rx, cancel);
    let _ = completion_tx.send(completion);
}

#[cfg(not(target_os = "linux"))]
fn actor_main(
    _spec: ProcessSpec,
    _config: OwnedInvocationConfig,
    _command_rx: Receiver<ActorCommand>,
    ready_tx: fcp_async_core::channel::oneshot::Sender<Result<(), OwnedInvocationError>>,
    completion_tx: SyncSender<Result<TerminationReport, OwnedInvocationError>>,
    _cancel: Arc<AtomicBool>,
    _stderr: Arc<StderrCounters>,
) {
    let _ = ready_tx.send(Err(OwnedInvocationError::UnsupportedPlatform));
    let _ = completion_tx.send(Err(OwnedInvocationError::UnsupportedPlatform));
}

#[cfg(target_os = "linux")]
fn actor_loop(
    process: &mut OwnedProcess,
    mut workers: WorkerSet,
    config: OwnedInvocationConfig,
    command_rx: Receiver<ActorCommand>,
    cancel: Arc<AtomicBool>,
) -> Result<TerminationReport, OwnedInvocationError> {
    let mut next_request_seq = 0_u64;

    loop {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        match command_rx.recv_timeout(ACTOR_POLL_INTERVAL) {
            Ok(ActorCommand::Request {
                method,
                params,
                reply,
            }) => {
                let result = rpc_exchange(
                    &workers.writer_tx,
                    &workers.frame_rx,
                    config.max_frame_bytes,
                    config.rpc_timeout,
                    &cancel,
                    &method,
                    params,
                    &mut next_request_seq,
                );
                let fatal = result.is_err();
                let _ = reply.send(result);
                if fatal {
                    break;
                }
            }
            Ok(ActorCommand::MemorySample { reply }) => {
                let result = if cancel.load(Ordering::Acquire) {
                    Err(OwnedInvocationError::Cancelled)
                } else {
                    process
                        .memory_sample()
                        .map_err(|_| OwnedInvocationError::WorkerStopped)
                };
                let _ = reply.send(result);
            }
            Ok(ActorCommand::Terminate) => break,
            Ok(ActorCommand::Cancel) => break,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    drop(workers.frame_rx);
    drop(workers.writer_tx);
    terminate_and_join(process, &mut workers.threads, config)
}

#[cfg(target_os = "linux")]
fn terminate_and_join(
    process: &mut OwnedProcess,
    workers: &mut [WorkerThread],
    config: OwnedInvocationConfig,
) -> Result<TerminationReport, OwnedInvocationError> {
    let process_result = process.terminate(config.termination_grace);
    let workers_joined = join_workers(workers, config.termination_grace);
    match process_result {
        Ok(report) if report.group_absent && report.reaped && workers_joined => Ok(report),
        Ok(_) => Err(OwnedInvocationError::TerminationIncomplete),
        Err(error) => Err(OwnedInvocationError::Termination(error)),
    }
}

#[cfg(target_os = "linux")]
fn take_and_spawn_workers(
    process: &mut OwnedProcess,
    max_frame_bytes: usize,
    stderr: &Arc<StderrCounters>,
) -> Result<WorkerSet, OwnedInvocationError> {
    let stdin = process
        .take_stdin()
        .ok_or(OwnedInvocationError::MissingPipe)?;
    let stdout = process
        .take_stdout()
        .ok_or(OwnedInvocationError::MissingPipe)?;
    let stderr_pipe = process
        .take_stderr()
        .ok_or(OwnedInvocationError::MissingPipe)?;

    let (writer_tx, writer_rx) = mpsc::sync_channel(1);
    let writer = spawn_writer(stdin, writer_rx)?;
    let (frame_tx, frame_rx) = mpsc::sync_channel(4);
    let reader = match spawn_reader(stdout, frame_tx, max_frame_bytes) {
        Ok(reader) => reader,
        Err(error) => {
            drop(writer_tx);
            let mut workers = vec![writer];
            let _ = join_workers(&mut workers, DEFAULT_OWNED_INVOCATION_TERMINATION_GRACE);
            return Err(error);
        }
    };
    let stderr_worker = match spawn_stderr(stderr_pipe, Arc::clone(stderr)) {
        Ok(worker) => worker,
        Err(error) => {
            drop(writer_tx);
            drop(frame_rx);
            let mut workers = vec![writer, reader];
            let _ = join_workers(&mut workers, DEFAULT_OWNED_INVOCATION_TERMINATION_GRACE);
            return Err(error);
        }
    };
    Ok(WorkerSet {
        writer_tx,
        frame_rx,
        threads: vec![writer, reader, stderr_worker],
    })
}

#[cfg(target_os = "linux")]
fn spawn_writer(
    mut stdin: std::process::ChildStdin,
    command_rx: Receiver<WriteCommand>,
) -> Result<WorkerThread, OwnedInvocationError> {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let join = thread::Builder::new()
        .name("fcp-owned-invocation-stdin".to_owned())
        .spawn(move || {
            while let Ok(command) = command_rx.recv() {
                let result = stdin
                    .write_all(&command.frame)
                    .and_then(|()| stdin.write_all(b"\n"))
                    .and_then(|()| stdin.flush());
                let failed = result.is_err();
                let _ = command.reply.send(result);
                if failed {
                    break;
                }
            }
            let _ = done_tx.send(());
        })
        .map_err(|_| OwnedInvocationError::WorkerStopped)?;
    Ok(WorkerThread {
        join: Some(join),
        done: done_rx,
    })
}

#[cfg(target_os = "linux")]
fn spawn_reader(
    stdout: std::process::ChildStdout,
    frame_tx: SyncSender<Result<Vec<u8>, FrameReadError>>,
    max_frame_bytes: usize,
) -> Result<WorkerThread, OwnedInvocationError> {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let join = thread::Builder::new()
        .name("fcp-owned-invocation-stdout".to_owned())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_bounded_frame(&mut reader, max_frame_bytes) {
                    Ok(Some(frame)) => {
                        if frame_tx.send(Ok(frame)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let _ = frame_tx.send(Err(error));
                        break;
                    }
                }
            }
            let _ = done_tx.send(());
        })
        .map_err(|_| OwnedInvocationError::WorkerStopped)?;
    Ok(WorkerThread {
        join: Some(join),
        done: done_rx,
    })
}

#[cfg(target_os = "linux")]
fn spawn_stderr(
    stderr: std::process::ChildStderr,
    counters: Arc<StderrCounters>,
) -> Result<WorkerThread, OwnedInvocationError> {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let join = thread::Builder::new()
        .name("fcp-owned-invocation-stderr".to_owned())
        .spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut buffer = [0_u8; 4096];
            let mut line_bytes = 0_usize;
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes) => {
                        counters
                            .bytes
                            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
                        for byte in &buffer[..bytes] {
                            if *byte == b'\n' {
                                line_bytes = 0;
                            } else {
                                line_bytes = line_bytes.saturating_add(1);
                                if line_bytes > STDERR_LINE_LIMIT_BYTES {
                                    counters.truncated.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = done_tx.send(());
        })
        .map_err(|_| OwnedInvocationError::WorkerStopped)?;
    Ok(WorkerThread {
        join: Some(join),
        done: done_rx,
    })
}

fn join_workers(workers: &mut [WorkerThread], grace: Duration) -> bool {
    let wait = grace.saturating_mul(WORKER_JOIN_GRACE_MULTIPLIER);
    let deadline = Instant::now() + wait;
    let mut all_done = true;
    for worker in workers.iter_mut() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || worker.done.recv_timeout(remaining).is_err() {
            all_done = false;
            break;
        }
    }
    if all_done {
        for worker in workers.iter_mut() {
            if let Some(join) = worker.join.take() {
                if join.join().is_err() {
                    all_done = false;
                }
            }
        }
    } else {
        // A worker that did not observe pipe closure is detached rather than
        // allowed to block the actor forever. A successful report is impossible
        // on this path because `all_done` is false.
        for worker in workers.iter_mut() {
            worker.join.take();
        }
    }
    all_done
}

fn rpc_exchange(
    writer_tx: &SyncSender<WriteCommand>,
    frame_rx: &Receiver<Result<Vec<u8>, FrameReadError>>,
    max_frame_bytes: usize,
    timeout: Duration,
    cancel: &AtomicBool,
    method: &str,
    params: Value,
    next_request_seq: &mut u64,
) -> Result<Value, OwnedInvocationError> {
    let request_id = format!("0:{next_request_seq}");
    *next_request_seq = next_request_seq.saturating_add(1);
    let request = json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    });
    let frame = serialize_frame(&request, max_frame_bytes)?;
    let (ack_tx, ack_rx) = mpsc::sync_channel(1);
    writer_tx
        .try_send(WriteCommand {
            frame,
            reply: ack_tx,
        })
        .map_err(|error| match error {
            TrySendError::Full(_) | TrySendError::Disconnected(_) => {
                OwnedInvocationError::WorkerStopped
            }
        })?;

    let deadline = Instant::now() + timeout;
    recv_with_cancel(&ack_rx, deadline, cancel)?.map_err(|_| OwnedInvocationError::Io)?;
    loop {
        let frame = recv_with_cancel(frame_rx, deadline, cancel)?.map_err(|error| match error {
            FrameReadError::Oversized => OwnedInvocationError::FrameTooLarge,
            FrameReadError::Io | FrameReadError::InvalidUtf8 | FrameReadError::UnexpectedEof => {
                OwnedInvocationError::MalformedFrame
            }
        })?;
        let response = serde_json::from_slice::<Value>(&frame)
            .map_err(|_| OwnedInvocationError::MalformedFrame)?;
        validate_response_id(&request_id, &response)?;
        return Ok(response);
    }
}

fn recv_with_cancel<T>(
    receiver: &Receiver<T>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<T, OwnedInvocationError> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(OwnedInvocationError::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(OwnedInvocationError::Timeout);
        }
        match receiver.recv_timeout(remaining.min(ACTOR_POLL_INTERVAL)) {
            Ok(value) => return Ok(value),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(OwnedInvocationError::WorkerStopped),
        }
    }
}

fn serialize_frame(value: &Value, max_frame_bytes: usize) -> Result<Vec<u8>, OwnedInvocationError> {
    let frame = serde_json::to_vec(value).map_err(|_| OwnedInvocationError::MalformedFrame)?;
    if frame.len() > max_frame_bytes || frame.contains(&b'\n') {
        return Err(OwnedInvocationError::FrameTooLarge);
    }
    Ok(frame)
}

fn validate_response_id(expected_id: &str, response: &Value) -> Result<(), OwnedInvocationError> {
    if response
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|actual_id| actual_id == expected_id)
    {
        Ok(())
    } else {
        Err(OwnedInvocationError::WrongResponseId)
    }
}

fn read_bounded_frame<R: BufRead>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, FrameReadError> {
    let mut frame = Vec::with_capacity(max_frame_bytes.min(1024));
    loop {
        let available = reader.fill_buf().map_err(|_| FrameReadError::Io)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(FrameReadError::UnexpectedEof)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consume = newline.map_or(available.len(), |index| index.saturating_add(1));
        let content_len = newline.unwrap_or(available.len());
        if frame.len().saturating_add(content_len) > max_frame_bytes {
            return Err(FrameReadError::Oversized);
        }
        frame.extend_from_slice(&available[..content_len]);
        reader.consume(consume);
        if newline.is_some() {
            if std::str::from_utf8(&frame).is_err() {
                return Err(FrameReadError::InvalidUtf8);
            }
            return Ok(Some(frame));
        }
    }
}

fn detach_actor(actor_join: JoinHandle<()>) {
    let _ = thread::Builder::new()
        .name("fcp-owned-invocation-detach".to_owned())
        .spawn(move || {
            let _ = actor_join.join();
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn configure_introspect_handshake_invoke_frames_are_jsonrpc() {
        let methods = ["configure", "introspect", "handshake", "invoke"];
        for (sequence, method) in methods.into_iter().enumerate() {
            let request = json!({
                "jsonrpc": "2.0",
                "id": format!("0:{sequence}"),
                "method": method,
                "params": {},
            });
            let frame = serialize_frame(&request, DEFAULT_OWNED_INVOCATION_MAX_FRAME_BYTES)
                .expect("bounded frame");
            let decoded: Value = serde_json::from_slice(&frame).expect("JSON frame");
            assert_eq!(decoded["method"], method);
            assert_eq!(decoded["id"], format!("0:{sequence}"));
        }
    }

    #[test]
    fn malformed_oversized_and_wrong_id_frames_fail_closed() {
        let mut malformed = BufReader::new(Cursor::new(b"not-json\n".to_vec()));
        let bytes = read_bounded_frame(&mut malformed, 64)
            .expect("frame bytes")
            .expect("one frame");
        assert!(serde_json::from_slice::<Value>(&bytes).is_err());

        let mut oversized = BufReader::new(Cursor::new(b"123456789\n".to_vec()));
        assert!(matches!(
            read_bounded_frame(&mut oversized, 8),
            Err(FrameReadError::Oversized)
        ));

        let wrong = json!({"jsonrpc":"2.0","id":"0:9","result":{}});
        assert!(matches!(
            validate_response_id("0:0", &wrong),
            Err(OwnedInvocationError::WrongResponseId)
        ));
    }

    #[test]
    fn timeout_and_cancellation_are_bounded() {
        let (_tx, rx) = mpsc::sync_channel::<()>(1);
        let cancel = AtomicBool::new(false);
        let timeout = recv_with_cancel(&rx, Instant::now() + Duration::from_millis(2), &cancel);
        assert!(matches!(timeout, Err(OwnedInvocationError::Timeout)));

        cancel.store(true, Ordering::Release);
        let cancelled = recv_with_cancel(&rx, Instant::now() + Duration::from_secs(1), &cancel);
        assert!(matches!(cancelled, Err(OwnedInvocationError::Cancelled)));
    }

    #[cfg(target_os = "linux")]
    fn shell_spec(script: &str) -> ProcessSpec {
        let launcher = std::path::PathBuf::from("/bin/sh");
        let runtime = std::fs::canonicalize(&launcher).expect("shell path");
        let launcher_digest = blake3::hash(&std::fs::read(&launcher).expect("launcher bytes"))
            .to_hex()
            .to_string();
        let runtime_digest = blake3::hash(&std::fs::read(&runtime).expect("runtime bytes"))
            .to_hex()
            .to_string();
        ProcessSpec {
            launcher_path: launcher,
            launcher_digest,
            runtime_executable: runtime,
            expected_runtime_executable_digest: runtime_digest,
            fixed_args: vec!["-c".into(), script.into()],
            fixed_env: std::collections::BTreeMap::new(),
            network_disabled: true,
        }
    }

    #[cfg(target_os = "linux")]
    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actor_runs_configure_introspect_handshake_invoke_and_proves_group_absent() {
        let script = r#"
while IFS= read -r line; do
  case "$line" in
    *'"method":"configure"'*) echo '{"jsonrpc":"2.0","id":"0:0","result":{}}' ;;
    *'"method":"introspect"'*) echo '{"jsonrpc":"2.0","id":"0:1","result":{}}' ;;
    *'"method":"handshake"'*) echo '{"jsonrpc":"2.0","id":"0:2","result":{}}' ;;
    *'"method":"invoke"'*) echo '{"jsonrpc":"2.0","id":"0:3","result":{"ok":true}}' ;;
  esac
done
"#;
        let (host_endpoint, child_endpoint) = UnixStream::pair().expect("socketpair");
        drop(host_endpoint);
        let mut handle = run(OwnedInvocationHandle::launch(
            shell_spec(script),
            child_endpoint,
            OwnedInvocationConfig::default(),
        ))
        .expect("actor launch");
        for method in ["configure", "introspect", "handshake", "invoke"] {
            let response = run(handle.request(method, json!({}))).expect("RPC response");
            assert!(
                response["id"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("0:")
            );
        }
        let report = run(handle.terminate()).expect("group teardown");
        assert!(report.group_absent);
        assert!(report.reaped);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actor_timeout_cancels_and_descendant_group_is_reaped() {
        let script = "sleep 30 & wait";
        let (host_endpoint, child_endpoint) = UnixStream::pair().expect("socketpair");
        drop(host_endpoint);
        let mut handle = run(OwnedInvocationHandle::launch(
            shell_spec(script),
            child_endpoint,
            OwnedInvocationConfig::new(
                DEFAULT_OWNED_INVOCATION_MAX_FRAME_BYTES,
                Duration::from_millis(20),
                Duration::from_millis(100),
            ),
        ))
        .expect("actor launch");
        let result = run(handle.request("invoke", json!({})));
        assert!(matches!(result, Err(OwnedInvocationError::Timeout)));
        let report = run(handle.terminate()).expect("bounded timeout teardown");
        assert!(report.group_absent);
        assert!(report.reaped);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fatal_wrong_id_then_terminate_reads_unconditional_completion() {
        let script = r#"
while IFS= read -r _line; do
  echo '{"jsonrpc":"2.0","id":"wrong","result":{}}'
done
"#;
        let (host_endpoint, child_endpoint) = UnixStream::pair().expect("socketpair");
        drop(host_endpoint);
        let mut handle = run(OwnedInvocationHandle::launch(
            shell_spec(script),
            child_endpoint,
            OwnedInvocationConfig::default(),
        ))
        .expect("actor launch");
        let result = run(handle.request("invoke", json!({})));
        assert!(matches!(result, Err(OwnedInvocationError::WrongResponseId)));
        let report = run(handle.terminate()).expect("fatal RPC teardown");
        assert!(report.group_absent);
        assert!(report.reaped);
    }
}
