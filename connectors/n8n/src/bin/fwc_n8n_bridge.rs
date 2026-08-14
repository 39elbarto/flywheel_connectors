//! Producer-neutral, fail-closed bridge to the verified `fcp-host` launcher.
//!
//! This module deliberately accepts a caller-supplied, already validated
//! `ZeroizingSecret`; it does not know how credentials are produced.  The
//! public wrapper remains disconnected until a separately reviewed producer
//! and invocation policy are available.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use fcp_prelude::ZeroizingSecret;
use serde::Deserialize;
use serde_json::Value;

use super::fwc_n8n_bundle::VerifiedBundle;
use super::{HostRunOnceEnvelope, HostRunOnceServerId};

const MAX_CREDENTIAL_BYTES: usize = 4096;
const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;
const PROCESS_GRACE: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, PartialEq, Eq)]
enum BridgeErrorCode {
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
    InvalidEnvelope,
    CredentialEmpty,
    CredentialOversized,
    CredentialInvalidUtf8,
    CredentialInvalidHeader,
    EnvelopeEncodeFailed,
    EnvelopeTooLarge,
    PathEncoding,
    Channel,
    ProcessSpawnFailed,
    StdinUnavailable,
    StdoutUnavailable,
    StderrUnavailable,
    CredentialWriteFailed,
    StdinWriteFailed,
    OutputReadFailed,
    OutputTooLarge,
    WaitFailed,
    Timeout,
    ChildFailed,
    TeardownFailed,
    GroupPresent,
    IoWorkerFailed,
    OutputEmpty,
    OutputInvalid,
    OutputTrailing,
}

impl BridgeErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::InvalidEnvelope => "invalid_envelope",
            Self::CredentialEmpty => "credential_empty",
            Self::CredentialOversized => "credential_oversized",
            Self::CredentialInvalidUtf8 => "credential_invalid_utf8",
            Self::CredentialInvalidHeader => "credential_invalid_header",
            Self::EnvelopeEncodeFailed => "envelope_encode_failed",
            Self::EnvelopeTooLarge => "envelope_too_large",
            Self::PathEncoding => "bundle_invalid",
            Self::Channel => "credential_channel_failed",
            Self::ProcessSpawnFailed => "process_spawn_failed",
            Self::StdinUnavailable => "stdin_unavailable",
            Self::StdoutUnavailable => "stdout_unavailable",
            Self::StderrUnavailable => "stderr_unavailable",
            Self::CredentialWriteFailed => "credential_write_failed",
            Self::StdinWriteFailed => "stdin_write_failed",
            Self::OutputReadFailed => "output_read_failed",
            Self::OutputTooLarge => "output_too_large",
            Self::WaitFailed => "process_wait_failed",
            Self::Timeout => "timeout",
            Self::ChildFailed => "child_failed",
            Self::TeardownFailed => "teardown_failed",
            Self::GroupPresent => "process_group_present",
            Self::IoWorkerFailed => "io_worker_failed",
            Self::OutputEmpty => "output_empty",
            Self::OutputInvalid => "output_invalid",
            Self::OutputTrailing => "output_trailing",
        }
    }
}

impl fmt::Debug for BridgeErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct BridgeError {
    code: BridgeErrorCode,
}

impl BridgeError {
    const fn new(code: BridgeErrorCode) -> Self {
        Self { code }
    }

    #[cfg(test)]
    pub(super) const fn code(self) -> &'static str {
        self.code.as_str()
    }
}

impl fmt::Debug for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for BridgeError {}

/// Run the verified host bridge without connecting it to the public command.
#[allow(dead_code)]
pub(super) fn run_verified_host_bridge(
    bundle: &VerifiedBundle,
    envelope: &HostRunOnceEnvelope,
    credential: ZeroizingSecret,
) -> Result<Value, BridgeError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bundle, envelope, credential);
        Err(BridgeError::new(BridgeErrorCode::UnsupportedPlatform))
    }

    #[cfg(target_os = "linux")]
    {
        let spec = process_spec(bundle, envelope.server_id)?;
        let working_directory = bundle_working_directory(bundle)?;
        let output = run_process(&spec, envelope, credential, working_directory)?;
        parse_response(&output.stdout)
    }
}

#[cfg(target_os = "linux")]
fn bundle_working_directory(bundle: &VerifiedBundle) -> Result<&Path, BridgeError> {
    let (host_path, _) = bundle.fcp_host();
    let parent = host_path
        .parent()
        .filter(|path| path.is_absolute())
        .ok_or_else(|| BridgeError::new(BridgeErrorCode::PathEncoding))?;
    if parent.file_name().and_then(|name| name.to_str()) != Some("bin") {
        return Err(BridgeError::new(BridgeErrorCode::PathEncoding));
    }
    Ok(parent)
}

#[cfg(target_os = "linux")]
fn process_spec(
    bundle: &VerifiedBundle,
    server_id: HostRunOnceServerId,
) -> Result<fcp_sandbox::ProcessSpec, BridgeError> {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::Path;

    let (host_path, host_digest) = bundle.fcp_host();
    let (inventory_path, _inventory_digest) = match server_id {
        HostRunOnceServerId::Eec => bundle.inventory_eec(),
        HostRunOnceServerId::Hetzner => bundle.inventory_hetzner(),
    };
    let policy = bundle.zone_policy();
    let env_value = |path: &Path| {
        path.to_str()
            .map(OsString::from)
            .ok_or_else(|| BridgeError::new(BridgeErrorCode::PathEncoding))
    };
    let inventory_value = env_value(inventory_path)?;
    let policy_value = env_value(policy.0)?;
    let mut fixed_env = BTreeMap::new();
    fixed_env.insert(OsString::from("FCP_HOST_CONNECTORS_FILE"), inventory_value);
    fixed_env.insert(OsString::from("FCP_HOST_ZONE_POLICIES_FILE"), policy_value);
    fixed_env.insert(
        OsString::from("FCP_HOST_LIFECYCLE_STATE_FILE"),
        OsString::new(),
    );

    Ok(fcp_sandbox::ProcessSpec {
        launcher_path: host_path.to_path_buf(),
        launcher_digest: host_digest.to_owned(),
        runtime_executable: host_path.to_path_buf(),
        expected_runtime_executable_digest: host_digest.to_owned(),
        fixed_args: vec![OsString::from("n8n-run-once")],
        fixed_env,
        network_disabled: false,
    })
}

#[cfg(target_os = "linux")]
pub(super) struct ProcessOutput {
    pub(super) stdout: Vec<u8>,
    #[allow(dead_code)]
    pub(super) stderr: Vec<u8>,
    pub(super) status: std::process::ExitStatus,
    pub(super) termination: fcp_sandbox::TerminationReport,
}

#[cfg(target_os = "linux")]
struct WorkerRecord {
    completion: std::sync::mpsc::Receiver<Result<Vec<u8>, BridgeError>>,
    handle: Option<std::thread::JoinHandle<()>>,
    completed: bool,
}

#[cfg(target_os = "linux")]
impl WorkerRecord {
    fn try_receive(&mut self) -> Option<Result<Vec<u8>, BridgeError>> {
        match self.completion.try_recv() {
            Ok(result) => {
                self.completed = true;
                Some(result)
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.completed = true;
                Some(Err(BridgeError::new(BridgeErrorCode::IoWorkerFailed)))
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn remaining(deadline: std::time::Instant) -> Result<Duration, BridgeError> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        Err(BridgeError::new(BridgeErrorCode::Timeout))
    } else {
        Ok(remaining)
    }
}

#[cfg(target_os = "linux")]
fn ensure_before(deadline: std::time::Instant) -> Result<(), BridgeError> {
    remaining(deadline).map(|_| ())
}

#[cfg(target_os = "linux")]
fn operation_deadline_at(
    request_deadline_at: std::time::Instant,
) -> Result<std::time::Instant, BridgeError> {
    let operation_deadline_at = request_deadline_at
        .checked_sub(PROCESS_GRACE.saturating_mul(2))
        .ok_or_else(|| BridgeError::new(BridgeErrorCode::Timeout))?;
    if operation_deadline_at <= std::time::Instant::now() {
        return Err(BridgeError::new(BridgeErrorCode::Timeout));
    }
    Ok(operation_deadline_at)
}

#[cfg(target_os = "linux")]
impl fmt::Debug for ProcessOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessOutput")
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .field("status_success", &self.status.success())
            .field("reaped", &self.termination.reaped)
            .field("group_absent", &self.termination.group_absent)
            .finish()
    }
}

#[cfg(target_os = "linux")]
pub(super) fn run_process(
    spec: &fcp_sandbox::ProcessSpec,
    envelope: &HostRunOnceEnvelope,
    credential: ZeroizingSecret,
    working_directory: &Path,
) -> Result<ProcessOutput, BridgeError> {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::Instant;

    let envelope_bytes = serde_json::to_vec(envelope)
        .map_err(|_| BridgeError::new(BridgeErrorCode::EnvelopeEncodeFailed))?;
    if envelope_bytes.is_empty() {
        return Err(BridgeError::new(BridgeErrorCode::InvalidEnvelope));
    }
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(BridgeError::new(BridgeErrorCode::EnvelopeTooLarge));
    }
    if credential.is_empty() {
        return Err(BridgeError::new(BridgeErrorCode::CredentialEmpty));
    }
    if credential.len() > MAX_CREDENTIAL_BYTES {
        return Err(BridgeError::new(BridgeErrorCode::CredentialOversized));
    }
    validate_credential(&credential)?;

    let deadline_ms = envelope
        .deadline_ms
        .ok_or_else(|| BridgeError::new(BridgeErrorCode::InvalidEnvelope))?
        .min(60_000);
    if deadline_ms == 0 {
        return Err(BridgeError::new(BridgeErrorCode::InvalidEnvelope));
    }
    let request_deadline_at = Instant::now()
        .checked_add(Duration::from_millis(deadline_ms))
        .ok_or_else(|| BridgeError::new(BridgeErrorCode::Timeout))?;
    let operation_deadline_at = operation_deadline_at(request_deadline_at)?;
    let cancel = Arc::new(AtomicBool::new(false));
    ensure_before(operation_deadline_at)?;

    let frame = credential_frame(&credential)?;
    ensure_before(operation_deadline_at)?;
    let (mut host_endpoint, child_endpoint) =
        UnixStream::pair().map_err(|_| BridgeError::new(BridgeErrorCode::Channel))?;
    ensure_before(operation_deadline_at)?;
    let mut process =
        fcp_sandbox::OwnedProcess::spawn_with_run_once_credential_channel_in_directory(
            spec,
            child_endpoint,
            working_directory,
        )
        .map_err(|_| BridgeError::new(BridgeErrorCode::ProcessSpawnFailed))?;

    if Instant::now() >= operation_deadline_at {
        cleanup(&mut process, &cancel, Vec::new(), request_deadline_at)?;
        return Err(BridgeError::new(BridgeErrorCode::Timeout));
    }

    let Some(stdin) = process.take_stdin() else {
        cleanup(&mut process, &cancel, Vec::new(), request_deadline_at)?;
        return Err(BridgeError::new(BridgeErrorCode::StdinUnavailable));
    };
    let Some(stdout) = process.take_stdout() else {
        cleanup(&mut process, &cancel, Vec::new(), request_deadline_at)?;
        return Err(BridgeError::new(BridgeErrorCode::StdoutUnavailable));
    };
    let Some(stderr) = process.take_stderr() else {
        cleanup(&mut process, &cancel, Vec::new(), request_deadline_at)?;
        return Err(BridgeError::new(BridgeErrorCode::StderrUnavailable));
    };

    if fcp_sandbox::set_nonblocking(&stdin).is_err()
        || fcp_sandbox::set_nonblocking(&stdout).is_err()
        || fcp_sandbox::set_nonblocking(&stderr).is_err()
    {
        cleanup(&mut process, &cancel, Vec::new(), request_deadline_at)?;
        return Err(BridgeError::new(BridgeErrorCode::OutputReadFailed));
    }

    let mut workers = Vec::with_capacity(3);
    let Ok(stdin_worker) =
        spawn_stdin_writer(stdin, envelope_bytes, cancel.clone(), operation_deadline_at)
    else {
        cleanup(&mut process, &cancel, workers, request_deadline_at)?;
        return Err(BridgeError::new(BridgeErrorCode::IoWorkerFailed));
    };
    workers.push(stdin_worker);
    let Ok(stdout_worker) = spawn_bounded_reader(
        stdout,
        MAX_OUTPUT_BYTES,
        cancel.clone(),
        operation_deadline_at,
    ) else {
        cleanup(&mut process, &cancel, workers, request_deadline_at)?;
        return Err(BridgeError::new(BridgeErrorCode::IoWorkerFailed));
    };
    workers.push(stdout_worker);
    let Ok(stderr_worker) = spawn_bounded_reader(
        stderr,
        MAX_STDERR_BYTES,
        cancel.clone(),
        operation_deadline_at,
    ) else {
        cleanup(&mut process, &cancel, workers, request_deadline_at)?;
        return Err(BridgeError::new(BridgeErrorCode::IoWorkerFailed));
    };
    workers.push(stderr_worker);

    let write_result = write_credential_frame(
        &mut host_endpoint,
        &frame,
        cancel.as_ref(),
        operation_deadline_at,
    );
    drop(frame);
    drop(host_endpoint);
    if let Err(error) = write_result {
        cleanup(&mut process, &cancel, workers, request_deadline_at)?;
        return Err(error);
    }

    if let Err(error) = ensure_before(operation_deadline_at) {
        cleanup(
            &mut process,
            &cancel,
            std::mem::take(&mut workers),
            request_deadline_at,
        )?;
        return Err(error);
    }
    let mut status = None;
    let mut stdin_result = None;
    let mut stdout_result = None;
    let mut stderr_result = None;
    let mut failure = None;
    while Instant::now() < operation_deadline_at {
        if status.is_none() {
            match process.try_wait() {
                Ok(child_status) => status = child_status,
                Err(_) => failure = Some(BridgeErrorCode::WaitFailed),
            }
        }
        receive_once(&mut workers[0], &mut stdin_result);
        receive_once(&mut workers[1], &mut stdout_result);
        receive_once(&mut workers[2], &mut stderr_result);
        if let Some(Err(error)) = stdin_result.as_ref() {
            failure = Some(error.code);
        } else if let Some(Err(error)) = stdout_result.as_ref() {
            failure = Some(error.code);
        } else if let Some(Err(error)) = stderr_result.as_ref() {
            failure = Some(error.code);
        }
        if failure.is_some()
            || (status.is_some()
                && stdin_result.is_some()
                && stdout_result.is_some()
                && stderr_result.is_some())
        {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }

    if failure.is_none()
        && (status.is_none()
            || stdin_result.is_none()
            || stdout_result.is_none()
            || stderr_result.is_none())
    {
        failure = Some(BridgeErrorCode::Timeout);
    }
    if let Some(code) = failure {
        cleanup(&mut process, &cancel, workers, request_deadline_at)?;
        return Err(BridgeError::new(code));
    }

    let status = status.ok_or_else(|| BridgeError::new(BridgeErrorCode::WaitFailed))?;
    let stdout =
        stdout_result.ok_or_else(|| BridgeError::new(BridgeErrorCode::OutputReadFailed))??;
    let stderr =
        stderr_result.ok_or_else(|| BridgeError::new(BridgeErrorCode::OutputReadFailed))??;
    stdin_result.ok_or_else(|| BridgeError::new(BridgeErrorCode::StdinWriteFailed))??;
    let termination = cleanup(&mut process, &cancel, workers, request_deadline_at)?;
    if !status.success() {
        return Err(BridgeError::new(BridgeErrorCode::ChildFailed));
    }
    Ok(ProcessOutput {
        stdout,
        stderr,
        status,
        termination,
    })
}

#[cfg(target_os = "linux")]
fn validate_credential(secret: &ZeroizingSecret) -> Result<(), BridgeError> {
    secret.with_bytes(|bytes| {
        let value = std::str::from_utf8(bytes)
            .map_err(|_| BridgeError::new(BridgeErrorCode::CredentialInvalidUtf8))?;
        if value.trim() != value
            || bytes
                .iter()
                .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
        {
            return Err(BridgeError::new(BridgeErrorCode::CredentialInvalidHeader));
        }
        Ok(())
    })
}

#[cfg(target_os = "linux")]
fn credential_frame(secret: &ZeroizingSecret) -> Result<ZeroizingSecret, BridgeError> {
    let mut frame = Vec::with_capacity(9 + secret.len());
    frame.extend_from_slice(b"FCPK");
    frame.push(1);
    let length = u32::try_from(secret.len())
        .map_err(|_| BridgeError::new(BridgeErrorCode::CredentialOversized))?;
    frame.extend_from_slice(&length.to_be_bytes());
    secret.with_bytes(|bytes| frame.extend_from_slice(bytes));
    Ok(ZeroizingSecret::with_zeroize_drop(frame))
}

#[cfg(target_os = "linux")]
fn write_credential_frame(
    stream: &mut std::os::unix::net::UnixStream,
    frame: &ZeroizingSecret,
    cancel: &std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
) -> Result<(), BridgeError> {
    use std::io::Write;

    stream
        .set_nonblocking(true)
        .map_err(|_| BridgeError::new(BridgeErrorCode::CredentialWriteFailed))?;
    let write_result = frame.with_bytes(|bytes| {
        let mut offset = 0;
        while offset < bytes.len() {
            check_worker_deadline(cancel, deadline)?;
            match stream.write(&bytes[offset..]) {
                Ok(0) => return Err(BridgeError::new(BridgeErrorCode::CredentialWriteFailed)),
                Ok(written) => offset += written,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_for_worker_io(cancel, deadline)?;
                }
                Err(_) => return Err(BridgeError::new(BridgeErrorCode::CredentialWriteFailed)),
            }
        }
        Ok(())
    });
    let restore_result = stream.set_nonblocking(false);
    if restore_result.is_err() {
        return Err(BridgeError::new(BridgeErrorCode::CredentialWriteFailed));
    }
    write_result
}

#[cfg(target_os = "linux")]
fn spawn_stdin_writer(
    mut stdin: std::process::ChildStdin,
    envelope: Vec<u8>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    deadline: std::time::Instant,
) -> Result<WorkerRecord, BridgeError> {
    use std::sync::mpsc;
    let (sender, receiver) = mpsc::channel();
    let join = std::thread::Builder::new()
        .spawn(move || {
            let result = write_nonblocking(&mut stdin, &envelope, &cancel, deadline);
            drop(stdin);
            let _ = sender.send(result.map(|()| Vec::new()));
        })
        .map_err(|_| BridgeError::new(BridgeErrorCode::IoWorkerFailed))?;
    Ok(WorkerRecord {
        completion: receiver,
        handle: Some(join),
        completed: false,
    })
}

#[cfg(target_os = "linux")]
fn spawn_bounded_reader<R: std::io::Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    deadline: std::time::Instant,
) -> Result<WorkerRecord, BridgeError> {
    use std::sync::mpsc;
    let (sender, receiver) = mpsc::channel();
    let join = std::thread::Builder::new()
        .spawn(move || {
            let result = read_bounded_nonblocking(&mut reader, max_bytes, &cancel, deadline);
            let _ = sender.send(result);
        })
        .map_err(|_| BridgeError::new(BridgeErrorCode::IoWorkerFailed))?;
    Ok(WorkerRecord {
        completion: receiver,
        handle: Some(join),
        completed: false,
    })
}

#[cfg(target_os = "linux")]
fn write_nonblocking<W: std::io::Write>(
    writer: &mut W,
    bytes: &[u8],
    cancel: &std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
) -> Result<(), BridgeError> {
    let mut offset = 0;
    while offset < bytes.len() {
        check_worker_deadline(cancel, deadline)?;
        match writer.write(&bytes[offset..]) {
            Ok(0) => return Err(BridgeError::new(BridgeErrorCode::StdinWriteFailed)),
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_for_worker_io(cancel, deadline)?;
            }
            Err(_) => return Err(BridgeError::new(BridgeErrorCode::StdinWriteFailed)),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_nonblocking<R: std::io::Read>(
    reader: &mut R,
    max_bytes: usize,
    cancel: &std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, BridgeError> {
    let mut output = Vec::with_capacity(max_bytes.min(4096));
    let mut buffer = [0_u8; 4096];
    loop {
        check_worker_deadline(cancel, deadline)?;
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(bytes) => {
                if output.len().saturating_add(bytes) > max_bytes {
                    return Err(BridgeError::new(BridgeErrorCode::OutputTooLarge));
                }
                output.extend_from_slice(&buffer[..bytes]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_for_worker_io(cancel, deadline)?;
            }
            Err(_) => return Err(BridgeError::new(BridgeErrorCode::OutputReadFailed)),
        }
    }
}

#[cfg(target_os = "linux")]
fn check_worker_deadline(
    cancel: &std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
) -> Result<(), BridgeError> {
    use std::sync::atomic::Ordering;

    if cancel.load(Ordering::Relaxed) {
        return Err(BridgeError::new(BridgeErrorCode::IoWorkerFailed));
    }
    if std::time::Instant::now() >= deadline {
        return Err(BridgeError::new(BridgeErrorCode::Timeout));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_worker_io(
    cancel: &std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
) -> Result<(), BridgeError> {
    check_worker_deadline(cancel, deadline)?;
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    std::thread::sleep(remaining.min(Duration::from_millis(2)));
    check_worker_deadline(cancel, deadline)
}

#[cfg(target_os = "linux")]
fn receive_once(worker: &mut WorkerRecord, slot: &mut Option<Result<Vec<u8>, BridgeError>>) {
    if slot.is_none() {
        if let Some(result) = worker.try_receive() {
            *slot = Some(result);
        }
    }
}

#[cfg(target_os = "linux")]
fn cleanup(
    process: &mut fcp_sandbox::OwnedProcess,
    cancel: &std::sync::atomic::AtomicBool,
    mut workers: Vec<WorkerRecord>,
    request_deadline_at: std::time::Instant,
) -> Result<fcp_sandbox::TerminationReport, BridgeError> {
    use std::sync::atomic::Ordering;

    cancel.store(true, Ordering::Relaxed);
    let termination = process
        .terminate_until(fcp_async_core::Deadline::at(request_deadline_at))
        .map_err(|_| BridgeError::new(BridgeErrorCode::TeardownFailed));
    while std::time::Instant::now() < request_deadline_at
        && workers.iter().any(|worker| !worker.completed)
    {
        for worker in &mut workers {
            if !worker.completed {
                let _ = worker.try_receive();
            }
        }
        if workers.iter().any(|worker| !worker.completed) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let mut worker_failed = workers.iter().any(|worker| !worker.completed);
    for worker in &mut workers {
        if worker.completed {
            if let Some(handle) = worker.handle.take() {
                if !join_worker_until(handle, request_deadline_at) {
                    worker_failed = true;
                }
            }
        } else {
            worker.handle.take();
            worker_failed = true;
        }
    }
    let termination = termination?;
    if !termination.reaped {
        return Err(BridgeError::new(BridgeErrorCode::TeardownFailed));
    }
    if !termination.group_absent {
        return Err(BridgeError::new(BridgeErrorCode::GroupPresent));
    }
    if worker_failed {
        return Err(BridgeError::new(BridgeErrorCode::IoWorkerFailed));
    }
    Ok(termination)
}

#[cfg(target_os = "linux")]
fn join_worker_until(handle: std::thread::JoinHandle<()>, deadline: std::time::Instant) -> bool {
    while !handle.is_finished() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(2)));
    }
    handle.join().is_ok()
}

#[cfg(target_os = "linux")]
fn parse_response(bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.is_empty() {
        return Err(BridgeError::new(BridgeErrorCode::OutputEmpty));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = Value::deserialize(&mut deserializer)
        .map_err(|_| BridgeError::new(BridgeErrorCode::OutputInvalid))?;
    deserializer
        .end()
        .map_err(|_| BridgeError::new(BridgeErrorCode::OutputTrailing))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn production_spec_has_only_fixed_host_controls() {
        use std::ffi::OsString;
        use std::path::PathBuf;

        let bundle = VerifiedBundle::test_fixture();
        let bundle_debug = format!("{bundle:?}");
        assert!(!bundle_debug.contains("/release"));
        assert!(!bundle_debug.contains(&"a".repeat(64)));
        let spec = process_spec(&bundle, HostRunOnceServerId::Eec).expect("EEC spec");
        assert_eq!(spec.launcher_path, PathBuf::from("/release/bin/fcp-host"));
        assert_eq!(spec.runtime_executable, spec.launcher_path);
        assert_eq!(spec.launcher_digest, "a".repeat(64));
        assert_eq!(spec.expected_runtime_executable_digest, "a".repeat(64));
        assert_eq!(spec.fixed_args, vec![OsString::from("n8n-run-once")]);
        assert_eq!(spec.fixed_env.len(), 3);
        assert_eq!(
            spec.fixed_env
                .get(&OsString::from("FCP_HOST_CONNECTORS_FILE")),
            Some(&OsString::from("/release/inventory/eec.json"))
        );
        assert_eq!(
            spec.fixed_env
                .get(&OsString::from("FCP_HOST_ZONE_POLICIES_FILE")),
            Some(&OsString::from("/release/policy/zone-policies.json"))
        );
        assert_eq!(
            spec.fixed_env
                .get(&OsString::from("FCP_HOST_LIFECYCLE_STATE_FILE")),
            Some(&OsString::new())
        );
        assert!(!spec.network_disabled);
        assert_eq!(
            bundle_working_directory(&bundle).expect("bundle cwd"),
            Path::new("/release/bin")
        );

        let hetzner = process_spec(&bundle, HostRunOnceServerId::Hetzner).expect("Hetzner spec");
        assert_eq!(
            hetzner
                .fixed_env
                .get(&OsString::from("FCP_HOST_CONNECTORS_FILE")),
            Some(&OsString::from("/release/inventory/hetzner.json"))
        );
    }

    #[test]
    fn bridge_errors_redact_secret_and_path_material() {
        let secret = "PRIVATE-BRIDGE-SECRET";
        let path = "/private/release/bin/fcp-host";
        let error = BridgeError::new(BridgeErrorCode::ProcessSpawnFailed);
        assert!(!format!("{error:?}").contains(secret));
        assert!(!format!("{error:?}").contains(path));
        assert_eq!(error.code(), "process_spawn_failed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn response_requires_one_bounded_json_value() {
        assert_eq!(
            parse_response(b"{\"status\":\"ok\"} \n")
                .expect("single response")
                .get("status")
                .and_then(Value::as_str),
            Some("ok")
        );
        assert_eq!(
            parse_response(br#"{"status":"ok"} {"extra":true}"#)
                .expect_err("trailing response")
                .code(),
            "output_trailing"
        );
        assert_eq!(
            parse_response(b"not-json")
                .expect_err("malformed response")
                .code(),
            "output_invalid"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_writer_transfers_the_fixed_frame_before_deadline() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::AtomicBool;
        use std::time::Instant;

        let (mut peer, mut stream) = UnixStream::pair().expect("credential socketpair");
        let expected = b"FCPK\x01\x00\x00\x00\x01x".to_vec();
        let frame = ZeroizingSecret::with_zeroize_drop(expected.clone());
        let cancel = AtomicBool::new(false);
        write_credential_frame(
            &mut stream,
            &frame,
            &cancel,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("fixed credential frame should transfer");
        let mut received = vec![0_u8; expected.len()];
        peer.read_exact(&mut received)
            .expect("read fixed credential frame");
        assert_eq!(received, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_writer_rejects_an_expired_deadline_before_writing() {
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::AtomicBool;
        use std::time::Instant;

        let (_peer, mut stream) = UnixStream::pair().expect("credential socketpair");
        let frame = ZeroizingSecret::with_zeroize_drop(b"FCPK".to_vec());
        let cancel = AtomicBool::new(false);
        let error = write_credential_frame(&mut stream, &frame, &cancel, Instant::now())
            .expect_err("expired credential deadline must fail closed");
        assert_eq!(error.code(), "timeout");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn operation_deadline_reserves_the_teardown_budget() {
        use std::time::Instant;

        let request_deadline_at = Instant::now() + Duration::from_millis(500);
        let operation_deadline_at =
            super::operation_deadline_at(request_deadline_at).expect("operation budget");
        let teardown_reserve = PROCESS_GRACE.saturating_mul(2);
        assert!(
            operation_deadline_at
                <= request_deadline_at
                    .checked_sub(teardown_reserve)
                    .expect("reserved deadline")
        );
        assert!(operation_deadline_at > Instant::now());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn operation_deadline_rejects_too_short_request_before_spawn() {
        use std::time::Instant;

        let request_deadline_at = Instant::now() + PROCESS_GRACE.saturating_mul(2);
        let error = super::operation_deadline_at(request_deadline_at)
            .expect_err("teardown reservation leaves no operation budget");
        assert_eq!(error.code(), "timeout");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_deadline_does_not_extend_the_request_deadline() {
        use std::time::Instant;

        let request_deadline_at = Instant::now() + Duration::from_millis(500);
        let cleanup_deadline = fcp_async_core::Deadline::at(request_deadline_at);
        let request_remaining_upper_bound =
            request_deadline_at.saturating_duration_since(Instant::now());
        let cleanup_remaining = cleanup_deadline.remaining();
        assert!(cleanup_remaining <= request_remaining_upper_bound);
        assert!(!cleanup_remaining.is_zero());
    }

    #[cfg(target_os = "linux")]
    struct StalledWriter;

    #[cfg(target_os = "linux")]
    impl std::io::Write for StalledWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    struct StalledReader;

    #[cfg(target_os = "linux")]
    impl std::io::Read for StalledReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_workers_honor_deadline_and_shared_cancel() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Instant;

        let cancel = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_millis(5);
        let error = write_nonblocking(&mut StalledWriter, b"payload", &cancel, deadline)
            .expect_err("stalled writer must time out");
        assert_eq!(error.code(), "timeout");

        cancel.store(true, Ordering::Relaxed);
        let error = read_bounded_nonblocking(
            &mut StalledReader,
            MAX_OUTPUT_BYTES,
            &cancel,
            Instant::now() + Duration::from_secs(1),
        )
        .expect_err("cancelled reader must stop");
        assert_eq!(error.code(), "io_worker_failed");
    }
}
