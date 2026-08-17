//! Producer-neutral, fail-closed bridge to the verified `fcp-host` launcher.
//!
//! This module deliberately accepts an already validated `ZeroizingSecret` and
//! one caller-owned absolute deadline; credential production remains isolated
//! in the fixed one-shot broker.

use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use fcp_crypto::{
    CredentialFrameError, ZeroizingSecret, encode_credential_frame, validate_credential_secret,
};
use serde::Deserialize;
use serde_json::Value;

use super::fwc_n8n_bundle::VerifiedBundle;
use super::{HostRunOnceEnvelope, HostRunOnceServerId};

const MAX_CREDENTIAL_BYTES: usize = 4096;
const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_OFFICIAL_MCP_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;
const PROCESS_GRACE: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const CHILD_INVOKE_DIAGNOSTIC_PREFIX: &[u8] = b"FCP-N8N-INVOKE-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const BRIDGE_INVOKE_DIAGNOSTIC_PREFIX: &str = "FWC-N8N-INVOKE-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const CHILD_HOST_ERROR_DIAGNOSTIC_PREFIX: &[u8] = b"FCP-N8N-HOST-ERROR-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const BRIDGE_HOST_ERROR_DIAGNOSTIC_PREFIX: &str = "FWC-N8N-HOST-ERROR-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const CHILD_OWNED_DIAGNOSTIC_PREFIX: &[u8] = b"FCP-N8N-OWNED-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const BRIDGE_OWNED_DIAGNOSTIC_PREFIX: &str = "FWC-N8N-OWNED-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const CHILD_CHILD_ERROR_DIAGNOSTIC_PREFIX: &[u8] = b"FCP-N8N-CHILD-ERROR-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const BRIDGE_CHILD_ERROR_DIAGNOSTIC_PREFIX: &str = "FWC-N8N-CHILD-ERROR-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const CHILD_EXTERNAL_PROVENANCE_DIAGNOSTIC_PREFIX: &[u8] =
    b"FCP-N8N-EXTERNAL-PROVENANCE-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const BRIDGE_EXTERNAL_PROVENANCE_DIAGNOSTIC_PREFIX: &str =
    "FWC-N8N-EXTERNAL-PROVENANCE-DIAGNOSTIC/v1 ";
#[cfg(target_os = "linux")]
const MAX_OWNED_DIAGNOSTIC_LABELS: usize = 4;
#[cfg(target_os = "linux")]
const SUPERVISOR_START_PREFIX: &[u8] = b"FCP-HOST-RUN-ONCE/v1/START";
#[cfg(target_os = "linux")]
const SUPERVISOR_READY_FRAME: &[u8] = b"FCP-HOST-RUN-ONCE/v1/READY";
#[cfg(target_os = "linux")]
const SUPERVISOR_GO_FRAME: &[u8] = b"FCP-HOST-RUN-ONCE/v1/GO";
#[cfg(target_os = "linux")]
const SUPERVISOR_ABORT_FRAME: &[u8] = b"FCP-HOST-RUN-ONCE/v1/ABORT";
#[cfg(target_os = "linux")]
const SUPERVISOR_MAX_BUDGET_MS: u64 = 60_000;
#[cfg(target_os = "linux")]
const SUPERVISOR_START_FRAME_LEN: usize = SUPERVISOR_START_PREFIX.len() + 4;
#[cfg(target_os = "linux")]
const CREATE_DRAFT_OWNER_ADMISSION: &str = r#"{"version":1,"mode":"owner-approved-single-host","zone_id":"z:work","connector_id":"fcp.n8n","operation":"n8n.workflows.create_draft"}"#;
#[cfg(target_os = "linux")]
const UPDATE_DRAFT_OWNER_ADMISSION: &str = r#"{"version":1,"mode":"owner-approved-single-host","zone_id":"z:work","connector_id":"fcp.n8n","operation":"n8n.workflows.update_draft"}"#;

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
    CgroupFailed,
    SupervisorGateFailed,
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
    HostConnectorNotFound,
    HostInvalidInput,
    HostPreflightDenied,
    HostConnectorUnavailable,
    HostConnectorFrameLimit,
    HostInternal,
    HostN8nInputFailed,
    HostN8nConfigFailed,
    HostN8nPlanFailed,
    HostN8nCredentialFailed,
    HostN8nPolicyFailed,
    HostN8nRuntimeStateFailed,
    HostN8nManifestFailed,
    HostN8nCapabilityFailed,
    HostN8nInvokeFailed,
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
            Self::CgroupFailed => "request_cgroup_failed",
            Self::SupervisorGateFailed => "supervisor_gate_failed",
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
            Self::HostConnectorNotFound => "host_connector_not_found",
            Self::HostInvalidInput => "host_invalid_input",
            Self::HostPreflightDenied => "host_preflight_denied",
            Self::HostConnectorUnavailable => "host_connector_unavailable",
            Self::HostConnectorFrameLimit => "host_connector_frame_limit",
            Self::HostInternal => "host_internal",
            Self::HostN8nInputFailed => "host_n8n_input_failed",
            Self::HostN8nConfigFailed => "host_n8n_config_failed",
            Self::HostN8nPlanFailed => "host_n8n_plan_failed",
            Self::HostN8nCredentialFailed => "host_n8n_credential_failed",
            Self::HostN8nPolicyFailed => "host_n8n_policy_failed",
            Self::HostN8nRuntimeStateFailed => "host_n8n_runtime_state_failed",
            Self::HostN8nManifestFailed => "host_n8n_manifest_failed",
            Self::HostN8nCapabilityFailed => "host_n8n_capability_failed",
            Self::HostN8nInvokeFailed => "host_n8n_invoke_failed",
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
pub struct BridgeError {
    code: BridgeErrorCode,
}

impl BridgeError {
    const fn new(code: BridgeErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> &'static str {
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

/// Run the verified host bridge with a broker-produced credential.
pub fn run_verified_host_bridge(
    bundle: &VerifiedBundle,
    envelope: &HostRunOnceEnvelope,
    credential: ZeroizingSecret,
    request_deadline_at: Instant,
) -> Result<Value, BridgeError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bundle, envelope, credential, request_deadline_at);
        Err(BridgeError::new(BridgeErrorCode::UnsupportedPlatform))
    }

    #[cfg(target_os = "linux")]
    {
        let spec = process_spec(bundle, envelope.server_id, envelope.operation)?;
        let working_directory = bundle_working_directory(bundle)?;
        let output = run_process(
            &spec,
            envelope,
            credential,
            working_directory,
            request_deadline_at,
        )?;
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
    operation: super::HostRunOnceOperation,
) -> Result<fcp_sandbox::ProcessSpec, BridgeError> {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::Path;

    let (host_path, host_digest) = bundle.fcp_host();
    let official_mcp = matches!(operation, super::HostRunOnceOperation::CapabilitiesInspect);
    let owner_admission = match operation {
        super::HostRunOnceOperation::WorkflowsCreateDraft => Some(CREATE_DRAFT_OWNER_ADMISSION),
        super::HostRunOnceOperation::WorkflowsUpdateDraft => Some(UPDATE_DRAFT_OWNER_ADMISSION),
        _ => None,
    };
    let write = owner_admission.is_some();
    let (inventory_path, _inventory_digest) = match (server_id, official_mcp) {
        (HostRunOnceServerId::Eec, false) => bundle.inventory_eec(),
        (HostRunOnceServerId::Hetzner, false) => bundle.inventory_hetzner(),
        (HostRunOnceServerId::Eec, true) => bundle.inventory_eec_official_mcp(),
        (HostRunOnceServerId::Hetzner, true) => bundle.inventory_hetzner_official_mcp(),
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
    if let Some(admission) = owner_admission {
        fixed_env.insert(
            OsString::from("FCP_HOST_OWNER_SINGLE_HOST_ADMISSION"),
            OsString::from(admission),
        );
    }

    Ok(fcp_sandbox::ProcessSpec {
        launcher_path: host_path.to_path_buf(),
        launcher_digest: host_digest.to_owned(),
        runtime_executable: host_path.to_path_buf(),
        expected_runtime_executable_digest: host_digest.to_owned(),
        fixed_args: vec![OsString::from(if official_mcp {
            "n8n-official-mcp-run-once-supervised"
        } else if write {
            "n8n-write-run-once-supervised"
        } else {
            "n8n-run-once-supervised"
        })],
        fixed_env,
        network_disabled: false,
    })
}

#[cfg(target_os = "linux")]
const fn max_output_bytes(operation: super::HostRunOnceOperation) -> usize {
    if matches!(operation, super::HostRunOnceOperation::CapabilitiesInspect) {
        MAX_OFFICIAL_MCP_OUTPUT_BYTES
    } else {
        MAX_OUTPUT_BYTES
    }
}

#[cfg(target_os = "linux")]
pub struct ProcessOutput {
    pub stdout: Vec<u8>,
    #[allow(dead_code)]
    pub stderr: Vec<u8>,
    pub status: std::process::ExitStatus,
    pub termination: fcp_sandbox::TerminationReport,
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
fn supervisor_start_frame(
    deadline: std::time::Instant,
) -> Result<[u8; SUPERVISOR_START_FRAME_LEN], BridgeError> {
    let remaining_ms = deadline
        .saturating_duration_since(std::time::Instant::now())
        .as_millis();
    let budget_ms = u64::try_from(remaining_ms)
        .unwrap_or(u64::MAX)
        .min(SUPERVISOR_MAX_BUDGET_MS);
    if !(1..=SUPERVISOR_MAX_BUDGET_MS).contains(&budget_ms) {
        return Err(BridgeError::new(BridgeErrorCode::Timeout));
    }
    let mut frame = [0_u8; SUPERVISOR_START_FRAME_LEN];
    frame[..SUPERVISOR_START_PREFIX.len()].copy_from_slice(SUPERVISOR_START_PREFIX);
    frame[SUPERVISOR_START_PREFIX.len()..].copy_from_slice(
        &u32::try_from(budget_ms)
            .map_err(|_| BridgeError::new(BridgeErrorCode::SupervisorGateFailed))?
            .to_be_bytes(),
    );
    Ok(frame)
}

#[cfg(target_os = "linux")]
const fn supervisor_control_error() -> BridgeError {
    BridgeError::new(BridgeErrorCode::SupervisorGateFailed)
}

#[cfg(target_os = "linux")]
fn wait_for_supervisor_io(deadline: std::time::Instant) -> Result<(), BridgeError> {
    ensure_before(deadline)?;
    std::thread::sleep(
        deadline
            .saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_millis(2)),
    );
    ensure_before(deadline)
}

#[cfg(target_os = "linux")]
fn write_supervisor_control_exact(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &[u8],
    deadline: std::time::Instant,
) -> Result<(), BridgeError> {
    use std::io::Write;

    stream
        .set_nonblocking(true)
        .map_err(|_| supervisor_control_error())?;
    let result = (|| {
        let mut offset = 0;
        while offset < bytes.len() {
            ensure_before(deadline)?;
            match stream.write(&bytes[offset..]) {
                Ok(0) => return Err(supervisor_control_error()),
                Ok(written) => offset += written,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_for_supervisor_io(deadline)?;
                }
                Err(_) => return Err(supervisor_control_error()),
            }
        }
        Ok(())
    })();
    if stream.set_nonblocking(false).is_err() {
        return Err(supervisor_control_error());
    }
    result
}

#[cfg(target_os = "linux")]
fn read_supervisor_control_exact(
    stream: &mut std::os::unix::net::UnixStream,
    buffer: &mut [u8],
    deadline: std::time::Instant,
) -> Result<(), BridgeError> {
    use std::io::Read;

    stream
        .set_nonblocking(true)
        .map_err(|_| supervisor_control_error())?;
    let result = (|| {
        let mut offset = 0;
        while offset < buffer.len() {
            ensure_before(deadline)?;
            match stream.read(&mut buffer[offset..]) {
                Ok(0) => return Err(supervisor_control_error()),
                Ok(read) => offset += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_for_supervisor_io(deadline)?;
                }
                Err(_) => return Err(supervisor_control_error()),
            }
        }
        Ok(())
    })();
    if stream.set_nonblocking(false).is_err() {
        return Err(supervisor_control_error());
    }
    result
}

#[cfg(target_os = "linux")]
fn reject_queued_supervisor_control_bytes(
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<(), BridgeError> {
    use std::io::Read;

    stream
        .set_nonblocking(true)
        .map_err(|_| supervisor_control_error())?;
    let mut probe = [0_u8; 1];
    let read_result = stream.read(&mut probe);
    if stream.set_nonblocking(false).is_err() {
        return Err(supervisor_control_error());
    }
    match read_result {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Ok(0) => Ok(()),
        Ok(_) | Err(_) => Err(supervisor_control_error()),
    }
}

#[cfg(target_os = "linux")]
fn best_effort_supervisor_abort(
    stream: &mut std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
) {
    if std::time::Instant::now() < deadline {
        let _ = write_supervisor_control_exact(stream, SUPERVISOR_ABORT_FRAME, deadline);
    }
}

#[cfg(target_os = "linux")]
fn write_supervisor_go_after_gate(
    stream: &mut std::os::unix::net::UnixStream,
    _gate: fcp_sandbox::SupervisorExecGate,
    deadline: std::time::Instant,
) -> Result<(), BridgeError> {
    write_supervisor_control_exact(stream, SUPERVISOR_GO_FRAME, deadline)
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
// The explicit phases intentionally remain together so all cancellation,
// zeroization, and process-group cleanup exits are auditable in one place.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
pub fn run_process(
    spec: &fcp_sandbox::ProcessSpec,
    envelope: &HostRunOnceEnvelope,
    credential: ZeroizingSecret,
    working_directory: &Path,
    request_deadline_at: Instant,
) -> Result<ProcessOutput, BridgeError> {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;

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
    if Instant::now() >= request_deadline_at {
        return Err(BridgeError::new(BridgeErrorCode::Timeout));
    }
    let operation_deadline_at = operation_deadline_at(request_deadline_at)?;
    let cancel = Arc::new(AtomicBool::new(false));
    ensure_before(operation_deadline_at)?;

    let frame = credential_frame(&credential)?;
    ensure_before(operation_deadline_at)?;
    let mut request_cgroup = fcp_sandbox::RequestCgroup::create()
        .map_err(|_| BridgeError::new(BridgeErrorCode::CgroupFailed))?;
    let Ok((attach_handle, attach_lease)) = request_cgroup.take_supervisor_attach_handle() else {
        return Err(fail_empty_cgroup(
            &mut request_cgroup,
            request_deadline_at,
            BridgeError::new(BridgeErrorCode::CgroupFailed),
        ));
    };
    let mut attach_lease = Some(attach_lease);
    let Ok((mut host_endpoint, child_endpoint)) = UnixStream::pair() else {
        return Err(fail_empty_cgroup(
            &mut request_cgroup,
            request_deadline_at,
            BridgeError::new(BridgeErrorCode::Channel),
        ));
    };
    if let Err(error) = ensure_before(operation_deadline_at) {
        return Err(fail_empty_cgroup(
            &mut request_cgroup,
            request_deadline_at,
            error,
        ));
    }
    let Ok((mut supervisor_endpoint, supervisor_child_endpoint)) = UnixStream::pair() else {
        return Err(fail_empty_cgroup(
            &mut request_cgroup,
            request_deadline_at,
            BridgeError::new(BridgeErrorCode::Channel),
        ));
    };
    if let Err(error) = ensure_before(operation_deadline_at) {
        return Err(fail_empty_cgroup(
            &mut request_cgroup,
            request_deadline_at,
            error,
        ));
    }
    let Ok(mut process) = fcp_sandbox::OwnedProcess::spawn_with_supervised_run_once_channels(
        spec,
        child_endpoint,
        supervisor_child_endpoint,
        attach_handle,
        working_directory,
    ) else {
        return Err(fail_empty_cgroup(
            &mut request_cgroup,
            request_deadline_at,
            BridgeError::new(BridgeErrorCode::ProcessSpawnFailed),
        ));
    };

    let start_frame = match supervisor_start_frame(operation_deadline_at) {
        Ok(frame) => frame,
        Err(error) => {
            best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
            return Err(fail_process(
                &mut process,
                &mut request_cgroup,
                &cancel,
                Vec::new(),
                request_deadline_at,
                error,
            ));
        }
    };
    if let Err(error) = write_supervisor_control_exact(
        &mut supervisor_endpoint,
        &start_frame,
        operation_deadline_at,
    ) {
        best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
        return Err(fail_process(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
            error,
        ));
    }
    let mut ready = [0_u8; SUPERVISOR_READY_FRAME.len()];
    if let Err(error) =
        read_supervisor_control_exact(&mut supervisor_endpoint, &mut ready, operation_deadline_at)
    {
        best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
        return Err(fail_process(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
            error,
        ));
    }
    if ready != SUPERVISOR_READY_FRAME
        || reject_queued_supervisor_control_bytes(&mut supervisor_endpoint).is_err()
    {
        best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
        return Err(fail_process(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
            supervisor_control_error(),
        ));
    }
    let lease = attach_lease
        .as_ref()
        .ok_or_else(supervisor_control_error)
        .map_err(|error| {
            best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
            fail_process(
                &mut process,
                &mut request_cgroup,
                &cancel,
                Vec::new(),
                request_deadline_at,
                error,
            )
        })?;
    let Ok(permit) = request_cgroup.verify_supervisor_membership(&process, lease) else {
        best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
        return Err(fail_process(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
            BridgeError::new(BridgeErrorCode::SupervisorGateFailed),
        ));
    };
    let Some(lease) = attach_lease.take() else {
        best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
        return Err(fail_process(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
            supervisor_control_error(),
        ));
    };
    let Ok(supervisor_exec_gate) = request_cgroup.consume_release_permit(permit, &process, lease)
    else {
        best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
        return Err(fail_process(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
            BridgeError::new(BridgeErrorCode::SupervisorGateFailed),
        ));
    };
    if let Err(error) = write_supervisor_go_after_gate(
        &mut supervisor_endpoint,
        supervisor_exec_gate,
        operation_deadline_at,
    ) {
        best_effort_supervisor_abort(&mut supervisor_endpoint, operation_deadline_at);
        return Err(fail_process(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
            error,
        ));
    }
    drop(supervisor_endpoint);

    if Instant::now() >= operation_deadline_at {
        return Err(fail_process(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
            BridgeError::new(BridgeErrorCode::Timeout),
        ));
    }

    let Some(stdin) = process.take_stdin() else {
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
        )?;
        return Err(BridgeError::new(BridgeErrorCode::StdinUnavailable));
    };
    let Some(stdout) = process.take_stdout() else {
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
        )?;
        return Err(BridgeError::new(BridgeErrorCode::StdoutUnavailable));
    };
    let Some(stderr) = process.take_stderr() else {
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
        )?;
        return Err(BridgeError::new(BridgeErrorCode::StderrUnavailable));
    };

    if fcp_sandbox::set_nonblocking(&stdin).is_err()
        || fcp_sandbox::set_nonblocking(&stdout).is_err()
        || fcp_sandbox::set_nonblocking(&stderr).is_err()
    {
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            Vec::new(),
            request_deadline_at,
        )?;
        return Err(BridgeError::new(BridgeErrorCode::OutputReadFailed));
    }

    let mut workers = Vec::with_capacity(3);
    let Ok(stdin_worker) =
        spawn_stdin_writer(stdin, envelope_bytes, cancel.clone(), operation_deadline_at)
    else {
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            workers,
            request_deadline_at,
        )?;
        return Err(BridgeError::new(BridgeErrorCode::IoWorkerFailed));
    };
    workers.push(stdin_worker);
    let Ok(stdout_worker) = spawn_bounded_reader(
        stdout,
        max_output_bytes(envelope.operation),
        cancel.clone(),
        operation_deadline_at,
    ) else {
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            workers,
            request_deadline_at,
        )?;
        return Err(BridgeError::new(BridgeErrorCode::IoWorkerFailed));
    };
    workers.push(stdout_worker);
    let Ok(stderr_worker) = spawn_bounded_reader(
        stderr,
        MAX_STDERR_BYTES,
        cancel.clone(),
        operation_deadline_at,
    ) else {
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            workers,
            request_deadline_at,
        )?;
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
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            workers,
            request_deadline_at,
        )?;
        return Err(error);
    }

    if let Err(error) = ensure_before(operation_deadline_at) {
        cleanup(
            &mut process,
            &mut request_cgroup,
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
        cleanup(
            &mut process,
            &mut request_cgroup,
            &cancel,
            workers,
            request_deadline_at,
        )?;
        return Err(BridgeError::new(code));
    }

    let status = status.ok_or_else(|| BridgeError::new(BridgeErrorCode::WaitFailed))?;
    let stdout =
        stdout_result.ok_or_else(|| BridgeError::new(BridgeErrorCode::OutputReadFailed))??;
    let stderr =
        stderr_result.ok_or_else(|| BridgeError::new(BridgeErrorCode::OutputReadFailed))??;
    stdin_result.ok_or_else(|| BridgeError::new(BridgeErrorCode::StdinWriteFailed))??;
    let termination = cleanup(
        &mut process,
        &mut request_cgroup,
        &cancel,
        workers,
        request_deadline_at,
    )?;
    if !status.success() {
        emit_child_invoke_diagnostic(&stderr);
        return Err(BridgeError::new(child_failure_code(&stdout)));
    }
    Ok(ProcessOutput {
        stdout,
        stderr,
        status,
        termination,
    })
}

#[cfg(target_os = "linux")]
fn child_invoke_diagnostic(stderr: &[u8]) -> Option<&'static str> {
    stderr.split(|byte| *byte == b'\n').find_map(|line| {
        let label = line.strip_prefix(CHILD_INVOKE_DIAGNOSTIC_PREFIX)?;
        match label {
            b"dispatch_4xx" => Some("dispatch_4xx"),
            b"dispatch_5xx" => Some("dispatch_5xx"),
            b"dispatch_other" => Some("dispatch_other"),
            b"response_protocol" => Some("response_protocol"),
            b"response_auth" => Some("response_auth"),
            b"response_rate_limited" => Some("response_rate_limited"),
            b"response_capability" => Some("response_capability"),
            b"response_zone" => Some("response_zone"),
            b"response_connector" => Some("response_connector"),
            b"response_resource" => Some("response_resource"),
            b"response_external_4xx" => Some("response_external_4xx"),
            b"response_external_5xx" => Some("response_external_5xx"),
            b"response_external_other" => Some("response_external_other"),
            b"response_external_unknown" => Some("response_external_unknown"),
            b"response_upstream_timeout" => Some("response_upstream_timeout"),
            b"response_dependency_unavailable" => Some("response_dependency_unavailable"),
            b"response_internal" => Some("response_internal"),
            _ => None,
        }
    })
}

#[cfg(target_os = "linux")]
fn emit_child_invoke_diagnostic(stderr: &[u8]) {
    if let Some(label) = child_invoke_diagnostic(stderr) {
        eprintln!("{BRIDGE_INVOKE_DIAGNOSTIC_PREFIX}{label}");
    }
    if let Some(label) = child_external_provenance_diagnostic(stderr) {
        eprintln!("{BRIDGE_EXTERNAL_PROVENANCE_DIAGNOSTIC_PREFIX}{label}");
    }
    if let Some(label) = child_host_error_diagnostic(stderr) {
        eprintln!("{BRIDGE_HOST_ERROR_DIAGNOSTIC_PREFIX}{label}");
    }
    for label in child_owned_diagnostics(stderr) {
        eprintln!("{BRIDGE_OWNED_DIAGNOSTIC_PREFIX}{label}");
    }
    if let Some(label) = child_child_error_diagnostic(stderr) {
        eprintln!("{BRIDGE_CHILD_ERROR_DIAGNOSTIC_PREFIX}{label}");
    }
}

#[cfg(target_os = "linux")]
fn child_external_provenance_diagnostic(stderr: &[u8]) -> Option<&'static str> {
    stderr.split(|byte| *byte == b'\n').find_map(|line| {
        let label = line.strip_prefix(CHILD_EXTERNAL_PROVENANCE_DIAGNOSTIC_PREFIX)?;
        match label {
            b"external.provider_5xx" => Some("external.provider_5xx"),
            b"external.host_proxy_rejected" => Some("external.host_proxy_rejected"),
            b"external.connector_egress_transport" => Some("external.connector_egress_transport"),
            b"external.connector_egress_inherited_channel" => {
                Some("external.connector_egress_inherited_channel")
            }
            b"external.connector_egress_inherited_request_id" => {
                Some("external.connector_egress_inherited_request_id")
            }
            b"external.connector_egress_inherited_poisoned" => {
                Some("external.connector_egress_inherited_poisoned")
            }
            b"external.connector_egress_inherited_write" => {
                Some("external.connector_egress_inherited_write")
            }
            b"external.connector_egress_inherited_read" => {
                Some("external.connector_egress_inherited_read")
            }
            b"external.connector_egress_inherited_read_eof" => {
                Some("external.connector_egress_inherited_read_eof")
            }
            b"external.connector_egress_inherited_frame" => {
                Some("external.connector_egress_inherited_frame")
            }
            b"external.connector_egress_inherited_json" => {
                Some("external.connector_egress_inherited_json")
            }
            b"external.connector_egress_inherited_validation" => {
                Some("external.connector_egress_inherited_validation")
            }
            b"external.connector_egress_inherited_timeout" => {
                Some("external.connector_egress_inherited_timeout")
            }
            b"external.connector_egress_request_too_large" => {
                Some("external.connector_egress_request_too_large")
            }
            b"external.connector_egress_request_malformed" => {
                Some("external.connector_egress_request_malformed")
            }
            b"external.connector_egress_response_too_large" => {
                Some("external.connector_egress_response_too_large")
            }
            b"external.connector_egress_response_malformed" => {
                Some("external.connector_egress_response_malformed")
            }
            _ => None,
        }
    })
}

#[cfg(target_os = "linux")]
fn child_host_error_diagnostic(stderr: &[u8]) -> Option<&'static str> {
    stderr.split(|byte| *byte == b'\n').find_map(|line| {
        let label = line.strip_prefix(CHILD_HOST_ERROR_DIAGNOSTIC_PREFIX)?;
        match label {
            b"local.capability_denied" => Some("local.capability_denied"),
            b"local.validation" => Some("local.validation"),
            b"local.policy_denied" => Some("local.policy_denied"),
            b"transport.host_connector" => Some("transport.host_connector"),
            b"transport.frame_limit" => Some("transport.frame_limit"),
            b"internal.registry" => Some("internal.registry"),
            b"internal.cache" => Some("internal.cache"),
            b"internal.runtime" => Some("internal.runtime"),
            _ => None,
        }
    })
}

#[cfg(target_os = "linux")]
fn child_owned_diagnostics(stderr: &[u8]) -> Vec<&'static str> {
    let mut diagnostics = Vec::with_capacity(MAX_OWNED_DIAGNOSTIC_LABELS);
    for line in stderr.split(|byte| *byte == b'\n') {
        let Some(label) = child_owned_diagnostic_label(line) else {
            continue;
        };
        if diagnostics.contains(&label) {
            continue;
        }
        diagnostics.push(label);
        if diagnostics.len() == MAX_OWNED_DIAGNOSTIC_LABELS {
            break;
        }
    }
    diagnostics
}

#[cfg(target_os = "linux")]
fn child_owned_diagnostic_label(line: &[u8]) -> Option<&'static str> {
    let label = line.strip_prefix(CHILD_OWNED_DIAGNOSTIC_PREFIX)?;
    match label {
        b"owned.setup" => Some("owned.setup"),
        b"owned.launch.unsupported_platform" => Some("owned.launch.unsupported_platform"),
        b"owned.launch.invalid_spec" => Some("owned.launch.invalid_spec"),
        b"owned.launch.io" => Some("owned.launch.io"),
        b"owned.launch.digest_mismatch" => Some("owned.launch.digest_mismatch"),
        b"owned.launch.identity_mismatch" => Some("owned.launch.identity_mismatch"),
        b"owned.launch.teardown" => Some("owned.launch.teardown"),
        b"owned.rpc_transport" => Some("owned.rpc_transport"),
        b"owned.rpc_protocol" => Some("owned.rpc_protocol"),
        b"owned.rpc_child_error" => Some("owned.rpc_child_error"),
        b"owned.response_protocol" => Some("owned.response_protocol"),
        b"owned.egress_codec.read_error" => Some("owned.egress_codec.read_error"),
        b"owned.egress_codec.read_eof" => Some("owned.egress_codec.read_eof"),
        b"owned.egress_codec.write_error" => Some("owned.egress_codec.write_error"),
        b"owned.egress_codec.truncated" => Some("owned.egress_codec.truncated"),
        b"owned.egress_codec.oversized" => Some("owned.egress_codec.oversized"),
        b"owned.egress_codec.empty_frame" => Some("owned.egress_codec.empty_frame"),
        b"owned.egress_codec.invalid_utf8" => Some("owned.egress_codec.invalid_utf8"),
        b"owned.egress_codec.invalid_json" => Some("owned.egress_codec.invalid_json"),
        b"owned.egress_codec.wrong_schema" => Some("owned.egress_codec.wrong_schema"),
        b"owned.egress_codec.wrong_auth" => Some("owned.egress_codec.wrong_auth"),
        b"owned.egress_codec.wrong_route_payload" => Some("owned.egress_codec.wrong_route_payload"),
        b"owned.egress_codec.wrong_request_id" => Some("owned.egress_codec.wrong_request_id"),
        b"owned.egress_codec.invalid_response" => Some("owned.egress_codec.invalid_response"),
        b"owned.egress_codec.invalid_auth_token" => Some("owned.egress_codec.invalid_auth_token"),
        b"owned.egress_codec.missing_request" => Some("owned.egress_codec.missing_request"),
        b"owned.teardown" => Some("owned.teardown"),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn child_child_error_diagnostic(stderr: &[u8]) -> Option<&'static str> {
    stderr.split(|byte| *byte == b'\n').find_map(|line| {
        let label = line.strip_prefix(CHILD_CHILD_ERROR_DIAGNOSTIC_PREFIX)?;
        match label {
            b"child.protocol" => Some("child.protocol"),
            b"child.auth" => Some("child.auth"),
            b"child.capability" => Some("child.capability"),
            b"child.zone" => Some("child.zone"),
            b"child.connector" => Some("child.connector"),
            b"child.resource" => Some("child.resource"),
            b"child.external" => Some("child.external"),
            b"child.internal" => Some("child.internal"),
            b"child.unknown" => Some("child.unknown"),
            _ => None,
        }
    })
}

#[cfg(target_os = "linux")]
fn validate_credential(secret: &ZeroizingSecret) -> Result<(), BridgeError> {
    validate_credential_secret(secret).map_err(map_credential_frame_error)
}

#[cfg(target_os = "linux")]
fn credential_frame(secret: &ZeroizingSecret) -> Result<ZeroizingSecret, BridgeError> {
    encode_credential_frame(secret).map_err(map_credential_frame_error)
}

#[cfg(target_os = "linux")]
const fn map_credential_frame_error(error: CredentialFrameError) -> BridgeError {
    let code = match error {
        CredentialFrameError::InvalidFrame
        | CredentialFrameError::Truncated
        | CredentialFrameError::InvalidHeaderValue
        | CredentialFrameError::TrailingData
        | CredentialFrameError::Io => BridgeErrorCode::CredentialInvalidHeader,
        CredentialFrameError::Oversized => BridgeErrorCode::CredentialOversized,
        CredentialFrameError::Empty => BridgeErrorCode::CredentialEmpty,
        CredentialFrameError::InvalidUtf8 => BridgeErrorCode::CredentialInvalidUtf8,
    };
    BridgeError::new(code)
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
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
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
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
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
fn cleanup_cgroup(
    cgroup: &mut fcp_sandbox::RequestCgroup,
    request_deadline_at: std::time::Instant,
) -> Result<(), BridgeError> {
    let kill_result = cgroup.abort_empty_until(fcp_async_core::Deadline::at(request_deadline_at));
    let kill_evidence = kill_result.ok();
    let remove_result = cgroup.remove_empty();
    if kill_evidence.is_none_or(|evidence| !evidence.kill_requested() || !evidence.populated_zero())
        || remove_result.is_err()
    {
        return Err(BridgeError::new(BridgeErrorCode::TeardownFailed));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup(
    process: &mut fcp_sandbox::OwnedProcess,
    cgroup: &mut fcp_sandbox::RequestCgroup,
    cancel: &std::sync::atomic::AtomicBool,
    mut workers: Vec<WorkerRecord>,
    request_deadline_at: std::time::Instant,
) -> Result<fcp_sandbox::TerminationReport, BridgeError> {
    use std::sync::atomic::Ordering;

    cancel.store(true, Ordering::Relaxed);
    let cgroup_kill = cgroup.kill_until(fcp_async_core::Deadline::at(request_deadline_at));
    let termination = process.terminate_until(fcp_async_core::Deadline::at(request_deadline_at));
    let cgroup_remove = cgroup.remove_empty();
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
    if cgroup_kill.is_err() || cgroup_remove.is_err() {
        return Err(BridgeError::new(BridgeErrorCode::TeardownFailed));
    }
    let cgroup_evidence =
        cgroup_kill.map_err(|_| BridgeError::new(BridgeErrorCode::TeardownFailed))?;
    if !cgroup_evidence.kill_requested() || !cgroup_evidence.populated_zero() {
        return Err(BridgeError::new(BridgeErrorCode::TeardownFailed));
    }
    let termination = termination.map_err(|_| BridgeError::new(BridgeErrorCode::TeardownFailed))?;
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
fn fail_empty_cgroup(
    cgroup: &mut fcp_sandbox::RequestCgroup,
    request_deadline_at: std::time::Instant,
    operation_error: BridgeError,
) -> BridgeError {
    cleanup_cgroup(cgroup, request_deadline_at)
        .err()
        .unwrap_or(operation_error)
}

#[cfg(target_os = "linux")]
fn fail_process(
    process: &mut fcp_sandbox::OwnedProcess,
    cgroup: &mut fcp_sandbox::RequestCgroup,
    cancel: &std::sync::atomic::AtomicBool,
    workers: Vec<WorkerRecord>,
    request_deadline_at: std::time::Instant,
    operation_error: BridgeError,
) -> BridgeError {
    cleanup(process, cgroup, cancel, workers, request_deadline_at)
        .err()
        .unwrap_or(operation_error)
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

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildFailureEnvelope {
    #[serde(rename = "type")]
    kind: String,
    error: ChildFailureDetail,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildFailureDetail {
    code: String,
}

#[cfg(target_os = "linux")]
fn child_failure_code(bytes: &[u8]) -> BridgeErrorCode {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let Ok(envelope) = ChildFailureEnvelope::deserialize(&mut deserializer) else {
        return BridgeErrorCode::ChildFailed;
    };
    if deserializer.end().is_err() || envelope.kind != "error" {
        return BridgeErrorCode::ChildFailed;
    }
    match envelope.error.code.as_str() {
        "connector_not_found" => BridgeErrorCode::HostConnectorNotFound,
        "invalid_input" => BridgeErrorCode::HostInvalidInput,
        "preflight_denied" => BridgeErrorCode::HostPreflightDenied,
        "connector_unavailable" => BridgeErrorCode::HostConnectorUnavailable,
        "connector_frame_limit" => BridgeErrorCode::HostConnectorFrameLimit,
        "internal" => BridgeErrorCode::HostInternal,
        "n8n_input_failed" => BridgeErrorCode::HostN8nInputFailed,
        "n8n_config_failed" => BridgeErrorCode::HostN8nConfigFailed,
        "n8n_plan_failed" => BridgeErrorCode::HostN8nPlanFailed,
        "n8n_credential_failed" => BridgeErrorCode::HostN8nCredentialFailed,
        "n8n_policy_failed" => BridgeErrorCode::HostN8nPolicyFailed,
        "n8n_runtime_state_failed" => BridgeErrorCode::HostN8nRuntimeStateFailed,
        "n8n_manifest_failed" => BridgeErrorCode::HostN8nManifestFailed,
        "n8n_capability_failed" => BridgeErrorCode::HostN8nCapabilityFailed,
        "n8n_invoke_failed" => BridgeErrorCode::HostN8nInvokeFailed,
        _ => BridgeErrorCode::ChildFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn official_mcp_has_a_scoped_larger_host_output_limit() {
        assert_eq!(
            max_output_bytes(crate::HostRunOnceOperation::CapabilitiesInspect),
            MAX_OFFICIAL_MCP_OUTPUT_BYTES
        );
        assert_eq!(
            max_output_bytes(crate::HostRunOnceOperation::WorkflowsList),
            MAX_OUTPUT_BYTES
        );
    }
    use crate::HostRunOnceOperation;

    #[cfg(target_os = "linux")]
    #[test]
    fn production_spec_has_only_fixed_host_controls() {
        use std::ffi::OsString;
        use std::path::PathBuf;

        let bundle = VerifiedBundle::test_fixture();
        let bundle_debug = format!("{bundle:?}");
        assert!(!bundle_debug.contains("/release"));
        assert!(!bundle_debug.contains(&"a".repeat(64)));
        let spec = process_spec(
            &bundle,
            HostRunOnceServerId::Eec,
            HostRunOnceOperation::WorkflowsGet,
        )
        .expect("EEC spec");
        assert_eq!(spec.launcher_path, PathBuf::from("/release/bin/fcp-host"));
        assert_eq!(spec.runtime_executable, spec.launcher_path);
        assert_eq!(spec.launcher_digest, "a".repeat(64));
        assert_eq!(spec.expected_runtime_executable_digest, "a".repeat(64));
        assert_eq!(
            spec.fixed_args,
            vec![OsString::from("n8n-run-once-supervised")]
        );
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

        let hetzner = process_spec(
            &bundle,
            HostRunOnceServerId::Hetzner,
            HostRunOnceOperation::WorkflowsGet,
        )
        .expect("Hetzner spec");
        assert_eq!(
            hetzner
                .fixed_env
                .get(&OsString::from("FCP_HOST_CONNECTORS_FILE")),
            Some(&OsString::from("/release/inventory/hetzner.json"))
        );

        let write = process_spec(
            &bundle,
            HostRunOnceServerId::Hetzner,
            HostRunOnceOperation::WorkflowsCreateDraft,
        )
        .expect("write spec");
        assert_eq!(
            write.fixed_args,
            vec![OsString::from("n8n-write-run-once-supervised")]
        );
        assert_eq!(
            write
                .fixed_env
                .get(&OsString::from("FCP_HOST_CONNECTORS_FILE")),
            Some(&OsString::from("/release/inventory/hetzner.json"))
        );
        assert_eq!(
            write
                .fixed_env
                .get(&OsString::from("FCP_HOST_OWNER_SINGLE_HOST_ADMISSION")),
            Some(&OsString::from(CREATE_DRAFT_OWNER_ADMISSION))
        );
        let admission: Value = serde_json::from_str(CREATE_DRAFT_OWNER_ADMISSION)
            .expect("fixed owner admission must remain valid JSON");
        assert_eq!(admission["version"], 1);
        assert_eq!(admission["mode"], "owner-approved-single-host");
        assert_eq!(admission["zone_id"], "z:work");
        assert_eq!(admission["connector_id"], "fcp.n8n");
        assert_eq!(admission["operation"], "n8n.workflows.create_draft");

        let update = process_spec(
            &bundle,
            HostRunOnceServerId::Eec,
            HostRunOnceOperation::WorkflowsUpdateDraft,
        )
        .expect("update spec");
        assert_eq!(
            update
                .fixed_env
                .get(&OsString::from("FCP_HOST_OWNER_SINGLE_HOST_ADMISSION")),
            Some(&OsString::from(UPDATE_DRAFT_OWNER_ADMISSION))
        );

        let official = process_spec(
            &bundle,
            HostRunOnceServerId::Eec,
            HostRunOnceOperation::CapabilitiesInspect,
        )
        .expect("official MCP spec");
        assert_eq!(
            official.fixed_args,
            vec![OsString::from("n8n-official-mcp-run-once-supervised")]
        );
        assert_eq!(
            official
                .fixed_env
                .get(&OsString::from("FCP_HOST_CONNECTORS_FILE")),
            Some(&OsString::from("/release/inventory/eec-official-mcp.json"))
        );
        assert!(
            official
                .fixed_env
                .get(&OsString::from("FCP_HOST_OWNER_SINGLE_HOST_ADMISSION"))
                .is_none()
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
    fn child_failure_exposes_only_exact_allowlisted_host_error_codes() {
        let cases = [
            ("connector_not_found", "host_connector_not_found"),
            ("invalid_input", "host_invalid_input"),
            ("preflight_denied", "host_preflight_denied"),
            ("connector_unavailable", "host_connector_unavailable"),
            ("connector_frame_limit", "host_connector_frame_limit"),
            ("internal", "host_internal"),
            ("n8n_input_failed", "host_n8n_input_failed"),
            ("n8n_config_failed", "host_n8n_config_failed"),
            ("n8n_plan_failed", "host_n8n_plan_failed"),
            ("n8n_credential_failed", "host_n8n_credential_failed"),
            ("n8n_policy_failed", "host_n8n_policy_failed"),
            ("n8n_runtime_state_failed", "host_n8n_runtime_state_failed"),
            ("n8n_manifest_failed", "host_n8n_manifest_failed"),
            ("n8n_capability_failed", "host_n8n_capability_failed"),
            ("n8n_invoke_failed", "host_n8n_invoke_failed"),
        ];
        for (host_code, expected) in cases {
            let encoded = format!(r#"{{"type":"error","error":{{"code":"{host_code}"}}}}"#);
            assert_eq!(child_failure_code(encoded.as_bytes()).as_str(), expected);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_failure_rejects_unknown_or_contaminated_error_envelopes() {
        for encoded in [
            br#"{"type":"error","error":{"code":"PRIVATE-PROVIDER-TEXT"}}"#.as_slice(),
            br#"{"type":"error","error":{"code":"n8n_invoke_response_external_5xx_failed"}}"#,
            br#"{"type":"error","error":{"code":"preflight_denied","detail":"PRIVATE"}}"#,
            br#"{"type":"error","error":{"code":"preflight_denied"},"extra":true}"#,
            br#"{"type":"response","error":{"code":"preflight_denied"}}"#,
            br#"{"type":"error","error":{"code":"PRIVATE","code":"preflight_denied"}}"#,
            br#"{"type":"response","type":"error","error":{"code":"preflight_denied"}}"#,
            br#"{"type":"error","error":{"code":"PRIVATE"},"error":{"code":"preflight_denied"}}"#,
            br#"not-json"#,
        ] {
            assert_eq!(child_failure_code(encoded).as_str(), "child_failed");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_invoke_diagnostic_accepts_only_exact_allowlisted_lines() {
        let labels = [
            "dispatch_4xx",
            "dispatch_5xx",
            "dispatch_other",
            "response_protocol",
            "response_auth",
            "response_rate_limited",
            "response_capability",
            "response_zone",
            "response_connector",
            "response_resource",
            "response_external_4xx",
            "response_external_5xx",
            "response_external_other",
            "response_external_unknown",
            "response_upstream_timeout",
            "response_dependency_unavailable",
            "response_internal",
        ];
        for label in labels {
            let stderr = format!("untrusted noise\nFCP-N8N-INVOKE-DIAGNOSTIC/v1 {label}\n");
            assert_eq!(child_invoke_diagnostic(stderr.as_bytes()), Some(label));
        }

        for stderr in [
            b"FCP-N8N-INVOKE-DIAGNOSTIC/v1 PRIVATE".as_slice(),
            b"FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx PRIVATE",
            b"prefix FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx",
            b"FCP-N8N-INVOKE-DIAGNOSTIC/v2 response_external_5xx",
        ] {
            assert_eq!(child_invoke_diagnostic(stderr), None);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_external_provenance_accepts_only_exact_allowlisted_lines() {
        for label in [
            "external.provider_5xx",
            "external.host_proxy_rejected",
            "external.connector_egress_transport",
            "external.connector_egress_inherited_channel",
            "external.connector_egress_inherited_request_id",
            "external.connector_egress_inherited_poisoned",
            "external.connector_egress_inherited_write",
            "external.connector_egress_inherited_read",
            "external.connector_egress_inherited_read_eof",
            "external.connector_egress_inherited_frame",
            "external.connector_egress_inherited_json",
            "external.connector_egress_inherited_validation",
            "external.connector_egress_inherited_timeout",
            "external.connector_egress_request_too_large",
            "external.connector_egress_request_malformed",
            "external.connector_egress_response_too_large",
            "external.connector_egress_response_malformed",
        ] {
            let stderr =
                format!("untrusted noise\nFCP-N8N-EXTERNAL-PROVENANCE-DIAGNOSTIC/v1 {label}\n");
            assert_eq!(
                child_external_provenance_diagnostic(stderr.as_bytes()),
                Some(label)
            );
        }

        for stderr in [
            b"FCP-N8N-EXTERNAL-PROVENANCE-DIAGNOSTIC/v1 PRIVATE".as_slice(),
            b"FCP-N8N-EXTERNAL-PROVENANCE-DIAGNOSTIC/v1 external.provider_5xx PRIVATE",
            b"prefix FCP-N8N-EXTERNAL-PROVENANCE-DIAGNOSTIC/v1 external.provider_5xx",
            b"FCP-N8N-EXTERNAL-PROVENANCE-DIAGNOSTIC/v2 external.provider_5xx",
        ] {
            assert_eq!(child_external_provenance_diagnostic(stderr), None);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_host_error_diagnostic_accepts_only_normalized_classes() {
        for label in [
            "local.capability_denied",
            "local.validation",
            "local.policy_denied",
            "transport.host_connector",
            "transport.frame_limit",
            "internal.registry",
            "internal.cache",
            "internal.runtime",
        ] {
            let stderr = format!("FCP-N8N-HOST-ERROR-DIAGNOSTIC/v1 {label}\n");
            assert_eq!(child_host_error_diagnostic(stderr.as_bytes()), Some(label));
        }

        for stderr in [
            b"FCP-N8N-HOST-ERROR-DIAGNOSTIC/v1 PRIVATE".as_slice(),
            b"FCP-N8N-HOST-ERROR-DIAGNOSTIC/v1 internal PRIVATE",
            b"prefix FCP-N8N-HOST-ERROR-DIAGNOSTIC/v1 internal",
            b"FCP-N8N-HOST-ERROR-DIAGNOSTIC/v2 internal",
        ] {
            assert_eq!(child_host_error_diagnostic(stderr), None);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_owned_diagnostic_accepts_only_fixed_stages() {
        for label in [
            "owned.setup",
            "owned.launch.unsupported_platform",
            "owned.launch.invalid_spec",
            "owned.launch.io",
            "owned.launch.digest_mismatch",
            "owned.launch.identity_mismatch",
            "owned.launch.teardown",
            "owned.rpc_transport",
            "owned.rpc_protocol",
            "owned.rpc_child_error",
            "owned.response_protocol",
            "owned.egress_codec.read_error",
            "owned.egress_codec.read_eof",
            "owned.egress_codec.write_error",
            "owned.egress_codec.truncated",
            "owned.egress_codec.oversized",
            "owned.egress_codec.empty_frame",
            "owned.egress_codec.invalid_utf8",
            "owned.egress_codec.invalid_json",
            "owned.egress_codec.wrong_schema",
            "owned.egress_codec.wrong_auth",
            "owned.egress_codec.wrong_route_payload",
            "owned.egress_codec.wrong_request_id",
            "owned.egress_codec.invalid_response",
            "owned.egress_codec.invalid_auth_token",
            "owned.egress_codec.missing_request",
            "owned.teardown",
        ] {
            let stderr = format!("FCP-N8N-OWNED-DIAGNOSTIC/v1 {label}\n");
            assert_eq!(child_owned_diagnostics(stderr.as_bytes()), vec![label]);
        }

        for stderr in [
            b"FCP-N8N-OWNED-DIAGNOSTIC/v1 PRIVATE".as_slice(),
            b"FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.launch",
            b"FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.rpc_child_error PRIVATE",
            b"prefix FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.rpc_child_error",
            b"FCP-N8N-OWNED-DIAGNOSTIC/v2 owned.rpc_child_error",
        ] {
            assert!(child_owned_diagnostics(stderr).is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_owned_diagnostics_preserve_bounded_distinct_order() {
        let stderr = b"FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.egress_codec.read_eof\n\
FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.launch.io\n\
FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.rpc_child_error\n\
FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.egress_codec.read_eof\n\
FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.response_protocol\n\
FCP-N8N-OWNED-DIAGNOSTIC/v1 owned.teardown\n";
        assert_eq!(
            child_owned_diagnostics(stderr),
            vec![
                "owned.egress_codec.read_eof",
                "owned.launch.io",
                "owned.rpc_child_error",
                "owned.response_protocol",
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_error_diagnostic_accepts_only_fixed_families() {
        for label in [
            "child.protocol",
            "child.auth",
            "child.capability",
            "child.zone",
            "child.connector",
            "child.resource",
            "child.external",
            "child.internal",
            "child.unknown",
        ] {
            let stderr = format!("FCP-N8N-CHILD-ERROR-DIAGNOSTIC/v1 {label}\n");
            assert_eq!(child_child_error_diagnostic(stderr.as_bytes()), Some(label));
        }
        for stderr in [
            b"FCP-N8N-CHILD-ERROR-DIAGNOSTIC/v1 PRIVATE".as_slice(),
            b"FCP-N8N-CHILD-ERROR-DIAGNOSTIC/v1 child.external PRIVATE",
            b"prefix FCP-N8N-CHILD-ERROR-DIAGNOSTIC/v1 child.external",
            b"FCP-N8N-CHILD-ERROR-DIAGNOSTIC/v2 child.external",
        ] {
            assert_eq!(child_child_error_diagnostic(stderr), None);
        }
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
    fn supervisor_start_frame_is_exact_and_bounded() {
        use std::time::Instant;

        let frame = supervisor_start_frame(Instant::now() + Duration::from_millis(250))
            .expect("start frame within budget");
        assert_eq!(
            &frame[..SUPERVISOR_START_PREFIX.len()],
            SUPERVISOR_START_PREFIX
        );
        let budget = u32::from_be_bytes(
            frame[SUPERVISOR_START_PREFIX.len()..]
                .try_into()
                .expect("fixed budget suffix"),
        );
        assert!((1..=u32::try_from(SUPERVISOR_MAX_BUDGET_MS).expect("max fits")).contains(&budget));
        let clamped = supervisor_start_frame(Instant::now() + Duration::from_secs(120))
            .expect("large deadline clamps");
        assert_eq!(
            u32::from_be_bytes(
                clamped[SUPERVISOR_START_PREFIX.len()..]
                    .try_into()
                    .expect("fixed budget suffix")
            ),
            u32::try_from(SUPERVISOR_MAX_BUDGET_MS).expect("max fits")
        );
        assert!(supervisor_start_frame(Instant::now()).is_err());
    }

    #[cfg(target_os = "linux")]
    fn read_ready_payload(payload: &[u8]) -> Result<(), BridgeError> {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::time::Instant;

        let (mut peer, mut stream) = UnixStream::pair().expect("supervisor socketpair");
        peer.write_all(payload).expect("write ready fixture");
        drop(peer);
        let mut ready = [0_u8; SUPERVISOR_READY_FRAME.len()];
        read_supervisor_control_exact(
            &mut stream,
            &mut ready,
            Instant::now() + Duration::from_secs(1),
        )?;
        if ready != SUPERVISOR_READY_FRAME {
            return Err(supervisor_control_error());
        }
        reject_queued_supervisor_control_bytes(&mut stream)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supervisor_ready_parser_rejects_malformed_short_eof_and_trailing() {
        let mut short = SUPERVISOR_READY_FRAME.to_vec();
        short.pop();
        let mut trailing = SUPERVISOR_READY_FRAME.to_vec();
        trailing.push(b'!');
        assert!(read_ready_payload(SUPERVISOR_READY_FRAME).is_ok());
        assert!(read_ready_payload(&short).is_err());
        assert!(read_ready_payload(b"").is_err());
        assert!(read_ready_payload(b"FCP-HOST-RUN-ONCE/v1/REJECT").is_err());
        assert!(read_ready_payload(&trailing).is_err());
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
