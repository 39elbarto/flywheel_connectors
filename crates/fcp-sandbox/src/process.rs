//! Exact Linux process-group ownership for request-scoped providers.
//!
//! This module deliberately has no name-based process lookup. A launch records
//! the PID, PGID, `/proc` start time, runtime executable, and runtime digest.
//! Signals are sent only after the complete identity is revalidated.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

/// A trusted launch description. The caller must obtain all values from fixed
/// policy; model input is never accepted here.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub launcher_path: PathBuf,
    pub launcher_digest: String,
    pub runtime_executable: PathBuf,
    pub expected_runtime_executable_digest: String,
    pub fixed_args: Vec<OsString>,
    pub fixed_env: BTreeMap<OsString, OsString>,
    pub network_disabled: bool,
}

/// Reserved child environment name for the inherited host-egress channel.
#[cfg(target_os = "linux")]
pub const FCP_HOST_EGRESS_FD: &str = "FCP_HOST_EGRESS_FD";

/// Fixed transport marker for the host run-once credential channel.
#[cfg(target_os = "linux")]
pub const FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT: &str = "FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT";
/// Reserved child environment name for the host run-once credential channel.
#[cfg(target_os = "linux")]
pub const FCP_HOST_RUN_ONCE_CREDENTIAL_FD: &str = "FCP_HOST_RUN_ONCE_CREDENTIAL_FD";
/// Only supported host run-once credential transport.
#[cfg(target_os = "linux")]
pub const FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT_VALUE: &str = "inherited-fd-v1";

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
enum InheritedChannelKind {
    HostEgress,
    RunOnceCredential,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct InheritedChannel {
    fd: RawFd,
    kind: InheritedChannelKind,
}

/// Identity captured at launch and required for every later signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub pgid: i32,
    pub session_id: i32,
    pub start_time_ticks: u64,
    pub runtime_executable: PathBuf,
    pub runtime_executable_digest: String,
}

/// Aggregated memory for the currently owned process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMemorySample {
    /// True when the sample was obtained from a verified process-group scan.
    /// A true zero count is therefore distinct from an unavailable sample.
    pub available: bool,
    pub process_count: u32,
    pub rss_bytes: Option<u64>,
    pub pss_bytes: Option<u64>,
    pub private_bytes: Option<u64>,
}

/// Result of the bounded TERM/KILL/reap sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminationReport {
    pub term_sent: bool,
    pub kill_sent: bool,
    pub reaped: bool,
    pub group_absent: bool,
}

/// Errors from exact process-group launch and teardown.
#[derive(Debug, thiserror::Error)]
pub enum ProcessGroupError {
    #[error("local provider process groups are unsupported on this platform")]
    UnsupportedPlatform,
    #[error("invalid local provider process specification")]
    InvalidSpec,
    #[error("local provider process I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("local provider launcher digest mismatch")]
    LauncherDigestMismatch,
    #[error("local provider runtime process identity mismatch")]
    IdentityMismatch,
    #[error("local provider process group did not stop before deadline")]
    TeardownTimeout,
    #[error("local provider process teardown is already terminal; retry disabled")]
    TeardownTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TeardownState {
    Active,
    TerminalFailure,
}

/// A spawned Linux process with owned stdio and exact group identity.
#[derive(Debug)]
pub struct OwnedProcess {
    child: Option<std::process::Child>,
    identity: ProcessIdentity,
    reaped: bool,
    term_sent: bool,
    kill_sent: bool,
    teardown_state: TeardownState,
}

impl OwnedProcess {
    /// Spawn one new session/process group with the supplied fixed policy.
    pub fn spawn(spec: &ProcessSpec) -> Result<Self, ProcessGroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = spec;
            return Err(ProcessGroupError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            Self::spawn_linux(spec, None, None)
        }
    }

    /// Spawn a Linux process with one host-owned, already-connected egress channel.
    ///
    /// The channel is passed by its current descriptor number through the fixed
    /// [`FCP_HOST_EGRESS_FD`] environment variable. No descriptor is duplicated
    /// to a caller-selected number, and all other descriptors are marked
    /// close-on-exec in the child before this channel is made inheritable.
    #[cfg(target_os = "linux")]
    pub fn spawn_with_host_egress_channel(
        spec: &ProcessSpec,
        child_endpoint: UnixStream,
    ) -> Result<Self, ProcessGroupError> {
        if !spec.network_disabled {
            return Err(ProcessGroupError::InvalidSpec);
        }
        if has_reserved_inherited_channel_env(spec) {
            return Err(ProcessGroupError::InvalidSpec);
        }
        let channel_fd = validate_host_egress_channel(&child_endpoint)?;
        let result = Self::spawn_linux(
            spec,
            Some(InheritedChannel {
                fd: channel_fd,
                kind: InheritedChannelKind::HostEgress,
            }),
            None,
        );
        drop(child_endpoint);
        result
    }

    /// Spawn a Linux host process with one inherited run-once credential channel.
    ///
    /// The transport name and descriptor environment variables are fixed by
    /// this API. The caller supplies only an already-connected Unix stream;
    /// every other inherited descriptor is marked close-on-exec before the
    /// selected channel is made inheritable. This is intentionally a
    /// network-enabled host launch: the caller must pin the exact `fcp-host`
    /// artifact and fixed one-shot arguments. Network-denied connector children
    /// continue to use [`Self::spawn_with_host_egress_channel`].
    #[cfg(target_os = "linux")]
    pub fn spawn_with_run_once_credential_channel(
        spec: &ProcessSpec,
        child_endpoint: UnixStream,
    ) -> Result<Self, ProcessGroupError> {
        if spec.network_disabled || has_reserved_inherited_channel_env(spec) {
            return Err(ProcessGroupError::InvalidSpec);
        }
        let channel_fd = validate_host_egress_channel(&child_endpoint)?;
        let result = Self::spawn_linux(
            spec,
            Some(InheritedChannel {
                fd: channel_fd,
                kind: InheritedChannelKind::RunOnceCredential,
            }),
            None,
        );
        drop(child_endpoint);
        result
    }

    /// Spawn a host run-once process with one trusted, fixed working directory.
    ///
    /// The directory must already be absolute, canonical, and a non-symlink
    /// directory.  This narrow variant exists so one-shot hosts cannot inherit
    /// a caller's cwd and accidentally read or write cwd-relative state.
    #[cfg(target_os = "linux")]
    pub fn spawn_with_run_once_credential_channel_in_directory(
        spec: &ProcessSpec,
        child_endpoint: UnixStream,
        working_directory: &Path,
    ) -> Result<Self, ProcessGroupError> {
        if spec.network_disabled || has_reserved_inherited_channel_env(spec) {
            return Err(ProcessGroupError::InvalidSpec);
        }
        let working_directory = validate_working_directory(working_directory)?;
        let channel_fd = validate_host_egress_channel(&child_endpoint)?;
        let result = Self::spawn_linux(
            spec,
            Some(InheritedChannel {
                fd: channel_fd,
                kind: InheritedChannelKind::RunOnceCredential,
            }),
            Some(&working_directory),
        );
        drop(child_endpoint);
        result
    }

    #[cfg(target_os = "linux")]
    fn spawn_linux(
        spec: &ProcessSpec,
        inherited_channel: Option<InheritedChannel>,
        working_directory: Option<&Path>,
    ) -> Result<Self, ProcessGroupError> {
        if !spec.launcher_path.is_absolute()
            || !spec.runtime_executable.is_absolute()
            || spec.launcher_digest.len() != 64
            || spec
                .launcher_digest
                .chars()
                .any(|ch| !ch.is_ascii_hexdigit() || ch.is_ascii_uppercase())
            || spec.expected_runtime_executable_digest.len() != 64
            || spec
                .expected_runtime_executable_digest
                .chars()
                .any(|ch| !ch.is_ascii_hexdigit() || ch.is_ascii_uppercase())
        {
            return Err(ProcessGroupError::InvalidSpec);
        }
        if digest_file(&spec.launcher_path)? != spec.launcher_digest {
            return Err(ProcessGroupError::LauncherDigestMismatch);
        }

        use std::os::unix::process::CommandExt;

        let network_disabled = spec.network_disabled;
        let mut command = Command::new(&spec.launcher_path);
        command
            .args(&spec.fixed_args)
            .env_clear()
            .envs(&spec.fixed_env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(working_directory) = working_directory {
            command.current_dir(working_directory);
        }
        configure_inherited_channel_environment(&mut command, inherited_channel);

        // SAFETY: the closure runs in the child between fork and exec and
        // performs only async-signal-safe libc calls. It captures no Rust
        // allocation that is mutated in the child.
        unsafe {
            command.pre_exec(move || {
                if let Some(channel) = inherited_channel {
                    mark_fds_cloexec_from_three()?;
                    clear_fd_cloexec(channel.fd)?;
                }
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if network_disabled {
                    install_network_deny_filter()?;
                }
                Ok(())
            });
        }

        let mut child = command.spawn()?;
        let pid = child.id();
        let identity = match read_identity(
            pid,
            &spec.runtime_executable,
            &spec.expected_runtime_executable_digest,
        ) {
            Ok(identity) => identity,
            Err(error) => {
                if let Ok(actual) = read_identity_unchecked(pid) {
                    let mut owned = Self {
                        child: Some(child),
                        identity: actual,
                        reaped: false,
                        term_sent: false,
                        kill_sent: false,
                        teardown_state: TeardownState::Active,
                    };
                    let _ = owned.terminate(Duration::from_secs(1));
                } else {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                return Err(match error {
                    ProcessGroupError::Io(_) => ProcessGroupError::IdentityMismatch,
                    other => other,
                });
            }
        };
        if identity.pgid != i32::try_from(pid).unwrap_or(i32::MAX) {
            let mut owned = Self {
                child: Some(child),
                identity,
                reaped: false,
                term_sent: false,
                kill_sent: false,
                teardown_state: TeardownState::Active,
            };
            let _ = owned.terminate(Duration::from_secs(1));
            return Err(ProcessGroupError::IdentityMismatch);
        }
        Ok(Self {
            child: Some(child),
            identity,
            reaped: false,
            term_sent: false,
            kill_sent: false,
            teardown_state: TeardownState::Active,
        })
    }

    /// Return the immutable launch identity.
    #[must_use]
    pub const fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Take the provider stdin pipe.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut()?.stdin.take()
    }

    /// Take the provider stdout pipe.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    /// Take the provider stderr pipe.
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.as_mut()?.stderr.take()
    }

    /// Prevent `Drop` from retrying termination after ownership verification
    /// has failed. The caller must have already taken the stdio handles and
    /// must report that the process group was not proven absent.
    pub fn abandon(&mut self) {
        self.child.take();
    }

    /// Poll the direct child without changing group ownership.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, ProcessGroupError> {
        if self.reaped {
            return Ok(None);
        }
        let result = self
            .child
            .as_mut()
            .ok_or(ProcessGroupError::IdentityMismatch)?
            .try_wait()
            .map_err(ProcessGroupError::Io)?;
        if result.is_some() {
            self.reaped = true;
        }
        Ok(result)
    }

    /// Reap the direct child. Descendants are handled by [`Self::terminate`].
    pub fn wait(&mut self) -> Result<ExitStatus, ProcessGroupError> {
        if self.reaped {
            return Err(ProcessGroupError::IdentityMismatch);
        }
        let status = self
            .child
            .as_mut()
            .ok_or(ProcessGroupError::IdentityMismatch)?
            .wait()
            .map_err(ProcessGroupError::Io)?;
        self.reaped = true;
        Ok(status)
    }

    /// Wait for the owned direct child to exit without sending any signal.
    ///
    /// This is safe after a runtime identity mismatch because `try_wait` uses
    /// the parent-owned child handle, not a PID or process-group lookup. It
    /// deliberately says nothing about descendants or process-group absence.
    pub fn reap_direct_child_until(
        &mut self,
        timeout: Duration,
    ) -> Result<bool, ProcessGroupError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.reap_if_needed()? {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }

    /// Return the lifecycle evidence accumulated for this owned child.
    ///
    /// `group_absent` is supplied by the caller because reaping the direct
    /// child alone does not prove that every descendant has exited.
    #[must_use]
    pub const fn termination_report(&self, group_absent: bool) -> TerminationReport {
        TerminationReport {
            term_sent: self.term_sent,
            kill_sent: self.kill_sent,
            reaped: self.reaped,
            group_absent,
        }
    }

    /// Verify the recorded PID, PGID, start time, runtime executable and digest.
    pub fn verify_identity(&self) -> Result<(), ProcessGroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(ProcessGroupError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            let current = read_identity(
                self.identity.pid,
                &self.identity.runtime_executable,
                &self.identity.runtime_executable_digest,
            )
            .map_err(|_| ProcessGroupError::IdentityMismatch)?;
            if current == self.identity {
                Ok(())
            } else {
                Err(ProcessGroupError::IdentityMismatch)
            }
        }
    }

    /// Sample the verified process group. Missing PSS/private data is explicit.
    pub fn memory_sample(&self) -> Result<ProcessMemorySample, ProcessGroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(ProcessGroupError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            let processes = self.verified_group_members()?;
            if processes.is_empty() {
                return Ok(ProcessMemorySample {
                    available: true,
                    process_count: 0,
                    rss_bytes: Some(0),
                    pss_bytes: Some(0),
                    private_bytes: Some(0),
                });
            }

            let mut rss = 0_u64;
            let mut pss = 0_u64;
            let mut private = 0_u64;
            let mut pss_complete = true;
            let mut private_complete = true;
            for process in &processes {
                let status = std::fs::read_to_string(format!("/proc/{}/status", process.pid))?;
                rss = rss.saturating_add(parse_kib_field(&status, "VmRSS:")?);
                match std::fs::read_to_string(format!("/proc/{}/smaps_rollup", process.pid)) {
                    Ok(smaps) => {
                        pss = pss.saturating_add(parse_kib_field(&smaps, "Pss:")?);
                        private = private
                            .saturating_add(parse_kib_field(&smaps, "Private_Clean:")?)
                            .saturating_add(parse_kib_field(&smaps, "Private_Dirty:")?)
                            .saturating_add(parse_kib_field(&smaps, "Private_Hugetlb:")?);
                    }
                    Err(_) => {
                        pss_complete = false;
                        private_complete = false;
                    }
                }
            }
            Ok(ProcessMemorySample {
                available: true,
                process_count: u32::try_from(processes.len()).unwrap_or(u32::MAX),
                rss_bytes: Some(rss.saturating_mul(1024)),
                pss_bytes: pss_complete.then_some(pss.saturating_mul(1024)),
                private_bytes: private_complete.then_some(private.saturating_mul(1024)),
            })
        }
    }

    /// Send SIGTERM, wait for the whole owned group, then use SIGKILL only
    /// after a second complete identity check.
    pub fn terminate(&mut self, grace: Duration) -> Result<TerminationReport, ProcessGroupError> {
        if self.teardown_state == TeardownState::TerminalFailure {
            return Err(ProcessGroupError::TeardownTerminal);
        }
        let result = self.terminate_inner(grace);
        if result.is_err() {
            self.teardown_state = TeardownState::TerminalFailure;
        }
        result
    }

    fn terminate_inner(&mut self, grace: Duration) -> Result<TerminationReport, ProcessGroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = grace;
            return Err(ProcessGroupError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            let _ = self.reap_if_needed();
            if self.verified_group_members()?.is_empty() {
                let _ = self.reap_if_needed()?;
                return Ok(self.termination_report(true));
            }
            let term_sent = self.send_verified_group_signal(libc::SIGTERM)?;
            self.term_sent |= term_sent;
            let term_deadline = Instant::now() + grace;
            while Instant::now() < term_deadline {
                let _ = self.try_wait();
                if self.verified_group_members()?.is_empty() {
                    let _ = self.reap_if_needed()?;
                    return Ok(self.termination_report(true));
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            let kill_sent = self.send_verified_group_signal(libc::SIGKILL)?;
            self.kill_sent |= kill_sent;
            let kill_deadline = Instant::now() + grace;
            while Instant::now() < kill_deadline {
                let _ = self.try_wait();
                if self.verified_group_members()?.is_empty() {
                    let _ = self.reap_if_needed()?;
                    return Ok(self.termination_report(true));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(ProcessGroupError::TeardownTimeout)
        }
    }

    fn reap_if_needed(&mut self) -> Result<bool, ProcessGroupError> {
        if self.reaped {
            return Ok(true);
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(true);
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.reaped = true;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => Err(ProcessGroupError::Io(error)),
        }
    }

    fn verified_group_members(&self) -> Result<Vec<ProcSnapshot>, ProcessGroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(ProcessGroupError::UnsupportedPlatform)
        }

        #[cfg(target_os = "linux")]
        {
            let members = group_processes(self.identity.pgid)?;
            if members.is_empty() {
                if std::path::Path::new(&format!("/proc/{}", self.identity.pid)).exists() {
                    let current = read_identity(
                        self.identity.pid,
                        &self.identity.runtime_executable,
                        &self.identity.runtime_executable_digest,
                    )
                    .map_err(|_| ProcessGroupError::IdentityMismatch)?;
                    if current != self.identity {
                        return Err(ProcessGroupError::IdentityMismatch);
                    }
                }
                return Ok(members);
            }

            let leader = members
                .iter()
                .find(|member| member.pid == self.identity.pid);
            if let Some(leader) = leader {
                if leader.pgid != self.identity.pgid
                    || leader.session_id != self.identity.session_id
                    || leader.start_time_ticks != self.identity.start_time_ticks
                {
                    return Err(ProcessGroupError::IdentityMismatch);
                }
                // A zombie still owns its PID and immutable launch identity,
                // but Linux no longer exposes `/proc/<pid>/exe`. Requiring the
                // executable link during this normal teardown transition turns
                // a successfully signalled child into an identity mismatch.
                // Live leaders retain the full executable and digest check.
                if leader.state != b'Z' {
                    let current = read_identity(
                        self.identity.pid,
                        &self.identity.runtime_executable,
                        &self.identity.runtime_executable_digest,
                    )
                    .map_err(|_| ProcessGroupError::IdentityMismatch)?;
                    if current != self.identity {
                        return Err(ProcessGroupError::IdentityMismatch);
                    }
                }
            }

            let expected_session = i32::try_from(self.identity.pid)
                .map_err(|_| ProcessGroupError::IdentityMismatch)?;
            if members.iter().any(|member| {
                member.pgid != self.identity.pgid
                    || member.session_id != expected_session
                    || member.start_time_ticks < self.identity.start_time_ticks
            }) {
                return Err(ProcessGroupError::IdentityMismatch);
            }
            Ok(members)
        }
    }

    #[cfg(target_os = "linux")]
    fn send_verified_group_signal(&self, signal: i32) -> Result<bool, ProcessGroupError> {
        if self.identity.pgid <= 1 {
            return Err(ProcessGroupError::InvalidSpec);
        }
        if self.verified_group_members()?.is_empty() {
            return Ok(false);
        }
        self.verified_group_members()?;
        if unsafe { libc::kill(-self.identity.pgid, signal) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH)
                && self.verified_group_members()?.is_empty()
            {
                return Ok(false);
            }
            return Err(ProcessGroupError::Io(error));
        }
        Ok(true)
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if self.child.is_some() && self.teardown_state == TeardownState::Active {
            let _ = self.terminate(Duration::from_secs(1));
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct ProcSnapshot {
    pid: u32,
    state: u8,
    pgid: i32,
    session_id: i32,
    start_time_ticks: u64,
}

#[cfg(target_os = "linux")]
fn configure_inherited_channel_environment(
    command: &mut Command,
    inherited_channel: Option<InheritedChannel>,
) {
    let Some(channel) = inherited_channel else {
        return;
    };
    match channel.kind {
        InheritedChannelKind::HostEgress => {
            command.env(FCP_HOST_EGRESS_FD, channel.fd.to_string());
        }
        InheritedChannelKind::RunOnceCredential => {
            command.env(
                FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT,
                FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT_VALUE,
            );
            command.env(FCP_HOST_RUN_ONCE_CREDENTIAL_FD, channel.fd.to_string());
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_working_directory(path: &Path) -> Result<PathBuf, ProcessGroupError> {
    if !path.is_absolute() {
        return Err(ProcessGroupError::InvalidSpec);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(ProcessGroupError::Io)?;
    if !metadata.file_type().is_dir() {
        return Err(ProcessGroupError::InvalidSpec);
    }
    let canonical = std::fs::canonicalize(path).map_err(ProcessGroupError::Io)?;
    if canonical != path {
        return Err(ProcessGroupError::InvalidSpec);
    }
    Ok(canonical)
}

/// Mark one owned Unix pipe/socket descriptor nonblocking.
#[cfg(target_os = "linux")]
pub fn set_nonblocking<F: std::os::fd::AsFd>(source: &F) -> Result<(), ProcessGroupError> {
    use std::os::fd::AsRawFd;

    let fd = source.as_fd().as_raw_fd();
    // SAFETY: `fd` is borrowed from the caller-owned descriptor and both
    // operations are confined to fcntl's integer flag interface.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(ProcessGroupError::Io(std::io::Error::last_os_error()));
    }
    if flags & libc::O_NONBLOCK != 0 {
        return Ok(());
    }
    // SAFETY: the descriptor remains borrowed for the duration of this call.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ProcessGroupError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_identity(
    pid: u32,
    expected_executable: &Path,
    expected_digest: &str,
) -> Result<ProcessIdentity, ProcessGroupError> {
    let identity = read_identity_unchecked(pid)?;
    let expected = std::fs::canonicalize(expected_executable)?;
    if identity.runtime_executable != expected
        || identity.runtime_executable_digest != expected_digest
    {
        return Err(ProcessGroupError::IdentityMismatch);
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn read_identity_unchecked(pid: u32) -> Result<ProcessIdentity, ProcessGroupError> {
    let stat = read_proc_stat(pid)?;
    let executable_link = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    let executable = std::fs::canonicalize(executable_link)?;
    Ok(ProcessIdentity {
        pid,
        pgid: stat.pgid,
        session_id: stat.session_id,
        start_time_ticks: stat.start_time_ticks,
        runtime_executable: executable.clone(),
        runtime_executable_digest: digest_file(&executable)?,
    })
}

#[cfg(target_os = "linux")]
fn read_proc_stat(pid: u32) -> Result<ProcSnapshot, ProcessGroupError> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = contents
        .rfind(')')
        .ok_or(ProcessGroupError::IdentityMismatch)?;
    let fields: Vec<&str> = contents[close + 2..].split_whitespace().collect();
    let state = fields
        .first()
        .filter(|value| value.len() == 1)
        .and_then(|value| value.as_bytes().first())
        .copied()
        .ok_or(ProcessGroupError::IdentityMismatch)?;
    let pgid = fields
        .get(2)
        .ok_or(ProcessGroupError::IdentityMismatch)?
        .parse::<i32>()
        .map_err(|_| ProcessGroupError::IdentityMismatch)?;
    let session_id = fields
        .get(3)
        .ok_or(ProcessGroupError::IdentityMismatch)?
        .parse::<i32>()
        .map_err(|_| ProcessGroupError::IdentityMismatch)?;
    let start_time_ticks = fields
        .get(19)
        .ok_or(ProcessGroupError::IdentityMismatch)?
        .parse::<u64>()
        .map_err(|_| ProcessGroupError::IdentityMismatch)?;
    Ok(ProcSnapshot {
        pid,
        state,
        pgid,
        session_id,
        start_time_ticks,
    })
}

#[cfg(target_os = "linux")]
fn group_processes(pgid: i32) -> Result<Vec<ProcSnapshot>, ProcessGroupError> {
    let mut processes = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        if let Ok(snapshot) = read_proc_stat(pid) {
            if snapshot.pgid == pgid {
                processes.push(snapshot);
            }
        }
    }
    Ok(processes)
}

/// Return whether an owned process group currently has no visible members.
pub fn process_group_absent(pgid: i32) -> Result<bool, ProcessGroupError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pgid;
        Err(ProcessGroupError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    {
        Ok(group_processes(pgid)?.is_empty())
    }
}

#[cfg(target_os = "linux")]
fn parse_kib_field(contents: &str, field: &str) -> Result<u64, ProcessGroupError> {
    let line = contents
        .lines()
        .find(|line| line.starts_with(field))
        .ok_or(ProcessGroupError::IdentityMismatch)?;
    line.split_whitespace()
        .nth(1)
        .ok_or(ProcessGroupError::IdentityMismatch)
        .and_then(|value| {
            value
                .parse::<u64>()
                .map_err(|_| ProcessGroupError::IdentityMismatch)
        })
}

#[cfg(target_os = "linux")]
/// Claim one inherited, connected Unix stream descriptor for connector use.
///
/// The descriptor is validated while borrowed, then consumed exactly once.
/// The returned stream owns a close-on-exec duplicate; the launcher's original
/// descriptor is closed before this function returns. Unsafe ownership and OS
/// checks stay contained in this sandbox crate's explicitly allowed layer.
pub fn claim_inherited_host_egress_channel(fd: RawFd) -> Result<UnixStream, ProcessGroupError> {
    if fd < 3 {
        return Err(ProcessGroupError::InvalidSpec);
    }

    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(ProcessGroupError::Io(std::io::Error::last_os_error()));
    }

    let mut domain: libc::c_int = 0;
    let mut domain_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let domain_result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&mut domain as *mut libc::c_int).cast(),
            &mut domain_len,
        )
    };
    if domain_result != 0
        || domain_len != std::mem::size_of::<libc::c_int>() as libc::socklen_t
        || domain != libc::AF_UNIX
    {
        return Err(ProcessGroupError::InvalidSpec);
    }

    let mut socket_type: libc::c_int = 0;
    let mut socket_type_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let socket_type_result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut socket_type_len,
        )
    };
    if socket_type_result != 0
        || socket_type_len != std::mem::size_of::<libc::c_int>() as libc::socklen_t
        || socket_type != libc::SOCK_STREAM
    {
        return Err(ProcessGroupError::InvalidSpec);
    }

    let mut peer_address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut peer_address_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let peer_result = unsafe {
        libc::getpeername(
            fd,
            (&mut peer_address as *mut libc::sockaddr_storage).cast(),
            &mut peer_address_len,
        )
    };
    if peer_result != 0 || peer_address.ss_family != libc::AF_UNIX as libc::sa_family_t {
        return Err(ProcessGroupError::InvalidSpec);
    }

    // `F_DUPFD_CLOEXEC` is used by `OwnedFd::try_clone`; verify the returned
    // descriptor keeps that invariant before closing the launcher's original.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let cloexec = owned.try_clone().map_err(ProcessGroupError::Io)?;
    let cloexec_flags = unsafe { libc::fcntl(cloexec.as_raw_fd(), libc::F_GETFD) };
    if cloexec_flags < 0 {
        return Err(ProcessGroupError::Io(std::io::Error::last_os_error()));
    }
    if cloexec_flags & libc::FD_CLOEXEC == 0 {
        return Err(ProcessGroupError::InvalidSpec);
    }
    drop(owned);

    Ok(UnixStream::from(cloexec))
}

#[cfg(target_os = "linux")]
fn has_reserved_inherited_channel_env(spec: &ProcessSpec) -> bool {
    [
        FCP_HOST_EGRESS_FD,
        FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT,
        FCP_HOST_RUN_ONCE_CREDENTIAL_FD,
    ]
    .iter()
    .any(|key| spec.fixed_env.contains_key(std::ffi::OsStr::new(key)))
}

#[cfg(target_os = "linux")]
fn validate_host_egress_channel(stream: &UnixStream) -> Result<RawFd, ProcessGroupError> {
    let fd = stream.as_raw_fd();
    if fd < 3 {
        return Err(ProcessGroupError::InvalidSpec);
    }

    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(ProcessGroupError::InvalidSpec);
    }

    let mut socket_type: libc::c_int = 0;
    let mut socket_type_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let socket_type_result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut socket_type_len,
        )
    };
    if socket_type_result != 0 || socket_type != libc::SOCK_STREAM {
        return Err(ProcessGroupError::InvalidSpec);
    }

    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let address_result = unsafe {
        libc::getsockname(
            fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_len,
        )
    };
    if address_result != 0 || address.ss_family != libc::AF_UNIX as libc::sa_family_t {
        return Err(ProcessGroupError::InvalidSpec);
    }

    stream
        .peer_addr()
        .map_err(|_| ProcessGroupError::InvalidSpec)?;
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn mark_fds_cloexec_from_three() -> Result<(), std::io::Error> {
    // close_range(2) gained CLOSE_RANGE_CLOEXEC in Linux 5.11. Use the raw
    // syscall so an older libc cannot silently omit the fail-closed check.
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    let result =
        unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn clear_fd_cloexec(fd: RawFd) -> Result<(), std::io::Error> {
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_network_deny_filter() -> Result<(), std::io::Error> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

    let expected_arch = expected_seccomp_arch().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Unsupported, "unsupported seccomp ABI")
    })?;

    let mut denied = vec![
        libc::SYS_socket as u32,
        libc::SYS_socketpair as u32,
        libc::SYS_connect as u32,
        libc::SYS_bind as u32,
        libc::SYS_listen as u32,
        libc::SYS_accept as u32,
        libc::SYS_accept4 as u32,
        libc::SYS_sendto as u32,
        libc::SYS_sendmsg as u32,
        libc::SYS_recvfrom as u32,
        libc::SYS_recvmsg as u32,
        libc::SYS_shutdown as u32,
        libc::SYS_sendmmsg as u32,
        libc::SYS_recvmmsg as u32,
        libc::SYS_io_uring_setup as u32,
        libc::SYS_io_uring_enter as u32,
        libc::SYS_io_uring_register as u32,
        libc::SYS_setsid as u32,
        libc::SYS_setpgid as u32,
    ];
    #[cfg(target_arch = "x86")]
    denied.push(libc::SYS_socketcall as u32);
    denied.sort_unstable();
    denied.dedup();

    let mut filter = Vec::with_capacity(5 + denied.len() * 2);
    filter.push(SeccompInstruction::stmt(BPF_LD_W_ABS, 4));
    filter.push(SeccompInstruction::jump(BPF_JMP_JEQ, expected_arch, 1, 0));
    filter.push(SeccompInstruction::stmt(
        BPF_RET_K,
        SECCOMP_RET_KILL_PROCESS,
    ));
    filter.push(SeccompInstruction::stmt(BPF_LD_W_ABS, 0));
    for syscall in denied {
        filter.push(SeccompInstruction::jump(BPF_JMP_JEQ, syscall, 0, 1));
        filter.push(SeccompInstruction::stmt(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1),
        ));
    }
    filter.push(SeccompInstruction::stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    let len = u16::try_from(filter.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "network filter too large")
    })?;
    let program = SeccompProgram {
        len,
        filter: filter.as_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const SeccompProgram,
            0,
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const fn expected_seccomp_arch() -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    {
        return Some(0xC000_003E);
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Some(0xC000_00B7);
    }
    #[cfg(target_arch = "x86")]
    {
        return Some(0x4000_0003);
    }
    #[cfg(target_arch = "arm")]
    {
        return Some(0x4000_0028);
    }
    #[cfg(target_arch = "riscv64")]
    {
        return Some(0xC000_00F3);
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SeccompInstruction {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(target_os = "linux")]
impl SeccompInstruction {
    const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SeccompProgram {
    len: u16,
    filter: *const SeccompInstruction,
}

fn digest_file(path: &Path) -> Result<String, ProcessGroupError> {
    let bytes = std::fs::read(path)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use std::io::{Read, Write};
    #[cfg(target_os = "linux")]
    use std::os::fd::{AsRawFd, FromRawFd};
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixStream;

    #[cfg(target_os = "linux")]
    fn test_process_spec(test_filter: &str, marker: &str) -> ProcessSpec {
        let executable = std::env::current_exe().expect("test executable");
        let digest = digest_file(&executable).expect("test executable digest");
        ProcessSpec {
            launcher_path: executable.clone(),
            launcher_digest: digest.clone(),
            runtime_executable: executable,
            expected_runtime_executable_digest: digest,
            fixed_args: vec![test_filter.into(), "--nocapture".into()],
            fixed_env: BTreeMap::from([(marker.into(), "1".into())]),
            network_disabled: true,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_egress_channel_child_probe() {
        if std::env::var_os("FCP_HOST_EGRESS_CHANNEL_CHILD").is_none() {
            return;
        }
        let channel_fd = std::env::var(FCP_HOST_EGRESS_FD)
            .expect("inherited channel fd environment")
            .parse::<i32>()
            .expect("numeric inherited channel fd");
        let mut channel = unsafe { std::fs::File::from_raw_fd(channel_fd) };
        let mut request = [0_u8; 4];
        channel.read_exact(&mut request).expect("channel request");
        assert_eq!(&request, b"ping");

        let socket_errno = unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd >= 0 {
                libc::close(fd);
                0
            } else {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            }
        };
        let connect_errno = unsafe {
            let result = libc::connect(channel.as_raw_fd(), std::ptr::null(), 0);
            if result == 0 {
                0
            } else {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            }
        };
        let response = format!("{socket_errno}:{connect_errno}:pong");
        channel
            .write_all(response.as_bytes())
            .expect("channel response");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_once_credential_channel_child_probe() {
        if std::env::var_os("FCP_HOST_RUN_ONCE_CREDENTIAL_CHANNEL_CHILD").is_none() {
            return;
        }
        assert_eq!(
            std::env::var(FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT)
                .expect("credential transport environment"),
            FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT_VALUE
        );
        let channel_fd = std::env::var(FCP_HOST_RUN_ONCE_CREDENTIAL_FD)
            .expect("credential channel fd environment")
            .parse::<i32>()
            .expect("numeric credential channel fd");
        let mut channel = unsafe { std::fs::File::from_raw_fd(channel_fd) };
        let mut request = [0_u8; 4];
        channel
            .read_exact(&mut request)
            .expect("credential channel request");
        assert_eq!(&request, b"ping");
        channel
            .write_all(b"pong")
            .expect("credential channel response");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_egress_channel_ambient_probe() {
        if std::env::var_os("FCP_HOST_EGRESS_CHANNEL_AMBIENT").is_none() {
            return;
        }
        let channel_fd = std::env::var(FCP_HOST_EGRESS_FD)
            .expect("inherited channel fd environment")
            .parse::<i32>()
            .expect("numeric inherited channel fd");
        let ambient_fd = std::env::var("FCP_HOST_EGRESS_AMBIENT_FD")
            .expect("ambient fd environment")
            .parse::<i32>()
            .expect("numeric ambient fd");
        let present = std::fs::read_link(format!("/proc/self/fd/{ambient_fd}")).is_ok();
        let mut channel = unsafe { std::fs::File::from_raw_fd(channel_fd) };
        channel
            .write_all(if present { b"present" } else { b"absent" })
            .expect("ambient probe response");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_egress_channel_rejects_reserved_env_and_invalid_streams() {
        let (child_endpoint, _host_endpoint) = UnixStream::pair().expect("socketpair");
        let mut reserved_spec = test_process_spec(
            "host_egress_channel_child_probe",
            "FCP_HOST_EGRESS_CHANNEL_CHILD",
        );
        reserved_spec.fixed_env.insert(
            FCP_HOST_EGRESS_FD.into(),
            "attacker-controlled-value".into(),
        );
        assert!(matches!(
            OwnedProcess::spawn_with_host_egress_channel(&reserved_spec, child_endpoint),
            Err(ProcessGroupError::InvalidSpec)
        ));

        let unconnected_fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(unconnected_fd >= 0, "unconnected Unix socket");
        let unconnected = unsafe { UnixStream::from_raw_fd(unconnected_fd) };
        let valid_spec = test_process_spec(
            "host_egress_channel_child_probe",
            "FCP_HOST_EGRESS_CHANNEL_CHILD",
        );
        assert!(matches!(
            OwnedProcess::spawn_with_host_egress_channel(&valid_spec, unconnected),
            Err(ProcessGroupError::InvalidSpec)
        ));

        let (non_cloexec, _peer) = UnixStream::pair().expect("socketpair");
        let fd = non_cloexec.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "get descriptor flags");
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        assert!(matches!(
            OwnedProcess::spawn_with_host_egress_channel(&valid_spec, non_cloexec),
            Err(ProcessGroupError::InvalidSpec)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_egress_channel_is_inherited_at_actual_fd_and_network_is_denied() {
        let (mut host_endpoint, child_endpoint) = UnixStream::pair().expect("socketpair");
        let spec = test_process_spec(
            "host_egress_channel_child_probe",
            "FCP_HOST_EGRESS_CHANNEL_CHILD",
        );
        let mut process = OwnedProcess::spawn_with_host_egress_channel(&spec, child_endpoint)
            .expect("spawn inherited channel child");
        host_endpoint
            .write_all(b"ping")
            .expect("write channel request");
        let expected = format!("{}:{}:pong", libc::EPERM, libc::EPERM);
        let mut response = vec![0_u8; expected.len()];
        host_endpoint
            .read_exact(&mut response)
            .expect("read channel response");
        assert_eq!(response, expected.as_bytes());
        let report = process
            .terminate(Duration::from_secs(1))
            .expect("terminate channel child");
        assert!(report.group_absent);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_once_credential_channel_uses_fixed_env_and_owned_teardown() {
        let (mut host_endpoint, child_endpoint) = UnixStream::pair().expect("socketpair");
        let mut spec = test_process_spec(
            "run_once_credential_channel_child_probe",
            "FCP_HOST_RUN_ONCE_CREDENTIAL_CHANNEL_CHILD",
        );
        spec.network_disabled = false;
        let mut process =
            OwnedProcess::spawn_with_run_once_credential_channel(&spec, child_endpoint)
                .expect("spawn credential channel child");
        host_endpoint
            .write_all(b"ping")
            .expect("write credential channel request");
        let mut response = [0_u8; 4];
        host_endpoint
            .read_exact(&mut response)
            .expect("read credential channel response");
        assert_eq!(&response, b"pong");
        let report = process
            .terminate(Duration::from_secs(1))
            .expect("terminate credential channel child");
        assert!(report.group_absent);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_once_credential_channel_rejects_reserved_env() {
        let (child_endpoint, _host_endpoint) = UnixStream::pair().expect("socketpair");
        let network_denied_spec = test_process_spec(
            "run_once_credential_channel_child_probe",
            "FCP_HOST_RUN_ONCE_CREDENTIAL_CHANNEL_CHILD",
        );
        assert!(matches!(
            OwnedProcess::spawn_with_run_once_credential_channel(
                &network_denied_spec,
                child_endpoint
            ),
            Err(ProcessGroupError::InvalidSpec)
        ));

        for key in [
            FCP_HOST_EGRESS_FD,
            FCP_HOST_RUN_ONCE_CREDENTIAL_TRANSPORT,
            FCP_HOST_RUN_ONCE_CREDENTIAL_FD,
        ] {
            let (child_endpoint, _host_endpoint) = UnixStream::pair().expect("socketpair");
            let mut spec = test_process_spec(
                "run_once_credential_channel_child_probe",
                "FCP_HOST_RUN_ONCE_CREDENTIAL_CHANNEL_CHILD",
            );
            spec.network_disabled = false;
            spec.fixed_env
                .insert(key.into(), "attacker-controlled-value".into());
            assert!(matches!(
                OwnedProcess::spawn_with_run_once_credential_channel(&spec, child_endpoint),
                Err(ProcessGroupError::InvalidSpec)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_egress_channel_closes_ambient_non_cloexec_fds_at_exec() {
        let (mut host_endpoint, child_endpoint) = UnixStream::pair().expect("socketpair");
        let ambient = std::fs::File::open("/dev/null").expect("ambient descriptor");
        let ambient_fd = ambient.as_raw_fd();
        let flags = unsafe { libc::fcntl(ambient_fd, libc::F_GETFD) };
        assert!(flags >= 0, "get ambient descriptor flags");
        assert_eq!(
            unsafe { libc::fcntl(ambient_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        let mut spec = test_process_spec(
            "host_egress_channel_ambient_probe",
            "FCP_HOST_EGRESS_CHANNEL_AMBIENT",
        );
        spec.fixed_env.insert(
            "FCP_HOST_EGRESS_AMBIENT_FD".into(),
            ambient_fd.to_string().into(),
        );
        let mut process = OwnedProcess::spawn_with_host_egress_channel(&spec, child_endpoint)
            .expect("spawn ambient-fd probe");
        let mut response = [0_u8; 6];
        host_endpoint
            .read_exact(&mut response)
            .expect("read ambient-fd probe");
        assert_eq!(&response, b"absent");
        let report = process
            .terminate(Duration::from_secs(1))
            .expect("terminate ambient-fd probe");
        assert!(report.group_absent);
    }

    #[test]
    fn invalid_digest_is_rejected_before_spawn() {
        let spec = ProcessSpec {
            launcher_path: PathBuf::from("/bin/true"),
            launcher_digest: "not-a-digest".to_string(),
            runtime_executable: PathBuf::from("/usr/bin/true"),
            expected_runtime_executable_digest: "not-a-digest".to_string(),
            fixed_args: Vec::new(),
            fixed_env: BTreeMap::new(),
            network_disabled: true,
        };
        assert!(matches!(
            OwnedProcess::spawn(&spec),
            Err(ProcessGroupError::InvalidSpec)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_once_working_directory_requires_canonical_absolute_directory() {
        let executable = std::fs::canonicalize(std::env::current_exe().expect("test executable"))
            .expect("canonical test executable");
        let directory = executable.parent().expect("test executable parent");
        assert_eq!(
            validate_working_directory(directory).expect("canonical directory"),
            directory
        );
        assert!(matches!(
            validate_working_directory(Path::new("relative")),
            Err(ProcessGroupError::InvalidSpec)
        ));
        assert!(matches!(
            validate_working_directory(&executable),
            Err(ProcessGroupError::InvalidSpec)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_stdio_can_be_marked_nonblocking() {
        let (stream, _peer) = UnixStream::pair().expect("socketpair");
        set_nonblocking(&stream).expect("set nonblocking");
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::O_NONBLOCK, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_stat_parser_reads_group_and_start_time() {
        let stat = read_proc_stat(std::process::id()).expect("self stat");
        assert!(stat.pgid > 1);
        assert!(stat.session_id > 1);
        assert!(stat.start_time_ticks > 0);
    }

    #[cfg(target_os = "linux")]
    fn long_running_process_spec() -> ProcessSpec {
        let runtime = std::fs::canonicalize("/bin/sleep").expect("sleep");
        let digest = digest_file(&runtime).expect("sleep digest");
        ProcessSpec {
            launcher_path: runtime.clone(),
            launcher_digest: digest.clone(),
            runtime_executable: runtime,
            expected_runtime_executable_digest: digest,
            fixed_args: vec!["30".into()],
            fixed_env: BTreeMap::new(),
            network_disabled: false,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refuses_pid_start_or_group_identity_drift_before_signal() {
        let spec = long_running_process_spec();
        let mut process = OwnedProcess::spawn(&spec).expect("process");
        let original = process.identity.clone();
        process.identity.pgid += 1;
        assert!(matches!(
            process.terminate(Duration::from_millis(50)),
            Err(ProcessGroupError::IdentityMismatch)
        ));
        assert_eq!(process.teardown_state, TeardownState::TerminalFailure);
        process.identity = original;
        let child = process.child.as_mut().expect("owned child");
        child.kill().expect("direct test cleanup");
        child.wait().expect("reap direct test child");
        process.reaped = true;
        assert!(matches!(
            process.terminate(Duration::from_secs(1)),
            Err(ProcessGroupError::TeardownTerminal)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_timeout_preserves_signal_evidence_and_disables_drop_retry() {
        let mut process = OwnedProcess::spawn(&long_running_process_spec()).expect("process");
        assert!(matches!(
            process.terminate(Duration::ZERO),
            Err(ProcessGroupError::TeardownTimeout)
        ));
        assert_eq!(process.teardown_state, TeardownState::TerminalFailure);
        assert!(process.term_sent);
        let term_sent = process.term_sent;
        let kill_sent = process.kill_sent;
        assert!(matches!(
            process.terminate(Duration::from_secs(1)),
            Err(ProcessGroupError::TeardownTerminal)
        ));
        assert_eq!(process.term_sent, term_sent);
        assert_eq!(process.kill_sent, kill_sent);
        let child = process.child.as_mut().expect("owned child");
        let _ = child.wait();
        process.reaped = true;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drop_does_not_retry_after_identity_mismatch() {
        let mut process = OwnedProcess::spawn(&long_running_process_spec()).expect("process");
        let original = process.identity.clone();
        let pid = original.pid;
        process.identity.pgid += 1;
        assert!(matches!(
            process.terminate(Duration::from_millis(50)),
            Err(ProcessGroupError::IdentityMismatch)
        ));
        assert_eq!(process.teardown_state, TeardownState::TerminalFailure);
        process.identity = original;
        drop(process);

        let snapshot = read_proc_stat(pid).expect("exact child survived Drop");
        assert_ne!(snapshot.state, b'Z');
        let pid = i32::try_from(pid).expect("Linux PID fits pid_t");

        // SAFETY: `pid` is the exact direct-child PID captured before Drop;
        // this test intentionally kills and reaps only that child, never by name.
        let kill_result = unsafe { libc::kill(pid, libc::SIGKILL) };
        assert_eq!(kill_result, 0, "kill exact still-live child");
        let mut status = 0;
        // SAFETY: the exact PID remains our direct child after OwnedProcess
        // drops its handle, so waitpid reaps that child and avoids a zombie.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_drop_cleanup_remains_bounded() {
        let started = Instant::now();
        {
            let _process = OwnedProcess::spawn(&long_running_process_spec()).expect("process");
        }
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
