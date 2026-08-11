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
}

/// A spawned Linux process with owned stdio and exact group identity.
#[derive(Debug)]
pub struct OwnedProcess {
    child: Option<std::process::Child>,
    identity: ProcessIdentity,
    reaped: bool,
    term_sent: bool,
    kill_sent: bool,
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

            // SAFETY: the closure runs in the child between fork and exec and
            // performs only async-signal-safe libc calls. It captures no Rust
            // allocation that is mutated in the child.
            unsafe {
                command.pre_exec(move || {
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
            })
        }
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
        if self.child.is_some() {
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
    fn proc_stat_parser_reads_group_and_start_time() {
        let stat = read_proc_stat(std::process::id()).expect("self stat");
        assert!(stat.pgid > 1);
        assert!(stat.session_id > 1);
        assert!(stat.start_time_ticks > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refuses_pid_start_or_group_identity_drift_before_signal() {
        let runtime = std::fs::canonicalize("/bin/sleep").expect("sleep");
        let spec = ProcessSpec {
            launcher_path: runtime.clone(),
            launcher_digest: digest_file(&runtime).expect("launcher digest"),
            runtime_executable: runtime.clone(),
            expected_runtime_executable_digest: digest_file(&runtime).expect("runtime digest"),
            fixed_args: vec!["5".into()],
            fixed_env: BTreeMap::new(),
            network_disabled: false,
        };
        let mut process = OwnedProcess::spawn(&spec).expect("process");
        let original = process.identity.clone();
        process.identity.pgid += 1;
        assert!(matches!(
            process.terminate(Duration::from_millis(50)),
            Err(ProcessGroupError::IdentityMismatch)
        ));
        process.identity = original;
        let report = process
            .terminate(Duration::from_secs(1))
            .expect("restored identity teardown");
        assert!(report.group_absent);
    }
}
