//! Request-scoped containment on a delegated Linux cgroup-v2 hierarchy.
//!
//! The API is deliberately narrow: the host derives the current unified
//! hierarchy from `/proc/self/cgroup`, creates a random leaf below it, and
//! hands one retained CLOEXEC `cgroup.procs` descriptor to a fixed trusted
//! supervisor plus a separate parent-side request lease. The supervisor
//! self-attaches by writing `0`, drops its fd before reporting ready, and never
//! crosses a Rust value boundary with the parent. There is no arbitrary numeric
//! PID attach, caller-selected path, systemd integration, or process-group
//! fallback. Final containment additionally requires the supervisor gate,
//! Landlock without a `/sys/fs/cgroup` allowlist, and closing all cgroup fds
//! before target exec; those integration claims remain deferred here.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fmt;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::time::Duration;

use fcp_async_core::Deadline;
use rand::RngCore;

#[cfg(target_os = "linux")]
use crate::process::OwnedProcess;

const CGROUP_COMPONENTS: [&str; 3] = ["sys", "fs", "cgroup"];
const LEAF_PREFIX: &str = "fcp-req-";
const LEAF_BYTES: usize = 16;
#[cfg(target_os = "linux")]
const LEAF_CREATE_ATTEMPTS: usize = 8;

/// Errors from request-scoped cgroup-v2 containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CgroupError {
    #[error("request cgroup-v2 containment is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("unified cgroup-v2 membership is unavailable")]
    MembershipUnavailable,
    #[error("unified cgroup-v2 membership is malformed")]
    MembershipMalformed,
    #[error("legacy cgroup membership is not supported")]
    LegacyMembership,
    #[error("duplicate unified cgroup membership")]
    DuplicateMembership,
    #[error("cgroup membership path is invalid")]
    InvalidMembershipPath,
    #[error("cgroup-v2 delegation is unavailable")]
    DelegationUnavailable,
    #[error("request cgroup operation failed")]
    Io,
    #[error("request cgroup leaf name is invalid")]
    InvalidLeaf,
    #[error("request cgroup state does not permit this operation")]
    InvalidState,
    #[error("owned process has already exited")]
    ProcessExited,
    #[error("owned process identity could not be verified")]
    ProcessIdentityMismatch,
    #[error("owned process membership did not match the request cgroup")]
    MembershipMismatch,
    #[error("cgroup.events is malformed")]
    EventsMalformed,
    #[error("request cgroup teardown exceeded its deadline")]
    TeardownTimeout,
    #[error("request cgroup is not empty")]
    CgroupNotEmpty,
    #[error("request cgroup leaf cleanup could not be proven safe")]
    LeafCleanupRequired,
    #[error("request cgroup request binding did not match")]
    RequestMismatch,
    #[error("request cgroup file-descriptor operation failed")]
    FdOperation,
}

/// Host-generated opaque identity for one request cgroup leaf.
///
/// The bytes are private and the name is never accepted from a caller.  The
/// fixed prefix and lowercase hexadecimal encoding are used only for the
/// kernel-visible leaf directory name.
pub struct CgroupLeafId([u8; LEAF_BYTES]);

impl CgroupLeafId {
    /// Generate a fresh host-owned leaf identity.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; LEAF_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn name(&self) -> String {
        let mut name = String::with_capacity(LEAF_PREFIX.len() + LEAF_BYTES * 2);
        name.push_str(LEAF_PREFIX);
        for byte in self.0 {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        name
    }

    #[cfg(test)]
    const fn from_test_bytes(bytes: [u8; LEAF_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for CgroupLeafId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CgroupLeafId(<redacted>)")
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, PartialEq, Eq)]
struct RequestStamp([u8; LEAF_BYTES]);

impl CgroupLeafId {
    const fn stamp(&self) -> RequestStamp {
        RequestStamp(self.0)
    }
}

/// Evidence that cgroup kill was requested and `populated=0` was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupKillEvidence {
    kill_requested: bool,
    populated_zero: bool,
}

impl CgroupKillEvidence {
    /// Whether the kernel accepted the kill request write.
    #[must_use]
    pub const fn kill_requested(self) -> bool {
        self.kill_requested
    }

    /// Whether strict event parsing observed an empty cgroup.
    #[must_use]
    pub const fn populated_zero(self) -> bool {
        self.populated_zero
    }
}

/// Marker returned only after exact attachment verification.
pub struct TargetReleasePermit {
    stamp: RequestStamp,
    #[cfg(target_os = "linux")]
    pid: u32,
    #[cfg(target_os = "linux")]
    start_time_ticks: u64,
}

impl fmt::Debug for TargetReleasePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetReleasePermit(<redacted>)")
    }
}

/// One-shot fd transfer handle for the fixed trusted supervisor.
pub struct SupervisorAttachHandle {
    #[cfg(target_os = "linux")]
    procs_fd: OwnedFd,
}

impl fmt::Debug for SupervisorAttachHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SupervisorAttachHandle(<redacted>)")
    }
}

/// Parent-side request-bound lease for one supervisor self-attachment.
///
/// This value contains no file descriptor and must be paired with the
/// child-side [`SupervisorAttachHandle`]. The fixed supervisor writes `0`
/// through its handle, drops that fd before reporting ready, and the parent
/// uses this lease only for membership verification and release.
pub struct SupervisorAttachLease {
    stamp: RequestStamp,
}

impl fmt::Debug for SupervisorAttachLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SupervisorAttachLease(<redacted>)")
    }
}

#[cfg(target_os = "linux")]
impl SupervisorAttachHandle {
    /// Self-attach the fixed supervisor by writing `0`, never an arbitrary PID.
    #[must_use = "the fixed supervisor must report self-attachment readiness"]
    pub fn self_attach(self) -> Result<(), CgroupError> {
        write_fd(&self.procs_fd, b"0")?;
        // Consuming `self` drops the CLOEXEC fd before the child reports
        // readiness. The parent owns the separate request-bound lease.
        drop(self);
        Ok(())
    }

    /// Transfer the one-shot CLOEXEC fd to the fixed supervisor launch path.
    ///
    /// The child launcher must perform any `dup2`/`dup3` mapping in the child
    /// after fork/spawn setup. This method never clears `FD_CLOEXEC` in the
    /// multithreaded parent.
    #[must_use = "the fd must be transferred to the fixed supervisor"]
    pub fn into_inherited_fd(self) -> OwnedFd {
        self.procs_fd
    }
}

/// One-shot gate marker after the cgroup fds are closed for supervisor exec.
#[derive(Debug)]
pub struct SupervisorExecGate {
    _private: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CgroupState {
    Created,
    HandoffIssued,
    SupervisorAttached,
    Verified,
    Released,
    Killed,
    Removed,
    TerminalFailure,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FdIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, PartialEq, Eq)]
struct ProcessBinding {
    stamp: RequestStamp,
    pid: u32,
    start_time_ticks: u64,
}

/// One host-created request cgroup.
pub struct RequestCgroup {
    leaf_id: CgroupLeafId,
    #[cfg(target_os = "linux")]
    parent_membership: RelativeCgroupPath,
    #[cfg(target_os = "linux")]
    parent_fd: OwnedFd,
    #[cfg(target_os = "linux")]
    parent_identity: FdIdentity,
    #[cfg(target_os = "linux")]
    leaf_fd: OwnedFd,
    #[cfg(target_os = "linux")]
    leaf_identity: FdIdentity,
    #[cfg(target_os = "linux")]
    procs_fd: Option<OwnedFd>,
    #[cfg(target_os = "linux")]
    kill_fd: OwnedFd,
    #[cfg(target_os = "linux")]
    events_fd: OwnedFd,
    #[cfg(target_os = "linux")]
    state: CgroupState,
    #[cfg(target_os = "linux")]
    binding: Option<ProcessBinding>,
}

#[cfg(target_os = "linux")]
struct CreatedLeaf {
    leaf_id: CgroupLeafId,
    leaf_fd: OwnedFd,
    leaf_identity: FdIdentity,
    procs_fd: OwnedFd,
    kill_fd: OwnedFd,
    events_fd: OwnedFd,
}

impl fmt::Debug for RequestCgroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RequestCgroup");
        debug.field("leaf_id", &"<redacted>");
        #[cfg(target_os = "linux")]
        {
            debug
                .field("state", &self.state)
                .field("has_supervisor_fd", &self.procs_fd.is_some())
                .field("bound", &self.binding.is_some());
        }
        #[cfg(not(target_os = "linux"))]
        debug.field("state", &"unsupported");
        debug.finish_non_exhaustive()
    }
}

impl RequestCgroup {
    /// Create a unique leaf under the caller's current delegated cgroup.
    ///
    /// The fixed mount and current membership are resolved into directory
    /// descriptors before any leaf is created. No wall-clock deadline is
    /// claimed for these synchronous filesystem/kernel calls.
    #[must_use = "the request cgroup must be explicitly created or rejected"]
    pub fn create() -> Result<Self, CgroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(CgroupError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            let parent_membership = read_current_membership()?;
            let mount_fd = open_fixed_cgroup_mount()?;
            let (parent_fd, parent_identity) =
                resolve_membership_dir(&mount_fd, &parent_membership)?;
            check_delegation(&parent_fd)?;
            let created = create_leaf(&parent_fd, &parent_identity)?;
            Ok(Self {
                leaf_id: created.leaf_id,
                parent_membership,
                parent_fd,
                parent_identity,
                leaf_fd: created.leaf_fd,
                leaf_identity: created.leaf_identity,
                procs_fd: Some(created.procs_fd),
                kill_fd: created.kill_fd,
                events_fd: created.events_fd,
                state: CgroupState::Created,
                binding: None,
            })
        }
    }

    /// Return the opaque host-generated leaf identity.
    #[must_use]
    pub const fn leaf_id(&self) -> &CgroupLeafId {
        &self.leaf_id
    }

    /// Split the one-shot handoff into child fd and parent lease halves.
    ///
    /// The first tuple element is transferred to the fixed supervisor; the
    /// second remains in the parent for later membership verification.
    #[must_use = "the one-shot supervisor handoff must be retained"]
    pub fn take_supervisor_attach_handle(
        &mut self,
    ) -> Result<(SupervisorAttachHandle, SupervisorAttachLease), CgroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(CgroupError::UnsupportedPlatform)
        }

        #[cfg(target_os = "linux")]
        {
            if self.state != CgroupState::Created {
                return Err(CgroupError::InvalidState);
            }
            let procs_fd = self.procs_fd.take().ok_or(CgroupError::InvalidState)?;
            self.state = CgroupState::HandoffIssued;
            let stamp = self.leaf_id.stamp();
            Ok((
                SupervisorAttachHandle { procs_fd },
                SupervisorAttachLease { stamp },
            ))
        }
    }

    /// Verify a self-attached, still-gated supervisor before target release.
    /// The fixed supervisor must remain alive and gated until the returned
    /// permit is consumed; a mismatch never yields a release permit.
    #[cfg(target_os = "linux")]
    #[must_use = "the verified permit must be consumed or teardown must be requested"]
    pub fn verify_supervisor_membership(
        &mut self,
        process: &OwnedProcess,
        lease: &SupervisorAttachLease,
    ) -> Result<TargetReleasePermit, CgroupError> {
        if self.state != CgroupState::HandoffIssued || lease.stamp != self.leaf_id.stamp() {
            return Err(CgroupError::RequestMismatch);
        }
        verify_leaf_binding(
            &self.parent_fd,
            &self.parent_identity,
            &self.leaf_fd,
            &self.leaf_identity,
            &self.leaf_id.name(),
        )?;
        self.state = CgroupState::SupervisorAttached;
        process
            .verify_identity()
            .map_err(|_| CgroupError::ProcessIdentityMismatch)?;
        let identity = process.identity();
        let actual =
            read_process_membership(identity.pid).map_err(|_| CgroupError::MembershipMismatch)?;
        process
            .verify_identity()
            .map_err(|_| CgroupError::ProcessIdentityMismatch)?;
        let expected = self.parent_membership.with_leaf(&self.leaf_id)?;
        if actual != expected {
            return Err(CgroupError::MembershipMismatch);
        }
        let binding = ProcessBinding {
            stamp: self.leaf_id.stamp(),
            pid: identity.pid,
            start_time_ticks: identity.start_time_ticks,
        };
        self.binding = Some(binding.clone());
        self.state = CgroupState::Verified;
        Ok(TargetReleasePermit {
            stamp: binding.stamp,
            pid: binding.pid,
            start_time_ticks: binding.start_time_ticks,
        })
    }

    /// Consume a verified permit and release the parent-side lease.
    ///
    /// The child fd is already consumed by `SupervisorAttachHandle::self_attach`
    /// before the fixed supervisor reports readiness; dropping this parent
    /// lease does not claim to close a cross-process descriptor.
    #[cfg(target_os = "linux")]
    #[must_use = "the permit and lease must be consumed before target release"]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "consuming both values enforces one-shot capability semantics"
    )]
    pub fn consume_release_permit(
        &mut self,
        permit: TargetReleasePermit,
        process: &OwnedProcess,
        lease: SupervisorAttachLease,
    ) -> Result<SupervisorExecGate, CgroupError> {
        if self.state != CgroupState::Verified {
            return Err(CgroupError::InvalidState);
        }
        let binding = self.binding.as_ref().ok_or(CgroupError::InvalidState)?;
        if !permit_matches_binding(binding, &permit) || lease.stamp != binding.stamp {
            return Err(CgroupError::RequestMismatch);
        }
        process
            .verify_identity()
            .map_err(|_| CgroupError::ProcessIdentityMismatch)?;
        if process.identity().pid != binding.pid
            || process.identity().start_time_ticks != binding.start_time_ticks
        {
            return Err(CgroupError::ProcessIdentityMismatch);
        }
        self.binding.take();
        self.state = CgroupState::Released;
        Ok(SupervisorExecGate { _private: () })
    }

    /// Explicitly abort an empty or still-gated leaf through cgroup kill.
    #[must_use = "the cgroup kill evidence must be handled before continuing"]
    pub fn abort_empty_until(
        &mut self,
        deadline: Deadline,
    ) -> Result<CgroupKillEvidence, CgroupError> {
        self.kill_until(deadline)
    }

    /// Request kernel kill and poll `cgroup.events` until `populated=0`.
    ///
    /// The deadline bounds polling and sleeps.  Individual filesystem and
    /// kernel calls are synchronous and cannot be pre-empted by this API.
    #[must_use = "the cgroup kill evidence must be handled before continuing"]
    pub fn kill_until(&mut self, deadline: Deadline) -> Result<CgroupKillEvidence, CgroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = deadline;
            return Err(CgroupError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            if !state_can_teardown(self.state) {
                return Err(CgroupError::InvalidState);
            }
            if let Err(error) = write_fd(&self.kill_fd, b"1") {
                self.state = CgroupState::TerminalFailure;
                return Err(error);
            }
            loop {
                let populated = match read_fd(&self.events_fd)
                    .map_err(|_| CgroupError::FdOperation)
                    .and_then(|events| parse_populated_event(&events))
                {
                    Ok(value) => value,
                    Err(error) => {
                        self.state = CgroupState::TerminalFailure;
                        return Err(error);
                    }
                };
                if !populated {
                    self.state = CgroupState::Killed;
                    return Ok(CgroupKillEvidence {
                        kill_requested: true,
                        populated_zero: true,
                    });
                }
                if deadline.is_expired() {
                    self.state = CgroupState::TerminalFailure;
                    return Err(CgroupError::TeardownTimeout);
                }
                std::thread::sleep(deadline.remaining().min(Duration::from_millis(10)));
            }
        }
    }

    /// Remove the leaf only after a successful kill and empty-state proof.
    #[must_use = "the empty cgroup removal result must be handled"]
    pub fn remove_empty(&mut self) -> Result<(), CgroupError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(CgroupError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            if self.state != CgroupState::Killed {
                return Err(CgroupError::InvalidState);
            }
            let populated = match read_fd(&self.events_fd)
                .map_err(|_| CgroupError::FdOperation)
                .and_then(|events| parse_populated_event(&events))
            {
                Ok(populated) => populated,
                Err(error) => {
                    self.state = CgroupState::TerminalFailure;
                    return Err(error);
                }
            };
            if populated {
                return Err(CgroupError::CgroupNotEmpty);
            }
            remove_leaf_checked(
                &self.parent_fd,
                &self.parent_identity,
                &self.leaf_fd,
                &self.leaf_identity,
                &self.leaf_id.name(),
            )?;
            self.state = CgroupState::Removed;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn create_leaf(
    parent_fd: &OwnedFd,
    parent_identity: &FdIdentity,
) -> Result<CreatedLeaf, CgroupError> {
    for _ in 0..LEAF_CREATE_ATTEMPTS {
        let leaf_token = CgroupLeafId::generate();
        let leaf_name = leaf_token.name();
        match mkdir_at(parent_fd, &leaf_name) {
            Ok(()) => {
                return create_leaf_from_directory(
                    parent_fd,
                    parent_identity,
                    leaf_token,
                    &leaf_name,
                );
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(classify_fd_error(&error)),
        }
    }
    Err(CgroupError::Io)
}

#[cfg(target_os = "linux")]
fn create_leaf_from_directory(
    parent_fd: &OwnedFd,
    parent_identity: &FdIdentity,
    leaf_token: CgroupLeafId,
    leaf_name: &str,
) -> Result<CreatedLeaf, CgroupError> {
    let leaf_dir_fd = match open_dir_at(parent_fd, leaf_name) {
        Ok(fd) => fd,
        Err(error) => {
            let error = classify_fd_error(&error);
            return Err(cleanup_created_leaf_or_required(
                error,
                parent_fd,
                parent_identity,
                leaf_name,
                None,
            ));
        }
    };
    let leaf_dir_identity = match stat_fd(&leaf_dir_fd) {
        Ok(identity) => identity,
        Err(error) => {
            return Err(cleanup_created_leaf_or_required(
                error,
                parent_fd,
                parent_identity,
                leaf_name,
                None,
            ));
        }
    };
    if stat_at(parent_fd, leaf_name).ok() != Some(leaf_dir_identity) {
        return Err(cleanup_created_leaf_or_required(
            CgroupError::RequestMismatch,
            parent_fd,
            parent_identity,
            leaf_name,
            Some((&leaf_dir_fd, &leaf_dir_identity)),
        ));
    }
    let (events_fd, kill_fd, procs_fd) = open_leaf_interfaces(
        parent_fd,
        parent_identity,
        leaf_name,
        &leaf_dir_fd,
        &leaf_dir_identity,
    )?;
    Ok(CreatedLeaf {
        leaf_id: leaf_token,
        leaf_fd: leaf_dir_fd,
        leaf_identity: leaf_dir_identity,
        procs_fd,
        kill_fd,
        events_fd,
    })
}

#[cfg(target_os = "linux")]
fn open_leaf_interfaces(
    parent_fd: &OwnedFd,
    parent_identity: &FdIdentity,
    request_leaf_name: &str,
    request_leaf_fd: &OwnedFd,
    request_leaf_identity: &FdIdentity,
) -> Result<(OwnedFd, OwnedFd, OwnedFd), CgroupError> {
    let events_fd = match open_file_at(request_leaf_fd, "cgroup.events", libc::O_RDONLY) {
        Ok(fd) => fd,
        Err(error) => {
            let error = classify_fd_error(&error);
            return Err(cleanup_created_leaf_or_required(
                error,
                parent_fd,
                parent_identity,
                request_leaf_name,
                Some((request_leaf_fd, request_leaf_identity)),
            ));
        }
    };
    let initial_events = match read_fd(&events_fd) {
        Ok(events) => events,
        Err(error) => {
            return Err(cleanup_created_leaf_or_required(
                error,
                parent_fd,
                parent_identity,
                request_leaf_name,
                Some((request_leaf_fd, request_leaf_identity)),
            ));
        }
    };
    let populated = match parse_populated_event(&initial_events) {
        Ok(populated) => populated,
        Err(error) => {
            return Err(cleanup_created_leaf_or_required(
                error,
                parent_fd,
                parent_identity,
                request_leaf_name,
                Some((request_leaf_fd, request_leaf_identity)),
            ));
        }
    };
    if populated {
        return Err(cleanup_created_leaf_or_required(
            CgroupError::LeafCleanupRequired,
            parent_fd,
            parent_identity,
            request_leaf_name,
            Some((request_leaf_fd, request_leaf_identity)),
        ));
    }
    let kill_fd = match open_file_at(request_leaf_fd, "cgroup.kill", libc::O_WRONLY) {
        Ok(fd) => fd,
        Err(error) => {
            return Err(cleanup_created_leaf_or_required(
                classify_fd_error(&error),
                parent_fd,
                parent_identity,
                request_leaf_name,
                Some((request_leaf_fd, request_leaf_identity)),
            ));
        }
    };
    let procs_fd = match open_file_at(request_leaf_fd, "cgroup.procs", libc::O_WRONLY) {
        Ok(fd) => fd,
        Err(error) => {
            return Err(cleanup_created_leaf_or_required(
                classify_fd_error(&error),
                parent_fd,
                parent_identity,
                request_leaf_name,
                Some((request_leaf_fd, request_leaf_identity)),
            ));
        }
    };
    Ok((events_fd, kill_fd, procs_fd))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelativeCgroupPath(Vec<String>);

impl RelativeCgroupPath {
    fn with_leaf(&self, leaf: &CgroupLeafId) -> Result<Self, CgroupError> {
        let name = leaf.name();
        validate_leaf_name(&name)?;
        let mut components = self.0.clone();
        components.push(name);
        Ok(Self(components))
    }
}

fn parse_unified_membership(input: &str) -> Result<RelativeCgroupPath, CgroupError> {
    let mut unified = None;
    for line in input.lines() {
        if line.is_empty() {
            return Err(CgroupError::MembershipMalformed);
        }
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 3 {
            return Err(CgroupError::MembershipMalformed);
        }
        if fields[0] != "0" || !fields[1].is_empty() {
            return Err(CgroupError::LegacyMembership);
        }
        if unified.is_some() {
            return Err(CgroupError::DuplicateMembership);
        }
        unified = Some(parse_membership_path(fields[2])?);
    }
    unified.ok_or(CgroupError::MembershipUnavailable)
}

fn parse_membership_path(path: &str) -> Result<RelativeCgroupPath, CgroupError> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(CgroupError::InvalidMembershipPath);
    }
    if path == "/" {
        return Ok(RelativeCgroupPath(Vec::new()));
    }
    let mut components = Vec::new();
    for component in path.split('/').skip(1) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(CgroupError::InvalidMembershipPath);
        }
        if component.chars().any(char::is_control) {
            return Err(CgroupError::InvalidMembershipPath);
        }
        components.push(component.to_owned());
    }
    Ok(RelativeCgroupPath(components))
}

fn parse_populated_event(input: &str) -> Result<bool, CgroupError> {
    let mut populated = None;
    for line in input.lines() {
        if line.is_empty() {
            return Err(CgroupError::EventsMalformed);
        }
        let mut fields = line.split_whitespace();
        let key = fields.next().ok_or(CgroupError::EventsMalformed)?;
        let value = fields.next().ok_or(CgroupError::EventsMalformed)?;
        if fields.next().is_some() {
            return Err(CgroupError::EventsMalformed);
        }
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || !matches!(value, "0" | "1")
        {
            return Err(CgroupError::EventsMalformed);
        }
        if key == "populated" {
            if populated.is_some() {
                return Err(CgroupError::EventsMalformed);
            }
            populated = Some(value == "1");
        }
    }
    populated.ok_or(CgroupError::EventsMalformed)
}

fn validate_leaf_name(name: &str) -> Result<(), CgroupError> {
    let suffix = name
        .strip_prefix(LEAF_PREFIX)
        .ok_or(CgroupError::InvalidLeaf)?;
    if suffix.len() != LEAF_BYTES * 2
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CgroupError::InvalidLeaf);
    }
    Ok(())
}

#[cfg(test)]
const fn state_can_release(state: CgroupState) -> bool {
    matches!(state, CgroupState::Released)
}

const fn state_can_teardown(state: CgroupState) -> bool {
    matches!(
        state,
        CgroupState::Created
            | CgroupState::HandoffIssued
            | CgroupState::SupervisorAttached
            | CgroupState::Verified
            | CgroupState::Released
    )
}

#[cfg(target_os = "linux")]
fn permit_matches_binding(binding: &ProcessBinding, permit: &TargetReleasePermit) -> bool {
    binding.stamp == permit.stamp
        && binding.pid == permit.pid
        && binding.start_time_ticks == permit.start_time_ticks
}

const fn classify_delegation_error(kind: io::ErrorKind) -> CgroupError {
    match kind {
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {
            CgroupError::DelegationUnavailable
        }
        _ => CgroupError::FdOperation,
    }
}

fn classify_delegation_io_error(error: &io::Error) -> CgroupError {
    classify_delegation_error(error.kind())
}

fn classify_fd_error(error: &io::Error) -> CgroupError {
    let kind = error.kind();
    match kind {
        io::ErrorKind::NotFound => CgroupError::MembershipUnavailable,
        io::ErrorKind::PermissionDenied => CgroupError::DelegationUnavailable,
        _ => CgroupError::FdOperation,
    }
}

#[cfg(target_os = "linux")]
fn read_current_membership() -> Result<RelativeCgroupPath, CgroupError> {
    std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|_| CgroupError::MembershipUnavailable)
        .and_then(|contents| parse_unified_membership(&contents))
}

#[cfg(target_os = "linux")]
fn read_process_membership(pid: u32) -> Result<RelativeCgroupPath, CgroupError> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| CgroupError::MembershipUnavailable)
        .and_then(|contents| parse_unified_membership(&contents))
}

#[cfg(target_os = "linux")]
fn make_cstring(value: &str) -> Result<CString, CgroupError> {
    CString::new(value).map_err(|_| CgroupError::InvalidLeaf)
}

#[cfg(target_os = "linux")]
fn open_at(dirfd: RawFd, name: &str, flags: i32) -> io::Result<OwnedFd> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))?;
    // SAFETY: `name` is a NUL-terminated immutable CString and the flags do
    // not request a caller-provided mutable buffer.
    let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a non-negative fd is uniquely owned by this return value.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "linux")]
fn open_dir_at(dirfd: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    open_at(
        dirfd.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
}

#[cfg(target_os = "linux")]
fn open_file_at(dirfd: &OwnedFd, name: &str, access: i32) -> io::Result<OwnedFd> {
    let fd = open_at(
        dirfd.as_raw_fd(),
        name,
        access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let identity = stat_fd(&fd).map_err(|_| io::Error::other("invalid cgroup interface"))?;
    if identity.device == 0 && identity.inode == 0 {
        return Err(io::Error::other("invalid cgroup interface"));
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn open_fixed_cgroup_mount() -> Result<OwnedFd, CgroupError> {
    let mut current = open_at(
        libc::AT_FDCWD,
        "/",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .map_err(|_| CgroupError::MembershipUnavailable)?;
    for component in CGROUP_COMPONENTS {
        current = open_dir_at(&current, component).map_err(|error| classify_fd_error(&error))?;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn resolve_membership_dir(
    mount_fd: &OwnedFd,
    membership: &RelativeCgroupPath,
) -> Result<(OwnedFd, FdIdentity), CgroupError> {
    let mut current = dup_fd(mount_fd)?;
    for component in &membership.0 {
        current = open_dir_at(&current, component).map_err(|error| classify_fd_error(&error))?;
    }
    let identity = stat_fd(&current)?;
    Ok((current, identity))
}

#[cfg(target_os = "linux")]
fn dup_fd(fd: &OwnedFd) -> Result<OwnedFd, CgroupError> {
    // SAFETY: `fd` is a valid borrowed descriptor and the result is owned.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        Err(CgroupError::FdOperation)
    } else {
        // SAFETY: a non-negative fcntl result is uniquely owned here.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}

#[cfg(target_os = "linux")]
fn mkdir_at(parent: &OwnedFd, name: &str) -> io::Result<()> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))?;
    // SAFETY: `name` is an immutable NUL-terminated CString.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn stat_fd(fd: &OwnedFd) -> Result<FdIdentity, CgroupError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the provided stat structure on success.
    let result = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(CgroupError::FdOperation);
    }
    // SAFETY: the successful fstat call initialized the structure.
    let stat = unsafe { stat.assume_init() };
    Ok(FdIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

#[cfg(target_os = "linux")]
fn stat_at(parent: &OwnedFd, name: &str) -> Result<FdIdentity, CgroupError> {
    let name = make_cstring(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the CString and output buffer are valid for this synchronous call.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(CgroupError::FdOperation);
    }
    // SAFETY: the successful fstatat call initialized the structure.
    let stat = unsafe { stat.assume_init() };
    Ok(FdIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

#[cfg(target_os = "linux")]
fn check_delegation(parent: &OwnedFd) -> Result<(), CgroupError> {
    open_file_at(parent, "cgroup.procs", libc::O_WRONLY)
        .map_err(|error| classify_delegation_io_error(&error))?;
    open_file_at(parent, "cgroup.subtree_control", libc::O_WRONLY)
        .map_err(|error| classify_delegation_io_error(&error))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_fd(fd: &OwnedFd, bytes: &[u8]) -> Result<(), CgroupError> {
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: the byte slice remains valid for this synchronous write.
        let result = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[written..].as_ptr().cast(),
                bytes.len() - written,
            )
        };
        if result < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(CgroupError::FdOperation);
        }
        if result == 0 {
            return Err(CgroupError::FdOperation);
        }
        written += usize::try_from(result).map_err(|_| CgroupError::FdOperation)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_fd(fd: &OwnedFd) -> Result<String, CgroupError> {
    // SAFETY: seeking and reading a retained cgroup interface fd use no
    // caller-provided mutable memory beyond the bounded stack buffer.
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(CgroupError::FdOperation);
    }
    let mut buffer = [0_u8; 4096];
    let length = loop {
        let length =
            unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if length < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break length;
    };
    if length < 0 {
        return Err(CgroupError::FdOperation);
    }
    let length = usize::try_from(length).map_err(|_| CgroupError::FdOperation)?;
    String::from_utf8(buffer[..length].to_vec()).map_err(|_| CgroupError::EventsMalformed)
}

#[cfg(target_os = "linux")]
fn remove_leaf_checked(
    parent: &OwnedFd,
    parent_identity: &FdIdentity,
    leaf_dir_fd: &OwnedFd,
    leaf_dir_identity: &FdIdentity,
    name: &str,
) -> Result<(), CgroupError> {
    verify_leaf_binding(
        parent,
        parent_identity,
        leaf_dir_fd,
        leaf_dir_identity,
        name,
    )?;
    let name = make_cstring(name)?;
    // SAFETY: the parent fd and private leaf name are retained and validated.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if result == 0 {
        Ok(())
    } else if io::Error::last_os_error().kind() == io::ErrorKind::DirectoryNotEmpty {
        Err(CgroupError::CgroupNotEmpty)
    } else {
        Err(CgroupError::FdOperation)
    }
}

#[cfg(target_os = "linux")]
fn verify_leaf_binding(
    parent: &OwnedFd,
    parent_identity: &FdIdentity,
    leaf_dir_fd: &OwnedFd,
    leaf_dir_identity: &FdIdentity,
    name: &str,
) -> Result<(), CgroupError> {
    if stat_fd(parent)? != *parent_identity || stat_fd(leaf_dir_fd)? != *leaf_dir_identity {
        return Err(CgroupError::RequestMismatch);
    }
    if stat_at(parent, name)? != *leaf_dir_identity {
        return Err(CgroupError::RequestMismatch);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_created_leaf_or_required(
    error: CgroupError,
    parent: &OwnedFd,
    parent_identity: &FdIdentity,
    name: &str,
    leaf_binding: Option<(&OwnedFd, &FdIdentity)>,
) -> CgroupError {
    if cleanup_created_leaf(parent, parent_identity, name, leaf_binding) {
        error
    } else {
        CgroupError::LeafCleanupRequired
    }
}

#[cfg(target_os = "linux")]
fn cleanup_created_leaf(
    parent: &OwnedFd,
    parent_identity: &FdIdentity,
    name: &str,
    leaf_binding: Option<(&OwnedFd, &FdIdentity)>,
) -> bool {
    if stat_fd(parent).ok() != Some(*parent_identity) {
        return false;
    }
    let opened_leaf_guard = if let Some((leaf_dir_fd, leaf_dir_identity)) = leaf_binding {
        if verify_leaf_binding(
            parent,
            parent_identity,
            leaf_dir_fd,
            leaf_dir_identity,
            name,
        )
        .is_err()
        {
            return false;
        }
        None
    } else {
        let Ok(cleanup_leaf_fd) = open_dir_at(parent, name) else {
            return false;
        };
        let Ok(cleanup_leaf_identity) = stat_fd(&cleanup_leaf_fd) else {
            return false;
        };
        if verify_leaf_binding(
            parent,
            parent_identity,
            &cleanup_leaf_fd,
            &cleanup_leaf_identity,
            name,
        )
        .is_err()
        {
            return false;
        }
        Some(cleanup_leaf_fd)
    };
    let Ok(name) = make_cstring(name) else {
        return false;
    };
    // SAFETY: the stable parent fd and private name are validated above;
    // `AT_REMOVEDIR` lets the kernel reject a non-directory or nonempty leaf.
    let removed =
        unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) == 0 };
    drop(opened_leaf_guard);
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_name_is_fixed_lowercase_hex_and_hostile_names_are_rejected() {
        let id = CgroupLeafId::from_test_bytes([0xab; LEAF_BYTES]);
        let name = id.name();
        assert_eq!(name, "fcp-req-".to_owned() + &"ab".repeat(LEAF_BYTES));
        assert!(validate_leaf_name(&name).is_ok());
        for hostile in ["", ".", "..", "../escape", "fcp-req-zz"] {
            assert_eq!(validate_leaf_name(hostile), Err(CgroupError::InvalidLeaf));
        }
    }

    #[test]
    fn unified_membership_parser_is_strict() {
        assert_eq!(
            parse_unified_membership("0::/\n").unwrap().0,
            Vec::<String>::new()
        );
        assert_eq!(
            parse_unified_membership("0::/user.slice/foo\n").unwrap().0,
            vec!["user.slice".to_owned(), "foo".to_owned()]
        );
        for (input, expected) in [
            ("1:name=systemd:/foo\n", CgroupError::LegacyMembership),
            ("0::/one\n0::/two\n", CgroupError::DuplicateMembership),
            ("0:name=cpu:/foo\n", CgroupError::LegacyMembership),
            ("0::../escape\n", CgroupError::InvalidMembershipPath),
            ("0::/.\n", CgroupError::InvalidMembershipPath),
            ("0::/foo//bar\n", CgroupError::InvalidMembershipPath),
            ("0:/foo\n", CgroupError::MembershipMalformed),
        ] {
            assert_eq!(parse_unified_membership(input), Err(expected));
        }
    }

    #[test]
    fn populated_event_parser_requires_one_binary_populated_field() {
        assert!(!parse_populated_event("populated 0\nfrozen 0\n").unwrap());
        assert!(parse_populated_event("populated 1\nfrozen 0\n").unwrap());
        for input in [
            "populated\n",
            "frozen 0\n",
            "populated 0\npopulated 1\n",
            "populated 2\n",
            "populated=0\n",
            "populated 0 extra\n",
            "",
        ] {
            assert_eq!(
                parse_populated_event(input),
                Err(CgroupError::EventsMalformed)
            );
        }
    }

    #[test]
    fn state_machine_separates_release_from_teardown() {
        assert!(!state_can_release(CgroupState::Created));
        assert!(!state_can_release(CgroupState::HandoffIssued));
        assert!(!state_can_release(CgroupState::SupervisorAttached));
        assert!(!state_can_release(CgroupState::Verified));
        assert!(state_can_release(CgroupState::Released));
        assert!(!state_can_release(CgroupState::Killed));
        assert!(!state_can_release(CgroupState::Removed));
        assert!(!state_can_release(CgroupState::TerminalFailure));
        assert!(state_can_teardown(CgroupState::Created));
        assert!(state_can_teardown(CgroupState::HandoffIssued));
        assert!(state_can_teardown(CgroupState::SupervisorAttached));
        assert!(state_can_teardown(CgroupState::Verified));
        assert!(state_can_teardown(CgroupState::Released));
        assert!(!state_can_teardown(CgroupState::Killed));
        assert!(!state_can_teardown(CgroupState::Removed));
        assert!(!state_can_teardown(CgroupState::TerminalFailure));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn release_permit_binds_request_and_process_identity() {
        let stamp = RequestStamp([0x11; LEAF_BYTES]);
        let binding = ProcessBinding {
            stamp,
            pid: 73,
            start_time_ticks: 91,
        };
        let permit = TargetReleasePermit {
            stamp,
            pid: 73,
            start_time_ticks: 91,
        };
        assert!(permit_matches_binding(&binding, &permit));
        assert!(!permit_matches_binding(
            &binding,
            &TargetReleasePermit {
                stamp: RequestStamp([0x22; LEAF_BYTES]),
                pid: 73,
                start_time_ticks: 91,
            }
        ));
        assert!(!permit_matches_binding(
            &binding,
            &TargetReleasePermit {
                stamp,
                pid: 74,
                start_time_ticks: 91,
            }
        ));
    }

    #[test]
    fn errors_and_debug_values_are_redacted() {
        let id = CgroupLeafId::from_test_bytes([0xcd; LEAF_BYTES]);
        let name = id.name();
        assert!(!format!("{id:?}").contains(&name));
        assert!(!format!("{:?}", CgroupError::MembershipUnavailable).contains("/sys/fs/cgroup"));
        let permit = TargetReleasePermit {
            stamp: id.stamp(),
            #[cfg(target_os = "linux")]
            pid: 41,
            #[cfg(target_os = "linux")]
            start_time_ticks: 9,
        };
        assert!(!format!("{permit:?}").contains(&name));
        let lease = SupervisorAttachLease { stamp: id.stamp() };
        assert!(!format!("{lease:?}").contains(&name));
    }

    #[test]
    fn unavailable_and_delegation_fail_closed() {
        assert_eq!(
            classify_delegation_error(io::ErrorKind::NotFound),
            CgroupError::DelegationUnavailable
        );
        assert_eq!(
            classify_delegation_error(io::ErrorKind::PermissionDenied),
            CgroupError::DelegationUnavailable
        );
        assert_eq!(
            classify_delegation_error(io::ErrorKind::InvalidData),
            CgroupError::FdOperation
        );
    }
}
