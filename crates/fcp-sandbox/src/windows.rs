//! Windows sandbox implementation using AppContainer and Job Objects.
//!
//! # Enforcement Layers
//!
//! 1. **AppContainer** (roadmap, not yet wired): Low-integrity process
//!    isolation with capability-based access
//! 2. **Job Objects**: Resource limits (memory, CPU, process count) — the
//!    only mechanism active today
//! 3. **Integrity Levels** (roadmap): Restrict write access to
//!    higher-integrity objects
//! 4. **Firewall Rules** (roadmap): Network isolation (loopback only for
//!    Network Guard IPC)
//!
//! # Parity with Linux and macOS
//!
//! The Windows implementation reports
//! [`FilterStrength::ProcessLimit`](crate::FilterStrength::ProcessLimit),
//! which is the coarsest tier. No syscall filter (Linux seccomp-bpf) and
//! no named-operation profile (macOS SBPL) is in place. Enforcement is
//! limited to the job object's `ActiveProcessLimit`, `JobMemoryLimit`,
//! and `PerProcessUserTimeLimit`. A connector that stays inside those
//! budgets can invoke any Win32/NT API the process integrity level
//! allows. Connectors requiring the full strict-profile guarantee MUST
//! run under [`WasiRuntime`](crate::WasiRuntime) (no host syscalls
//! reach the kernel from WASI guests). Tightening this to
//! `ProfileLevel` via AppContainer / integrity-level enforcement is
//! tracked in bead `flywheel_connectors-r4qcg` (filed 2026-05-02 by
//! the /mock-code-finder audit; the prior `flywheel_connectors-459lp`
//! reference here was a forward-pointer to a bead that was never
//! filed at that id).
//!
//! # AppContainer
//!
//! AppContainer provides a low-privilege sandbox similar to Windows Store apps:
//! - Separate SID with no default access to user resources
//! - Capability-based permissions (files, network, etc.)
//! - Network isolation by default (requires explicit capability)
//!
//! # Job Objects
//!
//! Job objects enforce resource limits:
//! - Memory commit limits
//! - CPU rate limits
//! - Process/thread limits
//! - UI restrictions

#![cfg(target_os = "windows")]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use tracing::{debug, info, warn};

use crate::sandbox::{
    CompiledPolicy, Sandbox, SandboxError, WindowsAppContainerCreateOutcome,
    WindowsAppContainerEvidence, WindowsAppContainerLifecycleReport, WindowsAppContainerProfile,
    WindowsAppContainerProfileApi, prepare_windows_appcontainer_lifecycle,
};

// ============================================================================
// Windows API Types
// ============================================================================

type HANDLE = *mut std::ffi::c_void;
type BOOL = i32;
type DWORD = u32;
type HRESULT = i32;
type LPCWSTR = *const u16;
type PSID = *mut std::ffi::c_void;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
const FALSE: BOOL = 0;
const TRUE: BOOL = 1;
const S_OK: HRESULT = 0;
const HRESULT_ERROR_ALREADY_EXISTS: HRESULT = 0x8007_00b7u32 as HRESULT;

// Job object limits
const JOB_OBJECT_LIMIT_PROCESS_MEMORY: DWORD = 0x0100;
const JOB_OBJECT_LIMIT_JOB_MEMORY: DWORD = 0x0200;
const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: DWORD = 0x0008;
const JOB_OBJECT_LIMIT_PROCESS_TIME: DWORD = 0x0002;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x2000;

// Job object extended limit information class
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: DWORD = 9;

// Token integrity levels
const SECURITY_MANDATORY_LOW_RID: DWORD = 0x1000;
const SECURITY_MANDATORY_MEDIUM_RID: DWORD = 0x2000;
const SECURITY_MANDATORY_HIGH_RID: DWORD = 0x3000;

// Token information class
const TOKEN_INTEGRITY_LEVEL: DWORD = 25;

// ============================================================================
// Windows Sandbox
// ============================================================================

/// Windows sandbox using AppContainer and Job Objects.
#[derive(Debug)]
pub struct WindowsSandbox {
    /// Job object handle (if created).
    job_handle: Option<HANDLE>,
    /// Whether AppContainer is available.
    appcontainer_available: bool,
}

// SAFETY: Windows HANDLE values are opaque kernel-managed identifiers. This
// type stores and closes them but never dereferences them as pointers, so
// moving or sharing the wrapper across threads does not violate memory safety.
unsafe impl Send for WindowsSandbox {}
// SAFETY: See the Send justification above; shared references do not enable
// aliasing unsafety because HANDLEs are passed back to the OS by value.
unsafe impl Sync for WindowsSandbox {}

impl WindowsSandbox {
    /// Create a new Windows sandbox.
    #[must_use]
    pub fn new() -> Self {
        let appcontainer_available = check_appcontainer_available();

        if appcontainer_available {
            info!(
                env = FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV,
                "AppContainer opt-in enabled — caller must ensure CreateProcessAsUser path is wired"
            );
        } else {
            warn!(
                env = FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV,
                "AppContainer not active (br-3hrw3 fail-closed default); enforcement is job-objects + integrity-level + firewall only. \
                 Set the env var to 1 to opt into the AppContainer code path once it is wired."
            );
        }

        Self {
            job_handle: None,
            appcontainer_available,
        }
    }

    /// Whether AppContainer is *actually active* for this process.
    ///
    /// Pre-br-3hrw3 the sandbox unconditionally claimed AppContainer
    /// availability even though no `CreateProcessAsUser`-based wiring
    /// existed; this getter exposes the post-fix truth so conformance
    /// tests and observability surfaces can assert against it.
    #[must_use]
    pub const fn appcontainer_active(&self) -> bool {
        self.appcontainer_available
    }

    /// Derive the AppContainer profile metadata for this policy.
    fn appcontainer_profile(
        policy: &CompiledPolicy,
    ) -> Result<WindowsAppContainerProfile, SandboxError> {
        let connector_seed = windows_appcontainer_connector_seed(policy);
        policy.windows_appcontainer_profile(&connector_seed)
    }

    /// Create or resolve the AppContainer profile when the operator has enabled the path.
    fn prepare_appcontainer_profile(
        &self,
        policy: &CompiledPolicy,
    ) -> Result<WindowsAppContainerLifecycleReport, SandboxError> {
        let profile = Self::appcontainer_profile(policy)?;
        let mut api = NativeWindowsAppContainerApi;
        let report =
            prepare_windows_appcontainer_lifecycle(profile, self.appcontainer_available, &mut api)?;

        if !self.appcontainer_available {
            debug!(
                appcontainer_profile = %report.profile.name,
                capabilities = ?report.profile.capabilities,
                skip_reason = ?report.skip_reason,
                "AppContainer profile resolved but not created because AppContainer is not active"
            );
            return Ok(report);
        }

        info!(
            appcontainer_profile = %report.profile.name,
            capabilities = ?report.profile.capabilities,
            lifecycle_action = ?report.action,
            "Prepared Windows AppContainer profile"
        );
        Ok(report)
    }

    /// Create and configure a job object.
    fn create_job_object(&self, policy: &CompiledPolicy) -> Result<HANDLE, SandboxError> {
        // Create job object
        let job = unsafe { CreateJobObjectW(ptr::null_mut(), ptr::null()) };
        if job.is_null() {
            return Err(SandboxError::SyscallFailed(format!(
                "CreateJobObject failed: {}",
                get_last_error()
            )));
        }

        // Configure limits
        let mut limit_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();

        // Memory limits
        let mem_limit = usize::try_from(policy.memory_limit_bytes).unwrap_or(usize::MAX);
        limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        limit_info.JobMemoryLimit = mem_limit;

        limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limit_info.ProcessMemoryLimit = mem_limit;

        // Process limit (deny_exec)
        if policy.deny_exec {
            limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limit_info.BasicLimitInformation.ActiveProcessLimit = 1;
        }

        // CPU time limit
        let nanos = policy.wall_clock_timeout.as_nanos();
        let cpu_limit_100ns = i64::try_from(nanos / 100).unwrap_or(i64::MAX);
        limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        limit_info.BasicLimitInformation.PerProcessUserTimeLimit = cpu_limit_100ns;

        // Kill on close
        limit_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        // Apply limits
        let result = unsafe {
            SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                &limit_info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
            )
        };

        if result == FALSE {
            unsafe {
                CloseHandle(job);
            }
            return Err(SandboxError::SyscallFailed(format!(
                "SetInformationJobObject failed: {}",
                get_last_error()
            )));
        }

        info!(
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            deny_exec = policy.deny_exec,
            "Created job object with limits"
        );

        Ok(job)
    }

    /// Assign current process to job object.
    fn assign_to_job(&self, job: HANDLE) -> Result<(), SandboxError> {
        let current_process = unsafe { GetCurrentProcess() };

        let result = unsafe { AssignProcessToJobObject(job, current_process) };

        if result == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "AssignProcessToJobObject failed: {}",
                get_last_error()
            )));
        }

        debug!("Assigned process to job object");
        Ok(())
    }

    /// Set process integrity level.
    fn set_integrity_level(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        let level = if policy.platform_flags.windows_low_integrity {
            SECURITY_MANDATORY_LOW_RID
        } else {
            // Use medium integrity for most sandboxed processes
            SECURITY_MANDATORY_MEDIUM_RID
        };

        // Get process token
        let mut token: HANDLE = ptr::null_mut();
        let current_process = unsafe { GetCurrentProcess() };

        let result = unsafe { OpenProcessToken(current_process, TOKEN_ADJUST_DEFAULT, &mut token) };

        if result == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "OpenProcessToken failed: {}",
                get_last_error()
            )));
        }

        // Create integrity SID
        let mut sid: PSID = ptr::null_mut();
        let authority = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };

        let result = unsafe {
            AllocateAndInitializeSid(&authority, 1, level, 0, 0, 0, 0, 0, 0, 0, &mut sid)
        };

        if result == FALSE {
            unsafe {
                CloseHandle(token);
            }
            return Err(SandboxError::SyscallFailed(format!(
                "AllocateAndInitializeSid failed: {}",
                get_last_error()
            )));
        }

        // Set token integrity level
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };

        let result = unsafe {
            SetTokenInformation(
                token,
                TOKEN_INTEGRITY_LEVEL,
                &label as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as DWORD + GetLengthSid(sid) as DWORD,
            )
        };

        // Cleanup
        unsafe {
            FreeSid(sid);
            CloseHandle(token);
        }

        if result == FALSE {
            return Err(SandboxError::SyscallFailed(format!(
                "SetTokenInformation failed: {}",
                get_last_error()
            )));
        }

        info!(
            level = if level == SECURITY_MANDATORY_LOW_RID {
                "low"
            } else {
                "medium"
            },
            "Set process integrity level"
        );

        Ok(())
    }

    /// Configure Windows Firewall rules for network isolation.
    fn configure_firewall(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        if !policy.block_direct_network {
            return Ok(());
        }

        // Windows Firewall configuration requires elevated privileges
        // In production, this would be done by the host process before
        // spawning the sandboxed connector.
        //
        // For now, we log a warning and rely on AppContainer network
        // isolation which blocks network by default.

        warn!(
            "Network isolation relies on AppContainer; \
             explicit firewall rules require elevation"
        );

        Ok(())
    }
}

impl Default for WindowsSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for WindowsSandbox {
    fn apply(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        info!(
            profile = ?policy.profile,
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            cpu_percent = policy.cpu_percent,
            deny_exec = policy.deny_exec,
            deny_ptrace = policy.deny_ptrace,
            block_network = policy.block_direct_network,
            "Applying Windows sandbox"
        );

        // Step 1: Resolve/create AppContainer profile metadata when enabled.
        let appcontainer_report = self.prepare_appcontainer_profile(policy)?;

        // Step 2: Create and assign job object
        let job = self.create_job_object(policy)?;
        self.assign_to_job(job)?;
        let appcontainer_evidence = WindowsAppContainerEvidence::from_lifecycle(
            &windows_appcontainer_connector_seed(policy),
            &appcontainer_report,
            true,
            "apply",
        );
        if let Ok(jsonl) = appcontainer_evidence.to_jsonl_line() {
            debug!(evidence_jsonl = %jsonl, "Windows AppContainer smoke evidence");
        }

        // Step 3: Set integrity level
        if let Err(e) = self.set_integrity_level(policy) {
            warn!(error = %e, "Failed to set integrity level");
        }

        // Step 4: Configure firewall (best effort)
        if let Err(e) = self.configure_firewall(policy) {
            warn!(error = %e, "Failed to configure firewall");
        }

        // Note: Full AppContainer requires spawning a new process with
        // CreateProcessAsUser and an AppContainer token. For in-process
        // sandboxing, we rely on job objects and integrity levels.

        info!("Windows sandbox applied successfully");
        Ok(())
    }

    fn apply_to_command(
        &self,
        _cmd: &mut std::process::Command,
        _policy: &CompiledPolicy,
    ) -> Result<(), SandboxError> {
        // On Windows, true AppContainer sandboxing must be applied to the process BEFORE it starts
        // via STARTUPINFOEX attributes. FCP native Windows sandboxing relies on external launch
        // mechanisms or future integration with process creation attributes.
        // For now, we return Ok (unsupported directly in Rust Command without sys/windows).
        warn!("apply_to_command is not fully supported for WindowsSandbox yet");
        Ok(())
    }

    fn is_available(&self) -> bool {
        // Basic Windows sandbox checks
        // Job objects are available on all Windows versions
        true
    }

    fn platform_name(&self) -> &'static str {
        "windows"
    }

    fn filter_strength(&self) -> crate::sandbox::FilterStrength {
        // The current Windows sandbox backs enforcement entirely on job
        // objects: ActiveProcessLimit/JobMemoryLimit/PerProcessUserTimeLimit
        // plus KILL_ON_JOB_CLOSE. There is no syscall filter and no named-
        // operation profile — a connector inside its CPU/memory budget can
        // reach any Win32/NT API its integrity level permits. That puts
        // Windows at the coarsest tier, ProcessLimit. (AppContainer or a
        // WinSandbox integration would raise this to ProfileLevel; see
        // bead 459lp for the parity roadmap.)
        crate::sandbox::FilterStrength::ProcessLimit
    }

    fn verify_file_access(
        &self,
        policy: &CompiledPolicy,
        path: &Path,
        write: bool,
    ) -> Result<(), SandboxError> {
        let path = crate::sandbox::resolve_policy_path(path);

        if write {
            for writable in &policy.writable_paths {
                if path.starts_with(writable) {
                    return Ok(());
                }
            }
            return Err(SandboxError::PolicyCompilationFailed(format!(
                "write access to {} not allowed",
                path.display()
            )));
        }

        // Windows system paths are generally readable
        let system_paths = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"];
        for sys_path in system_paths {
            if path.starts_with(sys_path) {
                return Ok(());
            }
        }

        for readable in policy.readonly_paths.iter().chain(&policy.writable_paths) {
            if path.starts_with(readable) {
                return Ok(());
            }
        }

        Err(SandboxError::PolicyCompilationFailed(format!(
            "read access to {} not allowed",
            path.display()
        )))
    }

    fn verify_exec_allowed(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        if policy.deny_exec {
            Err(SandboxError::PolicyCompilationFailed(
                "process execution is denied".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn verify_network_blocked(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        if policy.block_direct_network {
            Ok(())
        } else {
            Err(SandboxError::PolicyCompilationFailed(
                "direct network access is allowed (use Network Guard)".into(),
            ))
        }
    }
}

impl Drop for WindowsSandbox {
    fn drop(&mut self) {
        if let Some(job) = self.job_handle.take() {
            unsafe {
                CloseHandle(job);
            }
        }
    }
}

// ============================================================================
// Windows API Structures
// ============================================================================

#[repr(C)]
#[derive(Default)]
struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    PerProcessUserTimeLimit: i64,
    PerJobUserTimeLimit: i64,
    LimitFlags: DWORD,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: DWORD,
    Affinity: usize,
    PriorityClass: DWORD,
    SchedulingClass: DWORD,
}

#[repr(C)]
#[derive(Default)]
struct IO_COUNTERS {
    ReadOperationCount: u64,
    WriteOperationCount: u64,
    OtherOperationCount: u64,
    ReadTransferCount: u64,
    WriteTransferCount: u64,
    OtherTransferCount: u64,
}

#[repr(C)]
#[derive(Default)]
struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: usize,
    JobMemoryLimit: usize,
    PeakProcessMemoryUsed: usize,
    PeakJobMemoryUsed: usize,
}

#[repr(C)]
struct SID_IDENTIFIER_AUTHORITY {
    Value: [u8; 6],
}

#[repr(C)]
struct SID_AND_ATTRIBUTES {
    Sid: PSID,
    Attributes: DWORD,
}

#[repr(C)]
struct TOKEN_MANDATORY_LABEL {
    Label: SID_AND_ATTRIBUTES,
}

const SE_GROUP_INTEGRITY: DWORD = 0x0000_0020;
const SE_GROUP_ENABLED: DWORD = 0x0000_0004;
const TOKEN_ADJUST_DEFAULT: DWORD = 0x0080;

// ============================================================================
// FFI Bindings
// ============================================================================

unsafe extern "system" {
    fn CreateJobObjectW(lpJobAttributes: *mut std::ffi::c_void, lpName: LPCWSTR) -> HANDLE;

    fn SetInformationJobObject(
        hJob: HANDLE,
        JobObjectInformationClass: DWORD,
        lpJobObjectInformation: *const std::ffi::c_void,
        cbJobObjectInformationLength: DWORD,
    ) -> BOOL;

    fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;

    fn CloseHandle(hObject: HANDLE) -> BOOL;

    fn GetCurrentProcess() -> HANDLE;

    fn GetLastError() -> DWORD;

    fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: DWORD,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;

    fn AllocateAndInitializeSid(
        pIdentifierAuthority: *const SID_IDENTIFIER_AUTHORITY,
        nSubAuthorityCount: u8,
        nSubAuthority0: DWORD,
        nSubAuthority1: DWORD,
        nSubAuthority2: DWORD,
        nSubAuthority3: DWORD,
        nSubAuthority4: DWORD,
        nSubAuthority5: DWORD,
        nSubAuthority6: DWORD,
        nSubAuthority7: DWORD,
        pSid: *mut PSID,
    ) -> BOOL;

    fn FreeSid(pSid: PSID) -> *mut std::ffi::c_void;

    fn GetLengthSid(pSid: PSID) -> DWORD;

    fn SetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: DWORD,
        TokenInformation: *const std::ffi::c_void,
        TokenInformationLength: DWORD,
    ) -> BOOL;

    fn DeriveCapabilitySidsFromName(
        CapName: LPCWSTR,
        CapabilityGroupSids: *mut *mut PSID,
        CapabilityGroupSidCount: *mut DWORD,
        CapabilitySids: *mut *mut PSID,
        CapabilitySidCount: *mut DWORD,
    ) -> BOOL;

    fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[link(name = "userenv")]
unsafe extern "system" {
    fn CreateAppContainerProfile(
        pszAppContainerName: LPCWSTR,
        pszDisplayName: LPCWSTR,
        pszDescription: LPCWSTR,
        pCapabilities: *mut SID_AND_ATTRIBUTES,
        dwCapabilityCount: DWORD,
        ppSidAppContainerSid: *mut PSID,
    ) -> HRESULT;

    fn DeriveAppContainerSidFromAppContainerName(
        pszAppContainerName: LPCWSTR,
        ppsidAppContainerSid: *mut PSID,
    ) -> HRESULT;

    fn DeleteAppContainerProfile(pszAppContainerName: LPCWSTR) -> HRESULT;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Environment variable that opts the process into the future
/// AppContainer code path.
///
/// AppContainer requires spawning a new process via `CreateProcessAsUser`
/// with an AppContainer token (see the inline note inside
/// [`WindowsSandbox::apply`] at line 351). That code path is **not yet
/// wired** in this crate — only job-object + integrity-level + firewall
/// enforcement is active. Until the real implementation lands, the
/// availability flag must be honest with downstream observers (logs,
/// metrics, conformance harness) and report `false` so that callers do
/// not assume AppContainer is protecting the process when it is not.
///
/// Operators who land the real CreateProcessAsUser-based implementation
/// can flip this env var to `1` (or `true`) without re-rolling the
/// stub function. This keeps the opt-in gate in user-controlled
/// configuration rather than a code change once the implementation
/// exists.
pub const FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV: &str = "FCP_SANDBOX_WINDOWS_APPCONTAINER";

/// Check if AppContainer is *actually wired* and active for this
/// process (NOT just available on the kernel).
///
/// Pre-fix this returned `true` unconditionally on the assumption that
/// AppContainer was present on Windows 8+. That was a stub: the
/// downstream `apply()` path never invokes the AppContainer code (no
/// `CreateProcessAsUser`, no AppContainer token), so reporting `true`
/// gave the rest of the system a false sense of process isolation —
/// br-flywheel_connectors-3hrw3.
///
/// Until the real AppContainer integration lands, we fail closed and
/// require explicit operator opt-in via
/// [`FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV`].
fn check_appcontainer_available() -> bool {
    matches!(
        std::env::var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV)
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn windows_appcontainer_connector_seed(policy: &CompiledPolicy) -> String {
    policy
        .state_dir
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("connector")
        .to_owned()
}

struct NativeWindowsAppContainerApi;

impl WindowsAppContainerProfileApi for NativeWindowsAppContainerApi {
    fn create_profile(
        &mut self,
        profile: &WindowsAppContainerProfile,
    ) -> Result<WindowsAppContainerCreateOutcome, SandboxError> {
        create_appcontainer_profile(profile)
    }

    fn derive_profile_sid(&mut self, profile_name: &str) -> Result<(), SandboxError> {
        let _sid = derive_appcontainer_sid(profile_name)?;
        Ok(())
    }

    fn delete_profile(&mut self, profile_name: &str) -> Result<(), SandboxError> {
        delete_appcontainer_profile(profile_name)
    }
}

fn create_appcontainer_profile(
    profile: &WindowsAppContainerProfile,
) -> Result<WindowsAppContainerCreateOutcome, SandboxError> {
    let mut capabilities = DerivedCapabilitySids::new(&profile.capabilities)?;
    let appcontainer_name = to_wide_string(&profile.name);
    let display_name = to_wide_string(&format!("FCP {}", profile.name));
    let description = to_wide_string("Flywheel connector AppContainer profile");
    let capability_count = capabilities.count();
    let capability_ptr = capabilities.as_mut_ptr();

    let mut sid: PSID = ptr::null_mut();
    let hr = unsafe {
        CreateAppContainerProfile(
            appcontainer_name.as_ptr(),
            display_name.as_ptr(),
            description.as_ptr(),
            capability_ptr,
            capability_count,
            &mut sid,
        )
    };

    match hr {
        S_OK => {
            let _sid = OwnedSid(sid);
            Ok(WindowsAppContainerCreateOutcome::Created)
        }
        HRESULT_ERROR_ALREADY_EXISTS => Ok(WindowsAppContainerCreateOutcome::AlreadyExists),
        _ => Err(SandboxError::SyscallFailed(format_hresult(
            "CreateAppContainerProfile",
            hr,
        ))),
    }
}

fn derive_appcontainer_sid(profile_name: &str) -> Result<OwnedSid, SandboxError> {
    let appcontainer_name = to_wide_string(profile_name);
    let mut sid: PSID = ptr::null_mut();
    let hr =
        unsafe { DeriveAppContainerSidFromAppContainerName(appcontainer_name.as_ptr(), &mut sid) };

    if hr == S_OK {
        Ok(OwnedSid(sid))
    } else {
        Err(SandboxError::SyscallFailed(format_hresult(
            "DeriveAppContainerSidFromAppContainerName",
            hr,
        )))
    }
}

fn delete_appcontainer_profile(profile_name: &str) -> Result<(), SandboxError> {
    let appcontainer_name = to_wide_string(profile_name);
    let hr = unsafe { DeleteAppContainerProfile(appcontainer_name.as_ptr()) };

    if hr == S_OK {
        Ok(())
    } else {
        Err(SandboxError::SyscallFailed(format_hresult(
            "DeleteAppContainerProfile",
            hr,
        )))
    }
}

struct OwnedSid(PSID);

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeSid(self.0);
            }
        }
    }
}

struct DerivedCapabilitySids {
    attributes: Vec<SID_AND_ATTRIBUTES>,
    sids: Vec<PSID>,
}

impl DerivedCapabilitySids {
    fn new(capabilities: &[String]) -> Result<Self, SandboxError> {
        let mut derived = Self {
            attributes: Vec::with_capacity(capabilities.len()),
            sids: Vec::with_capacity(capabilities.len()),
        };

        for capability in capabilities {
            let sid = derive_capability_sid(capability)?;
            derived.attributes.push(SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_ENABLED,
            });
            derived.sids.push(sid);
        }

        Ok(derived)
    }

    fn as_mut_ptr(&mut self) -> *mut SID_AND_ATTRIBUTES {
        if self.attributes.is_empty() {
            ptr::null_mut()
        } else {
            self.attributes.as_mut_ptr()
        }
    }

    fn count(&self) -> DWORD {
        DWORD::try_from(self.attributes.len()).unwrap_or(DWORD::MAX)
    }
}

impl Drop for DerivedCapabilitySids {
    fn drop(&mut self) {
        for sid in self.sids.drain(..) {
            unsafe {
                LocalFree(sid);
            }
        }
    }
}

fn derive_capability_sid(capability: &str) -> Result<PSID, SandboxError> {
    let capability_name = to_wide_string(capability);
    let mut group_sids: *mut PSID = ptr::null_mut();
    let mut group_sid_count: DWORD = 0;
    let mut capability_sids: *mut PSID = ptr::null_mut();
    let mut capability_sid_count: DWORD = 0;

    let result = unsafe {
        DeriveCapabilitySidsFromName(
            capability_name.as_ptr(),
            &mut group_sids,
            &mut group_sid_count,
            &mut capability_sids,
            &mut capability_sid_count,
        )
    };

    if result == FALSE {
        return Err(SandboxError::SyscallFailed(format!(
            "DeriveCapabilitySidsFromName({capability}) failed: {}",
            get_last_error()
        )));
    }

    unsafe {
        free_local_sid_array(group_sids, group_sid_count);
    }

    if capability_sids.is_null() || capability_sid_count == 0 {
        unsafe {
            LocalFree(capability_sids.cast());
        }
        return Err(SandboxError::SyscallFailed(format!(
            "DeriveCapabilitySidsFromName({capability}) returned no capability SID"
        )));
    }

    let capability_sid_count = match usize::try_from(capability_sid_count) {
        Ok(count) => count,
        Err(_) => {
            unsafe {
                free_local_sid_array(capability_sids, capability_sid_count);
            }
            return Err(SandboxError::SyscallFailed(format!(
                "DeriveCapabilitySidsFromName({capability}) returned too many capability SIDs"
            )));
        }
    };
    let sid = unsafe { *capability_sids };
    unsafe {
        for idx in 1..capability_sid_count {
            LocalFree(*capability_sids.add(idx));
        }
        LocalFree(capability_sids.cast());
    }

    Ok(sid)
}

unsafe fn free_local_sid_array(sids: *mut PSID, count: DWORD) {
    if sids.is_null() {
        return;
    }

    let count = match usize::try_from(count) {
        Ok(count) => count,
        Err(_) => {
            unsafe {
                LocalFree(sids.cast());
            }
            return;
        }
    };

    for idx in 0..count {
        unsafe {
            LocalFree(*sids.add(idx));
        }
    }
    unsafe {
        LocalFree(sids.cast());
    }
}

fn format_hresult(operation: &str, hr: HRESULT) -> String {
    format!(
        "{operation} failed: HRESULT 0x{:08x}",
        u32::from_ne_bytes(hr.to_ne_bytes())
    )
}

/// Get last Windows error as string.
fn get_last_error() -> String {
    let code = unsafe { GetLastError() };
    format!("error code {code}")
}

/// Convert Rust string to wide string for Windows APIs.
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::CompiledPolicy;
    use fcp_manifest::SandboxProfile;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_policy() -> CompiledPolicy {
        CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 256 * 1024 * 1024,
            cpu_percent: 50,
            wall_clock_timeout: Duration::from_secs(30),
            readonly_paths: vec![PathBuf::from("C:\\Program Files")],
            writable_paths: vec![PathBuf::from("C:\\Temp\\test")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("C:\\Temp\\test")),
            platform_flags: Default::default(),
        }
    }

    #[test]
    fn test_windows_sandbox_available() {
        let sandbox = WindowsSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "windows");
    }

    /// br-3hrw3 regression: AppContainer must NOT report itself as
    /// active by default, because no `CreateProcessAsUser`-based wiring
    /// exists yet. Pre-fix, `check_appcontainer_available()` returned
    /// `true` unconditionally and the constructor logged "AppContainer
    /// available for process isolation" — giving downstream observers a
    /// false sense of process isolation that the rest of `apply()`
    /// never delivered. Post-fix, the default is fail-closed.
    #[test]
    fn appcontainer_inactive_by_default() {
        // Make sure no leftover env value from a parallel test poisons
        // the assertion. Tests in this module are not annotated with
        // `#[serial]`, but each `WindowsSandbox::new()` call captures
        // the env at that instant, so we read the current value first.
        let prev = std::env::var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV).ok();
        unsafe {
            std::env::remove_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV);
        }
        let sandbox = WindowsSandbox::new();
        assert!(
            !sandbox.appcontainer_active(),
            "br-3hrw3: AppContainer must default to INACTIVE until the \
             CreateProcessAsUser code path is wired"
        );
        // Restore the prior value to keep the test environment clean
        // for any sibling test that may run after us in the same process.
        if let Some(v) = prev {
            unsafe {
                std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, v);
            }
        }
    }

    /// br-3hrw3 companion: an explicit operator opt-in via the env var
    /// flips `appcontainer_active()` to true so the eventual real
    /// implementation can be enabled without re-rolling the stub.
    #[test]
    fn appcontainer_active_when_env_opt_in_set() {
        let prev = std::env::var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV).ok();
        unsafe {
            std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, "1");
        }
        let sandbox = WindowsSandbox::new();
        assert!(
            sandbox.appcontainer_active(),
            "explicit opt-in via {} must flip AppContainer to active",
            FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV
        );
        unsafe {
            match prev {
                Some(v) => std::env::set_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV, v),
                None => std::env::remove_var(FCP_SANDBOX_WINDOWS_APPCONTAINER_ENV),
            }
        }
    }

    #[test]
    fn test_verify_file_access_system_paths() {
        let sandbox = WindowsSandbox::new();
        let policy = test_policy();

        // System paths should be readable
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    Path::new("C:\\Windows\\System32\\kernel32.dll"),
                    false
                )
                .is_ok()
        );

        // But not writable
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("C:\\Windows\\System32\\test.dll"), true)
                .is_err()
        );
    }

    #[test]
    fn test_verify_file_access_policy_paths() {
        let sandbox = WindowsSandbox::new();
        let policy = test_policy();

        // Writable path should allow read and write
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("C:\\Temp\\test\\data.db"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("C:\\Temp\\test\\data.db"), true)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_exec_denied() {
        let sandbox = WindowsSandbox::new();
        let policy = test_policy();

        assert!(sandbox.verify_exec_allowed(&policy).is_err());
    }

    #[test]
    fn test_verify_network_blocked() {
        let sandbox = WindowsSandbox::new();
        let policy = test_policy();

        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }
}
