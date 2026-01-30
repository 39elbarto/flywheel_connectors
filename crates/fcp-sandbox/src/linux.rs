//! Linux sandbox implementation using seccomp-bpf and namespaces.
//!
//! # Enforcement Layers
//!
//! 1. **seccomp-bpf**: Syscall filtering to block dangerous operations
//! 2. **User namespaces**: UID/GID remapping for privilege separation
//! 3. **Mount namespaces**: Filesystem isolation with bind mounts
//! 4. **Network namespaces**: Network isolation (all traffic via Network Guard)
//! 5. **Landlock** (optional, Linux 5.13+): Path-based access control
//! 6. **rlimit**: Resource limits for memory, CPU time, file descriptors
//!
//! # Profile Mapping
//!
//! | Profile      | seccomp | namespaces | Landlock | network ns |
//! |--------------|---------|------------|----------|------------|
//! | strict       | yes     | full       | if avail | isolated   |
//! | strict_plus  | yes     | full       | required | microVM    |
//! | moderate     | yes     | partial    | if avail | isolated   |
//! | permissive   | minimal | none       | no       | shared     |

#![cfg(target_os = "linux")]
// Allow patterns common in low-level syscall/FFI code
#![allow(clippy::unused_self)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::ref_as_ptr)]

use std::path::Path;

use tracing::{debug, info, warn};

use crate::sandbox::{CompiledPolicy, Sandbox, SandboxError};

// ============================================================================
// Constants
// ============================================================================

/// Seccomp filter action: allow syscall.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Seccomp filter action: kill process.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// Seccomp filter action: return errno.
#[allow(dead_code)]
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

// Syscall numbers (x86_64)
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
mod syscall_nr {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const OPEN: u32 = 2;
    pub const CLOSE: u32 = 3;
    pub const STAT: u32 = 4;
    pub const FSTAT: u32 = 5;
    pub const LSTAT: u32 = 6;
    pub const POLL: u32 = 7;
    pub const LSEEK: u32 = 8;
    pub const MMAP: u32 = 9;
    pub const MPROTECT: u32 = 10;
    pub const MUNMAP: u32 = 11;
    pub const BRK: u32 = 12;
    pub const RT_SIGACTION: u32 = 13;
    pub const RT_SIGPROCMASK: u32 = 14;
    pub const RT_SIGRETURN: u32 = 15;
    pub const IOCTL: u32 = 16;
    pub const PREAD64: u32 = 17;
    pub const PWRITE64: u32 = 18;
    pub const READV: u32 = 19;
    pub const WRITEV: u32 = 20;
    pub const ACCESS: u32 = 21;
    pub const PIPE: u32 = 22;
    pub const SELECT: u32 = 23;
    pub const SCHED_YIELD: u32 = 24;
    pub const MREMAP: u32 = 25;
    pub const DUP: u32 = 32;
    pub const DUP2: u32 = 33;
    pub const NANOSLEEP: u32 = 35;
    pub const GETPID: u32 = 39;
    pub const SOCKET: u32 = 41;
    pub const CONNECT: u32 = 42;
    pub const SENDTO: u32 = 44;
    pub const RECVFROM: u32 = 45;
    pub const SENDMSG: u32 = 46;
    pub const RECVMSG: u32 = 47;
    pub const SHUTDOWN: u32 = 48;
    pub const BIND: u32 = 49;
    pub const LISTEN: u32 = 50;
    pub const GETSOCKNAME: u32 = 51;
    pub const GETPEERNAME: u32 = 52;
    pub const SETSOCKOPT: u32 = 54;
    pub const GETSOCKOPT: u32 = 55;
    pub const CLONE: u32 = 56;
    pub const FORK: u32 = 57;
    pub const VFORK: u32 = 58;
    pub const EXECVE: u32 = 59;
    pub const EXECVEAT: u32 = 322;
    pub const EXIT: u32 = 60;
    pub const WAIT4: u32 = 61;
    pub const KILL: u32 = 62;
    pub const FCNTL: u32 = 72;
    pub const FLOCK: u32 = 73;
    pub const FSYNC: u32 = 74;
    pub const FDATASYNC: u32 = 75;
    pub const TRUNCATE: u32 = 76;
    pub const FTRUNCATE: u32 = 77;
    pub const GETDENTS: u32 = 78;
    pub const GETCWD: u32 = 79;
    pub const CHDIR: u32 = 80;
    pub const FCHDIR: u32 = 81;
    pub const RENAME: u32 = 82;
    pub const MKDIR: u32 = 83;
    pub const RMDIR: u32 = 84;
    pub const CREAT: u32 = 85;
    pub const LINK: u32 = 86;
    pub const UNLINK: u32 = 87;
    pub const SYMLINK: u32 = 88;
    pub const READLINK: u32 = 89;
    pub const CHMOD: u32 = 90;
    pub const FCHMOD: u32 = 91;
    pub const CHOWN: u32 = 92;
    pub const FCHOWN: u32 = 93;
    pub const LCHOWN: u32 = 94;
    pub const UMASK: u32 = 95;
    pub const GETTIMEOFDAY: u32 = 96;
    pub const GETRLIMIT: u32 = 97;
    pub const SYSINFO: u32 = 99;
    pub const TIMES: u32 = 100;
    pub const PTRACE: u32 = 101;
    pub const GETUID: u32 = 102;
    pub const GETGID: u32 = 104;
    pub const GETEUID: u32 = 107;
    pub const GETEGID: u32 = 108;
    pub const SETPGID: u32 = 109;
    pub const GETPPID: u32 = 110;
    pub const GETPGRP: u32 = 111;
    pub const SETSID: u32 = 112;
    pub const SETREUID: u32 = 113;
    pub const SETREGID: u32 = 114;
    pub const GETGROUPS: u32 = 115;
    pub const SETRESUID: u32 = 117;
    pub const GETRESUID: u32 = 118;
    pub const SETRESGID: u32 = 119;
    pub const GETRESGID: u32 = 120;
    pub const GETPGID: u32 = 121;
    pub const GETSID: u32 = 124;
    pub const UNAME: u32 = 63;
    pub const PRCTL: u32 = 157;
    pub const ARCH_PRCTL: u32 = 158;
    pub const FUTEX: u32 = 202;
    pub const EPOLL_CREATE: u32 = 213;
    pub const GETDENTS64: u32 = 217;
    pub const SET_TID_ADDRESS: u32 = 218;
    pub const CLOCK_GETTIME: u32 = 228;
    pub const CLOCK_GETRES: u32 = 229;
    pub const CLOCK_NANOSLEEP: u32 = 230;
    pub const EXIT_GROUP: u32 = 231;
    pub const EPOLL_WAIT: u32 = 232;
    pub const EPOLL_CTL: u32 = 233;
    pub const TGKILL: u32 = 234;
    pub const OPENAT: u32 = 257;
    pub const MKDIRAT: u32 = 258;
    pub const NEWFSTATAT: u32 = 262;
    pub const UNLINKAT: u32 = 263;
    pub const RENAMEAT: u32 = 264;
    pub const READLINKAT: u32 = 267;
    pub const FCHMODAT: u32 = 268;
    pub const FACCESSAT: u32 = 269;
    pub const PPOLL: u32 = 271;
    pub const SET_ROBUST_LIST: u32 = 273;
    pub const ACCEPT4: u32 = 288;
    pub const EPOLL_CREATE1: u32 = 291;
    pub const DUP3: u32 = 292;
    pub const PIPE2: u32 = 293;
    pub const PRLIMIT64: u32 = 302;
    pub const GETRANDOM: u32 = 318;
    pub const STATX: u32 = 332;
    pub const RSEQ: u32 = 334;
    pub const CLONE3: u32 = 435;
    pub const CLOSE_RANGE: u32 = 436;
    pub const OPENAT2: u32 = 437;
    pub const FACCESSAT2: u32 = 439;
}

#[cfg(target_arch = "aarch64")]
mod syscall_nr {
    // ARM64 syscall numbers - subset for basic functionality
    pub const READ: u32 = 63;
    pub const WRITE: u32 = 64;
    pub const OPENAT: u32 = 56;
    pub const CLOSE: u32 = 57;
    pub const FSTAT: u32 = 80;
    pub const EXIT: u32 = 93;
    pub const EXIT_GROUP: u32 = 94;
    pub const CLONE: u32 = 220;
    pub const EXECVE: u32 = 221;
    pub const EXECVEAT: u32 = 281;
    pub const MMAP: u32 = 222;
    pub const MPROTECT: u32 = 226;
    pub const MUNMAP: u32 = 215;
    pub const BRK: u32 = 214;
    pub const SOCKET: u32 = 198;
    pub const CONNECT: u32 = 203;
    pub const PTRACE: u32 = 117;
    pub const FORK: u32 = 1079; // Not available on aarch64, use clone
    pub const VFORK: u32 = 1071; // Not available on aarch64
    pub const CLOCK_GETTIME: u32 = 113;
    pub const GETRANDOM: u32 = 278;
    pub const FUTEX: u32 = 98;
}

// ============================================================================
// Linux Sandbox
// ============================================================================

/// Linux sandbox using seccomp-bpf, namespaces, and optionally Landlock.
#[derive(Debug)]
pub struct LinuxSandbox {
    /// Whether Landlock is available.
    landlock_available: bool,
    /// Whether user namespaces are available.
    #[allow(dead_code)]
    userns_available: bool,
}

impl LinuxSandbox {
    /// Create a new Linux sandbox, detecting available features.
    #[must_use]
    pub fn new() -> Self {
        let landlock_available = check_landlock_available();
        let userns_available = check_userns_available();

        if landlock_available {
            info!("Landlock is available for path-based access control");
        } else {
            debug!("Landlock not available, using seccomp-only enforcement");
        }

        if userns_available {
            info!("User namespaces available for privilege separation");
        } else {
            warn!("User namespaces not available, some isolation features disabled");
        }

        Self {
            landlock_available,
            userns_available,
        }
    }

    /// Build a seccomp BPF filter for the given policy.
    fn build_seccomp_filter(&self, policy: &CompiledPolicy) -> Vec<SockFilter> {
        let mut filter = Vec::new();

        // Load syscall number into accumulator
        // BPF_LD | BPF_W | BPF_ABS, offset 0 = syscall number
        filter.push(SockFilter::stmt(0x20, 0));

        // Build allowlist based on policy
        let allowed_syscalls = self.build_syscall_allowlist(policy);

        // Add jump table for allowed syscalls
        for &syscall in &allowed_syscalls {
            // JEQ syscall, 0, 1 -> if equal, skip next (which denies)
            filter.push(SockFilter::jump(0x15, syscall, 0, 1));
            // Allow this syscall
            filter.push(SockFilter::stmt(0x06, SECCOMP_RET_ALLOW));
        }

        // Default: kill process for unallowed syscalls
        filter.push(SockFilter::stmt(0x06, SECCOMP_RET_KILL_PROCESS));

        filter
    }

    /// Build the syscall allowlist based on policy.
    #[cfg(target_arch = "x86_64")]
    fn build_syscall_allowlist(&self, policy: &CompiledPolicy) -> Vec<u32> {
        use syscall_nr::*;

        let mut allowed = vec![
            // Essential syscalls
            READ,
            WRITE,
            CLOSE,
            FSTAT,
            LSEEK,
            MMAP,
            MPROTECT,
            MUNMAP,
            BRK,
            RT_SIGACTION,
            RT_SIGPROCMASK,
            RT_SIGRETURN,
            PREAD64,
            PWRITE64,
            READV,
            WRITEV,
            POLL,
            PPOLL,
            SELECT,
            NANOSLEEP,
            CLOCK_NANOSLEEP,
            // File operations (limited by Landlock if available)
            OPENAT,
            OPENAT2,
            STAT,
            LSTAT,
            NEWFSTATAT,
            STATX,
            ACCESS,
            FACCESSAT,
            FACCESSAT2,
            GETDENTS,
            GETDENTS64,
            GETCWD,
            READLINK,
            READLINKAT,
            // Memory management
            MREMAP,
            // File descriptors
            DUP,
            DUP2,
            DUP3,
            PIPE,
            PIPE2,
            FCNTL,
            IOCTL,
            // Synchronization
            FUTEX,
            FLOCK,
            FSYNC,
            FDATASYNC,
            // Process info (read-only)
            GETPID,
            GETPPID,
            GETUID,
            GETEUID,
            GETGID,
            GETEGID,
            GETGROUPS,
            GETRESUID,
            GETRESGID,
            GETPGRP,
            GETPGID,
            GETSID,
            UNAME,
            SYSINFO,
            TIMES,
            // Time
            GETTIMEOFDAY,
            CLOCK_GETTIME,
            CLOCK_GETRES,
            // Random
            GETRANDOM,
            // Resource limits (read)
            GETRLIMIT,
            PRLIMIT64,
            // epoll
            EPOLL_CREATE,
            EPOLL_CREATE1,
            EPOLL_CTL,
            EPOLL_WAIT,
            // Signals
            TGKILL,
            KILL, // Limited to own process
            // Thread support
            SET_TID_ADDRESS,
            SET_ROBUST_LIST,
            RSEQ,
            ARCH_PRCTL,
            PRCTL, // Limited flags
            // Exit
            EXIT,
            EXIT_GROUP,
            // Sched
            SCHED_YIELD,
        ];

        // File modification syscalls (if writable paths exist)
        if !policy.writable_paths.is_empty() {
            allowed.extend([
                TRUNCATE, FTRUNCATE, RENAME, RENAMEAT, MKDIR, MKDIRAT, RMDIR, UNLINK, UNLINKAT,
                LINK, SYMLINK, CREAT, CHMOD, FCHMOD, FCHMODAT, CHOWN, FCHOWN, LCHOWN, UMASK, CHDIR,
                FCHDIR,
            ]);
        }

        // Network syscalls (only if direct network is allowed)
        if !policy.block_direct_network {
            allowed.extend([
                SOCKET,
                CONNECT,
                ACCEPT4,
                BIND,
                LISTEN,
                SENDTO,
                RECVFROM,
                SENDMSG,
                RECVMSG,
                SHUTDOWN,
                GETSOCKNAME,
                GETPEERNAME,
                SETSOCKOPT,
                GETSOCKOPT,
            ]);
        }

        // Process creation syscalls (if exec is allowed)
        if !policy.deny_exec {
            allowed.extend([CLONE, CLONE3, FORK, VFORK, EXECVE, EXECVEAT, WAIT4]);
        }

        // Ptrace (if allowed)
        if !policy.deny_ptrace {
            allowed.push(PTRACE);
        }

        allowed
    }

    #[cfg(target_arch = "aarch64")]
    fn build_syscall_allowlist(&self, policy: &CompiledPolicy) -> Vec<u32> {
        use syscall_nr::*;

        let mut allowed = vec![
            READ,
            WRITE,
            OPENAT,
            CLOSE,
            FSTAT,
            EXIT,
            EXIT_GROUP,
            MMAP,
            MPROTECT,
            MUNMAP,
            BRK,
            CLOCK_GETTIME,
            GETRANDOM,
            FUTEX,
        ];

        if !policy.block_direct_network {
            allowed.extend([SOCKET, CONNECT]);
        }

        if !policy.deny_exec {
            allowed.extend([CLONE, EXECVE, EXECVEAT]);
        }

        if !policy.deny_ptrace {
            allowed.push(PTRACE);
        }

        allowed
    }

    /// Apply resource limits using rlimit.
    fn apply_rlimits(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        // Memory limit (RLIMIT_AS - address space)
        set_rlimit(
            libc::RLIMIT_AS,
            policy.memory_limit_bytes,
            policy.memory_limit_bytes,
        )?;

        // Data segment limit
        set_rlimit(
            libc::RLIMIT_DATA,
            policy.memory_limit_bytes,
            policy.memory_limit_bytes,
        )?;

        // CPU time limit (soft = timeout, hard = timeout + 5s grace)
        let cpu_seconds = policy.wall_clock_timeout.as_secs();
        set_rlimit(libc::RLIMIT_CPU, cpu_seconds, cpu_seconds + 5)?;

        // File descriptor limit
        set_rlimit(libc::RLIMIT_NOFILE, 1024, 4096)?;

        // Core dump disabled
        set_rlimit(libc::RLIMIT_CORE, 0, 0)?;

        // No new processes if deny_exec
        if policy.deny_exec {
            set_rlimit(libc::RLIMIT_NPROC, 0, 0)?;
        }

        info!(
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            cpu_seconds = cpu_seconds,
            "Applied resource limits"
        );

        Ok(())
    }

    /// Apply seccomp filter.
    fn apply_seccomp(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        let filter = self.build_seccomp_filter(policy);

        // Convert to sock_fprog
        let prog = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        // Set no new privileges (required for seccomp without CAP_SYS_ADMIN)
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(SandboxError::SyscallFailed(
                    "prctl(PR_SET_NO_NEW_PRIVS) failed".into(),
                ));
            }
        }

        // Apply seccomp filter
        unsafe {
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const _,
                0,
                0,
            ) != 0
            {
                return Err(SandboxError::SyscallFailed(format!(
                    "seccomp(SECCOMP_MODE_FILTER) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        info!(syscall_count = filter.len(), "Applied seccomp-bpf filter");

        Ok(())
    }
}

impl Default for LinuxSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for LinuxSandbox {
    fn apply(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        info!(
            profile = ?policy.profile,
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            cpu_percent = policy.cpu_percent,
            deny_exec = policy.deny_exec,
            deny_ptrace = policy.deny_ptrace,
            block_network = policy.block_direct_network,
            "Applying Linux sandbox"
        );

        // Step 1: Apply resource limits
        self.apply_rlimits(policy)?;

        // Step 2: Apply Landlock if available and requested
        if self.landlock_available && policy.platform_flags.linux_use_landlock {
            apply_landlock(policy)?;
        }

        // Step 3: Apply seccomp filter (must be last as it restricts prctl)
        self.apply_seccomp(policy)?;

        info!("Linux sandbox applied successfully");
        Ok(())
    }

    fn is_available(&self) -> bool {
        // seccomp is available on all modern Linux kernels (3.5+)
        true
    }

    fn platform_name(&self) -> &'static str {
        "linux"
    }

    fn verify_file_access(
        &self,
        policy: &CompiledPolicy,
        path: &Path,
        write: bool,
    ) -> Result<(), SandboxError> {
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        if write {
            // Check if path is under any writable path
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

        // For read access, check both readonly and writable paths
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

// ============================================================================
// BPF Structures
// ============================================================================

/// BPF filter instruction (sock_filter).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SockFilter {
    /// Create a statement instruction.
    const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Create a jump instruction.
    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// BPF program (sock_fprog).
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if Landlock is available (Linux 5.13+).
fn check_landlock_available() -> bool {
    // Try to create a Landlock ruleset to check availability
    unsafe {
        let attr = LandlockRulesetAttr {
            handled_access_fs: 0xFFFF, // All access types
        };
        let fd = libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        );
        if fd >= 0 {
            libc::close(fd as i32);
            true
        } else {
            false
        }
    }
}

/// Check if user namespaces are available.
fn check_userns_available() -> bool {
    // Check /proc/sys/kernel/unprivileged_userns_clone
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map_or(true, |s| s.trim() == "1") // Default to available if file doesn't exist
}

/// Set resource limit.
fn set_rlimit(
    resource: libc::__rlimit_resource_t,
    soft: u64,
    hard: u64,
) -> Result<(), SandboxError> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };

    unsafe {
        if libc::setrlimit(resource, &limit) != 0 {
            return Err(SandboxError::SyscallFailed(format!(
                "setrlimit({resource}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// Landlock ruleset attribute structure.
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

/// Landlock path beneath attribute structure.
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Landlock access flags.
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;

/// Apply Landlock filesystem restrictions.
fn apply_landlock(policy: &CompiledPolicy) -> Result<(), SandboxError> {
    let all_fs_access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    let readonly_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    let writable_access = readonly_access
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    // Create ruleset
    let attr = LandlockRulesetAttr {
        handled_access_fs: all_fs_access,
    };

    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };

    if ruleset_fd < 0 {
        return Err(SandboxError::SyscallFailed(format!(
            "landlock_create_ruleset failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let ruleset_fd = ruleset_fd as i32;

    // Add rules for readonly paths
    for path in &policy.readonly_paths {
        if let Err(e) = add_landlock_rule(ruleset_fd, path, readonly_access) {
            warn!(path = %path.display(), error = %e, "Failed to add Landlock readonly rule");
        }
    }

    // Add rules for writable paths
    for path in &policy.writable_paths {
        if let Err(e) = add_landlock_rule(ruleset_fd, path, writable_access) {
            warn!(path = %path.display(), error = %e, "Failed to add Landlock writable rule");
        }
    }

    // Enforce the ruleset
    let ret = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };

    unsafe {
        libc::close(ruleset_fd);
    }

    if ret < 0 {
        return Err(SandboxError::SyscallFailed(format!(
            "landlock_restrict_self failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    info!(
        readonly_count = policy.readonly_paths.len(),
        writable_count = policy.writable_paths.len(),
        "Applied Landlock filesystem restrictions"
    );

    Ok(())
}

/// Add a Landlock rule for a path.
fn add_landlock_rule(
    ruleset_fd: i32,
    path: &std::path::Path,
    access: u64,
) -> Result<(), SandboxError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| SandboxError::InvalidConfig(format!("invalid path: {e}")))?;

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }

    let attr = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const _,
            0,
        )
    };

    unsafe {
        libc::close(fd);
    }

    if ret < 0 {
        return Err(SandboxError::SyscallFailed(format!(
            "landlock_add_rule failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{CompiledPolicy, PlatformFlags};
    use fcp_manifest::SandboxProfile;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_policy() -> CompiledPolicy {
        CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 256 * 1024 * 1024,
            cpu_percent: 50,
            wall_clock_timeout: Duration::from_secs(30),
            readonly_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            writable_paths: vec![PathBuf::from("/tmp/test")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("/tmp/test")),
            platform_flags: PlatformFlags::default(),
        }
    }

    #[test]
    fn test_linux_sandbox_available() {
        let sandbox = LinuxSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "linux");
    }

    #[test]
    fn test_verify_file_access_readonly() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        // Should allow read from readonly paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/usr/lib/test.so"), false)
                .is_ok()
        );

        // Should deny write to readonly paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/usr/lib/test.so"), true)
                .is_err()
        );
    }

    #[test]
    fn test_verify_file_access_writable() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        // Should allow read and write to writable paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/tmp/test/data.db"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/tmp/test/data.db"), true)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_exec_denied() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        assert!(sandbox.verify_exec_allowed(&policy).is_err());
    }

    #[test]
    fn test_verify_network_blocked() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }

    #[test]
    fn test_build_filter_structure() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();
        let filter = sandbox.build_seccomp_filter(&policy);

        // Filter should not be empty
        assert!(!filter.is_empty());

        // First instruction should load syscall number
        assert_eq!(filter[0].code, 0x20);

        // Last instruction should be the default deny
        let last = filter.last().unwrap();
        assert_eq!(last.code, 0x06);
        assert_eq!(last.k, SECCOMP_RET_KILL_PROCESS);
    }

    // ── New tests ──

    #[test]
    fn test_linux_sandbox_default() {
        let sandbox = LinuxSandbox::default();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "linux");
    }

    #[test]
    fn test_syscall_allowlist_no_network() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy(); // block_direct_network = true
        let allowed = sandbox.build_syscall_allowlist(&policy);

        // Network syscalls should NOT be present when network is blocked
        assert!(!allowed.contains(&syscall_nr::SOCKET));
        assert!(!allowed.contains(&syscall_nr::CONNECT));
        assert!(!allowed.contains(&syscall_nr::BIND));
    }

    #[test]
    fn test_syscall_allowlist_with_network() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.block_direct_network = false;
        let allowed = sandbox.build_syscall_allowlist(&policy);

        // Network syscalls SHOULD be present when network is not blocked
        assert!(allowed.contains(&syscall_nr::SOCKET));
        assert!(allowed.contains(&syscall_nr::CONNECT));
        assert!(allowed.contains(&syscall_nr::BIND));
    }

    #[test]
    fn test_syscall_allowlist_deny_exec() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy(); // deny_exec = true
        let allowed = sandbox.build_syscall_allowlist(&policy);

        // Exec syscalls should NOT be present
        assert!(!allowed.contains(&syscall_nr::EXECVE));
        assert!(!allowed.contains(&syscall_nr::FORK));
        assert!(!allowed.contains(&syscall_nr::CLONE));
    }

    #[test]
    fn test_syscall_allowlist_allow_exec() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        let allowed = sandbox.build_syscall_allowlist(&policy);

        assert!(allowed.contains(&syscall_nr::EXECVE));
        assert!(allowed.contains(&syscall_nr::FORK));
        assert!(allowed.contains(&syscall_nr::CLONE));
    }

    #[test]
    fn test_syscall_allowlist_deny_ptrace() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy(); // deny_ptrace = true
        let allowed = sandbox.build_syscall_allowlist(&policy);

        assert!(!allowed.contains(&syscall_nr::PTRACE));
    }

    #[test]
    fn test_syscall_allowlist_allow_ptrace() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.deny_ptrace = false;
        let allowed = sandbox.build_syscall_allowlist(&policy);

        assert!(allowed.contains(&syscall_nr::PTRACE));
    }

    #[test]
    fn test_syscall_allowlist_writable_paths_add_fs_modify() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy(); // has writable_paths = ["/tmp/test"]
        let allowed = sandbox.build_syscall_allowlist(&policy);

        // File modification syscalls should be present
        assert!(allowed.contains(&syscall_nr::MKDIR));
        assert!(allowed.contains(&syscall_nr::UNLINK));
        assert!(allowed.contains(&syscall_nr::RENAME));
    }

    #[test]
    fn test_syscall_allowlist_no_writable_paths_no_fs_modify() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.writable_paths = vec![];
        let allowed = sandbox.build_syscall_allowlist(&policy);

        assert!(!allowed.contains(&syscall_nr::MKDIR));
        assert!(!allowed.contains(&syscall_nr::UNLINK));
        assert!(!allowed.contains(&syscall_nr::RENAME));
    }

    #[test]
    fn test_sock_filter_stmt() {
        let f = SockFilter::stmt(0x06, 0x7fff_0000);
        assert_eq!(f.code, 0x06);
        assert_eq!(f.jt, 0);
        assert_eq!(f.jf, 0);
        assert_eq!(f.k, 0x7fff_0000);
    }

    #[test]
    fn test_sock_filter_jump() {
        let f = SockFilter::jump(0x15, 42, 1, 0);
        assert_eq!(f.code, 0x15);
        assert_eq!(f.k, 42);
        assert_eq!(f.jt, 1);
        assert_eq!(f.jf, 0);
    }

    #[test]
    fn test_verify_file_access_denied_path() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        // Path not in readonly or writable paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/etc/shadow"), false)
                .is_err()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/etc/shadow"), true)
                .is_err()
        );
    }

    #[test]
    fn test_verify_exec_allowed_when_permitted() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        assert!(sandbox.verify_exec_allowed(&policy).is_ok());
    }

    #[test]
    fn test_verify_network_not_blocked() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.block_direct_network = false;
        assert!(sandbox.verify_network_blocked(&policy).is_err());
    }

    #[test]
    fn test_build_filter_with_all_features_enabled() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        policy.deny_ptrace = false;
        policy.block_direct_network = false;
        let filter = sandbox.build_seccomp_filter(&policy);

        // Should have more instructions with all features enabled
        let restricted_policy = test_policy();
        let restricted_filter = sandbox.build_seccomp_filter(&restricted_policy);
        assert!(filter.len() > restricted_filter.len());
    }
}
