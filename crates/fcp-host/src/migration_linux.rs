//! Linux connector subprocess checkpoint/restore helpers built around CRIU.
//!
//! The host intentionally shells out to the `criu` binary instead of binding
//! libcriu. This keeps the FCP host binary free of CRIU FFI surface area while
//! still giving the migration lane a deterministic command wrapper, bounded
//! snapshot accounting, and portable trace manifests.

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

use chrono::{DateTime, Utc};
use fcp_core::ObjectId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CRIU_DUMP_LOG: &str = "criu-dump.log";
const CRIU_RESTORE_LOG: &str = "criu-restore.log";
const DEFAULT_MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

/// Errors returned by Linux connector migration helpers.
#[derive(Debug, Error)]
pub enum LinuxMigrationError {
    /// CRIU is Linux-only.
    #[error("CRIU connector migration is only supported on Linux hosts")]
    UnsupportedPlatform,
    /// A caller supplied PID 0, which is not a dumpable process tree.
    #[error("connector pid must be non-zero")]
    InvalidPid,
    /// Snapshot image directories must start empty so stale files cannot mix
    /// with a newly captured process image.
    #[error("checkpoint images directory is not empty: {path:?}")]
    ImagesDirNotEmpty {
        /// Directory that already contained entries.
        path: PathBuf,
    },
    /// Snapshot output exceeded the configured cap.
    #[error("checkpoint size {size_bytes} bytes exceeds cap {max_snapshot_bytes} bytes")]
    SnapshotTooLarge {
        /// Actual directory size.
        size_bytes: u64,
        /// Configured maximum.
        max_snapshot_bytes: u64,
    },
    /// A file descriptor path was outside the caller's migration policy.
    #[error("file descriptor {fd} path is not allowed by migration policy: {path:?}")]
    FileDescriptorNotAllowed {
        /// Descriptor number reported by the caller.
        fd: i32,
        /// Host path rejected by policy.
        path: PathBuf,
    },
    /// Portable remap roots must not be absolute or escape upward.
    #[error("portable fd root must be relative and non-escaping: {path:?}")]
    InvalidPortableRoot {
        /// Invalid portable remap root.
        path: PathBuf,
    },
    /// The snapshot directory contained an unsupported filesystem entry.
    #[error("unsupported checkpoint image entry under {path:?}")]
    UnsupportedSnapshotEntry {
        /// Entry path.
        path: PathBuf,
    },
    /// The CRIU subprocess returned a non-zero status.
    #[error("criu {action} failed with {status}: {stderr}")]
    CriuCommandFailed {
        /// CRIU action, e.g. dump or restore.
        action: &'static str,
        /// Exit status rendered by std.
        status: String,
        /// Captured stderr.
        stderr: String,
    },
    /// Filesystem or process-spawn failure.
    #[error("io error while {context}: {source}")]
    Io {
        /// Operation being attempted.
        context: &'static str,
        /// Source IO error.
        #[source]
        source: std::io::Error,
    },
}

/// Snapshot and restore limits enforced before migration artifacts are
/// published to the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorMigrationLimits {
    /// Maximum total bytes allowed in a CRIU image directory.
    pub max_snapshot_bytes: u64,
}

impl Default for ConnectorMigrationLimits {
    fn default() -> Self {
        Self {
            max_snapshot_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
        }
    }
}

/// Host file descriptor discovered before checkpointing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFileDescriptor {
    /// Numeric file descriptor.
    pub fd: i32,
    /// Host-local path backing the descriptor.
    pub host_path: PathBuf,
}

impl OpenFileDescriptor {
    /// Build a descriptor record for policy validation.
    #[must_use]
    pub fn new(fd: i32, host_path: impl Into<PathBuf>) -> Self {
        Self {
            fd,
            host_path: host_path.into(),
        }
    }
}

/// Portable file-descriptor remap that is safe to include in trace manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDescriptorRemap {
    /// Numeric file descriptor.
    pub fd: i32,
    /// BLAKE3 digest of the original host path.
    pub source_path_digest: String,
    /// Portable path relative to the migrated connector bundle.
    pub portable_path: PathBuf,
}

/// Capability-aware descriptor remapping policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptorRemapPolicy {
    allowed_host_prefixes: Vec<PathBuf>,
    portable_root: PathBuf,
}

impl FileDescriptorRemapPolicy {
    /// Create a policy from host prefixes already authorized by connector
    /// capabilities and a portable root such as `connector-fds`.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxMigrationError::InvalidPortableRoot`] when the portable
    /// root is absolute or contains parent-directory components.
    pub fn new(
        allowed_host_prefixes: Vec<PathBuf>,
        portable_root: impl Into<PathBuf>,
    ) -> Result<Self, LinuxMigrationError> {
        let portable_root = portable_root.into();
        if !is_safe_relative_path(&portable_root) {
            return Err(LinuxMigrationError::InvalidPortableRoot {
                path: portable_root,
            });
        }
        Ok(Self {
            allowed_host_prefixes,
            portable_root,
        })
    }

    /// Remap every descriptor through the configured policy.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxMigrationError::FileDescriptorNotAllowed`] if any
    /// descriptor is outside all allowed host prefixes.
    pub fn remap_all(
        &self,
        descriptors: &[OpenFileDescriptor],
    ) -> Result<Vec<FileDescriptorRemap>, LinuxMigrationError> {
        descriptors
            .iter()
            .map(|descriptor| self.remap_one(descriptor))
            .collect()
    }

    fn remap_one(
        &self,
        descriptor: &OpenFileDescriptor,
    ) -> Result<FileDescriptorRemap, LinuxMigrationError> {
        let allowed_prefix = self
            .allowed_host_prefixes
            .iter()
            .find(|prefix| descriptor.host_path.starts_with(prefix))
            .ok_or_else(|| LinuxMigrationError::FileDescriptorNotAllowed {
                fd: descriptor.fd,
                path: descriptor.host_path.clone(),
            })?;
        let relative = descriptor
            .host_path
            .strip_prefix(allowed_prefix)
            .map_err(|_| LinuxMigrationError::FileDescriptorNotAllowed {
                fd: descriptor.fd,
                path: descriptor.host_path.clone(),
            })?;
        let portable_path = self
            .portable_root
            .join(format!("fd-{}", descriptor.fd))
            .join(relative);
        let source_path_digest = blake3::hash(descriptor.host_path.as_os_str().as_encoded_bytes())
            .to_hex()
            .to_string();

        Ok(FileDescriptorRemap {
            fd: descriptor.fd,
            source_path_digest,
            portable_path,
        })
    }
}

/// Request to checkpoint a live connector subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCheckpointRequest {
    /// Connector ID being checkpointed.
    pub connector_id: String,
    /// Root PID of the connector process tree.
    pub pid: u32,
    /// CRIU image directory. It is created if absent and must be empty.
    pub images_dir: PathBuf,
    /// Optional CRIU work directory.
    pub work_dir: Option<PathBuf>,
    /// Pass `--leave-running` to CRIU so the source connector keeps running.
    pub leave_running: bool,
    /// Pass `--shell-job` to support connector subprocesses without a separate
    /// service manager.
    pub shell_job: bool,
    /// Pass `--tcp-established` when the connector has established sockets that
    /// the caller has decided are portable.
    pub tcp_established: bool,
    /// File descriptors discovered by the host before checkpointing.
    pub open_file_descriptors: Vec<OpenFileDescriptor>,
    /// Descriptor remapping policy. When omitted, any open descriptors are
    /// rejected because no capability scope was provided.
    pub fd_policy: Option<FileDescriptorRemapPolicy>,
}

impl ConnectorCheckpointRequest {
    /// Create a checkpoint request with conservative CRIU options.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, pid: u32, images_dir: impl Into<PathBuf>) -> Self {
        Self {
            connector_id: connector_id.into(),
            pid,
            images_dir: images_dir.into(),
            work_dir: None,
            leave_running: true,
            shell_job: true,
            tcp_established: false,
            open_file_descriptors: Vec::new(),
            fd_policy: None,
        }
    }
}

/// Portable manifest returned after a successful checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorCheckpointManifest {
    /// Connector ID that was checkpointed.
    pub connector_id: String,
    /// Source process ID.
    pub source_pid: u32,
    /// Content-addressed identifier for the CRIU image directory contents.
    pub snapshot_object_id: ObjectId,
    /// Total snapshot bytes captured under the image directory.
    pub snapshot_size_bytes: u64,
    /// Capture timestamp.
    pub captured_at: DateTime<Utc>,
    /// Captured CRIU stderr for trace/replay debugging.
    pub criu_stderr: String,
    /// Capability-filtered descriptor remaps that do not expose host paths.
    pub file_descriptors_remapped: Vec<FileDescriptorRemap>,
    /// Local image directory, intentionally omitted from serialized manifests
    /// because it is host-specific.
    #[serde(skip)]
    pub local_images_dir: PathBuf,
}

/// Request to restore a connector subprocess from CRIU images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRestoreRequest {
    /// Connector ID being restored.
    pub connector_id: String,
    /// Existing CRIU image directory.
    pub images_dir: PathBuf,
    /// Optional CRIU work directory.
    pub work_dir: Option<PathBuf>,
    /// Pass `--shell-job` to mirror the dump side.
    pub shell_job: bool,
    /// Pass `--tcp-established` when restoring established sockets.
    pub tcp_established: bool,
}

impl ConnectorRestoreRequest {
    /// Create a restore request with conservative CRIU options.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, images_dir: impl Into<PathBuf>) -> Self {
        Self {
            connector_id: connector_id.into(),
            images_dir: images_dir.into(),
            work_dir: None,
            shell_job: true,
            tcp_established: false,
        }
    }
}

/// Report returned after a restore attempt succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorRestoreReport {
    /// Connector ID restored from checkpoint images.
    pub connector_id: String,
    /// PID parsed from CRIU output when available.
    pub restored_pid: Option<u32>,
    /// Restore duration in milliseconds.
    pub restore_duration_ms: u64,
    /// Captured CRIU stdout.
    pub criu_stdout: String,
    /// Captured CRIU stderr.
    pub criu_stderr: String,
}

/// CRIU-backed Linux connector migrator.
#[derive(Debug, Clone)]
pub struct CriuConnectorMigrator {
    criu_binary: PathBuf,
    limits: ConnectorMigrationLimits,
    require_linux: bool,
}

impl Default for CriuConnectorMigrator {
    fn default() -> Self {
        Self::new("criu", ConnectorMigrationLimits::default())
    }
}

impl CriuConnectorMigrator {
    /// Create a migrator using the provided CRIU binary path and limits.
    #[must_use]
    pub fn new(criu_binary: impl Into<PathBuf>, limits: ConnectorMigrationLimits) -> Self {
        Self {
            criu_binary: criu_binary.into(),
            limits,
            require_linux: true,
        }
    }

    /// Checkpoint a connector subprocess with CRIU.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxMigrationError`] if the platform is unsupported, CRIU
    /// fails, the image directory is dirty, snapshot output exceeds the cap, or
    /// descriptor remapping violates the supplied policy.
    pub fn dump_connector(
        &self,
        request: &ConnectorCheckpointRequest,
    ) -> Result<ConnectorCheckpointManifest, LinuxMigrationError> {
        self.ensure_supported_platform()?;
        if request.pid == 0 {
            return Err(LinuxMigrationError::InvalidPid);
        }
        ensure_empty_directory(&request.images_dir)?;
        let remaps = match (&request.fd_policy, request.open_file_descriptors.is_empty()) {
            (Some(policy), _) => policy.remap_all(&request.open_file_descriptors)?,
            (None, true) => Vec::new(),
            (None, false) => {
                if let Some(descriptor) = request.open_file_descriptors.first() {
                    return Err(LinuxMigrationError::FileDescriptorNotAllowed {
                        fd: descriptor.fd,
                        path: descriptor.host_path.clone(),
                    });
                }
                Vec::new()
            }
        };

        let args = dump_args(request);
        let output = self.run_criu("dump", &args)?;
        let snapshot_size_bytes = directory_size_bytes(&request.images_dir)?;
        if snapshot_size_bytes > self.limits.max_snapshot_bytes {
            return Err(LinuxMigrationError::SnapshotTooLarge {
                size_bytes: snapshot_size_bytes,
                max_snapshot_bytes: self.limits.max_snapshot_bytes,
            });
        }
        let snapshot_object_id = object_id_for_directory(&request.images_dir)?;

        Ok(ConnectorCheckpointManifest {
            connector_id: request.connector_id.clone(),
            source_pid: request.pid,
            snapshot_object_id,
            snapshot_size_bytes,
            captured_at: Utc::now(),
            criu_stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            file_descriptors_remapped: remaps,
            local_images_dir: request.images_dir.clone(),
        })
    }

    /// Restore a connector subprocess from CRIU images.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxMigrationError`] if the platform is unsupported, the
    /// image directory cannot be read, or CRIU restore fails.
    pub fn restore_connector(
        &self,
        request: &ConnectorRestoreRequest,
    ) -> Result<ConnectorRestoreReport, LinuxMigrationError> {
        self.ensure_supported_platform()?;
        let _ = fs::read_dir(&request.images_dir).map_err(|source| LinuxMigrationError::Io {
            context: "opening checkpoint images directory",
            source,
        })?;
        let started_at = Instant::now();
        let args = restore_args(request);
        let output = self.run_criu("restore", &args)?;
        let restore_duration_ms =
            u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let restored_pid = parse_restored_pid(&stdout);

        Ok(ConnectorRestoreReport {
            connector_id: request.connector_id.clone(),
            restored_pid,
            restore_duration_ms,
            criu_stdout: stdout,
            criu_stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn ensure_supported_platform(&self) -> Result<(), LinuxMigrationError> {
        if self.require_linux && !cfg!(target_os = "linux") {
            return Err(LinuxMigrationError::UnsupportedPlatform);
        }
        Ok(())
    }

    fn run_criu(
        &self,
        action: &'static str,
        args: &[OsString],
    ) -> Result<Output, LinuxMigrationError> {
        let output = Command::new(&self.criu_binary)
            .args(args)
            .output()
            .map_err(|source| LinuxMigrationError::Io {
                context: "running criu",
                source,
            })?;
        if !output.status.success() {
            return Err(LinuxMigrationError::CriuCommandFailed {
                action,
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        Ok(output)
    }

    #[cfg(test)]
    fn for_tests(criu_binary: impl Into<PathBuf>, limits: ConnectorMigrationLimits) -> Self {
        Self {
            criu_binary: criu_binary.into(),
            limits,
            require_linux: false,
        }
    }
}

fn dump_args(request: &ConnectorCheckpointRequest) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("dump"),
        OsString::from("--tree"),
        OsString::from(request.pid.to_string()),
        OsString::from("--images-dir"),
        request.images_dir.as_os_str().to_os_string(),
        OsString::from("--log-file"),
        OsString::from(CRIU_DUMP_LOG),
    ];
    if let Some(work_dir) = &request.work_dir {
        args.push(OsString::from("--work-dir"));
        args.push(work_dir.as_os_str().to_os_string());
    }
    if request.leave_running {
        args.push(OsString::from("--leave-running"));
    }
    if request.shell_job {
        args.push(OsString::from("--shell-job"));
    }
    if request.tcp_established {
        args.push(OsString::from("--tcp-established"));
    }
    args
}

fn restore_args(request: &ConnectorRestoreRequest) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("restore"),
        OsString::from("--images-dir"),
        request.images_dir.as_os_str().to_os_string(),
        OsString::from("--log-file"),
        OsString::from(CRIU_RESTORE_LOG),
    ];
    if let Some(work_dir) = &request.work_dir {
        args.push(OsString::from("--work-dir"));
        args.push(work_dir.as_os_str().to_os_string());
    }
    if request.shell_job {
        args.push(OsString::from("--shell-job"));
    }
    if request.tcp_established {
        args.push(OsString::from("--tcp-established"));
    }
    args
}

fn ensure_empty_directory(path: &Path) -> Result<(), LinuxMigrationError> {
    fs::create_dir_all(path).map_err(|source| LinuxMigrationError::Io {
        context: "creating checkpoint images directory",
        source,
    })?;
    let mut entries = fs::read_dir(path).map_err(|source| LinuxMigrationError::Io {
        context: "reading checkpoint images directory",
        source,
    })?;
    if entries
        .next()
        .transpose()
        .map_err(|source| LinuxMigrationError::Io {
            context: "reading checkpoint images directory entry",
            source,
        })?
        .is_some()
    {
        return Err(LinuxMigrationError::ImagesDirNotEmpty {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn directory_size_bytes(path: &Path) -> Result<u64, LinuxMigrationError> {
    let mut total = 0_u64;
    for file in snapshot_files(path)? {
        let len = fs::metadata(&file)
            .map_err(|source| LinuxMigrationError::Io {
                context: "reading checkpoint image metadata",
                source,
            })?
            .len();
        total = total.saturating_add(len);
    }
    Ok(total)
}

fn object_id_for_directory(path: &Path) -> Result<ObjectId, LinuxMigrationError> {
    let mut files = snapshot_files(path)?;
    files.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-HOST-CRIU-SNAPSHOT-V1");
    for file in files {
        let relative = file
            .strip_prefix(path)
            .map_err(|_| LinuxMigrationError::UnsupportedSnapshotEntry { path: file.clone() })?;
        hasher.update(relative.as_os_str().as_encoded_bytes());
        let bytes = fs::read(&file).map_err(|source| LinuxMigrationError::Io {
            context: "reading checkpoint image bytes",
            source,
        })?;
        hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(ObjectId::from_unscoped_bytes(hasher.finalize().as_bytes()))
}

fn snapshot_files(root: &Path) -> Result<Vec<PathBuf>, LinuxMigrationError> {
    let mut files = Vec::new();
    collect_snapshot_files(root, &mut files)?;
    Ok(files)
}

fn collect_snapshot_files(
    path: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), LinuxMigrationError> {
    for entry in fs::read_dir(path).map_err(|source| LinuxMigrationError::Io {
        context: "reading checkpoint images directory",
        source,
    })? {
        let entry = entry.map_err(|source| LinuxMigrationError::Io {
            context: "reading checkpoint images directory entry",
            source,
        })?;
        let file_type = entry
            .file_type()
            .map_err(|source| LinuxMigrationError::Io {
                context: "reading checkpoint image file type",
                source,
            })?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_snapshot_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        } else {
            return Err(LinuxMigrationError::UnsupportedSnapshotEntry { path });
        }
    }
    Ok(())
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn parse_restored_pid(stdout: &str) -> Option<u32> {
    stdout
        .split(|ch: char| !ch.is_ascii_digit())
        .find_map(|token| token.parse::<u32>().ok().filter(|pid| *pid != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_policy_remaps_allowed_paths_without_serializing_host_path() {
        let policy = FileDescriptorRemapPolicy::new(
            vec![PathBuf::from("/var/lib/fcp/connectors")],
            "connector-fds",
        )
        .unwrap();
        let remaps = policy
            .remap_all(&[OpenFileDescriptor::new(
                7,
                "/var/lib/fcp/connectors/github/state.db",
            )])
            .unwrap();

        assert_eq!(remaps.len(), 1);
        assert_eq!(remaps[0].fd, 7);
        assert_eq!(
            remaps[0].portable_path,
            PathBuf::from("connector-fds/fd-7/github/state.db")
        );
        let serialized = serde_json::to_string(&remaps[0]).unwrap();
        assert!(!serialized.contains("/var/lib/fcp/connectors"));
        assert!(serialized.contains("source_path_digest"));
    }

    #[test]
    fn fd_policy_rejects_unapproved_host_paths() {
        let policy =
            FileDescriptorRemapPolicy::new(vec![PathBuf::from("/var/lib/fcp")], "fds").unwrap();
        let err = policy
            .remap_all(&[OpenFileDescriptor::new(4, "/etc/passwd")])
            .unwrap_err();

        assert!(matches!(
            err,
            LinuxMigrationError::FileDescriptorNotAllowed { fd: 4, .. }
        ));
    }

    #[test]
    fn fd_policy_rejects_absolute_portable_root() {
        let err = FileDescriptorRemapPolicy::new(vec![PathBuf::from("/var/lib/fcp")], "/tmp/fds")
            .unwrap_err();

        assert!(matches!(
            err,
            LinuxMigrationError::InvalidPortableRoot { .. }
        ));
    }

    #[test]
    fn parse_restored_pid_extracts_first_nonzero_number() {
        assert_eq!(parse_restored_pid("restored pid: 4242\n"), Some(4242));
        assert_eq!(parse_restored_pid("pid=0 pid=9"), Some(9));
        assert_eq!(parse_restored_pid("no pid"), None);
    }

    #[test]
    fn dump_refuses_pid_zero() {
        let migrator = CriuConnectorMigrator::for_tests(
            "does-not-run",
            ConnectorMigrationLimits {
                max_snapshot_bytes: 1024,
            },
        );
        let dir = tempfile::tempdir().unwrap();
        let request = ConnectorCheckpointRequest::new("fcp.test.echo:utility:1.0.0", 0, dir.path());

        let err = migrator.dump_connector(&request).unwrap_err();

        assert!(matches!(err, LinuxMigrationError::InvalidPid));
    }

    #[test]
    fn dump_refuses_non_empty_images_dir_without_cleanup() {
        let migrator = CriuConnectorMigrator::for_tests(
            "does-not-run",
            ConnectorMigrationLimits {
                max_snapshot_bytes: 1024,
            },
        );
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale.img");
        fs::write(&stale, b"stale").unwrap();
        let request =
            ConnectorCheckpointRequest::new("fcp.test.echo:utility:1.0.0", 1234, dir.path());

        let err = migrator.dump_connector(&request).unwrap_err();

        assert!(matches!(err, LinuxMigrationError::ImagesDirNotEmpty { .. }));
        assert!(stale.exists());
    }

    #[cfg(unix)]
    mod unix_tests {
        use std::os::unix::fs::PermissionsExt;

        use super::*;

        fn fake_criu_script(dir: &Path, payload: &str) -> PathBuf {
            let script = dir.join("fake-criu.sh");
            let body = format!(
                r#"#!/bin/sh
set -eu
mode="$1"
shift
images_dir=""
args="$*"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --images-dir)
      images_dir="$2"
      shift 2
      ;;
    --log-file|--work-dir|--tree)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$images_dir"
printf "%s" "$args" > "$images_dir/args.txt"
if [ "$mode" = "dump" ]; then
  printf "{payload}" > "$images_dir/core.img"
  echo "dump stderr" >&2
elif [ "$mode" = "restore" ]; then
  echo "restored pid: 4321"
  echo "restore stderr" >&2
else
  echo "unknown mode" >&2
  exit 64
fi
"#
            );
            fs::write(&script, body).unwrap();
            let mut perms = fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script, perms).unwrap();
            script
        }

        #[test]
        fn dump_runs_criu_and_returns_content_addressed_manifest() {
            let tmp = tempfile::tempdir().unwrap();
            let images = tmp.path().join("images");
            let fake_criu = fake_criu_script(tmp.path(), "checkpoint-bytes");
            let migrator = CriuConnectorMigrator::for_tests(
                fake_criu,
                ConnectorMigrationLimits {
                    max_snapshot_bytes: 1024,
                },
            );
            let policy =
                FileDescriptorRemapPolicy::new(vec![tmp.path().to_path_buf()], "connector-fds")
                    .unwrap();
            let mut request =
                ConnectorCheckpointRequest::new("fcp.test.echo:utility:1.0.0", 1234, &images);
            request.open_file_descriptors =
                vec![OpenFileDescriptor::new(3, tmp.path().join("state.db"))];
            request.fd_policy = Some(policy);

            let manifest = migrator.dump_connector(&request).unwrap();

            assert_eq!(manifest.connector_id, "fcp.test.echo:utility:1.0.0");
            assert_eq!(manifest.source_pid, 1234);
            assert!(manifest.snapshot_size_bytes > 0);
            assert_eq!(manifest.file_descriptors_remapped.len(), 1);
            assert!(manifest.criu_stderr.contains("dump stderr"));
            let args = fs::read_to_string(images.join("args.txt")).unwrap();
            assert!(args.contains("--tree 1234"));
            assert!(args.contains("--leave-running"));
            assert!(args.contains("--shell-job"));
            let serialized = serde_json::to_string(&manifest).unwrap();
            assert!(!serialized.contains(tmp.path().to_str().unwrap()));
            assert_ne!(
                manifest.snapshot_object_id,
                ObjectId::from_bytes([0_u8; 32])
            );
        }

        #[test]
        fn dump_enforces_snapshot_size_cap_after_criu_succeeds() {
            let tmp = tempfile::tempdir().unwrap();
            let fake_criu = fake_criu_script(tmp.path(), "too-large");
            let migrator = CriuConnectorMigrator::for_tests(
                fake_criu,
                ConnectorMigrationLimits {
                    max_snapshot_bytes: 4,
                },
            );
            let request = ConnectorCheckpointRequest::new(
                "fcp.test.echo:utility:1.0.0",
                1234,
                tmp.path().join("images"),
            );

            let err = migrator.dump_connector(&request).unwrap_err();

            assert!(matches!(
                err,
                LinuxMigrationError::SnapshotTooLarge {
                    size_bytes,
                    max_snapshot_bytes: 4
                } if size_bytes > 4
            ));
        }

        #[test]
        fn restore_runs_criu_and_captures_output() {
            let tmp = tempfile::tempdir().unwrap();
            let images = tmp.path().join("images");
            fs::create_dir_all(&images).unwrap();
            let fake_criu = fake_criu_script(tmp.path(), "unused");
            let migrator = CriuConnectorMigrator::for_tests(
                fake_criu,
                ConnectorMigrationLimits {
                    max_snapshot_bytes: 1024,
                },
            );
            let request = ConnectorRestoreRequest::new("fcp.test.echo:utility:1.0.0", &images);

            let report = migrator.restore_connector(&request).unwrap();

            assert_eq!(report.connector_id, "fcp.test.echo:utility:1.0.0");
            assert_eq!(report.restored_pid, Some(4321));
            assert!(report.criu_stdout.contains("restored pid"));
            assert!(report.criu_stderr.contains("restore stderr"));
        }
    }
}
