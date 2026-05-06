//! macOS connector process snapshots for migration.
//!
//! Linux connector migration is handled by CRIU. macOS does not expose a CRIU
//! equivalent, so this module builds the platform-specific snapshot envelope
//! from Mach task state when a privileged task port is available, and otherwise
//! falls back to connector-emitted checkpoint bytes. The canonical bytes
//! produced here are chunked and signed with the `MachoMach` process snapshot
//! manifest format from `fcp-store`.

#![allow(unsafe_code)]

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use fcp_crypto::Ed25519SigningKey;
use fcp_raptorq::{ChunkedObjectManifest, RawChunk};
use fcp_store::{ProcessSnapshotError, ProcessSnapshotFormat, ProcessSnapshotManifest};
use mach2::kern_return::{KERN_INVALID_ADDRESS, KERN_SUCCESS, kern_return_t};
use mach2::mach_port::mach_port_deallocate;
use mach2::mach_types::task_name_t;
use mach2::message::mach_msg_type_number_t;
use mach2::port::{MACH_PORT_DEAD, MACH_PORT_NULL, mach_port_t};
use mach2::task::task_info;
use mach2::task_info::{TASK_DYLD_INFO, task_dyld_info};
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_read_overwrite, mach_vm_region};
use mach2::vm_prot::VM_PROT_READ;
use mach2::vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info_64};
use mach2::vm_types::{integer_t, mach_vm_address_t, mach_vm_size_t};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const MACOS_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;
const DEFAULT_MAX_REGIONS: usize = 512;
const DEFAULT_MAX_REGION_SAMPLE_BYTES: u64 = 4096;
const DEFAULT_MAX_TOTAL_SAMPLE_BYTES: u64 = 4 * 1024 * 1024;

/// Errors returned by the macOS migration snapshotter.
#[derive(Debug, Error)]
pub enum MacosProcessSnapshotError {
    /// Process IDs above `pid_t::MAX` cannot be passed to `task_for_pid`.
    #[error("pid {pid} cannot be represented by macOS task_for_pid")]
    InvalidPid {
        /// Rejected process ID.
        pid: u32,
    },

    /// The caller does not have a Mach task port and no graceful checkpoint
    /// bytes were supplied by the connector.
    #[error(
        "task_for_pid denied pid {pid} with kern_return {kern_return}; graceful checkpoint bytes required"
    )]
    TaskPortUnavailable {
        /// Process ID being captured.
        pid: u32,
        /// Kernel return from `task_for_pid`.
        kern_return: kern_return_t,
    },

    /// A Mach call failed after the task port was acquired.
    #[error("{call} failed with kern_return {kern_return}")]
    MachCall {
        /// Mach API name.
        call: &'static str,
        /// Kernel return code.
        kern_return: kern_return_t,
    },

    /// Canonical CBOR serialization failed.
    #[error("canonical serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// Process snapshot manifest signing failed.
    #[error("process snapshot manifest error: {0}")]
    Manifest(#[from] ProcessSnapshotError),

    /// System clock could not be represented as milliseconds since epoch.
    #[error("system clock cannot be represented as unix milliseconds")]
    Clock,

    /// A byte count could not be represented in the canonical snapshot shape.
    #[error("length overflow while encoding {field}")]
    LengthOverflow {
        /// Field whose byte length overflowed.
        field: &'static str,
    },

    /// Snapshot chunk sizes must be non-zero.
    #[error("snapshot chunk size must be non-zero")]
    ZeroChunkSize,
}

/// Bounds for Mach task-port capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosSnapshotLimits {
    /// Maximum number of VM regions to enumerate.
    pub max_regions: usize,
    /// Maximum bytes sampled from any single readable VM region.
    pub max_region_sample_bytes: u64,
    /// Maximum aggregate bytes sampled across all readable VM regions.
    pub max_total_sample_bytes: u64,
}

impl Default for MacosSnapshotLimits {
    fn default() -> Self {
        Self {
            max_regions: DEFAULT_MAX_REGIONS,
            max_region_sample_bytes: DEFAULT_MAX_REGION_SAMPLE_BYTES,
            max_total_sample_bytes: DEFAULT_MAX_TOTAL_SAMPLE_BYTES,
        }
    }
}

/// Snapshot request for one connector subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosConnectorSnapshotRequest {
    /// Stable connector instance ID.
    pub connector_id: String,
    /// Process ID of the connector subprocess.
    pub pid: u32,
    /// Optional deterministic capture timestamp used by tests and replay.
    pub captured_at_unix_ms: Option<u64>,
    /// Connector-emitted checkpoint bytes used when Mach task ports are denied.
    pub graceful_checkpoint_bytes: Option<Vec<u8>>,
}

impl MacosConnectorSnapshotRequest {
    /// Build a snapshot request for `pid`.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, pid: u32) -> Self {
        Self {
            connector_id: connector_id.into(),
            pid,
            captured_at_unix_ms: None,
            graceful_checkpoint_bytes: None,
        }
    }

    /// Override the capture timestamp for deterministic tests or replay.
    #[must_use]
    pub const fn with_captured_at_unix_ms(mut self, captured_at_unix_ms: u64) -> Self {
        self.captured_at_unix_ms = Some(captured_at_unix_ms);
        self
    }

    /// Supply connector-emitted checkpoint bytes for unprivileged fallback.
    #[must_use]
    pub fn with_graceful_checkpoint_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.graceful_checkpoint_bytes = Some(bytes);
        self
    }
}

/// macOS capture mechanism used for a snapshot payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosSnapshotCaptureMode {
    /// Process state was captured through a Mach task port.
    MachTaskPort,
    /// The connector emitted checkpoint bytes because task-port capture was not
    /// available to the host process.
    GracefulCheckpoint {
        /// `task_for_pid` return code when a Mach attempt was made.
        task_for_pid_kern_return: Option<kern_return_t>,
    },
}

/// Dyld all-image info exported by `task_info(TASK_DYLD_INFO)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosDyldInfo {
    /// Address of dyld's all-image-info structure in the target task.
    pub all_image_info_addr: u64,
    /// Byte size of dyld's all-image-info structure.
    pub all_image_info_size: u64,
    /// Dyld info format tag reported by the kernel.
    pub all_image_info_format: i32,
}

/// Bounded memory bytes captured from a readable VM region.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosMemorySample {
    /// Number of bytes stored in `bytes`.
    pub len: u64,
    /// BLAKE3 digest of `bytes`.
    pub blake3: [u8; 32],
    /// Bounded bytes read from the target task.
    pub bytes: Vec<u8>,
}

impl MacosMemorySample {
    fn new(field: &'static str, bytes: Vec<u8>) -> Result<Self, MacosProcessSnapshotError> {
        let len = u64::try_from(bytes.len())
            .map_err(|_| MacosProcessSnapshotError::LengthOverflow { field })?;
        Ok(Self {
            len,
            blake3: *blake3::hash(&bytes).as_bytes(),
            bytes,
        })
    }
}

impl fmt::Debug for MacosMemorySample {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosMemorySample")
            .field("len", &self.len)
            .field("blake3", &hex::encode(self.blake3))
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// One VM region discovered through `mach_vm_region`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosVmRegion {
    /// Region start address.
    pub address: u64,
    /// Region byte size.
    pub size: u64,
    /// Current Mach protection flags.
    pub protection: i32,
    /// Maximum Mach protection flags.
    pub max_protection: i32,
    /// Mach inheritance policy.
    pub inheritance: u32,
    /// Whether the region is shared.
    pub shared: bool,
    /// File or object offset reported by Mach.
    pub offset: u64,
    /// Mach VM behavior hint.
    pub behavior: i32,
    /// User-wired page count.
    pub user_wired_count: u16,
    /// Optional bounded bytes from the region.
    pub sample: Option<MacosMemorySample>,
}

/// Connector-emitted checkpoint bytes used when task-port capture is denied.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosGracefulCheckpoint {
    /// Number of checkpoint bytes.
    pub len: u64,
    /// BLAKE3 digest of `bytes`.
    pub blake3: [u8; 32],
    /// Canonical checkpoint payload emitted by the connector.
    pub bytes: Vec<u8>,
}

impl MacosGracefulCheckpoint {
    fn new(bytes: Vec<u8>) -> Result<Self, MacosProcessSnapshotError> {
        let len =
            u64::try_from(bytes.len()).map_err(|_| MacosProcessSnapshotError::LengthOverflow {
                field: "graceful_checkpoint",
            })?;
        Ok(Self {
            len,
            blake3: *blake3::hash(&bytes).as_bytes(),
            bytes,
        })
    }
}

impl fmt::Debug for MacosGracefulCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosGracefulCheckpoint")
            .field("len", &self.len)
            .field("blake3", &hex::encode(self.blake3))
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Canonical macOS process snapshot payload stored by the mesh object plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosProcessSnapshot {
    /// Schema version for the macOS process snapshot payload.
    pub schema_version: u16,
    /// Stable connector instance ID.
    pub connector_id: String,
    /// Original connector process ID.
    pub pid: u32,
    /// Capture timestamp in milliseconds since Unix epoch.
    pub captured_at_unix_ms: u64,
    /// Capture mechanism.
    pub capture_mode: MacosSnapshotCaptureMode,
    /// Dyld all-image metadata, present for Mach task-port captures.
    pub dyld_info: Option<MacosDyldInfo>,
    /// VM regions discovered through Mach.
    pub regions: Vec<MacosVmRegion>,
    /// Connector-emitted checkpoint payload when task-port capture is not
    /// available.
    pub graceful_checkpoint: Option<MacosGracefulCheckpoint>,
}

impl MacosProcessSnapshot {
    /// Canonical schema used for macOS process snapshot bytes.
    #[must_use]
    pub fn schema_id() -> SchemaId {
        SchemaId::new("fcp.host", "MacosProcessSnapshot", Version::new(1, 0, 0))
    }

    /// Encode the snapshot as deterministic schema-prefixed CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`MacosProcessSnapshotError::Serialization`] if canonical
    /// serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MacosProcessSnapshotError> {
        Ok(CanonicalSerializer::serialize(self, &Self::schema_id())?)
    }

    /// Chunk the canonical snapshot payload for mesh object storage.
    ///
    /// # Errors
    ///
    /// Returns [`MacosProcessSnapshotError::ZeroChunkSize`] when `chunk_size`
    /// is zero, or serialization errors if canonical bytes cannot be produced.
    pub fn chunked_payload(
        &self,
        chunk_size: u32,
    ) -> Result<(ChunkedObjectManifest, Vec<RawChunk>), MacosProcessSnapshotError> {
        if chunk_size == 0 {
            return Err(MacosProcessSnapshotError::ZeroChunkSize);
        }

        let bytes = self.canonical_bytes()?;
        Ok(ChunkedObjectManifest::from_payload(&bytes, chunk_size))
    }

    /// Sign a `ProcessSnapshotManifest` over this snapshot using
    /// `ProcessSnapshotFormat::MachoMach`.
    ///
    /// # Errors
    ///
    /// Returns serialization errors for the snapshot bytes or manifest signing
    /// errors from `fcp-store`.
    pub fn sign_process_snapshot_manifest(
        &self,
        originating_node: impl Into<String>,
        capability_token_bytes: &[u8],
        signing_key: &Ed25519SigningKey,
        chunk_size: u32,
    ) -> Result<(ProcessSnapshotManifest, Vec<RawChunk>), MacosProcessSnapshotError> {
        let (chunk_manifest, chunks) = self.chunked_payload(chunk_size)?;
        let manifest = ProcessSnapshotManifest::sign(
            self.pid,
            originating_node,
            ProcessSnapshotFormat::MachoMach,
            chunk_manifest,
            capability_token_bytes,
            signing_key,
        )?;
        Ok((manifest, chunks))
    }
}

/// macOS process snapshotter.
#[derive(Debug, Clone)]
pub struct MacosConnectorSnapshotter {
    limits: MacosSnapshotLimits,
    mach_task_capture: bool,
    chunk_size: u32,
}

impl Default for MacosConnectorSnapshotter {
    fn default() -> Self {
        Self {
            limits: MacosSnapshotLimits::default(),
            mach_task_capture: true,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

impl MacosConnectorSnapshotter {
    /// Build a snapshotter with explicit Mach capture limits.
    #[must_use]
    pub const fn new(limits: MacosSnapshotLimits) -> Self {
        Self {
            limits,
            mach_task_capture: true,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Enable or disable Mach task-port capture.
    #[must_use]
    pub const fn with_mach_task_capture(mut self, enabled: bool) -> Self {
        self.mach_task_capture = enabled;
        self
    }

    /// Set the chunk size used by [`Self::snapshot_and_sign`].
    #[must_use]
    pub const fn with_chunk_size(mut self, chunk_size: u32) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    /// Capture connector process state.
    ///
    /// # Errors
    ///
    /// Returns [`MacosProcessSnapshotError::TaskPortUnavailable`] if
    /// `task_for_pid` is denied and no graceful checkpoint bytes are supplied.
    /// Other errors represent Mach API failures or canonical serialization
    /// failures.
    pub fn snapshot_connector(
        &self,
        request: &MacosConnectorSnapshotRequest,
    ) -> Result<MacosProcessSnapshot, MacosProcessSnapshotError> {
        let captured_at_unix_ms = request
            .captured_at_unix_ms
            .map_or_else(unix_epoch_millis, Ok)?;

        if !self.mach_task_capture {
            return Self::fallback_snapshot(request, captured_at_unix_ms, None);
        }

        let task_port = match MachTaskPort::for_pid(request.pid) {
            Ok(task_port) => task_port,
            Err(MacosProcessSnapshotError::TaskPortUnavailable { kern_return, .. }) => {
                return Self::fallback_snapshot(request, captured_at_unix_ms, Some(kern_return));
            }
            Err(error) => return Err(error),
        };

        let dyld_info = task_port.dyld_info()?;
        let regions = task_port.enumerate_regions(self.limits)?;

        Ok(MacosProcessSnapshot {
            schema_version: MACOS_SNAPSHOT_SCHEMA_VERSION,
            connector_id: request.connector_id.clone(),
            pid: request.pid,
            captured_at_unix_ms,
            capture_mode: MacosSnapshotCaptureMode::MachTaskPort,
            dyld_info: Some(dyld_info),
            regions,
            graceful_checkpoint: None,
        })
    }

    /// Capture state and immediately build a signed mesh process-snapshot
    /// manifest.
    ///
    /// # Errors
    ///
    /// Returns snapshot capture, canonical serialization, or manifest signing
    /// errors.
    pub fn snapshot_and_sign(
        &self,
        request: &MacosConnectorSnapshotRequest,
        originating_node: impl Into<String>,
        capability_token_bytes: &[u8],
        signing_key: &Ed25519SigningKey,
    ) -> Result<
        (MacosProcessSnapshot, ProcessSnapshotManifest, Vec<RawChunk>),
        MacosProcessSnapshotError,
    > {
        let snapshot = self.snapshot_connector(request)?;
        let (manifest, chunks) = snapshot.sign_process_snapshot_manifest(
            originating_node,
            capability_token_bytes,
            signing_key,
            self.chunk_size,
        )?;
        Ok((snapshot, manifest, chunks))
    }

    fn fallback_snapshot(
        request: &MacosConnectorSnapshotRequest,
        captured_at_unix_ms: u64,
        task_for_pid_kern_return: Option<kern_return_t>,
    ) -> Result<MacosProcessSnapshot, MacosProcessSnapshotError> {
        let bytes = request.graceful_checkpoint_bytes.clone().ok_or_else(|| {
            MacosProcessSnapshotError::TaskPortUnavailable {
                pid: request.pid,
                kern_return: task_for_pid_kern_return.unwrap_or(KERN_SUCCESS),
            }
        })?;

        Ok(MacosProcessSnapshot {
            schema_version: MACOS_SNAPSHOT_SCHEMA_VERSION,
            connector_id: request.connector_id.clone(),
            pid: request.pid,
            captured_at_unix_ms,
            capture_mode: MacosSnapshotCaptureMode::GracefulCheckpoint {
                task_for_pid_kern_return,
            },
            dyld_info: None,
            regions: Vec::new(),
            graceful_checkpoint: Some(MacosGracefulCheckpoint::new(bytes)?),
        })
    }
}

struct MachTaskPort {
    name: mach_port_t,
}

impl MachTaskPort {
    fn for_pid(pid: u32) -> Result<Self, MacosProcessSnapshotError> {
        let pid_i32 =
            i32::try_from(pid).map_err(|_| MacosProcessSnapshotError::InvalidPid { pid })?;
        let mut task = MACH_PORT_NULL;
        // SAFETY: `mach_task_self` returns the current task send right, and
        // `task_for_pid` writes one Mach port name into the valid `task`
        // out-parameter. The pid is bounds-checked for the C `pid_t` ABI.
        let kern_return = unsafe { task_for_pid(mach_task_self(), pid_i32, &raw mut task) };
        if kern_return != KERN_SUCCESS || task == MACH_PORT_NULL || task == MACH_PORT_DEAD {
            return Err(MacosProcessSnapshotError::TaskPortUnavailable { pid, kern_return });
        }
        Ok(Self { name: task })
    }

    fn dyld_info(&self) -> Result<MacosDyldInfo, MacosProcessSnapshotError> {
        let mut dyld_info = task_dyld_info::default();
        let mut count = mach_count::<task_dyld_info>();
        // SAFETY: `self.name` is a live task port owned by this wrapper.
        // `dyld_info` points to enough initialized writable storage for the
        // TASK_DYLD_INFO flavor, and `count` is initialized to the ABI word
        // count for that structure.
        let kern_return = unsafe {
            task_info(
                self.name as task_name_t,
                TASK_DYLD_INFO,
                (&raw mut dyld_info).cast::<integer_t>(),
                &raw mut count,
            )
        };
        if kern_return != KERN_SUCCESS {
            return Err(MacosProcessSnapshotError::MachCall {
                call: "task_info(TASK_DYLD_INFO)",
                kern_return,
            });
        }

        Ok(MacosDyldInfo {
            all_image_info_addr: dyld_info.all_image_info_addr,
            all_image_info_size: dyld_info.all_image_info_size,
            all_image_info_format: dyld_info.all_image_info_format,
        })
    }

    fn enumerate_regions(
        &self,
        limits: MacosSnapshotLimits,
    ) -> Result<Vec<MacosVmRegion>, MacosProcessSnapshotError> {
        let mut regions = Vec::new();
        let mut next_address: mach_vm_address_t = 0;
        let mut total_sampled = 0_u64;

        while regions.len() < limits.max_regions {
            let mut address = next_address;
            let mut size: mach_vm_size_t = 0;
            let mut region_info = vm_region_basic_info_64::default();
            let mut count = mach_count::<vm_region_basic_info_64>();
            let mut object_name = MACH_PORT_NULL;

            // SAFETY: `self.name` is a live task port. The address, size,
            // region_info, count, and object_name pointers are valid mutable
            // out-parameters for `mach_vm_region` with
            // `VM_REGION_BASIC_INFO_64`.
            let kern_return = unsafe {
                mach_vm_region(
                    self.name,
                    &raw mut address,
                    &raw mut size,
                    VM_REGION_BASIC_INFO_64,
                    (&raw mut region_info).cast::<integer_t>(),
                    &raw mut count,
                    &raw mut object_name,
                )
            };
            deallocate_port_name(object_name);

            if kern_return == KERN_INVALID_ADDRESS {
                break;
            }
            if kern_return != KERN_SUCCESS {
                return Err(MacosProcessSnapshotError::MachCall {
                    call: "mach_vm_region",
                    kern_return,
                });
            }

            let sample = self.read_region_sample(
                address,
                size,
                region_info.protection,
                limits,
                &mut total_sampled,
            )?;
            regions.push(MacosVmRegion {
                address,
                size,
                protection: region_info.protection,
                max_protection: region_info.max_protection,
                inheritance: region_info.inheritance,
                shared: region_info.shared != 0,
                offset: region_info.offset,
                behavior: region_info.behavior,
                user_wired_count: region_info.user_wired_count,
                sample,
            });

            let Some(next) = address.checked_add(size) else {
                break;
            };
            if next <= next_address {
                break;
            }
            next_address = next;
        }

        Ok(regions)
    }

    fn read_region_sample(
        &self,
        address: mach_vm_address_t,
        size: mach_vm_size_t,
        protection: i32,
        limits: MacosSnapshotLimits,
        total_sampled: &mut u64,
    ) -> Result<Option<MacosMemorySample>, MacosProcessSnapshotError> {
        if size == 0
            || protection & VM_PROT_READ == 0
            || *total_sampled >= limits.max_total_sample_bytes
        {
            return Ok(None);
        }

        let remaining_budget = limits.max_total_sample_bytes - *total_sampled;
        let sample_size = size
            .min(limits.max_region_sample_bytes)
            .min(remaining_budget);
        if sample_size == 0 {
            return Ok(None);
        }

        let sample_capacity = usize::try_from(sample_size).map_err(|_| {
            MacosProcessSnapshotError::LengthOverflow {
                field: "region_sample",
            }
        })?;
        let mut bytes = vec![0_u8; sample_capacity];
        let data_address =
            mach_vm_address_t::try_from(bytes.as_mut_ptr() as usize).map_err(|_| {
                MacosProcessSnapshotError::LengthOverflow {
                    field: "region_sample_ptr",
                }
            })?;
        let mut out_size: mach_vm_size_t = 0;

        // SAFETY: `self.name` is a live task port. `bytes` is allocated with at
        // least `sample_size` writable bytes, and `data_address` is the address
        // of that allocation in this process. Mach writes at most `sample_size`
        // bytes and reports the initialized byte count via `out_size`.
        let kern_return = unsafe {
            mach_vm_read_overwrite(
                self.name,
                address,
                sample_size,
                data_address,
                &raw mut out_size,
            )
        };
        if kern_return != KERN_SUCCESS {
            return Ok(None);
        }

        let initialized_len =
            usize::try_from(out_size).map_err(|_| MacosProcessSnapshotError::LengthOverflow {
                field: "region_sample_out",
            })?;
        bytes.truncate(initialized_len);
        *total_sampled = total_sampled.saturating_add(out_size);

        MacosMemorySample::new("region_sample", bytes).map(Some)
    }
}

impl Drop for MachTaskPort {
    fn drop(&mut self) {
        deallocate_port_name(self.name);
    }
}

fn deallocate_port_name(name: mach_port_t) {
    if name == MACH_PORT_NULL || name == MACH_PORT_DEAD {
        return;
    }

    // SAFETY: `name` is a Mach port name returned by a Mach API in this
    // process. Deallocating the send right is the documented ownership cleanup
    // for `task_for_pid` and `mach_vm_region` object names.
    let _ = unsafe { mach_port_deallocate(mach_task_self(), name) };
}

fn mach_count<T>() -> mach_msg_type_number_t {
    mach_msg_type_number_t::try_from(mem::size_of::<T>() / mem::size_of::<integer_t>())
        .unwrap_or(mach_msg_type_number_t::MAX)
}

fn unix_epoch_millis() -> Result<u64, MacosProcessSnapshotError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MacosProcessSnapshotError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| MacosProcessSnapshotError::Clock)
}

#[cfg(test)]
mod tests {
    use fcp_store::ProcessSnapshotFormat;
    use std::error::Error;

    use super::*;

    const CAPABILITY_TOKEN: &[u8] = b"macos-snapshot-test-token";

    type TestResult = Result<(), Box<dyn Error>>;

    fn fixed_signing_key() -> Result<Ed25519SigningKey, Box<dyn Error>> {
        Ok(Ed25519SigningKey::from_bytes(&[0x42; 32])?)
    }

    #[test]
    fn graceful_checkpoint_fallback_canonical_bytes_are_stable() -> TestResult {
        let request = MacosConnectorSnapshotRequest::new("connector-alpha", 44_001)
            .with_captured_at_unix_ms(1_800_000_000_000)
            .with_graceful_checkpoint_bytes(b"checkpoint cursor=42\n".to_vec());
        let snapshotter = MacosConnectorSnapshotter::default().with_mach_task_capture(false);

        let snapshot = snapshotter.snapshot_connector(&request)?;
        let first = snapshot.canonical_bytes()?;
        let decoded = CanonicalSerializer::deserialize::<MacosProcessSnapshot>(
            &first,
            &MacosProcessSnapshot::schema_id(),
        )?;
        let second = decoded.canonical_bytes()?;

        assert_eq!(
            snapshot.capture_mode,
            MacosSnapshotCaptureMode::GracefulCheckpoint {
                task_for_pid_kern_return: None,
            }
        );
        assert_eq!(first, second);
        assert_eq!(decoded, snapshot);
        Ok(())
    }

    #[test]
    fn fallback_snapshot_signs_macho_mach_manifest() -> TestResult {
        let request = MacosConnectorSnapshotRequest::new("connector-beta", 44_002)
            .with_captured_at_unix_ms(1_800_000_000_100)
            .with_graceful_checkpoint_bytes(b"checkpoint cursor=99\n".to_vec());
        let snapshotter = MacosConnectorSnapshotter::default().with_mach_task_capture(false);
        let (snapshot, manifest, chunks) = snapshotter.snapshot_and_sign(
            &request,
            "node-macos-a",
            CAPABILITY_TOKEN,
            &fixed_signing_key()?,
        )?;
        let payload = manifest.chunk_manifest.reconstruct(&chunks)?;

        assert_eq!(manifest.original_pid, request.pid);
        assert_eq!(manifest.snapshot_format, ProcessSnapshotFormat::MachoMach);
        assert_eq!(payload, snapshot.canonical_bytes()?);
        assert!(manifest.verify_snapshot_id().is_ok());
        Ok(())
    }

    #[test]
    fn mach_capture_self_skips_when_task_port_is_unavailable() -> TestResult {
        let request = MacosConnectorSnapshotRequest::new("connector-self", std::process::id())
            .with_captured_at_unix_ms(1_800_000_000_200);
        let snapshotter = MacosConnectorSnapshotter::new(MacosSnapshotLimits {
            max_regions: 4,
            max_region_sample_bytes: 64,
            max_total_sample_bytes: 128,
        });

        match snapshotter.snapshot_connector(&request) {
            Ok(snapshot) => {
                assert_eq!(
                    snapshot.capture_mode,
                    MacosSnapshotCaptureMode::MachTaskPort
                );
                assert!(snapshot.dyld_info.is_some());
                assert!(snapshot.regions.len() <= 4);
            }
            Err(MacosProcessSnapshotError::TaskPortUnavailable { .. }) => {
                // Unentitled developer shells commonly lack task_for_pid even
                // for self; the fallback tests above pin the storage contract.
            }
            Err(error) => return Err(format!("unexpected macOS snapshot error: {error:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn zero_chunk_size_is_rejected_before_chunking() -> TestResult {
        let request = MacosConnectorSnapshotRequest::new("connector-gamma", 44_003)
            .with_captured_at_unix_ms(1_800_000_000_300)
            .with_graceful_checkpoint_bytes(b"checkpoint".to_vec());
        let snapshotter = MacosConnectorSnapshotter::default().with_mach_task_capture(false);
        let snapshot = snapshotter.snapshot_connector(&request)?;

        let Err(error) = snapshot.chunked_payload(0) else {
            return Err("zero chunk size unexpectedly succeeded".into());
        };

        assert!(matches!(error, MacosProcessSnapshotError::ZeroChunkSize));
        Ok(())
    }
}
